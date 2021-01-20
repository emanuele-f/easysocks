#!/usr/bin/env python3
# (C) 2021 Emanuele Faranda

import argparse
import os
import sys
import logging as log
import socket
import pexpect
import signal
import time
import tempfile
import subprocess
import psutil
from shutil import which
from contextlib import closing
from getpass import getpass
from pwd import getpwnam

# ############################################

# Maximum timeout in seconds for sockets to accept connections
CONNECT_TIMEOUT=10

# ############################################

exit_now = False
wan_iface = None
unpriv_user = None
unpriv_uid = None
redsocks = None
socks_port = None
ssh_cmd = None
redirect_port = None
redsocks_proc = None
ssh_proc = None
ssh_password = None

# ############################################

def getWan():
  with open("/proc/net/route", "r") as fin:
    line = fin.readline()

    while line:
      parts = line.split()
      if parts[1] == "00000000":
        return parts[0]

      line = fin.readline()

  assert 0, "Could not determine WAN interface"

# ############################################

def unpriv(cmd):
  if type(cmd) == str:
    return f"sudo -u {unpriv_user} {cmd}"
  else:
    return ["sudo", "-u", unpriv_user, ] + cmd

# ############################################

def killSubprocess(proc_pid):
  process = psutil.Process(proc_pid)

  for proc in process.children(recursive=True):
    proc.kill()

  process.kill()

# ############################################

def getTCPPorts(n=1, rv=[]):
  with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rv.append(s.getsockname()[1])

    if n == 1:
      return rv
    else:
      return getTCPPorts(n-1, rv)  

# ############################################

def waitTCPPort(host, port, max_wait=CONNECT_TIMEOUT):
  log.debug(f"Waiting for TCP port '{port}'...")

  start = time.time()

  while((time.time() - start) <= max_wait):
    try:
      with socket.create_connection((host, port), timeout=1):
        return True
    except OSError as ex:
      time.sleep(1)

  return False

# ############################################

def parseArgs():
  parser = argparse.ArgumentParser(prog="easy_socks")
  parser.add_argument("-u", type=str, dest="sudo_user", metavar="user", help="unprivileged user name", required=True)
  parser.add_argument("-c", type=str, dest="ssh_host", metavar="ssh host", help="the ssh host and user", required=True)
  parser.add_argument("-p", type=int, dest="ssh_port", metavar="ssh port", help="the ssh port to connect", default=22)
  parser.add_argument("-v", dest="verbose", help="enable verbose log", action="store_const", const=True, default=False)
  parser.add_argument("program", help="command to execute with args. If nothing is provided, bash is executed", nargs='*', default=[])

  args = parser.parse_args()

  return(args)

# ##############################################

def startRedsocks():
  global redsocks_proc

  # Redsocks
  redsocks_conf = """
base {
    log = "file:/dev/null";
    redirector = iptables;
}

redsocks {
    local_port = %d;
    ip = 127.0.0.1;
    port = %d;
    type = socks5;
}
""" % (redirect_port, socks_port)

  with tempfile.NamedTemporaryFile() as temp:
    os.chown(temp.name, unpriv_uid, unpriv_gid)
    temp.write(redsocks_conf.encode())
    temp.flush()

    redsocks_cmd = unpriv(["redsocks", "-c", temp.name])
    log.debug(f"Running '{' '.join(redsocks_cmd)}'...")
    redsocks_proc = subprocess.Popen(redsocks_cmd)

    log.debug(f"redsocks spawned with PID {redsocks_proc.pid}")

    if not waitTCPPort("127.0.0.1", redirect_port):
      log.critical(f"redsocks TCP port {redirect_port} did not open")
      return 1

  return 0

# ##############################################

def startNetwork():
  cmds = [
    f"ip netns add easy{socks_port}",
    f"ip link add easy{socks_port} type veth peer name easy{socks_port}b",
    f"ifconfig easy{socks_port} 172.16.1.1/24 up",
    f"ip link set easy{socks_port}b netns easy{socks_port}",
    f"ip netns exec easy{socks_port} ifconfig easy{socks_port}b 172.16.1.10/24 up",
    f"ip netns exec easy{socks_port} ifconfig lo up",
    f"ip netns exec easy{socks_port} ip route add default via 172.16.1.1",
    f"sysctl -wq net.ipv4.conf.easy{socks_port}.route_localnet=1",
    # ~ f"sysctl -wq net.ipv4.conf.easy{socks_port}.forwarding=1",
    f"sysctl -wq net.ipv4.ip_forward=1",

    f"iptables -t nat -A POSTROUTING -s 172.16.1.0/24 -o {wan_iface} -j MASQUERADE",
    f"iptables -t nat -A PREROUTING -p tcp -i easy{socks_port} -j DNAT --to-destination 127.0.0.1:{redirect_port}",
  ]

  for cmd in cmds:
    log.debug(f"[cmd] {cmd}")
    p = subprocess.Popen(cmd.split())
    rv = p.communicate()
    retcode = p.returncode

    if retcode != 0:
      log.critical(f"Command failed [{retcode}]: {rv[1]}")
      return 1

  return 0

# ##############################################

def stopNetwork():
  cmds = [
    f"iptables -t nat -D POSTROUTING -s 172.16.1.0/24 -o {wan_iface} -j MASQUERADE",
    f"iptables -t nat -D PREROUTING -p tcp -i easy{socks_port} -j DNAT --to-destination 127.0.0.1:{redirect_port}",

    f"ip netns delete easy{socks_port}",
    f"ip link del easy{socks_port}",
  ]

  for cmd in cmds:
    log.debug(f"[cmd] {cmd}")

    p = subprocess.Popen(cmd.split(), stderr=subprocess.DEVNULL)
    rv = p.communicate()
    retcode = p.returncode

# ##############################################

def startSSH():
  global ssh_proc
  global ssh_password

  if ssh_proc:
    ssh_proc.close(True)

  log.debug(f"Running '{ssh_cmd}'...")
  rv = 0

  try:
    ssh_proc = pexpect.spawn(unpriv(ssh_cmd), encoding='utf-8')
    log.debug(f"SSH spawned with PID {ssh_proc.pid}")

    ssh_proc.logfile_read = sys.stdout
    ssh_proc.expect('assword:', timeout=5)

    # NOTE: ssh_password is cached in memory
    if not ssh_password:
      ssh_password = getpass(prompt='')

    ssh_proc.sendline(ssh_password)

    # Wait for socket to be open
    if not waitTCPPort("127.0.0.1", socks_port):
      log.critical("Connection did not open, wrong password?")
      rv = 1
  except pexpect.exceptions.ExceptionPexpect as e:
    log.debug("pexpect exception %s" % e.__class__.__name__)
    rv = 1

  if rv != 0:
    ssh_proc.close(True)

  return rv

# ##############################################

def termHandler(*args):
  global exit_now

  if not exit_now:
    log.info("Terminating...")
    exit_now = True
  else:
    log.info("Exit now")
    exit(1)

# ##############################################

def main(program):
  ns_proc = None
  max_reconnect_t = 600 # 10 minutes
  reconnect_t = 5 # initial reconnect timeout
  next_ssh = 0

  # Start SSH and network
  rv = startSSH()

  if rv != 0:
    log.error("SSH connection failed")
    return rv

  stopNetwork()
  rv = startNetwork()

  if rv != 0:
    return rv

  # Start main process
  rc_conf = """
source $HOME/.bashrc
PS1="(%s) $ "
""" % (f"easy{socks_port}")

  with tempfile.NamedTemporaryFile() as temp:
    os.chown(temp.name, unpriv_uid, unpriv_gid)
    temp.write(rc_conf.encode())
    temp.flush()

    # run the program
    if not program:
      program = ['/bin/bash', "--rcfile", temp.name]

    cmd = ["ip", "netns", "exec", f"easy{socks_port}"] + unpriv(program)
    log.debug(f"Running '{' '.join(cmd)}'...")

    log.info("Starting namespace...")
    ns_proc = subprocess.Popen(cmd)

  signal.signal(signal.SIGINT, termHandler)
  signal.signal(signal.SIGTERM, termHandler)
  signal.signal(signal.SIGHUP, termHandler)

  # Monitor SSH / main process
  while not exit_now:
    time.sleep(1)

    if exit_now:
      break

    rc = ns_proc.poll()

    if rc != None:
      log.info("Namespace closed, terminating")
      rv = rc
      break

    if (not ssh_proc.isalive()) and (time.time() >= next_ssh):
      rc = startSSH()

      if rc != 0:
        log.debug("\nSSH connection failed, retrying in %d sec", reconnect_t)
        next_ssh = time.time() + reconnect_t
        reconnect_t = min(reconnect_t * 2, max_reconnect_t)
      else:
        reconnect_t = 0

  # Termination
  stopNetwork()

  ssh_proc.close(True)

  return rv

# ##############################################

if __name__ == "__main__":
  args = parseArgs()

  log.basicConfig(
    format='[%(levelname)-.1s][%(filename)s:%(lineno)s] %(message)s',
    level = log.DEBUG if args.verbose else log.INFO,
  )

  if os.geteuid() != 0:
    log.critical("This script must be run as root")
    exit(1)

  unpriv_user = args.sudo_user
  pwname = getpwnam(unpriv_user)
  unpriv_uid = pwname[2]
  unpriv_gid = pwname[3]
  log.debug(f"Unprivileged commands as uid={unpriv_uid} - gid={unpriv_gid}")

  wan_iface = getWan()
  log.debug(f"WAN interface: {wan_iface}")

  # Check programs
  if not which("ssh"):
    log.critical("Cannot find 'ssh'. Is openssh installed?")
    exit(1)

  if not which("sudo"):
    log.critical("Cannot find 'sudo'. Is sudo installed?")
    exit(1)

  redsocks = which("redsocks")
  if not redsocks:
    log.critical("Cannot find 'redsocks'. Is redsocks installed?")
    exit(1)

  # Ports
  socks_port, redirect_port = getTCPPorts(2)

  # SSH tunnel
  ssh_cmd = ["ssh", "-D", str(socks_port), "-qCNp", str(args.ssh_port), args.ssh_host]
  ssh_cmd = ' '.join(ssh_cmd)

  rv = startRedsocks()

  if rv != 0:
    log.critical("Could not start redsocks")
    exit(1)

  rv = main(args.program)

  if redsocks_proc:
    log.debug(f"Killing redsocks ({redsocks_proc.pid})")
    killSubprocess(redsocks_proc.pid)

  exit(rv)
