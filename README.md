easysocks is an helper script to easily tunnel programs via SSH SOCKSv5.
By using linux network namespaces, it does not require any additional configuration (e.g. no `http_proxy` env variable setup).

After running:

```
./easysocks.py -u emanuele -c admin@192.168.1.1
```

A shell is started inside a linux network namespace. Any TCP connection run inside the shell will be tunneled via the SSH server.

E.g:

```
(easy41275) $ curl https://wtfismyip.com/text
```

will return the IP address of the machine where the SSH server is running.

Requirements
------------

The following dependencies are required:
  - `redsocks`
  - `python-pexpect`
  - `python-psutil`

The ssh server must have the dynamic forwarding enabled:
  - `AllowTcpForwarding yes` for openssh
  - `/ip ssh set forwarding-enabled=local` on RouterOS

Notes
-----

  - Any protococol other than TCP (e.g. DNS queries, ping) will *not* be tunneled! It will go straight out of your machine.
  - An SSH server with password autentication is required
  - The SSH server should be already known (should be in `.ssh/known_hosts`)
  - The SSH password is stored in memory as easysocks monitors the SSH connection and restarts it when necessary

How it Works
------------

1. an SSH connection to the remote SSH server is enstablished and a local SOCKSv5 socket is open
2. `redsocks` is started to use the SOCKSv5 socket
3. a new network namespace is created
4. `iptables` is used to redirect all the TCP connections of the namespace to `redsocks`
5. a shell is run into the network namespace

TODO
----

- Support multiple instances by randomizing veth interface address (currently `172.16.1.1`)
- Allow custom ssh options to be specified
- Allow custom redsocks options to be specified
- Support public key ssh connections
