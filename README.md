## LIBPAM-NET: create/join network namespaces at login 

**libpam-net** implements two pam modules:

- **pam_newnet.so**: users belonging to the *newnet* group get a new
network namespace at login.

- **pam_usernet.so** users belonging to the *usernet* group get their own
network name at login. If a network namespace having the same name as the
username exists, pam runs the user shell in that namespace. If such a
namespace does does not exist, it is created during the login process.

### INSTALL:

get the source code, from the root of the source tree run:
```
$ autoreconf -if
$ ./configure --with-libsecuritydir=/lib/x86_64-linux-gnu/security
$ make
$ sudo make install
```

Add the rules to the pam configuration files: e.g. */etc/pam.d/sshd* or
*/etc/pam.d/login*
```
session   required  pam_newnet.so
session   required  pam_usernet.so
```

Create the groups *newnet* and *usernet* including all the users that
must be subject to one or the other service:

e.g. in /etc/group:
```
newnet:x:148:renzononet
usernet:x:149:renzousernet
```

### Usage cases.

- **pam_newnet.so**. Users in the *newnet* group can log-in through a
  network connection (e.g. by ssh) but their processes cannot communicate
(the only interface they can see is the localhost of the namespace created
at login time.
Networking can take place just between processes of the same
session).

- **pam_usernet.so**. The system administrator can create a network
  namespace for each user in *usernet* group. Each namespace must be named
  after each username.
Users will *land* in their own network namespace at
login. e.g. the sysadm can create *renzousernet*'s network namespace as
follows:

```
# ip netns add renzousernet
# ip netns exec renzousernet ip addr add 127.0.0.1/8 dev lo
# ip netns exec renzousernet tunctl -t eth0
# ...
```

- **pam_newnet.so** or **pam_usernet.so** with **cado** (see [cado on
  GitHub](https://github.com/rd235/cado). Users in *newnet* or *usernet*
which are allowed to gain **CAP_NET_ADMIN** capability can manage their
networks by themselves. They can create tap interfaces (by **tunctl** or
**vde_tunctl**), assign IP addresses, define routing etc. Users can
configure only their own network namespaces, not the real network
interfaces and services.

- **pam_newnet.so** or **pam_usernet.so** with **cado** and **vde**
  (virtual distributed ethernet). Users can connect their networks to vde
services (e.g. vde switches).

- **pam_newnet.so** and **netnsjoin** (a tool of nsutils, see [nsutils on
  GitHub](https://github.com/rd235/nsutils)). Each user can create new
namespaces (just by starting a new session), he/she can keep namespaces
alive, assign meaningful tags for an easier management, 
and later join any of their own namespaces.

