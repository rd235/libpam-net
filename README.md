## LIBPAM-NET: create/join network namespaces at login

**libpam-net** implements two pam modules:

- **pam_newnet.so**: users belonging to the *newnet* group get a new
network namespace at login

- **pam_usernet.so** users belonging to the *usernet* group get their own
network name at login. If a network namespace having the same name as the
username exists, pam runs the user's shell in that namespace. If such a
namespace does does not exist, it is created during the login process.

### INSTALL:

#### Get the source code:
```
git clone --recurse-submodules https://github.com/rd235/libpam-net.git
```
#### Update the source code:
```
git pull --recurse-submodules
git submodule foreach -q --recursive 'git checkout master; git pull'
```
#### Compile and install
Run the following commands from the root of the source tree:
```
mkdir build
cd build
cmake .. -DLIBSECURITYDIR=/lib/x86_64-linux-gnu/security/
make
sudo make install
```
#### Configuration
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
newnet:x:149:renzononet
usernet:x:150:renzousernet
```

### Use Cases

#### Disallowing external network access for selected users

Using **pam_newnet.so** users in the *newnet* group can log-in through a network
connection (e.g. by ssh) but their processes cannot communicate with the network
at all. The only interface they can see is an isolated loopback **lo** interface
created at login time.

##### Segregated network namespaces for selected user

Using **pam_usernet.so** the system administrator can create network namespaces
for each user in the *usernet* group. Each namespace must be named after each
username.

Users will *land* in their assigned network namespace at login. e.g. the
sysadmin can create a network namespace for user *renzousernet* as follows:

```
# ip netns add renzousernet
# ip -netns renzousernet  link set dev lo up
# ip netns exec renzousernet tunctl -t eth0
# ...
```

If the directory `/etc/netns/<username>/` exists files directly underneath it are
mounted over files in `/etc`. This can be used for overriding the DNS nameserver
settings in the user's netns.

Taking *renzousernet* as an example again, this is what you'd do:

```
# cat > /etc/netns/renzousernet/resolv.conf <<EOF
nameserver 1.2.3.4
EOF
```

This will result in `/etc/resolv.conf` being overriden when *renzousernet* logs
in.

##### User-managed unpriviledged network namespaces

- Using **pam_newnet.so** or **pam_usernet.so** together with **cado** (see
  [cado on GitHub](https://github.com/rd235/cado). Users in the *newnet* or
  *usernet* groups which are allowed to gain **CAP_NET_ADMIN** capability can
  manage their network namespaces by themselves. They can create tap interfaces
  with **tunctl** or **vde_tunctl**, assign IP addresses, define routing,
  etc. Users can only configure their own network namespace, not the real network
  interfaces and services.

- Using **pam_newnet.so** or **pam_usernet.so** together with **cado** and
  **vde** (virtual distributed ethernet) users can connect their own networks to
  vde services (e.g. vde switches).

- Using **pam_newnet.so** and **netnsjoin** (a tool of nsutils, see
  [nsutils on GitHub](https://github.com/rd235/nsutils)). Each user can create
  new namespaces (just by starting a new session), they can keep namespaces
  alive, assign meaningful tags for easier management, and later join any of
  their own namespaces.

