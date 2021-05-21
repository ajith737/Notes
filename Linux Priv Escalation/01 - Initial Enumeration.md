#### System Enumeration
`hostname`
`uname -a`
`cat /proc/version`
`cat /etc/issue`

`lscpu` to see architecture. Information about CPU.
`ps aux` to see what process are running.
* * *

#### User Enumeration
`whoami`
`id`
`sudo -l`
`cat etc\passwd | cut -d : -f 1`
`cat etc\shadow`
`cat etc\group`
`history`
`sudo .. ` escalate by typing some password.
* * *

#### Network Enumeration
`ifconfig`
`ip address`
`route`
`ip route`
`arp -a`
`ip neighbour`
`netstat`

#### Password Hunting
`grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null` or can use PASS....
`locate password | more` or `locate pass | more`
`find / -name id_rsa 2> /dev/null`