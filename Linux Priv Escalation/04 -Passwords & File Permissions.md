## Passwords & File permissions

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