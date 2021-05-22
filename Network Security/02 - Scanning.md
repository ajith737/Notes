# Scanning
[Service Name and Transport Protocol Port Number Registry
](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

[nping](https://nmap.org/nping/), [hping](http://hping.org/)
<br>
* * *
***

## hping Basics
- `hping3 -S [ip_address] -p 80 -c 4`
`-S` - Syn scan
`-p` - port
`-c` - send 4 packets
- `hping3 -S --scan 1-1000  [target_ip]`
`--scan` - for scanning listed ports. Can be given in seperated commas to. `all` can be used to scan all ports.
- `hping3 -2 --scan 1-1000 [target_ip]` for udp ping.
- `hping3 -F -P -U [target_ip] -c 3` for Xmas scan.
- `hping3 --scan 1-1000 [target_ip]` null scan.
- To find zombie candidate `hping3 -S -r -p [port] [ip_address]`
- To perform idle scan `hping3 -a [zombie_ip] -S -p [target_port] [target_IP]`
***
***

## Detect Live Hosts and Port
- `nmap -sS -p 53 [target_ip]` for syn scan against port 53.
- `nmap -sT -p 53 [target_ip]` for TCP scan against port 53.
- `nmap -sT -p 53 [target_ip]` for UDP scan against port 53.
- To find zombie candidate `nmap -O -v [ip_address]` or `sudo nmap --script ipidseq [zombie_ip] -p 135`
- `nmap -Pn -sI [zombie_ip:port] [target_ip] -p- -v` for idle scan using zombie.
- `--packet-trace` for detailed list of every packet.
- `-n` - never do DNS resolution.
- `-b` - FTP bounce scan. This will help us utilize vulnerable ftp ports and can use this ftp port scan other hosts.
- `-sN`, `-sF`, `-sX` - Null scan, FIN, Xmas scan.
XMas scan uses FIN, PSH, URG instead of SYN, RST, ACK.
- `-sA` - TCP Ack scan and can be used to determine if there is a firewall.
- `-sO` - IP protocol scan.
- `-oN` - normal output, `-oX` - XML output, `-oG` - Grepable output
- `nmap -S [zombie_ip] [target_ip] -p 23 -Pn -n -e tap0`

Other useful tools are: [Angry IP Scanner](https://angryip.org/), [masscan](https://github.com/robertdavidgraham/masscan).

***
***
## NMAP NSE
`sudo nmap --script whois-domain [target.com] -sn` 
`sudo nmap --script smb-os--discovery -p 445 [target_ip]`
`sudo nmap --script smb-enum-shares [target_ip]`
`sudo nmap --script auth [target_ip]`
`sudo nmap --script default [target_ip]`
`sudo nmap --script ipidseq [zombie_ip] -p 135`
***
***
## Service and OS detection
- ncat: `ncat [target_ip] 22`
- netcat: `nc [target_ip] 22`
- telnet: `telnet [target_ip] 22`
- `nmap -sV [options] [target_ip]`
- `nmap -O -n [target_ip`
- `nmap -A -n [target_ip`
- `./p0f -i eth0`
- `sudo nmap --script smb-os--discovery -p 445 [target_ip]`
***
***

## Firewall IDS evasion
**Fragmentation**
- `sudo nmap -sS -f [target_ip]` for fragmentation. `--mtu` for custom offset.

**Decoys**
- `sudo nmap -sS -D [Decoy#1],[Decoy#2],ME,[DECOY#3] [target_ip]`

**Timing**
- `sudo nmap -sS T[0-5] [target] --max-retries 1`

**Source Port**
- `sudo nmap -sS --source-port 53 [target]`
- `sudo nmap -sS -g 53 [target]`
[Firewall/IDS Evasion and Spoofing](https://nmap.org/book/man-bypass-firewalls-ids.html)
***
***

## Advanced Port Scanning for Firewall Evasion
- *Fragmentation*
 `sudo nmap -f [target_ip] -n -p 80 --disable-arp-ping -Pn` for fragmentation.
`sudo nmap -f -sS [target_ip] -n -p 80 --data-length 100 --disable-arp-ping` data length is used for random packets
`sudo hping3 -S -f -p 80 192.168.2.1 -c 1`

- *Decoys*
`sudo nmap -D RND:10 [target_ip] -sS -p 80 -Pn --disable-arp-ping` here it uses 10 decoys.
`sudo hping3 --rand-source -S -p 80 [target_ip] -c 3`
`sudo hping3 -a [spoof_ip] -S -p 80 [target_ip]`

- *Source Port*
`sudo nmap --source-port 53 [target_ip] -sS`
`sudo hping3 -S -s 53 --scan known [target_ip]`

- *Random data*
`sudo nmap -sS --data-length 10 [target_ip]`
`sudo hping3 -S -p 21 --data 24 [target_ip]`

- `sudo nmap --spoof-mac apple [target_ip] -p 80 -Pn --disable-arp-ping -n`
`sudo nmap --spoof-mac 0 [target_ip] -p 80 -Pn --disable-arp-ping -n` for random mac address.
`sudo nmap --spoof-mac [mac_address] [target_ip] -p 80 -Pn --disable-arp-ping -n`

- *Random hosts*
`sudo nmap -iL hosts.list -sS -p 80,443,135,5555,21,22 --randomize-hosts`hosts.list is list of hosts ip.
`sudo hping3 -l --rand-dest 192.168.2.x -I eth2`

- *Delay Time*
`sudo nmap [target_ips] -sS -p 80  --randomize-hosts -T2`
`sudo hping3 -S --scan 80,443,21,22 [target_ip] -i u10` 10 microsecond.
***
***