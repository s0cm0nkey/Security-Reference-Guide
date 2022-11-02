# NMAP

## **Links and Resources**

* Documentation and Reference
  * [https://nmap.org/book/toc.html](https://nmap.org/book/toc.html)&#x20;
  * [NSEDoc Reference Portal](https://nmap.org/nsedoc/)&#x20;
  * [https://www.amazon.com/Nmap-Network-Scanning-Official-Discovery/dp/0979958717](https://www.amazon.com/Nmap-Network-Scanning-Official-Discovery/dp/0979958717)&#x20;
  * [https://blogs.sans.org/pen-testing/files/2013/10/NmapCheatSheetv1.1.pdf](https://blogs.sans.org/pen-testing/files/2013/10/NmapCheatSheetv1.1.pdf)&#x20;
  * [https://blog.zsec.uk/nmap-rtfm/](https://blog.zsec.uk/nmap-rtfm/)&#x20;
  * [https://gtfobins.github.io/gtfobins/nmap/](https://gtfobins.github.io/gtfobins/nmap/)
  * _Operator Handbook: NMAP - pg. 222_
  * _Penetration Testing: Port Scanning with NMAP - pg.125_
* NMAP Scripting
  * [https://nmap.org/book/man-nse.html](https://nmap.org/book/man-nse.html)&#x20;
  * [Ultimate List of Nmap NSE Scripts (Interactive Spreadsheet) - InfosecMatter](https://www.infosecmatter.com/ultimate-list-of-nmap-nse-scripts-interactive-table/)&#x20;
* Nmap for pentester articles
  * [Nmap for Pentester: Host Discovery](https://www.hackingarticles.in/nmap-for-pentester-host-discovery/)
  * [Nmap for Pentester: Output Format Scan](https://www.hackingarticles.in/nmap-for-pentester-output-format-scan/)
  * [Nmap for Pentester: Vulnerability Scan](https://www.hackingarticles.in/nmap-for-pentester-vulnerability-scan/)
  * [Nmap for Pentester: Timing Scan](https://www.hackingarticles.in/nmap-for-pentester-timing-scan/)
  * [Nmap for Pentester: Ping Scan](https://www.hackingarticles.in/nmap-for-pentester-ping-scan/)
  * [Nmap for Pentester: Port Status](https://www.hackingarticles.in/nmap-for-pentester-port-status/)
  * [Nmap for Pentester: Password Cracking](https://www.hackingarticles.in/nmap-for-pentester-password-cracking/)
* Training
  * [https://tryhackme.com/room/nmap01](https://tryhackme.com/room/nmap01)
  * [https://tryhackme.com/room/furthernmap](https://tryhackme.com/room/furthernmap)

## **Commands**

### Handy options&#x20;

* \-sS - Stealthy SYN scan
* \-sV - Loud version scan, will make complete connection, grab banner, and version info&#x20;
* \-A - run service enumeration scripts&#x20;
* \-oA \[filename] - Print nmap output to file name&#x20;
* \-Pn - disable ping. Most big companies will have ping diabled on most external entities&#x20;
* \-n - disable DNS resolution, helps speed up scan

### Basic scan&#x20;

```
#nmap [IP Address] or nmap [website.com]
```

### Specify ports&#x20;

Top Ports

```
#nmap [IP Address] --top-ports 
```

All Ports

```
#nmap -p- [IP Address] 
```

UDP Ports

```
#nmap -sU [IP Address]
```

TCP Ports (Connect Scan)

```
#nmap -sT [IP Address]
```

Quick TCP Scan

```
nmap -sC -sV -vv -oA quick 10.10.10.10
```

Quick UDP Scan

```
nmap -sU -sV -vv -oA quick_udp 10.10.10.10
```

Full TCP Scan

```
nmap -sC -sV -p- -vv -oA full 10.10.10.10
```

### Port knock

```
for x in 7000 8000 9000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x 10.10.10.10; done
```

### Network Sweep&#x20;

Broad scans then specific on hosts of interest&#x20;

```
#nmap -sn 10.0.0.1-254 
```

### Banner grabbing&#x20;

```
nmap -sV -v -p- [IP Address]
```

### OS scan&#x20;

```
#sudo nmap -O -sV [IP Address]
```

* \--osscan-guess provides a faster, more aggressive scan, which is useful when Nmap retrieves close to 100% OS detection. However, aggressive scanning may result in missing some ports.
* \--osscan-limit is an option used to limit what targets to scan. This option is useful when you have a large range of IPs to scan.

## NSE - Nmap scripting Engine&#x20;

Nmap Scripting Engine (NSE) allows users to run custom and community generated scripts. ◇ stored in /usr/share/nmap/scripts&#x20;

The most basic way of running Nmap scripts is by using the -sC option, invoking the default scripts.

```
#nmap -sV -sC 192.168.1.1
```

To run a specific script against a target, the name of the script must be specified in the command.&#x20;

```
#nmap -sV --script http-sql-injection.nse 192.168.1.1
```

As well as specifying the name of the script, it is sometimes necessary to specify arguments to achieve the desired behaviour

```
#nmap --script http-wordpress-brute.nse --script-args ‘passdb=passwords.txt’ 192.168.1.1
#nmap -sV --script mysql-dump-hashes 10.102.9.39 --script-args='username=root,password=abc123'
```

Run all NSE scripts against found ports

```
$nmap -Pn -sV -O -pT:{TCP ports found},U:{UDP ports found} --script *vuln* $ip
```

### [vulscan](https://github.com/scipag/vulscan)&#x20;

Advanced vulnerability scanning with Nmap NSE

```
$ mkdir /usr/share/nmap/scripts/vulnscan
$ cd /usr/share/nmap/scripts/vulnscan
$ git clone https://github.com/scipag/vulscan.git
$ nmap -sS -sV --script=/usr/share/nmap/scripts/vulnscan/vulscan.nse $ip
```

* [https://hakin9.org/vulscan-advanced-vulnerability-scanning-with-nmap-nse/](https://hakin9.org/vulscan-advanced-vulnerability-scanning-with-nmap-nse/)
* [https://www.computec.ch/projekte/vulscan/](https://www.computec.ch/projekte/vulscan/)

## IDS and IPS Evasion

****[**https://book.hacktricks.xyz/pentesting/pentesting-network/ids-evasion**](https://book.hacktricks.xyz/pentesting/pentesting-network/ids-evasion)****

### **TTL Manipulation**

Send some packets with a TTL enough to arrive to the IDS/IPS but not enough to arrive to the final system. And then, send another packets with the same sequences as the other ones so the IPS/IDS will think that they are repetitions and won't check them, but indeed they are carrying the malicious content.

**Nmap option:** `--ttlvalue <value>`

### Avoiding signatures

Just add garbage data to the packets so the IPS/IDS signature is avoided.

**Nmap option:** `--data-length 25`

### **Fragmented Packets**

Just fragment the packets and send them. If the IDS/IPS doesn't have the ability to reassemble them, they will arrive to the final host.

**Nmap option:** `-f`

### **Invalid** _**checksum**_

Sensors usually don't calculate checksum for performance reasons. _****_ So an attacker can send a packet that will be **interpreted by the sensor but rejected by the final host.** Example:Send a packet with the flag RST and a invalid checksum, so then, the IPS/IDS may thing that this packet is going to close the connection, but the final host will discard the packet as the checksum is invalid.

### **Uncommon IP and TCP options**

A sensor might disregard packets with certain flags and options set within IP and TCP headers, whereas the destination host accepts the packet upon receipt.

### **Overlapping**

It is possible that when you fragment a packet, some kind of overlapping exists between packets (maybe first 8 bytes of packet 2 overlaps with last 8 bytes of packet 1, and 8 last bytes of packet 2 overlaps with first 8 bytes of packet 3). Then, if the IDS/IPS reassembles them in a different way than the final host, a different packet will be interpreted. Or maybe, 2 packets with the same offset comes and the host has to decide which one it takes.

* **BSD**: It has preference for packets with smaller _offset_. For packets with same offset, it will choose the first one.
* **Linux**: Like BSD, but it prefers the last packet with the same offset.
* **First** (Windows): First value that comes, value that stays.
* **Last** (cisco): Last value that comes, value that stays.

## Video Instruction

Hackersploit has one of the best video series on using NMAP.

{% embed url="https://youtu.be/5MTZdN9TEO4" %}

{% embed url="https://youtu.be/VFJLMOk6daQ" %}

{% embed url="https://youtu.be/OUQkCAHdX_g" %}
