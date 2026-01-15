# Packet Analysis

## **Basics of Packet Capture**

Raw network traffic can be captured and stored for later analysis via a process called packet capture. This is a format that captures all network traffic from a given source, and organizes it by time and packet number so that all details of the traffic, from contents to metadata, can be parseable for analysis.

Raw packet captures are a staple for security analysis since they can be a complete log source, potentially storing all traffic traversing a device/interface at a given time. This granular level of detail can provide answers that no other log source can. The drawback to packet captures is the storage. When capturing all data from a given device/interface, the data can total to incredible volumes in a short time, which can cause issues when working with limited storage capacity.

**Terms**

* PCAP - Standard file format for packet captures.
* BPF - Stands for Berkeley Packet Filters. BPF syntax is used in packet analyzers like Wireshark to filter out specific packets from a capture during network analysis. It can also be used in a Linux terminal through tools like tcpdump.
* Libpcap - The most common library used by other programs to read packet capture files.
* Five-Tuple - The core set of five values that identify a TCP/IP connection: Source IP, Source Port, Destination IP, Destination Port, and Protocol.
* Promiscuous Mode - A mode for a network interface controller (NIC) that causes the controller to pass all traffic it receives to the central processing unit (CPU) rather than passing only the frames meant for that interface.
* NetFlow/IPFIX - A protocol for collecting metadata about IP traffic flows as they traverse a network device. Unlike full packet capture, it stores summary data (who, what, where, when, how much).

## Capture and Indexing Tools

<details>

<summary>Capture and Tools</summary>

* [Awesome Collection: Pcap Tools](https://github.com/caesar0301/awesome-pcaptools)
* [Arkime (Moloch)](https://github.com/arkime/arkime) - Arkime augments your current security infrastructure to store and index network traffic in standard PCAP format, providing fast, indexed access.
* [Zeek (formerly Bro)](https://zeek.org/) - A powerful network analysis framework that observes network traffic to generate high-fidelity transaction logs, file content, and fully-customized output.
* [Stenographer by Google](https://github.com/google/stenographer) - A full-packet-capture utility for buffering packets to disk for intrusion detection and incident response purposes. It provides a high-performance implementation of NIC-to-disk packet writing, handles deleting those files as disk fills up, and provides methods for reading back specific sets of packets quickly and easily.
* [CapMe](https://github.com/Security-Onion-Solutions/security-onion/wiki/CapMe) - The Web Interface for easy interaction with packet captures, located within Security Onion.
* [NTOP / ntopng](https://www.ntop.org/) - Handy and flexible tool stack that can create packet captures, netflow logs, and network probes for recording traffic of different types. `ntopng` is the modern, high-speed version of the original `ntop`.
* [Dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) **-** Tool included with Wireshark for simple capture of packet data and writing to a disk.
* [Netsniff-ng](http://netsniff-ng.org/) - A fast network analyzer based on packet mmap(2) mechanisms. It can record pcap files to disk, replay them and also do an offline and online analysis.
* _Attacking Network Protocols: Ch. 2 Capturing Application Traffic - pg. 11_

</details>

## Decrypting Encrypted Packets <a href="#decrypting-encrypted-packets" id="decrypting-encrypted-packets"></a>

<details>

<summary>Decrypting Encrypted Packets</summary>

This can be done in a few ways:

Man-in-the-middle (MITM)

* [MITM Through mitmproxy](https://mitmproxy.org/)
* [MITM Through SSLStrip](https://github.com/moxie0/sslstrip) (Note: This is a legacy technique and is largely ineffective against modern HSTS-enabled sites).

Using Keys/Secrets:

* [Using the (Pre)-Master-Secret SSLKEYLOGFILE](https://wiki.wireshark.org/TLS#Using\_the\_.28Pre.29-Master-Secret)
* [Using an RSA Private Key](https://docs.microsoft.com/en-us/archive/blogs/nettracer/decrypting-ssltls-sessions-with-wireshark-reloaded)

</details>

## Common Analysis Techniques

* **Traffic Baselining** - Establishing a pattern of "normal" network behavior (volume, protocols, times) to easily identify anomalies.
* **Beaconing Detection** - Identifying regular, periodic communication intervals often used by malware C2 (Command & Control) channels.
* **TLS Fingerprinting (JA3)** - A method for creating fingerprints for SSL/TLS client applications (like malware or valid tools) based on the fields in the Client Hello packet.
* **Protocol Hierarchy Analysis** - Examining the distribution of protocols to identify non-standard port usage (e.g., HTTP on port 443) or unexpected protocols (e.g., IRC).

## PCAP Analysis Tools

### [**Wireshark**](https://www.wireshark.org/#download)

The world’s foremost and widely-used network protocol analyzer. It lets you see what’s happening on your network at a microscopic level and is the de facto (and often de jure) standard across many commercial and non-profit enterprises, government agencies, and educational institutions.

<details>

<summary>Wireshark Resources</summary>

* Filter cheatsheet - [https://packetlife.net/media/library/13/Wireshark\_Display\_Filters.pdf](https://packetlife.net/media/library/13/Wireshark\_Display\_Filters.pdf)
* Display guide - [https://311hrs.wordpress.com/2016/04/02/costumize-column-display-in-wireshark/](https://311hrs.wordpress.com/2016/04/02/costumize-column-display-in-wireshark/)
* [https://hackertarget.com/wireshark-tutorial-and-cheat-sheet/](https://hackertarget.com/wireshark-tutorial-and-cheat-sheet/)
* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [General Wireshark Filter Reference](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
* [Full Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
* [https://hunter.jorgetesta.tech/analisis-de-red/wireshark/filtros](https://hunter.jorgetesta.tech/analisis-de-red/wireshark/filtros)
* [Customizing Wireshark – Changing Your Column Display](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [Using Wireshark – Display Filter Expressions](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [Using Wireshark: Identifying Hosts and Users](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [Using Wireshark: Exporting Objects from a Pcap](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)
* [Wireshark Tutorial: Examining Trickbot Infections](https://unit42.paloaltonetworks.com/wireshark-tutorial-examining-trickbot-infections/)
* [Wireshark Tutorial: Examining Ursnif Infections](https://unit42.paloaltonetworks.com/wireshark-tutorial-examining-ursnif-infections/)
* [https://www.hackingarticles.in/wireshark-for-pentesters-a-beginners-guide/](https://www.hackingarticles.in/wireshark-for-pentesters-a-beginners-guide/)
* _Operator Handbook: Wireshark - pg. 426_
* _Wireshark for NSM Analysis - Applied Network Security Monitoring, pg.363_

</details>

{% embed url="https://youtu.be/6ywAHXEOHZE" %}

### **TShark**

Command line version of Wireshark

{% tabs %}
{% tab title="Resources" %}
* [Beginners Guide to TShark (Part 1)](https://www.hackingarticles.in/beginners-guide-to-tshark-part-1/)
* [Beginners Guide to TShark (Part 2)](https://www.hackingarticles.in/beginners-guide-to-tshark-part-2/)
* [Beginners Guide to TShark (Part 3)](https://www.hackingarticles.in/beginners-guide-to-tshark-part-3/)
* [https://tryhackme.com/room/tshark](https://tryhackme.com/room/tshark)
{% endtab %}

{% tab title="Basic Commands" %}
* Read a file:
  ```bash
  tshark -r [filename]
  ```
* Read with a display filter:
  ```bash
  tshark -r [filename] -Y [wireshark display filter]
  ```
  * The `-Y` option specifies a display filter to help organize packet captures and filter out specific data such as protocols or host information.
* Read with specific fields output:
  ```bash
  tshark -r [filename] -Y [wireshark display filter] -T fields -e [field]
  ```
  * You can further filter the packets using the `-T fields` and `-e` option. With these you can specify different layers of filters using Wireshark syntax. `-T` determines the format of the text output of tshark, `-e` will allow you to specify different fields of a packet to be printed.
* Complex filter example:
  ```bash
  tshark -r [filename] "tcp.port == 80 || udp.port == 80"
  ```
  * Display filters also use BPF syntax, can be applied after the capture and can be extremely useful when used correctly. Display/BPF filters use primitives in the arguments (&&, ||, !).
* [https://linux.die.net/man/1/tshark](https://linux.die.net/man/1/tshark)
* [https://hackertarget.com/tshark-tutorial-and-filter-examples/](https://hackertarget.com/tshark-tutorial-and-filter-examples/)
* _BTFM: tshark - pg. 43_
* _Operator Handbook: TShark - pg.304_
* _Tshark for Packet Analysis - Applied Network Security Monitoring, pg.359_
{% endtab %}

{% tab title="Utility Commands" %}
### Merging multiple pcap files <a href="#merging-multiple-pcap-files" id="merging-multiple-pcap-files"></a>

Note: [mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html)

```bash
mergecap <directory>/*.pcap -w <directory>/capture.pcap
```

### List Unique IP Sources in Pcap <a href="#list-unique-ip-sources-in-pcap" id="list-unique-ip-sources-in-pcap"></a>

```bash
tshark -T fields -r 'capture.pcap' -e ip.src | sort -u
```

### List Unique IP Sources and Destination for HTTP traffic <a href="#list-unique-ip-sources-and-destination-for-http-traffic" id="list-unique-ip-sources-and-destination-for-http-traffic"></a>

```bash
tshark -T fields -r 'capture.pcap' -e ip.src -e ip.dst -Y "http" | sort -u
```

### Live DNS Request and Responses on WiFi <a href="#live-dns-request-and-responses-on-wifi" id="live-dns-request-and-responses-on-wifi"></a>

**Note**: Replace `wlan0` with your active interface identifier (e.g., `en0` on macOS, `Ethernet` on Windows, or `wlp2s0` on Linux).

```bash
tshark -i wlan0 -T fields -f "src port 53" -n -e dns.qry.name -e dns.resp.addr
```

### Extract All Objects/Files from Supported Protocols <a href="#extract-all-objectsfiles-from-supported-protocols" id="extract-all-objectsfiles-from-supported-protocols"></a>

Note: This will create a folder called ‘exported’ and put the results in there

```bash
tshark -r 'capture.pcap' --export-objects http,exported
tshark -r 'capture.pcap' --export-objects dicom,exported
tshark -r 'capture.pcap' --export-objects imf,exported
tshark -r 'capture.pcap' --export-objects smb,exported
tshark -r 'capture.pcap' --export-objects tftp,exported
```

### List URIs Accessed <a href="#list-uris-accessed" id="list-uris-accessed"></a>

```bash
tshark -T fields -r capture.pcap -e http.host -e ip.dst -e http.request.full_uri -Y "http.request"
```

### Get HTTP POST Requests and Output to JSON <a href="#get-http-post-requests-and-output-to-json" id="get-http-post-requests-and-output-to-json"></a>

```bash
tshark -T json -r capture.pcap -Y "http.request.method == POST"
```
{% endtab %}
{% endtabs %}

### **TCPDump**

A command line packet analysis tool.

{% tabs %}
{% tab title="Guides" %}
* [**Comprehensive Guide to tcpdump (Part 1)**](https://www.hackingarticles.in/comprehensive-guide-to-tcpdump-part-1/)
* [**Comprehensive Guide to tcpdump (Part 2)**](https://www.hackingarticles.in/comprehensive-guide-to-tcpdump-part-2/)
* [**Comprehensive Guide to tcpdump (Part 3)**](https://www.hackingarticles.in/comprehensive-guide-to-tcpdump-part-3/)
{% endtab %}

{% tab title="Basic Commands" %}
* Filter by host IP:
  ```bash
  tcpdump -r [filename.pcapng] host [IPADDRESS]
  ```
  * Display all packets transferred to and from a specified IP address.
* Write to file:
  ```bash
  tcpdump -r [filename.pcapng] -w [filename]
  ```
  * Output your results into a specified file type such as pcap, csv, or txt.
{% endtab %}

{% tab title="Filtering Traffic" %}
* Using awk and sort
  * `#sudo tcpdump -n -r File.pcap | awk -F" " '{print $3}' | sort | uniq -c | head`
* `-n` - skip dns resolution
* `-r` - read from pcap file
* `awk` - printing out desired output (the third space-separated field)
* `sort` and `uniq -c` - sort and count the number of times the first appears in the capture.
* `head` - show only the first 10 lines of the output
* Use “src host \[ip]”, “dst host \[ip]”, “port \[port]”
* [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)
* [http://alumni.cs.ucr.edu/\~marios/ethereal-tcpdump.pdf](http://alumni.cs.ucr.edu/\~marios/ethereal-tcpdump.pdf)
* [https://github.com/SergK/cheatsheat-tcpdump/blob/master/tcpdump\_advanced\_filters.txt](https://github.com/SergK/cheatsheat-tcpdump/blob/master/tcpdump\_advanced\_filters.txt)
* [https://www.andreafortuna.org/technology/networking/tcpdump-a-simple-cheatsheet/](https://www.andreafortuna.org/technology/networking/tcpdump-a-simple-cheatsheet/)
* _TCPDump for NSM Analysis - Applied Network Security Monitoring, pg.355_
{% endtab %}
{% endtabs %}

{% embed url="https://youtu.be/1lDfCRM6dWk" %}

### NGREP

Command line packet analysis tool which enables users to search for words and phrases at the network layer.

* **Basic use**
  ```bash
  ngrep -I [pcapfile]
  ```
* **Search for "POST" method**
  ```bash
  ngrep -I ngrep.pcap "POST"
  ```
* **Filters** - ngrep understands BPF syntax, which can be applied alongside the pattern match.
  ```bash
  ngrep -I ngrep.pcap "POST" host '192.168.1.1'
  ```

### Online Packet Capture Analyzers

* [APackets](https://apackets.com/) -  Web utility that can analyze pcap files to view HTTP headers and data, extract transferred binaries, files, office documents, pictures.
* [PacketTotal](https://packettotal.com/) - PacketTotal is an engine for analyzing, categorizing, and sharing .pcap files. The tool was built with the InfoSec community in mind and has applications in malware analysis and network forensics.

## Powershell Packet Capture

**Modern Alternative: PktMon (Windows 10/11)**

Recent versions of Windows include a built-in packet monitor tool called `PktMon`. This is generally preferred over custom PowerShell scripts for basic capture needs without third-party tools.

```powershell
# Start capturing all traffic on all ports
pktmon start --etw -p 0 -c 16

# Stop capture
pktmon stop

# Convert the resulting .etl log to .pcapng for Wireshark analysis
pktmon pcapng log.etl -o log.pcapng
```

#### Legacy PowerShell Script Method <a href="#pcap-collection" id="pcap-collection"></a>

\*Note: Script and pcap should be located under: C:\Windows\System32 or your user directory.

```powershell
Invoke-Command -ScriptBlock {ipconfig} -Session $s1

Invoke-Command -ScriptBlock {
$url = "https://raw.githubusercontent.com/nospaceships/raw-socket-sniffer/master/raw-socket-sniffer.ps1"
Invoke-WebRequest -Uri $url `
	-OutFile "raw-socket-sniffer.ps1"
PowerShell.exe -ExecutionPolicy bypass .\raw-socket-sniffer.ps1 `
	-InterfaceIp "[RemoteIPv4Address]" `
	-CaptureFile "capture.cap"
	} -Session $s1
```

## **Other Tools**

* [Zui (formerly Brim)](https://zui.brimdata.io/) - Desktop application to efficiently search large packet captures and Zeek logs.
* [BruteShark](https://github.com/odedshimon/BruteShark) - BruteShark is a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files, but it also capable of directly live capturing from a network interface). It includes: password extracting, building a network map, reconstruct TCP sessions, extract hashes of encrypted passwords and even convert them to a Hashcat format in order to perform an offline Brute Force attack.
* [PCredz](https://github.com/lgandx/PCredz) - This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
* [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) - NetworkMiner is an [open source](https://www.netresec.com/?page=NetworkMinerSourceCode) Network Forensic Analysis Tool (NFAT) for Windows (but also [works in Linux](https://www.netresec.com/?page=Blog\&month=2014-02\&post=HowTo-install-NetworkMiner-in-Ubuntu-Fedora-and-Arch-Linux) / [Mac OS X](https://netresec.com/?b=146F525) / [FreeBSD](https://netresec.com/?b=11C135E)). NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.

## **Legacy / Deprecated Tools**

* [Daemon Logger](https://github.com/Cisco-Talos/Daemonlogger) - Simple packet logging & soft tap daemon. Project is largely unmaintained.
* [Net-creds](https://github.com/DanMcInerney/net-creds) - Sniffs sensitive data from interface or pcap. Last updated ~2019, reliant on Python 2.
* [Chaosreader](https://www.kali.org/tools/chaosreader/) - Chaosreader traces TCP/UDP/others sessions and fetches application data. It is an older tool (Perl-based) that has largely been superseded by tools like Wireshark/TShark "Export Objects".

## **Resources**

* Sans cheatsheets for analyzing packet captures - [https://wiki.sans.blue/#!Packets.md](https://wiki.sans.blue/#!Packets.md)
* [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) - A comprehensive source for traffic analysis exercises and tutorials.
* [https://www.sans.org/reading-room/whitepapers/tools/extracting-files-network-packet-captures-36562](https://www.sans.org/reading-room/whitepapers/tools/extracting-files-network-packet-captures-36562)
* [Detecting Network Attacks with Wireshark - InfosecMatter](https://www.infosecmatter.com/detecting-network-attacks-with-wireshark/)
* Hack-the-box Packet Analysis Course - [https://academy.hackthebox.eu/course/preview/intro-to-network-traffic-analysis](https://academy.hackthebox.eu/course/preview/intro-to-network-traffic-analysis)
* [https://dfirmadness.com/case-001-pcap-analysis/](https://dfirmadness.com/case-001-pcap-analysis/)
* [https://www.antisyphontraining.com/getting-started-with-packet-decoding-w-chris-brenton/](https://www.antisyphontraining.com/getting-started-with-packet-decoding-w-chris-brenton/)
* _Packet Analysis - Applied Network Security Monitoring, pg.341_

__
