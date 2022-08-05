# Scanning/Active-Recon

## Host Discovery

* [https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts](https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts)
* [https://www.secjuice.com/osint-detecting-enumerating-firewalls-gateways/](https://www.secjuice.com/osint-detecting-enumerating-firewalls-gateways/)

### Tools

* [fierce](https://www.kali.org/tools/fierce/) - Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It’s really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for.
* [hosthunter](https://www.kali.org/tools/hosthunter/) - This package contains a tool to efficiently discover and extract hostnames providing a large set of target IP addresses. HostHunter utilises simple OSINT techniques to map IP addresses with virtual hostnames.

### Host Command

Name Servers

```
$ host -t ns domain.com
```

Email Server

```
$ host -t mx domain.com
```

### Via ICMP

```
#ping -c 1 199.66.11.4    #1 echo request to a host
#fping -sagq 192.168.0.0/24 #Send echo requests to ranges
#nmap -PEPM -sP -n 199.66.11.0/24 #Send echo, timestamp requests and subnet mask requests
```

* s = print status after completion&#x20;
* a - show active/alive targets&#x20;
* g = generate target list&#x20;
* q = dont show per target list (we dont care about unreachables)&#x20;

### Via ARP

[arp-scan](https://www.kali.org/tools/arp-scan/) - sends arp requests to look for link layer devices&#x20;

```
#sudo arp-scan -l
#nmap -sn <Network> #ARP Requests (Discover IPs)
#netdiscover -r <Network> #ARP requests (Discover IPs)
```

### NBT Discovery

```
nbtscan -r 192.168.0.1/24 #Search in Domain
```

### [Bettercap2](https://github.com/bettercap/bettercap)

```
net.probe on/off #Activate all service discover and ARP
net.probe.mdns #Search local mDNS services (Discover local)
net.probe.nbns #Ask for NetBios name (Discover local)
net.probe.upnp # Search services (Discover local)
net.probe.wsd # Search Web Services Discovery (Discover local)
net.probe.throttle 10 #10ms between requests sent (Discover local)
```

### **Wake On Lan**

Wake On Lan is used to turn on computers through a network message. The magic packet used to turn on the computer is only a packet where a MAC Dst is provided and then it is repeated 16 times inside the same paket. Then this kind of packets are usually sent in an ethernet 0x0842 or in a UDP packet to port 9. If no \[MAC] is provided, the packet is sent to broadcast ethernet (and the broadcast MAC will be the one being repeated).

```
#WOL (without MAC is used ff:...:ff)
wol.eth [MAC] #Send a WOL as a raw ethernet packet of type 0x0847
wol.udp [MAC] #Send a WOL as an IPv4 broadcast packet to UDP port 9
## Bettercap2 can also be used for this purpose
```

## **Port-Scanning**

* **Open** port: _SYN --> SYN/ACK --> RST_
* **Closed** port: _SYN --> RST/ACK_
* **Filtered** port: _SYN --> \[NO RESPONSE]_
* **Filtered** port: _SYN --> ICMP message_

### **NMAP**&#x20;

{% content-ref url="nmap.md" %}
[nmap.md](nmap.md)
{% endcontent-ref %}

### [Masscan](https://github.com/robertdavidgraham/masscan)&#x20;

This is an Internet-scale port scanner. It can scan the entire Internet in under 5 minutes, transmitting 10 million packets per second, from a single machine.

```
# sudo apt install masscan 
# sudo masscan -p [port(s)] [IP CIDR] 
```

* \-oL \[log file]&#x20;
* \-e specify interface&#x20;
* \--rate rate of packet transmission&#x20;
* \--router-ip - specify the IP address for the appropriate gateway

### Other Port Scanning Tools

* [WebMap](https://github.com/DeadNumbers/WebMap) - Nmap Web Dashboard and Reporting
* [Scantron](https://github.com/rackerlabs/scantron) - Scantron is a distributed nmap and [Masscan](https://github.com/robertdavidgraham/masscan) scanner comprised of two components. The first is a console node that consists of a web front end used for scheduling scans and storing scan targets and results. The second component is an engine that pulls scan jobs from the console and conducts the actual scanning.
* [Scanless](https://github.com/vesche/scanless) - This is a Python 3 command-line utility and library for using websites that can perform port scans on your behalf.
* [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests
* [RustScan](https://github.com/RustScan/RustScan) - The Modern Port Scanner. **Find ports quickly (3 seconds at its fastest)**. Run scripts through our scripting engine (Python, Lua, Shell supported).
  * [https://reconshell.com/rustscan-faster-port-scanning-tool/](https://reconshell.com/rustscan-faster-port-scanning-tool/)
  * [https://tryhackme.com/room/rustscan](https://tryhackme.com/room/rustscan)
* [knocker](https://www.kali.org/tools/knocker/) - Knocker is a new, simple, and easy to use TCP security port scanner written in C, using threads. It is able to analyze hosts and the network services which are running on them.
* [unicornscan](https://www.kali.org/tools/unicornscan/) - Unicornscan is an attempt at a User-land Distributed TCP/IP stack. It is intended to provide a researcher a superior interface for introducing a stimulus into and measuring a response from a TCP/IP enabled device or network.
  * [https://linuxhint.com/unicornscan\_beginner\_tutorial/](https://linuxhint.com/unicornscan\_beginner\_tutorial/)
* [unimap](https://github.com/Edu4rdSHL/unimap) - Scan only once by IP address and reduce scan times with Nmap for large amounts of data.

{% embed url="https://youtu.be/X_DdYUeKS-o" %}

### Manual Port Checks

Netcat banner grab

```
nc -v 10.10.10.10 port
```

Telnet banner grab

```
telnet 10.10.10.10 port
```

## Application Detection

[AMAP](https://www.kali.org/tools/amap/) - Attempts to identify applications even if they are running on a different port than normal.

```
$ amap -d $ip <port>
```

## **Vulnerability Scanning**

* _BTFM: Scanning and Vulnerabilities - pg. 11_
* _Penetration Testing: Finding Vulnerabilities - pg.133_

### [Nessus](https://www.tenable.com/products/nessus/nessus-professional)&#x20;

The most popular vulnerability scanning tool on the web.

* Getting started with Nessus Guide - [https://www.tenable.com/blog/getting-started-with-nessus-on-kali-linux](https://www.tenable.com/blog/getting-started-with-nessus-on-kali-linux)
* Nessus Essentials (Home Version) - [https://www.tenable.com/products/nessus/nessus-essentials](https://www.tenable.com/products/nessus/nessus-essentials)
* [https://www.infosecmatter.com/install-nessus-and-plugins-offline-tutorial-with-pictures/](https://www.infosecmatter.com/install-nessus-and-plugins-offline-tutorial-with-pictures/)

Commands

* Install and manual download - [https://www.tenable.com/downloads/nessus](https://www.tenable.com/downloads/nessus)
  * \#sudo apt install ./Nessus-X.X.X.deb
* Start nessus service
  * \#sudo /etc/init.d/nessusd start
  * Browser > [https://localhost:8834](https://localhost:8834)

### [OpenVAS](https://github.com/greenbone/openvas)&#x20;

Open Source Vulnerability Assessment Scanner. Free and comes pre installed on Kali Linux.

* [https://docs.greenbone.net/](https://docs.greenbone.net/)
* [https://www.kali.org/tools/gvm/](https://www.kali.org/tools/gvm/)
* [https://tryhackme.com/room/openvas](https://tryhackme.com/room/openvas)

Commands

* Setup
  * \# openvas-setup
* Update Signature
  * \# openvas-feed-update
* After setup and update, check listening ports to see if OpenVAS is active
  * \#ss -lnt4
* Navigate to WebUI
  * https://127.0.0.1:9392

{% embed url="https://youtu.be/fEANg6gyV5A" %}

{% embed url="https://youtu.be/koMo_fSQGlk" %}

### **Other Scanning Tools**

* [ReconMap](https://reconmap.org/) - Reconmap is a vulnerability assessment and penetration testing (VAPT) platform. It helps software engineers and infosec pros collaborate on security projects, from planning, to implementation and documentation. The tool's aim is to go from recon to report in the least possible time.
  * [https://github.com/reconmap/reconmap](https://github.com/reconmap/reconmap)
* [Vulmap](https://github.com/vulmon/Vulmap) - Vulmap Online Local Vulnerability Scanners Project
  * [https://vulmon.com/](https://vulmon.com/)
* [Vuls](https://github.com/future-architect/vuls)  - Vulnerability scanner for Linux/FreeBSD, agent-less, written in Go.
* [Tsunami Scanner](https://github.com/google/tsunami-security-scanner) - Tsunami is a general purpose network security scanner with an extensible plugin system for detecting high severity vulnerabilities with high confidence.
* [Flan Scan](https://github.com/cloudflare/flan) - Flan Scan is a lightweight network vulnerability scanner. With Flan Scan you can easily find open ports on your network, identify services and their version, and get a list of relevant CVEs affecting your network.
* [NSE Nmap Scripts](https://nmap.org/nsedoc/) - NSE Scripts can perform various scanning techniques for enumerating services and scanning targets for specific vulnerabilities.
  * Show all available scripts and thier details
    * \# nmap --script-help default
  * Show all vuln/exploit scripts
    * \# cat script.db | grep '"vuln"\\|"exploit"'
  * Run all scripts in "vuln' category
    * \# sudo nmap --script vuln \[ip]
* [https://github.com/v3n0m-Scanner/V3n0M-Scanner](https://github.com/v3n0m-Scanner/V3n0M-Scanner) - Popular Pentesting scanner in Python3.6 for SQLi/XSS/LFI/RFI and other Vulns

## **Attack Surface Mapping/Asset Discovery**

* [Awesome Lists Collection: Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
* [https://redhuntlabs.com/](https://redhuntlabs.com/)

### [Amass](https://github.com/OWASP/Amass)&#x20;

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

* Hakluke's Amass Guide - [https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
* Dionach's Amass Guide - [https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [https://www.youtube.com/watch?v=mEQnVkSG19M](https://www.youtube.com/watch?v=mEQnVkSG19M)

### **Other Tools**

* [Intrigue](https://github.com/intrigueio/intrigue-core) - Intrigue Core is a framework for discovering attack surface. It discovers security-relevant assets and exposures within the context of projects and can be used with a human-in-the-loop running individual tasks, and/or automated through the use of workflows.
* [Odin](https://github.com/chrismaddalena/ODIN) - ODIN is Python tool for automating intelligence gathering, asset discovery, and reporting.
* [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) - AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target. You feed in a mixture of one or more domains, subdomains and IP addresses and it uses numerous techniques to find more targets.
* [Asnip](https://github.com/harleo/asnip) - Asnip retrieves all IPs of a target organization—used for attack surface mapping in reconnaissance phases.
* [Microsoft Attack Surface Analyzer](https://github.com/Microsoft/AttackSurfaceAnalyzer) - Attack Surface Analyzer is a [Microsoft](https://github.com/microsoft/) developed open source security tool that analyzes the attack surface of a target system and reports on potential security vulnerabilities introduced during the installation of software or system misconfiguration.
* [https://ivre.rocks/](https://ivre.rocks/) - IVRE is an open-source framework for network recon. It relies on open-source well-known tools ([Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), [ZGrab2](https://github.com/zmap/zgrab2), [ZDNS](https://github.com/zmap/zdns) and [Zeek (Bro)](https://www.zeek.org/)) to gather data (_network intelligence_), stores it in a database ([MongoDB](https://www.mongodb.com/) is the recommended backend), and provides tools to analyze it.

## **SSL/TLS Scanning**

* [SSL Cipher Suite Enum](https://github.com/portcullislabs/ssl-cipher-suite-enum) - Perl script to enumerate supported SSL cipher suites supported by network services (principally HTTPS).
* [sslScrape](https://github.com/cheetz/sslScrape) - strips hostnames form certs over port 443 connections
* [SSLYZE](https://github.com/nabla-c0d3/sslyze) - TLS/SSL config analyzer
* [tls\_prober](https://github.com/WestpointLtd/tls\_prober) - TLS Prober is a tool for identifying the implementation in use by SSL/TLS servers. It analyses the behaviour of a server by sending a range of probes then comparing the responses with a database of known signatures.
* [testssl.sh](https://github.com/drwetter/testssl.sh) - A free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
* [https://pentestbook.six2dez.com/enumeration/ssl-tls](https://pentestbook.six2dez.com/enumeration/ssl-tls) - List of commads to test for specific SSL/TLS Vulnerabilities.

## DNS Scanning/Enumeration

{% content-ref url="../../../web-app-hacking/mapping-the-site.md" %}
[mapping-the-site.md](../../../web-app-hacking/mapping-the-site.md)
{% endcontent-ref %}

### **Commands**

DNS Enumeration

* Host command - find ip address(s) associated with a domain\
  &#x20;◇ # host \[domain]\
  &#x20;◇ -t \[mx, txt, cname, etc] specifcy record to return. will default to A record
* DNS Zone transfer - database replication between realted dns servers.
  * where the zone file is copied from a master DNS to a slave server
  * Use the results of previous host commands to get the hostname of DNS servers
  * \> host -l \[domain name] \[dns server address]
  * \> host -l test.com ns1.test.com
    * \-l lists zones
  * Get name server command
    * host -t ns megacorpone.com | cut -d " " -f 4
  * [https://en.wikipedia.org/wiki/DNS\_zone\_transfer](https://en.wikipedia.org/wiki/DNS\_zone\_transfer)
  * [https://security.stackexchange.com/questions/10452/dns-zone-transfer-attack](https://security.stackexchange.com/questions/10452/dns-zone-transfer-attack)
* DNSRecon - DNS enumeration script - [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon)
  * \#dnsrecon -d \[domain] -t axfr
    * \-d specify domain
    * &#x20;\-t specify the type of enumeration&#x20;
  * \#dnsrecon -d \[domain] -D \~/name.txt -t brt
    * this will brute force hostnames
* DNSenum
  * \# dnsenum \[domain]

{% embed url="https://youtu.be/rQ-dc5kwRtU" %}

## **Misc Scanning tools**

* [HoneyCaught](https://github.com/aswinmguptha/HoneyCaught) - Honeypot detection tool
* [Sniffing Bear](https://github.com/MrSuicideParrot/SniffingBear) - A modular and distributed tool developed in python to scan networks for honeypots
* [https://honeyscore.shodan.io/](https://honeyscore.shodan.io/) - Shodan honeypot detector.
* [changeme](https://www.kali.org/tools/changeme/) - This package contains a default credential scanner. changeme supports the http/https, MSSQL, MySQL, Postgres, ssh and ssh w/key protocols.
* [SharpShare](https://github.com/djhohnstein/SharpShares/) - Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.
* [Phishious](https://github.com/Rices/Phishious) - An open-source Secure Email Gateway (SEG) evaluation toolkit designed for red-teamers.
* [firewalk](https://www.kali.org/tools/firewalk/) - Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a given IP forwarding device will pass.
* [ftester](https://www.kali.org/tools/ftester/) - The Firewall Tester (FTester) is a tool designed for testing firewall filtering policies and Intrusion Detection System (IDS) capabilities.

****
