# Reconnaissance and Scanning

## Passive Reconnaissance

This section focuses on the very first part of a penetration test: Passive Reconnaissance. This is where you use all the tools and resources at your disposal to gather up all of the information you can on your target, without interacting with the target in anyway (no scanning).

For more tools and resources on intelligence gathering outside of the below frameworks, please see the OSINT section under Cyber Intelligence.

After your passive reconnaissance phase, the next step is active scanning of your target. This usually involves port scanning and scanning for any vulnerabilities that your target might have, preferably with out them noticing. Active scanning does have direct interaction with your target and does run the risk of being detected. There are ways to subtle scan your target and not draw too much attention. This can include slowing the rate of your scanning or performing them in such a way as to not create a full connection request that would trigger any defensive alerts.

{% content-ref url="../../cyber-intelligence/osint/" %}
[osint](../../cyber-intelligence/osint/)
{% endcontent-ref %}

For ease of collection, there are many Recon Frameworks available that can gather intel from multiple sources and leverage multiple tools. They are a great way to save time on your Recon tasks.

{% hint style="info" %}
Note: Many Recon Frameworks have both passive and active reconnaissance capabilities.
{% endhint %}

{% content-ref url="recon-frameworks.md" %}
[recon-frameworks.md](recon-frameworks.md)
{% endcontent-ref %}

* [https://tryhackme.com/room/passiverecon](https://tryhackme.com/room/passiverecon)
* [https://tryhackme.com/room/redteamrecon](https://tryhackme.com/room/redteamrecon)
* _Penetration Testing: Information Gathering - pg.113_

## Active Recon and Scanning

The following section will contain scanning tools and resources such as port scanners, vulnerability scanners, and so much more!

* [https://tryhackme.com/room/activerecon](https://tryhackme.com/room/activerecon)

### Attack Surface Mapping and Discovery

Attack Surface Mapping is the process of discovering, identifying, and analyzing all potential attack vectors on an organization’s IT infrastructure. This helps to identify vulnerabilities and threats to the system, as well as helping to decide how best to protect the system from malicious attack and exploitation. Attack surface mapping involves analyzing the assets and services available on a network, determining the boundaries of the system, and looking for potential attack vectors and vulnerabilities.

The first step in attack surface mapping is asset discovery. This involves gathering information about the system, including the hardware, software, and services that are running on the network. This includes both internal and external assets, such as web applications, databases, and other services. This information can be gathered manually, or with the help of automated tools.

The next step is to identify the attack vectors. Attack vectors are the various methods and techniques attackers can use to gain access to the network and its services. These include physical access, remote access, phishing attacks, malware, and social engineering. Once the attack vectors have been identified, the security team can then analyze them to determine the potential for exploitation.

The third step is to analyze the attack vectors and identify any vulnerabilities. This involves looking for any weaknesses in the system that could be exploited by an attacker. This can include weak passwords, unpatched software, and insecure configurations. Once the vulnerabilities have been identified, the security team can then decide on the best course of action to protect the system from potential attacks.

* [Awesome Lists Collection: Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
* [https://cheatsheetseries.owasp.org/cheatsheets/Attack\_Surface\_Analysis\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Attack\_Surface\_Analysis\_Cheat\_Sheet.html)
* [https://redhuntlabs.com/](https://redhuntlabs.com/)
* [https://github.com/hasr00t/Frameworthy](https://github.com/hasr00t/Frameworthy) - The best collection of Attack Surface Management tooling out there.
  * Shout out to @hasr00t and thier amazing ASM Class.

{% hint style="info" %}
Many Recon Frameworks can be excellent for Attack Surface Management.
{% endhint %}

{% content-ref url="recon-frameworks.md" %}
[recon-frameworks.md](recon-frameworks.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Amass" %}
### [Amass](https://github.com/OWASP/Amass)&#x20;

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

* Hakluke's Amass Guide - [https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
* Dionach's Amass Guide - [https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [https://medium.com/@nynan/automated-and-continuous-recon-attack-surface-management-amass-track-and-db-fabcaffce3c3](https://medium.com/@nynan/automated-and-continuous-recon-attack-surface-management-amass-track-and-db-fabcaffce3c3)
* [https://www.youtube.com/watch?v=mEQnVkSG19M](https://www.youtube.com/watch?v=mEQnVkSG19M)
{% endtab %}

{% tab title="Project Discovery" %}
### [projectdiscovery.io](https://projectdiscovery.io/#/)

&#x20;Collection of open source tools for attack surface management or Bug Bounties.

* [nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner based on simple YAML based DSL.
  * [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  * [https://github.com/projectdiscovery/nuclei-docs](https://github.com/projectdiscovery/nuclei-docs)
* [subfinder](https://github.com/projectdiscovery/subfinder) - Subfinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.
  * To get better results remember to use api keys. The following need them, [Binaryedge](https://binaryedge.io/), [C99](https://api.c99.nl/), [Certspotter](https://sslmate.com/certspotter/api/), [Chinaz](http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi), [Censys](https://censys.io/), [Chaos](https://chaos.projectdiscovery.io/), [DnsDB](https://api.dnsdb.info/), [Fofa](https://fofa.so/static\_pages/api\_help), [Github](https://github.com/), [Intelx](https://intelx.io/), [Passivetotal](http://passivetotal.org/), [Robtex](https://www.robtex.com/api/), [SecurityTrails](http://securitytrails.com/), [Shodan](https://shodan.io/), [Spyse](https://spyse.com/), [Threatbook](https://x.threatbook.cn/en), [Virustotal](https://www.virustotal.com/), [Zoomeye](https://www.zoomeye.org/)
  * API key file is located at $HOME/.config/subfinder/provider-config.yaml and the github has an example
* [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests
* [httpx](https://github.com/projectdiscovery/httpx) - httpx is a fast and multi-purpose HTTP toolkit allows to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads.
* [proxify](https://github.com/projectdiscovery/proxify) - Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
* [dnsx](https://github.com/projectdiscovery/dnsx) - dnsx is a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.
{% endtab %}

{% tab title="OSINT for ASM" %}
* URL: [https://www.runzero.com/](https://www.runzero.com/) About: runZero is a network discovery and asset inventory platform that uncovers every network in use and identifies every device connected–without credentials. \*\* Free Trial is available. \*\*
* [https://www.reconness.com/](https://www.reconness.com/) About: ReconNess helps you to run and keep all your recon in the same place allowing you to focus only on the potentially vulnerable targets without distraction and without required a lot of bash skill or programing skill in general.
* [https://github.com/yogeshojha/rengine](https://github.com/yogeshojha/rengine) About: reNgine is a web application reconnaissance suite with focus on a highly configurable streamlined recon process via Engines, recon data correlation, continuous monitoring, recon data backed by a database, and a simple yet intuitive User Interface. With features such as sub-scan, deeper co-relation, report generation, etc. reNgine aims to fix the gap in the traditional recon tools and probably a better alternative for existing commercial tools.\
  reNgine makes it easy for penetration testers and security auditors to gather reconnaissance data with bare minimal configuration.
* [https://github.com/slithery0/eReKon](https://github.com/slithery0/eReKon) About: Web reconnaissance tool, only available in dark mode. Provides subdomain scanning, port scanning, version fingerprinting and screenshots of web applications. \
  \*\* While it appears there is some development being done, the overall application appears to be under development still and should be used with caution. \*\*
{% endtab %}

{% tab title="ASM Frameworks" %}
* [https://github.com/archerysec/archerysec](https://github.com/archerysec/archerysec) About: ArcherySec allow to interact with continuous integration/continuous delivery (CI/CD) toolchains to specify testing, and control the release of a given build based on results. Its include prioritization functions, enabling you to focus on the most critical vulnerabilities. ArcherySec uses popular opensource tools to perform comprehensive scanning for web application and network. The developers can also utilize the tool for implementation of their DevOps CI/CD environment.
  * [https://www.archerysec.com/](https://www.archerysec.com/)&#x20;
* [https://github.com/microsoft/AttackSurfaceAnalyzer](https://github.com/microsoft/AttackSurfaceAnalyzer) About: Attack Surface Analyzer is a Microsoft developed open source security tool that analyzes the attack surface of a target system and reports on potential security vulnerabilities introduced during the installation of software or system misconfiguration.
* [https://github.com/vmware-labs/attack-surface-framework](https://github.com/vmware-labs/attack-surface-framework) About: ASF aims to protect organizations acting as an attack surface watchdog, provided an “Object” which might be a: Domain, IP address or CIDR (Internal or External), ASF will discover assets/subdomains, enumerate their ports and services, track deltas and serve as a continuous and flexible attacking and alerting framework leveraging an additional layer of support against 0 day vulnerabilities with publicly available POCs.
* [https://github.com/superhedgy/AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) About: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target. You feed in a mixture of one or more domains, subdomains and IP addresses and it uses numerous techniques to find more targets. It enumerates subdomains with bruteforcing and passive lookups, Other IPs of the same network block owner, IPs that have multiple domain names pointing to them and so on.\
  Once the target list is fully expanded it performs passive reconnaissance on them, taking screenshots of websites, generating visual maps, looking up credentials in public breaches, passive port scanning with Shodan/Censys and scraping employees from LinkedIn.
* [https://github.com/pry0cc/axiom](https://github.com/pry0cc/axiom) About: Axiom is a dynamic infrastructure framework to efficiently work with multi-cloud environments, build and deploy repeatable infrastructure focussed on offensive and defensive security.\
  Axiom works by pre-installing your tools of choice onto a 'base image', and then using that image to deploy fresh instances. From there, you can connect and instantly gain access to many tools useful for both bug hunters and pentesters. With the power of immutable infrastructure, most of which is done for you, you can just spin up 15 boxes, perform a distributed nmap/ffuf/screenshotting scan, and then shut them down.\
  Axiom supports several cloud providers, eventually, axiom should be completely cloud agnostic allowing unified control of a wide variety of different cloud environments with ease. Currently, DigitalOcean, IBM Cloud, Linode, Azure and AWS are officially supported providers. GCP isnt supported but is partially implemented and on the roadmap.
* [https://github.com/riskprofiler/CloudFrontier](https://github.com/riskprofiler/CloudFrontier) About: Monitor the internet attack surface of various public cloud environments. Currently supports AWS, GCP, Azure, DigitalOcean and Oracle Cloud. \
  \*\* It should be noted that this project has not been updated in some time and there are open issues. \*\*
* [https://github.com/Findomain/Findomain](https://github.com/Findomain/Findomain) About: The complete solution for domain recognition. Supports screenshoting, port scan, HTTP check, data import from other tools, subdomain monitoring, alerts via Discord, Slack and Telegram, multiple API Keys for sources and much more.
* [https://core.intrigue.io/](https://core.intrigue.io/) About: Intrigue Core is a framework for discovering attack surface. It discovers security-relevant assets and exposures within the context of projects and can be used with a human-in-the-loop running individual tasks, and/or automated through the use of workflows. With a flexible entity model and an incredibly deep enrichment system, it is the most full-featured attack surface discovery framework of its kind.\
  \*\* A slack channel is available for support. Also, as of October 1, 2021, this component of the Intrigue project is no longer actively maintained on Github, and the code in Github has been re-licensed under the terms of the Mandiant Limited Open Source License Agreement. \*\*
* [https://ivre.rocks/](https://ivre.rocks/) - IVRE is an open-source framework for network recon. It relies on open-source well-known tools ([Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), [ZGrab2](https://github.com/zmap/zgrab2), [ZDNS](https://github.com/zmap/zdns) and [Zeek (Bro)](https://www.zeek.org/)) to gather data (_network intelligence_), stores it in a database ([MongoDB](https://www.mongodb.com/) is the recommended backend), and provides tools to analyze it.
{% endtab %}

{% tab title="Other Tools" %}
* [Odin](https://github.com/chrismaddalena/ODIN) - ODIN is Python tool for automating intelligence gathering, asset discovery, and reporting.
* [Asnip](https://github.com/harleo/asnip) - Asnip retrieves all IPs of a target organization—used for attack surface mapping in reconnaissance phases.
{% endtab %}
{% endtabs %}

### Host/Asset discovery

Once on or apart of a target network we can perform a more detailed round of enumeration and discovery. By directly interacting with local network applications, host discovery can be used to identify vulnerable systems, services, and network topology.

Once the active devices on the network have been identified, the penetration tester can move on to the next steps in the penetration test process, such as vulnerability analysis and exploitation.

Host discovery can be performed by a few handy tools as well as command to enumerate hosts via various services.

* [https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts](https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts)
* [https://www.secjuice.com/osint-detecting-enumerating-firewalls-gateways/](https://www.secjuice.com/osint-detecting-enumerating-firewalls-gateways/)
* [fierce](https://www.kali.org/tools/fierce/) - Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It’s really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for.
* [hosthunter](https://www.kali.org/tools/hosthunter/) - This package contains a tool to efficiently discover and extract hostnames providing a large set of target IP addresses. HostHunter utilises simple OSINT techniques to map IP addresses with virtual hostnames.

{% tabs %}
{% tab title="DHCP" %}
```
nmap --script broadcast-dhcp-discover
```
{% endtab %}

{% tab title="DNS" %}
AD-DS (Active Directory Domain Services) rely on DNS SRV RR (service location resource records). Those records can be queried to find the location of some servers: the global catalog, LDAP servers, the Kerberos KDC and so on.

nslookup is a DNS client that can be used to query SRV records. It usually comes with the [https://packages.debian.org/buster/dnsutils](https://packages.debian.org/buster/dnsutils) package.

```
# find the PDC (Principal Domain Controller)
nslookup -type=srv _ldap._tcp.pdc._msdcs.$FQDN_DOMAIN
​
# find the DCs (Domain Controllers)
nslookup -type=srv _ldap._tcp.dc._msdcs.$FQDN_DOMAIN
​
# find the GC (Global Catalog, i.e. DC with extended data)
nslookup -type=srv gc._msdcs.$FQDN_DOMAIN
​
# Other ways to find services hosts that may be DCs 
nslookup -type=srv _kerberos._tcp.$FQDN_DOMAIN
nslookup -type=srv _kpasswd._tcp.$FQDN_DOMAIN
nslookup -type=srv _ldap._tcp.$FQDN_DOMAIN
```

This can also be accomplished by an NMAP Script

```
nmap --script dns-srv-enum --script-args dns-srv-enum.domain=$FQDN_DOMAIN
```
{% endtab %}

{% tab title="Host Cmd" %}
Name Servers

```
$ host -t ns domain.com
```

Email Server

```
$ host -t mx domain.com
```
{% endtab %}

{% tab title="ICMP" %}
```
#ping -c 1 199.66.11.4    #1 echo request to a host
#fping -sagq 192.168.0.0/24 #Send echo requests to ranges
#nmap -PEPM -sP -n 199.66.11.0/24 #Send echo, timestamp requests and subnet mask requests
```

* s = print status after completion&#x20;
* a - show active/alive targets&#x20;
* g = generate target list&#x20;
* q = dont show per target list (we dont care about unreachables)&#x20;
{% endtab %}

{% tab title="ARP" %}
[arp-scan](https://www.kali.org/tools/arp-scan/) - sends arp requests to look for link layer devices&#x20;

```
#sudo arp-scan -l
#nmap -sn <Network> #ARP Requests (Discover IPs)
#netdiscover -r <Network> #ARP requests (Discover IPs)
```
{% endtab %}

{% tab title="WOL" %}
Wake On Lan is used to turn on computers through a network message. The magic packet used to turn on the computer is only a packet where a MAC Dst is provided and then it is repeated 16 times inside the same paket. Then this kind of packets are usually sent in an ethernet 0x0842 or in a UDP packet to port 9. If no \[MAC] is provided, the packet is sent to broadcast ethernet (and the broadcast MAC will be the one being repeated).

```
#WOL (without MAC is used ff:...:ff)
wol.eth [MAC] #Send a WOL as a raw ethernet packet of type 0x0847
wol.udp [MAC] #Send a WOL as an IPv4 broadcast packet to UDP port 9
## Bettercap2 can also be used for this purpose
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="Responder" %}
[Responder](https://github.com/lgandx/Responder) is a great tool for spoofing various network protocols but can also be used in "analyze" modes.

* **BROWSER mode**: inspect [Browse Service](http://ubiqx.org/cifs/Browsing.html)  messages and map IP addresses with NetBIOS names
* **LANMAN mode**: passively map domain controllers, servers and workstations joined to a domain with the Browser protocol
* **LLMNR, NBTNS, MDNS modes**: inspect broadcast and multicast name resolution requests

The following command will enable the analyze modes and will give interesting information like:

* Domain Controller, SQL servers, workstations
* Fully Qualified Domain Name (FQDN)
* Windows versions in used
* The "enabled" or "disabled" state of protocols like LLMNR, NBTNS, MDNS, LANMAN, BROWSER

```
// Some code
```



[https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/responder-20-owning-windows-networks-part-3/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/responder-20-owning-windows-networks-part-3/)
{% endtab %}

{% tab title="NBTSCAN" %}
Just like DNS, the NTB-NS (NetBIOS name service) protocol is used to translate names to IP addresses. By default, it's used as a fallback in AD-DS.

[https://wiki.wireshark.org/NetBIOS/NBNS](https://wiki.wireshark.org/NetBIOS/NBNS)

```
nbtscan -r 192.168.0.1/24 #Search in Domain
```
{% endtab %}

{% tab title="Bettercap2" %}
```
net.probe on/off #Activate all service discover and ARP
net.probe.mdns #Search local mDNS services (Discover local)
net.probe.nbns #Ask for NetBios name (Discover local)
net.probe.upnp # Search services (Discover local)
net.probe.wsd # Search Web Services Discovery (Discover local)
net.probe.throttle 10 #10ms between requests sent (Discover local)
```

[https://github.com/bettercap/bettercap](https://github.com/bettercap/bettercap)
{% endtab %}
{% endtabs %}

### **Port-Scanning**

Port Scanning is a security penetration test that involves the use of software to identify open ports on a network and the services running on those ports. It is an important part of a security assessment because it can uncover security vulnerabilities that may otherwise be overlooked.

During a port scan, the software sends packets to each port on the target system and listens for a response. Depending on the response, the software can determine whether a port is open or closed. If a port is open, the software can also determine the service running on it. This information can help the tester identify any vulnerable services that can be exploited.

Port Scanning can help determine if there are any unauthorized access points, such as open ports or services running without authentication. It can also help determine if any services are running outdated versions of software that could be vulnerable to exploits.

Port status and other details can be gathered via manual requests, or through port scanning tools.&#x20;

The tool NMAP has long been the standard for port scanning is an essential tool for all security testers to know.

{% content-ref url="nmap.md" %}
[nmap.md](nmap.md)
{% endcontent-ref %}

<details>

<summary><a href="https://github.com/robertdavidgraham/masscan">Masscan</a></summary>

This is an Internet-scale port scanner. It can scan the entire Internet in under 5 minutes, transmitting 10 million packets per second, from a single machine.

```
# sudo apt install masscan 
# sudo masscan -p [port(s)] [IP CIDR] 
```

* \-oL \[log file]&#x20;

<!---->

* \-e specify interface&#x20;

<!---->

* \--rate rate of packet transmission&#x20;

<!---->

* \--router-ip - specify the IP address for the appropriate gateway

</details>

<details>

<summary><a href="https://www.kali.org/tools/unicornscan/">UnicornScan</a></summary>

Unicornscan is an attempt at a User-land Distributed TCP/IP stack. It is intended to provide a researcher a superior interface for introducing a stimulus into and measuring a response from a TCP/IP enabled device or network.

* [https://linuxhint.com/unicornscan\_beginner\_tutorial/](https://linuxhint.com/unicornscan\_beginner\_tutorial/)
* Port Scanning with UnicornScan - [https://youtu.be/X\_DdYUeKS-o](https://youtu.be/X\_DdYUeKS-o)

</details>

<details>

<summary>Other Tools</summary>

* [WebMap](https://github.com/DeadNumbers/WebMap) - Nmap Web Dashboard and Reporting
* [Scantron](https://github.com/rackerlabs/scantron) - Scantron is a distributed nmap and [Masscan](https://github.com/robertdavidgraham/masscan) scanner comprised of two components. The first is a console node that consists of a web front end used for scheduling scans and storing scan targets and results. The second component is an engine that pulls scan jobs from the console and conducts the actual scanning.
* [Scanless](https://github.com/vesche/scanless) - This is a Python 3 command-line utility and library for using websites that can perform port scans on your behalf.
* [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests
* [RustScan](https://github.com/RustScan/RustScan) - The Modern Port Scanner. **Find ports quickly (3 seconds at its fastest)**. Run scripts through our scripting engine (Python, Lua, Shell supported).
  * [https://reconshell.com/rustscan-faster-port-scanning-tool/](https://reconshell.com/rustscan-faster-port-scanning-tool/)
  * [https://tryhackme.com/room/rustscan](https://tryhackme.com/room/rustscan)
* [knocker](https://www.kali.org/tools/knocker/) - Knocker is a new, simple, and easy to use TCP security port scanner written in C, using threads. It is able to analyze hosts and the network services which are running on them.
* [unimap](https://github.com/Edu4rdSHL/unimap) - Scan only once by IP address and reduce scan times with Nmap for large amounts of data.

</details>

<details>

<summary>Manual Port Checks</summary>

Netcat banner grab

```
nc -v 10.10.10.10 port
```

Telnet banner grab

```
telnet 10.10.10.10 port
```

</details>

<details>

<summary>Probe Response CheatSheet</summary>

* **Open** port: _SYN --> SYN/ACK --> RST_

<!---->

* **Closed** port: _SYN --> RST/ACK_

<!---->

* **Filtered** port: _SYN --> \[NO RESPONSE]_

<!---->

* **Filtered** port: _SYN --> ICMP message_

</details>

### Application Detection

For more detailed identification of running appications, even if they are running on a non-standard port, we can use Application Detection tools to enumerate these.

[AMAP](https://www.kali.org/tools/amap/) - Attempts to identify applications even if they are running on a different port than normal.

```
$ amap -d $ip <port>
```

## **Vulnerability Scanning**

Vulnerability scanning is a process of identifying, detecting, and assessing security vulnerabilities in a computer system. It is designed to find known and unknown security risks in a network or computer system. Vulnerability scanning helps organizations identify and address any weaknesses in their systems before they can be exploited by attackers.

A vulnerability scan usually involves using automated tools to scan a system for known vulnerabilities. The scan looks for known weaknesses, such as incorrect settings, outdated software, missing patches, or other security flaws that could be exploited by attackers. After the scan is complete, a report is generated outlining the weaknesses found and providing recommendations on how to address them.

Vulnerability scanning is an important part of a comprehensive security program, and helps organizations identify and address weaknesses before attackers can exploit them. Conversely, vulnerability scanners are often used by offensive security testers to identify weak targets for exploitation.

* _BTFM: Scanning and Vulnerabilities - pg. 11_
* _Penetration Testing: Finding Vulnerabilities - pg.133_

{% tabs %}
{% tab title="Nessus " %}
[https://www.tenable.com/products/nessus/nessus-professional](https://www.tenable.com/products/nessus/nessus-professional)

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
{% endtab %}

{% tab title="OpenVAS" %}
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
  * https://127.0.0.1:939[NSE Nmap Scripts](https://nmap.org/nsedoc/) - NSE Scripts can perform various scanning techniques for enumerating services and scanning targets for specific vulnerabilities.

{% embed url="https://youtu.be/fEANg6gyV5A" %}

{% embed url="https://youtu.be/koMo_fSQGlk" %}
{% endtab %}

{% tab title="NSE Scripts" %}
* Show all available scripts and thier details
  * \# nmap --script-help default
* Show all vuln/exploit scripts
  * \# cat script.db | grep '"vuln"\\|"exploit"'
* Run all scripts in "vuln' category
  * \# sudo nmap --script vuln \[ip]
{% endtab %}

{% tab title="Other Scanning Tools" %}
### **Other Scanning Tools**

* [ReconMap](https://reconmap.org/) - Reconmap is a vulnerability assessment and penetration testing (VAPT) platform. It helps software engineers and infosec pros collaborate on security projects, from planning, to implementation and documentation. The tool's aim is to go from recon to report in the least possible time.
  * [https://github.com/reconmap/reconmap](https://github.com/reconmap/reconmap)
* [Vulmap](https://github.com/vulmon/Vulmap) - Vulmap Online Local Vulnerability Scanners Project
  * [https://vulmon.com/](https://vulmon.com/)
* [Vuls](https://github.com/future-architect/vuls)  - Vulnerability scanner for Linux/FreeBSD, agent-less, written in Go.
* [Tsunami Scanner](https://github.com/google/tsunami-security-scanner) - Tsunami is a general purpose network security scanner with an extensible plugin system for detecting high severity vulnerabilities with high confidence.
* [Flan Scan](https://github.com/cloudflare/flan) - Flan Scan is a lightweight network vulnerability scanner. With Flan Scan you can easily find open ports on your network, identify services and their version, and get a list of relevant CVEs affecting your network.
* [https://github.com/v3n0m-Scanner/V3n0M-Scanner](https://github.com/v3n0m-Scanner/V3n0M-Scanner) - Popular Pentesting scanner in Python3.6 for SQLi/XSS/LFI/RFI and other Vulns
{% endtab %}
{% endtabs %}

## Web Application Scanning and Testing

Web Application Security Testing is a type of security testing that is used to identify and address security vulnerabilities in web applications. It is a process that involves testing the security of web applications for weaknesses that could potentially be exploited by attackers. The goal of this type of testing is to identify and fix any security issues that could lead to the unauthorized access, manipulation, or destruction of data, or any other malicious activity.

Dynamic application security testing (DAST) is a process used to assess the security of a web application while it is running. This type of testing can be used to identify application-level vulnerabilities, such as cross-site scripting (XSS) and SQL injection.

For testing various web applications there are a multitude of testing tools for both individual vulnerabilities, as well as comprehensive suites. The foremost of these is Burp Suite.

{% content-ref url="burp-suite.md" %}
[burp-suite.md](burp-suite.md)
{% endcontent-ref %}

{% content-ref url="web-app-testing-frameworks.md" %}
[web-app-testing-frameworks.md](web-app-testing-frameworks.md)
{% endcontent-ref %}

{% content-ref url="scanning-utilities.md" %}
[scanning-utilities.md](scanning-utilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Web Content Discovery" %}
...burp...

* [Photon](https://github.com/s0md3v/Photon) - Incredibly fast crawler designed for OSINT.
* [URLgrab](https://github.com/IAmStoxe/urlgrab) - A golang utility to spider through a website searching for additional links.
* [hakrawler](https://github.com/hakluke/hakrawler) - Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application. Also built by the Legendary Hakluke
* [gospider](https://www.kali.org/tools/gospider/) - This package contains a Fast web spider written in Go.&#x20;
* [filebuster](https://github.com/henshin/filebuster) - Filebuster is a HTTP fuzzer / content discovery script with loads of features and built to be easy to use and fast! It uses one of the fastest HTTP classes in the world (of PERL) - Furl::HTTP. Also the thread modelling is optimized to run as fast as possible.
* [feroxbuster](https://www.kali.org/tools/feroxbuster/) - feroxbuster is a tool designed to perform Forced Browsing. Forced browsing is an attack where the aim is to enumerate and access resources that are not referenced by the web application, but are still accessible by an attacker.
{% endtab %}

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}

<details>

<summary>Misc Web App Testing Tools</summary>

* [https://www.webgap.io/](https://www.webgap.io/) - [WEBGAP](https://www.urbandictionary.com/define.php?term=webgap) remote browser isolation physically isolates you from the risks of using the internet by isolating your web browsing activity away from your local device.

<!---->

* [https://requestbin.com/](https://requestbin.com/) - A modern request bin to collect, inspect and debug HTTP requests and webhooks

<!---->

* [Race-the-web](https://github.com/TheHackerDev/race-the-web) - Tests for race conditions in web applications. Includes a RESTful API to integrate into a continuous integration pipeline.

<!---->

* [DVCS-Ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, etc.

<!---->

* [SSLStrip](https://github.com/LeonardoNve/sslstrip2) - This is a new version of \[Moxie´s SSLstrip] ([http://www.thoughtcrime.org/software/sslstrip/](http://www.thoughtcrime.org/software/sslstrip/)) with the new feature to avoid HTTP Strict Transport Security (HSTS) protection mechanism.

<!---->

* [BB King's Quieter Firefox template](https://bitbucket.org/mrbbking/quieter-firefox/src/master/) - Stripped down Firefox with no callouts to throw off traffic. Great for testing of all sorts.

<!---->

* [Unfurl](https://dfir.blog/unfurl/) - Tool for breaking down a URL to better understand its components.Fake credit card numbers for testing payment systems

<!---->

* [Credit Cards numbers](https://stripe.com/docs/testing#cards) for use in testing

<!---->

* [interactsh](https://github.com/projectdiscovery/interactsh) - An OOB interaction gathering server and client library
  * [https://app.interactsh.com/](https://app.interactsh.com/)

<!---->

* [Firebounty](https://firebounty.com) — Bug bounty search engine

<!---->

* [https://github.com/brevityinmotion/goodfaith](https://github.com/brevityinmotion/goodfaith) - A tool that helps you stay within scope for bug bounty recon automation.

</details>

## Other Scanning Utilities

<details>

<summary><strong>SSL/TLS Scanning</strong></summary>

* [SSL Cipher Suite Enum](https://github.com/portcullislabs/ssl-cipher-suite-enum) - Perl script to enumerate supported SSL cipher suites supported by network services (principally HTTPS).
* [sslScrape](https://github.com/cheetz/sslScrape) - strips hostnames form certs over port 443 connections
* [SSLYZE](https://github.com/nabla-c0d3/sslyze) - TLS/SSL config analyzer
* [tls\_prober](https://github.com/WestpointLtd/tls\_prober) - TLS Prober is a tool for identifying the implementation in use by SSL/TLS servers. It analyses the behaviour of a server by sending a range of probes then comparing the responses with a database of known signatures.
* [testssl.sh](https://github.com/drwetter/testssl.sh) - A free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
* [https://pentestbook.six2dez.com/enumeration/ssl-tls](https://pentestbook.six2dez.com/enumeration/ssl-tls) - List of commads to test for specific SSL/TLS Vulnerabilities.

</details>

<details>

<summary>Misc Scanning tools</summary>

* [HoneyCaught](https://github.com/aswinmguptha/HoneyCaught) - Honeypot detection tool
* [Sniffing Bear](https://github.com/MrSuicideParrot/SniffingBear) - A modular and distributed tool developed in python to scan networks for honeypots
* [https://honeyscore.shodan.io/](https://honeyscore.shodan.io/) - Shodan honeypot detector.
* [changeme](https://www.kali.org/tools/changeme/) - This package contains a default credential scanner. changeme supports the http/https, MSSQL, MySQL, Postgres, ssh and ssh w/key protocols.
* [SharpShare](https://github.com/djhohnstein/SharpShares/) - Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.
* [Phishious](https://github.com/Rices/Phishious) - An open-source Secure Email Gateway (SEG) evaluation toolkit designed for red-teamers.
* [firewalk](https://www.kali.org/tools/firewalk/) - Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a given IP forwarding device will pass.
* [ftester](https://www.kali.org/tools/ftester/) - The Firewall Tester (FTester) is a tool designed for testing firewall filtering policies and Intrusion Detection System (IDS) capabilities.

</details>
