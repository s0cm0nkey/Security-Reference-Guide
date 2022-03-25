# Mapping the Site

## Attack Surface Mapping and Asset Discovery

* [Awesome Lists Collection: Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
* [https://cheatsheetseries.owasp.org/cheatsheets/Attack\_Surface\_Analysis\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Attack\_Surface\_Analysis\_Cheat\_Sheet.html)

### [Amass](https://github.com/OWASP/Amass)&#x20;

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

* Hakluke's Amass Guide - [https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
* Dionach's Amass Guide - [https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [https://www.youtube.com/watch?v=mEQnVkSG19M](https://www.youtube.com/watch?v=mEQnVkSG19M)

### [projectdiscovery.io](https://projectdiscovery.io/#/)

&#x20;Collection of open source tools for attack surface management or Bug Bounties.

* [nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner based on simple YAML based DSL.
  * [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  * [https://github.com/projectdiscovery/nuclei-docs](https://github.com/projectdiscovery/nuclei-docs)
* [subfinder](https://github.com/projectdiscovery/subfinder) - Subfinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.
* [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests
* [httpx](https://github.com/projectdiscovery/httpx) - httpx is a fast and multi-purpose HTTP toolkit allows to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads.
* [proxify](https://github.com/projectdiscovery/proxify) - Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
* [dnsx](https://github.com/projectdiscovery/dnsx) - dnsx is a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.

### Other tools

* [Intrigue](https://github.com/intrigueio/intrigue-core) - Intrigue Core is a framework for discovering attack surface. It discovers security-relevant assets and exposures within the context of projects and can be used with a human-in-the-loop running individual tasks, and/or automated through the use of workflows.
* [Odin](https://github.com/chrismaddalena/ODIN) - ODIN is Python tool for automating intelligence gathering, asset discovery, and reporting.
* [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) - AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target. You feed in a mixture of one or more domains, subdomains and IP addresses and it uses numerous techniques to find more targets.
* [Goby](https://github.com/gobysec/Goby) - **Goby** is a new generation network security assessment tool. It can efficiently and practically scan vulnerabilities while sorting out the most complete attack surface information for a target enterprise.
  * [https://gobies.org/](https://gobies.org)
* [Asnip](https://github.com/harleo/asnip) - Asnip retrieves all IPs of a target organization—used for attack surface mapping in reconnaissance phases.
* [Microsoft Attack Surface Analyzer](https://github.com/Microsoft/AttackSurfaceAnalyzer) - Attack Surface Analyzer is a [Microsoft](https://github.com/microsoft/) developed open source security tool that analyzes the attack surface of a target system and reports on potential security vulnerabilities introduced during the installation of software or system misconfiguration.
* [https://securitytrails.com/](https://securitytrails.com) - Powerful tools for third-party risk, attack surface management, and total intel
* [https://www.whoisxmlapi.com/](https://www.whoisxmlapi.com) - Domain & IP Data Intelligence for Greater Enterprise Security
* [https://www.riskiq.com/](https://www.riskiq.com) - RiskIQ Digital Footprint gives complete visibility beyond the firewall. Unlike scanners and IP-dependent data vendors, RiskIQ Digital Footprint is the only solution with composite intelligence, code-level discovery and automated threat detection and exposure monitoring—security intelligence mapped to your attack surface.
* [https://dehashed.com/](https://dehashed.com) - Scan domain for indicators found in breaches
* [https://fullhunt.io/](https://fullhunt.io) - **FullHunt** is the attack surface database of the entire Internet.

## Spider/Crawler

...burp...

* [Photon](https://github.com/s0md3v/Photon) - Incredibly fast crawler designed for OSINT.
* [BlackWidow](https://github.com/1N3/BlackWidow) - A Python based web application scanner to gather OSINT and fuzz for OWASP vulnerabilities on a target website.
* [URLgrab](https://github.com/IAmStoxe/urlgrab) - A golang utility to spider through a website searching for additional links.
* [hakrawler](https://github.com/hakluke/hakrawler) - Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application. Also built by the Legendary Hakluke
* [gospider](https://www.kali.org/tools/gospider/) - This package contains a Fast web spider written in Go.&#x20;

## DNS/Subdomain

[https://pentestbook.six2dez.com/others/subdomain-tools-review](https://pentestbook.six2dez.com/others/subdomain-tools-review)

### **Enumeration Tools**

* [dnsdumpster](https://github.com/nmmapper/dnsdumpster) - A tool to perform DNS reconnaissance on target networks. Among the DNS information got from include subdomains, mx records, web application firewall detection and more fingerprinting and lookups
* [DNSRecon](https://github.com/darkoperator/dnsrecon) - The Original DNS recon script.
  * [https://www.kali.org/tools/dnsrecon/](https://www.kali.org/tools/dnsrecon/)
* [dnscan](https://github.com/rbsec/dnscan) - dnscan is a python wordlist-based DNS subdomain scanner.
* [dnsenum](https://www.kali.org/tools/dnsenum/) - Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.
* [dnsmap](https://www.kali.org/tools/dnsmap/) - dnsmap scans a domain for common subdomains using a built-in or an external wordlist
* [dnstracer](https://www.kali.org/tools/dnstracer/) - determines where a given Domain Name Server (DNS) gets its information from for a given hostname, and follows the chain of DNS servers back to the authoritative answer.
* [Lepus](https://github.com/gfek/Lepus) - A tool for enumerating subdomains, checking for subdomain takeovers and perform port scans - and boy, is it fast!
* [Knock](https://github.com/guelfoweb/knock) - Knockpy is a python3 tool designed to enumerate subdomains on a target domain through dictionary attack.
* [HostileSubBruteForcer](https://github.com/nahamsec/HostileSubBruteforcer) - Aggressive SubDomain brute forcing tool  written by Nahamsec.
* [altdns](https://www.kali.org/tools/altdns/) - a DNS recon tool that allows for the discovery of subdomains that conform to patterns.
* [assetfinder](https://www.kali.org/tools/assetfinder/) - A tool to find domains and subdomains potentially related to a given domain.
* [fierce](https://www.kali.org/tools/fierce/) - Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It’s really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for.
* [cansina](https://github.com/deibit/cansina) - a Web Content Discovery Application. Help you making requests and filtering and inspecting the responses to tell apart if it is an existing resource or just an annoying or disguised 404.
* [subbrute](https://github.com/TheRook/subbrute) - A DNS meta-query spider that enumerates DNS records, and subdomains.
* [dnsx](https://github.com/projectdiscovery/dnsx) - dnsx is a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.

### **Subdomain Takeover**

* [TKO-subs](https://github.com/anshumanbh/tko-subs) - A tool that can help detect and takeover subdomains with dead DNS records
* [Subjack](https://github.com/haccer/subjack) - Subjack is a Subdomain Takeover tool written in Go designed to scan a list of subdomains concurrently and identify ones that are able to be hijacked.
* [Second-Order](https://github.com/mhmdiaa/second-order) - Scans web applications for second-order subdomain takeover by crawling the app, and collecting URLs (and other data) that match some specific rules, or respond in a specific way.
* [dnstake](https://github.com/pwnesia/dnstake) - A fast tool to check missing hosted DNS zones that can lead to subdomain takeover

### **Subdomain wordlists**

* [gotator](https://github.com/Josue87/gotator) - Gotator is a tool to generate DNS wordlists through permutations.
* Knock Wordlist - [https://github.com/guelfoweb/knock/blob/4.1/knockpy/wordlist/wordlist.txt](https://github.com/guelfoweb/knock/blob/4.1/knockpy/wordlist/wordlist.txt)
* Seclists Subdomains - [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
* Seclists Web Content - [https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
* Cheetz all.txt - [https://gist.githubusercontent.com/cheetz/4d6a26bb122a942592ab9ac21894e57b/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt](https://gist.githubusercontent.com/cheetz/4d6a26bb122a942592ab9ac21894e57b/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt)

## Directory Enumeration

* [dirb](https://www.kali.org/tools/dirb/) - DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the responses.
* [DirBuster](https://tools.kali.org/web-applications/dirbuster) - DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers.
  * [https://www.kali.org/tools/dirbuster/](https://www.kali.org/tools/dirbuster/)
  * [https://www.hackingarticles.in/comprehensive-guide-on-dirbuster-tool/](https://www.hackingarticles.in/comprehensive-guide-on-dirbuster-tool/)
* [Dirsearch](https://github.com/maurosoria/dirsearch) - An advanced command-line tool designed to brute force directories and files in webservers, AKA web path scanner
  * [https://www.kali.org/tools/dirsearch/](https://www.kali.org/tools/dirsearch/)
* [filebuster](https://github.com/henshin/filebuster) - Filebuster is a HTTP fuzzer / content discovery script with loads of features and built to be easy to use and fast! It uses one of the fastest HTTP classes in the world (of PERL) - Furl::HTTP. Also the thread modelling is optimized to run as fast as possible.
* [feroxbuster](https://www.kali.org/tools/feroxbuster/) - feroxbuster is a tool designed to perform Forced Browsing. Forced browsing is an attack where the aim is to enumerate and access resources that are not referenced by the web application, but are still accessible by an attacker.

### [Go Buster](https://github.com/OJ/gobuster)&#x20;

Directory/File, DNS and VHost busting tool written in Go. [https://www.kali.org/tools/gobuster/](https://www.kali.org/tools/gobuster/)

Gobuster quick directory busting

```
gobuster -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -a Linux
```

Gobuster comprehensive directory busting

```
gobuster -s 200,204,301,302,307,403 -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/big.txt -t 80 -a 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
```

Gobuster search with file extension

```
gobuster -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -a Linux -x .txt,.php
```

