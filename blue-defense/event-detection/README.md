# Event Detection

## **Intro**

Event detection is the bread and butter of the security analyst. Whether you are a blue teamer building automated alerting or a threat hunter looking deeper at the data, it is essential to understand what you are looking for, how to look for it, and what tools can make it easier to find it. One of the best new resources for starting your detection strategy is [https://d3fend.mitre.org/](https://d3fend.mitre.org/). This is a fantastic resource that allows you to create a per task approach to creating detection use cases.

For proper event detection, we usually need 3 elements: A device/application that can generate a log relevant to what we are looking for, the log itself, and a collection tool. The device/application that generates the log does not have to be a security device in order to give us security relevant logs. One thing you will find however, is that security relevant devices send us significantly less volume of data, as they are only sending alerts and the information surrounding a detection. When we are looking at logs from non-security related devices, we must develop our own detection logic to pull out what events we deem suspicious from those logs.

For parsing through logs and organizing them into an easy format, there is a wonderful set of tools called the SIEM: Security Incident and Event Management. With many tools you can look at their data and events directly, but a SIEM allows you to gather all of your logs in one place and parse through them. With them all in one place, you can even correlate activities across your logs. One other big thing that SIEMs can do is help normalize your data. Every type of log is different even if it is the same type if device/application. Example: McAfee AV logs are in a completely different format that MS Defender logs. Well what if your environment has both? Is there an easy way to look at them both at the same time? Yes! Many SIEMs have plugins or apps that can normalize the data into CIM: Common Information Model format. This makes them parsable by your SIEM tools, and  much easier to create detection rules around.

## **SIEM and Enrichment**

{% content-ref url="siem-and-enrichment.md" %}
[siem-and-enrichment.md](siem-and-enrichment.md)
{% endcontent-ref %}

## **IDS/IPS**

{% content-ref url="ids-ips.md" %}
[ids-ips.md](ids-ips.md)
{% endcontent-ref %}

## NSM: Network Security Monitoring

For Netflow logs and Packet Capture, please see the following:

{% content-ref url="../../yellow-neteng-sysadmin/security-logging/logging-guide-network-services.md" %}
[logging-guide-network-services.md](../../yellow-neteng-sysadmin/security-logging/logging-guide-network-services.md)
{% endcontent-ref %}

{% content-ref url="../packet-analysis.md" %}
[packet-analysis.md](../packet-analysis.md)
{% endcontent-ref %}

* [ZEEK](https://github.com/zeek/zeek) - A departure from traditional signature based detection, ZEEK is a network traffic analysis engine that allows network security monitoring at the application layer event in large networks. This tool was formerly called BRO.
  * [Anomalous DNS](https://github.com/jbaggs/anomalous-dns) -  A set of ZEEK scripts providing a module for tracking and correlating abnormal DNS behavior.&#x20;
  * [Mitre ATT\&CK's BZAR](https://github.com/mitre-attack/bzar) - A set of ZEEKk scripts to detect ATT\&CK techniques.&#x20;
  * [GQUIC\_Protocol\_Analyzer](https://github.com/salesforce/GQUIC\_Protocol\_Analyzer): GQUIC Protocol Analyzer for ZEEK (Bro) Network Security Monitor&#x20;
  * [ZEEK-agent](https://github.com/zeek/zeek-agent) - An endpoint monitoring agent that provides host activity to ZEEK
  * [RDFP](https://github.com/theparanoids/rdfp) - Zeek Remote desktop fingerprinting script based on FATT (Fingerprint All The Things)
  * [https://www.pluralsight.com/courses/writing-zeek-rules](https://www.pluralsight.com/courses/writing-zeek-rules)
  * [https://github.com/JustinAzoff/bro-pdns](https://github.com/JustinAzoff/bro-pdns)
  * _PTFM: Zeek Commands - pg. 168_
  * _Bro - Applied Network Security Monitoring - pg.255fc_
* [Corelight](https://corelight.com/) - The premium, Enterprise grade, Zeek Alternative.
* [arpwatch](https://www.kali.org/tools/arpwatch/) - Arpwatch maintains a database of Ethernet MAC addresses seen on the network, with their associated IP pairs. Alerts the system administrator via e-mail if any change happens, such as new station/activity, flip-flops, changed and re-used old addresses.
* [maltrail](https://github.com/stamparm/maltrail) - **Maltrail** is a malicious traffic detection system, utilizing publicly available (black)lists containing malicious and/or generally suspicious trails, along with static trails compiled from various AV reports and custom user defined lists, where trail can be anything from domain name (e.g. `zvpprsensinaix.com` for [Banjori](http://www.johannesbader.ch/2015/02/the-dga-of-banjori/) malware), URL (e.g. `hXXp://109.162.38.120/harsh02.exe` for known malicious [executable](https://www.virustotal.com/en/file/61f56f71b0b04b36d3ef0c14bbbc0df431290d93592d5dd6e3fffcc583ec1e12/analysis/)), IP address (e.g. `185.130.5.231` for known attacker) or HTTP User-Agent header value (e.g. `sqlmap` for automatic SQL injection and database takeover tool). Also, it uses (optional) advanced heuristic mechanisms that can help in discovery of unknown threats (e.g. new malware).

## Endpoint

### Open Source EDR: Endpoint Detection and Response

* [OSSEC](https://www.ossec.net/about/) - a scalable, multi-platform, open source Host-based Intrusion Detection System (HIDS)
* [Wazuh](https://github.com/wazuh/wazuh) -  Starting as a fork of OSSEC, it was built with more reliability and scalability in mind . It differs from OSSEC in its ability to be integrated with Elastic Stack, a better rule set, and it can use a restful API. File integrity Monitoring, Vulnerability Management, Config Management, Enhances Incident Response, and even an easy to use UI. Wazuh has it all.
* [BlueSpawn](https://github.com/ION28/BLUESPAWN) - EDR + Active Defense tool. Has the ability to interact with OS APIs to actively respond to certain detections in the platform.
* [OpenEDR](https://github.com/ComodoSecurity/openedr) - Comodo security's open source EDR platform. Great community and solid product.
* Aurora - Sigma-based EDR agent
  * [https://www.nextron-systems.com/2021/11/13/aurora-sigma-based-edr-agent-preview/](https://www.nextron-systems.com/2021/11/13/aurora-sigma-based-edr-agent-preview/)
* [whids](https://github.com/0xrawsec/whids) - Open Source EDR for Windows

### [OSQuery ](https://osquery.io/)

* One of the most advanced endpoint visibility tools on the market. Can be used for File Integrity monitoring, change management, even security endpoint detection.
  * [Awesome Lists Collection: OSQuery Resources](https://github.com/sttor/awesome-osquery)
  * [OSQuery-extension](https://github.com/trailofbits/osquery-extensions) - OSQuery extensions by Trail of Bits&#x20;
  * [OSQuery-attck](https://github.com/teoseller/osquery-attck) - Mapping the MITRE ATT\&CK Matrix with Osquery&#x20;
  * [OSQuery-configuration](https://github.com/palantir/osquery-configuration): A repository for using osquery for incident detection and response
  * [Introduction to osquery for Threat Detection and DFIR](https://www.rapid7.com/blog/post/2016/05/09/introduction-to-osquery-for-threat-detection-dfir/)
  * [Using osquery for remote forensics](https://blog.trailofbits.com/2019/05/31/using-osquery-for-remote-forensics/)
  * [OSQuery: Incident Response Across the Enterprise.](https://blog.palantir.com/osquery-across-the-enterprise-3c3c9d13ec55)
  * OSQuery for Security by Chris Long[ - Part 1](https://medium.com/@clong/osquery-for-security-b66fffdf2daf)[,  Part 2](https://medium.com/@clong/osquery-for-security-part-2-2e03de4d3721)
  * [osquery-defense-kit](https://github.com/chainguard-dev/osquery-defense-kit) - Production-ready detection & response queries for osquery

### Other Tools

* [Sysdig](https://github.com/draios/sysdig): Linux system exploration and visibility tool
* [ZEEK-agent](https://github.com/zeek/zeek-agent) - An endpoint monitoring agent that provides host activity to ZEEK
* [Veliciraptor](https://github.com/Velocidex/velociraptor) - a tool for collecting host based state information.

## Sysmon

{% content-ref url="sysmon.md" %}
[sysmon.md](sysmon.md)
{% endcontent-ref %}

## Fingerprinting

* Fingerprint Databases&#x20;
  * [SSL Fingerprint JA3](https://ja3er.com/)&#x20;
  * [TLSfingerprint.io](https://tlsfingerprint.io/)&#x20;
  * [https://sslbl.abuse.ch/ja3-fingerprints/](https://sslbl.abuse.ch/ja3-fingerprints/)
  * [https://github.com/trisulnsm/ja3prints](https://github.com/trisulnsm/ja3prints)
* [JA3](https://github.com/salesforce/ja3) - A method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.
  * Sales Force Guide: \* READ FIRST\* - [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)
  * [Open Sourcing JA3. SSL/TLS Client Fingerprinting](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41)
  * [RDP Fingerprinting. Profiling RDP Clients with JA3 and RDFP](https://medium.com/@0x4d31/rdp-client-fingerprinting-9e7ac219f7f4)
  * [Effective TLS Fingerprinting Beyond JA3](https://www.ntop.org/ndpi/effective-tls-fingerprinting-beyond-ja3/)
* [HASSH](https://github.com/salesforce/hassh) - A network fingerprinting standard which can be used to identify specific Client and Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of a small MD5 fingerprint.&#x20;
* [FATT: Fingerprint All The Things](https://github.com/0x4D31/fatt) -A pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic&#x20;
* [RDFP](https://github.com/theparanoids/rdfp) - Zeek Remote desktop fingerprinting script based on FATT (Fingerprint All The Things)
* [Recog](https://github.com/rapid7/recog) - A framework for identifying products, services, operating systems, and hardware by matching fingerprints against data returned from various network probes. Recog makes it simple to extract useful information from web server banners, snmp system description fields, and a whole lot more.

## Attack Surface Monitoring and Asset Discovery

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
  * [https://gobies.org/](https://gobies.org/)
* [Asnip](https://github.com/harleo/asnip) - Asnip retrieves all IPs of a target organization—used for attack surface mapping in reconnaissance phases.
* [Microsoft Attack Surface Analyzer](https://github.com/Microsoft/AttackSurfaceAnalyzer) - Attack Surface Analyzer is a [Microsoft](https://github.com/microsoft/) developed open source security tool that analyzes the attack surface of a target system and reports on potential security vulnerabilities introduced during the installation of software or system misconfiguration.
* [https://securitytrails.com/](https://securitytrails.com/) - Powerful tools for third-party risk, attack surface management, and total intel
* [https://www.whoisxmlapi.com/](https://www.whoisxmlapi.com/) - Domain & IP Data Intelligence for Greater Enterprise Security
* [https://www.riskiq.com/](https://www.riskiq.com/) - RiskIQ Digital Footprint gives complete visibility beyond the firewall. Unlike scanners and IP-dependent data vendors, RiskIQ Digital Footprint is the only solution with composite intelligence, code-level discovery and automated threat detection and exposure monitoring—security intelligence mapped to your attack surface.
* [https://dehashed.com/](https://dehashed.com/) - Scan domain for indicators found in breaches

### Network Diffing&#x20;

A simple but effective monitoring method, where regular port scans are run and then compared to previous scan results. This can be handy for detecting newly open ports on scanned devices. This action can be easily and quickly performed by [Masscan](https://github.com/robertdavidgraham/masscan).

* _The Hacker Playbook 3: Monitoring an Environment - pg.24_

## User Behavior Analytics

* [OpenUBA](https://github.com/GACWR/OpenUBA) - A robust, and flexible open source User & Entity Behavior Analytics (UEBA) framework used for Security Analytics. Developed with luv by Data Scientists & Security Analysts from the Cyber Security Industry.
  * [https://openuba.org/](https://openuba.org/)

## File Integrity Monitoring

The actions needed to setup persistence typically require the attacker to interact with the target machine like creating or modifying a file. This gives defenders the opportunity to catch them if we are able to lookout for file creation or modification related to special files of directories.

* [AuditBeat's FIM](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-module-file\_integrity.html)
* [auditd](https://www.redhat.com/sysadmin/configure-linux-auditing-auditd)
* [Wazuh's FIM](https://documentation.wazuh.com/current/learning-wazuh/detect-fs-changes.html)

## Misc Tools

* [SAGAN](https://github.com/quadrantsec/sagan) - An open source (GNU/GPLv2) high performance, real-time log analysis & correlation engine that can be used with popular IDS tools and rules sets like Surricata and SNORT.
* [RITA](https://github.com/activecm/rita) - A tool that scans ZEEK logs for beaconing detection and DNS tunneling.
* [Flare](https://github.com/austin-taylor/flare) - Not to be confused with the malware reverse engineering VM, This Flare is a network analysis tool by Austin Taylor that can take logs from Elastic stack and Surricate and perform various types of nework analysis and detection, including beaconing detection.
* [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - Powershell obfuscation detection tool
* [dnstwist](https://github.com/elceef/dnstwist) - Tool for creation of potential typo-squatting domains by use of multi-character permutation and checking for registration of those domains.
  * [https://dnstwister.report/](https://dnstwister.report/) - Online Version and DNS monitoring service

## **Detection Use Cases**

{% content-ref url="detection-use-cases/" %}
[detection-use-cases](detection-use-cases/)
{% endcontent-ref %}
