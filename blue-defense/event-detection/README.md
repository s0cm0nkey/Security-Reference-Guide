# Event Detection

## **Intro**

Event detection is foundational for the security analyst and Blue Team. Whether you are building automated alerting or threat hunting, it is essential to understand what you are looking for, how to look for it, and what tools can assist in the process. A vital resource for developing a detection strategy is [MITRE D3FEND](https://d3fend.mitre.org/), which allows for a task-based approach to creating detection use cases.

Effective event detection typically requires three elements: a source (device or application) that generates relevant logs, the logs themselves, and a collection mechanism. The source does not need to be a security device to provide security-relevant data. However, security-specific devices often generate lower data volumes compared to general applications, as they typically transmit only alerts and contextual information surrounding a detection. When analyzing logs from non-security devices, analysts must develop logic to identify and extract suspicious events.

To parse, organize, and analyze logs, we use a SIEM (Security Information and Event Management) system. While individual tools allow for direct data inspection, a SIEM aggregates logs from diverse sources into a centralized location. This centralization enables correlation of activities across different log sources. Additionally, a key function of a SIEM is data normalization. Different devices and applications often output logs in unique formats (e.g., McAfee AV logs differ from Microsoft Defender logs). A SIEM can normalize this disparate data into a standard format, such as the CIM (Common Information Model). This standardization simplifies parsing and facilitates the creation of universal detection rules.

## **SIEM and Enrichment**

{% content-ref url="siem-and-enrichment.md" %}
[siem-and-enrichment.md](siem-and-enrichment.md)
{% endcontent-ref %}

## **Detection Engineering & Standards**

* [Sigma](https://github.com/SigmaHQ/sigma) - Often described as the "Snort for generic log events," Sigma is an open, text-based signature format that allows you to describe relevant log events in a straightforward manner. These rules can be converted into query languages for most SIEMs (Splunk, Elastic, QRadar, etc.), enabling "Detection as Code" and cross-platform rule sharing.
* [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) - An open source specification that defines a common set of fields for data ingested into Elasticsearch.
* [Splunk Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) - Providing a methodology to normalize data to a common standard, allowing analysts to write single searches that cover similar data across different sources.

## **IDS/IPS**

{% content-ref url="ids-ips.md" %}
[ids-ips.md](ids-ips.md)
{% endcontent-ref %}

## NSM: Network Security Monitoring

For Netflow logs and Packet Capture, please see the following:

{% content-ref url="../../security-logging/logging-guide-network-services.md" %}
[logging-guide-network-services.md](../../security-logging/logging-guide-network-services.md)
{% endcontent-ref %}

{% content-ref url="../packet-analysis.md" %}
[packet-analysis.md](../packet-analysis.md)
{% endcontent-ref %}

* [Zeek](https://github.com/zeek/zeek) - A departure from traditional signature based detection, Zeek is a network traffic analysis engine that allows network security monitoring at the application layer even in large networks. This tool was formerly known as Bro.
  * [Zeek Agent v2](https://github.com/zeek/zeek-agent-v2) - The modern endpoint monitoring agent that provides host activity to Zeek (supersedes the archived zeek-agent).
  * [Anomalous DNS](https://github.com/jbaggs/anomalous-dns) -  A set of Zeek scripts providing a module for tracking and correlating abnormal DNS behavior.&#x20;
  * [Mitre ATT\&CK's BZAR](https://github.com/mitre-attack/bzar) - A set of Zeek scripts to detect ATT\&CK techniques.&#x20;
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
* [Wazuh](https://github.com/wazuh/wazuh) -  Starting as a fork of OSSEC, it was built with reliability and scalability in mind. It differs from OSSEC by integrating with the Elastic Stack, offering an improved rule set, and providing a RESTful API. Features include File Integrity Monitoring, Vulnerability Management, Configuration Management, Incident Response capabilities, and a user-friendly UI.
* [BlueSpawn](https://github.com/ION28/BLUESPAWN) - EDR + Active Defense tool. (Note: Project is currently dormant/inactive).
* [Aurora](https://www.nextron-systems.com/aurora/) - Sigma-based EDR agent.
  * [https://www.nextron-systems.com/2021/11/13/aurora-sigma-based-edr-agent-preview/](https://www.nextron-systems.com/2021/11/13/aurora-sigma-based-edr-agent-preview/)

### [osquery](https://osquery.io/)

* **osquery** is one of the most advanced endpoint visibility tools available. It can be used for File Integrity Monitoring (FIM), change management, and security endpoint detection.
  * [Awesome Lists Collection: osquery Resources](https://github.com/sttor/awesome-osquery)
  * [OSQuery-extension](https://github.com/trailofbits/osquery-extensions) - OSQuery extensions by Trail of Bits&#x20;
  * [OSQuery-attck](https://github.com/teoseller/osquery-attck) - Mapping the MITRE ATT\&CK Matrix with Osquery&#x20;
  * [OSQuery-configuration](https://github.com/palantir/osquery-configuration): A repository for using osquery for incident detection and response
  * [Introduction to osquery for Threat Detection and DFIR](https://www.rapid7.com/blog/post/2016/05/09/introduction-to-osquery-for-threat-detection-dfir/)
  * [Using osquery for remote forensics](https://blog.trailofbits.com/2019/05/31/using-osquery-for-remote-forensics/)
  * [OSQuery: Incident Response Across the Enterprise.](https://blog.palantir.com/osquery-across-the-enterprise-3c3c9d13ec55)
  * eek-agent](https://github.com/zeek/zeek-agent) - An endpoint monitoring agent that provides host activity to Zeek
* [Velociraptor](https://github.com/Velocidex/velociraptor) - a tool for collecting host based state information.
* [Hayabusa](https://github.com/Yamato-Security/hayabusa) - A fast forensics timeline generator and threat hunting tool for Windows event logs. It utilizes Sigma rules to scan logs to identify anomalies and specific attack techniques.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - A PowerShell script that analyzes Windows Security, System, and Application event logs to automatically detect suspicious behaviors like password spraying and command line obfuscation.

## Cloud & Container Security

* [Falco](https://falco.org/) - The cloud-native runtime security project. Falco parses Linux system calls at runtime to detect unexpected behavior, making it the standard for threat detection in Kubernetes and containerized environments.
* [Prowler](https://github.com/prowler-cloud/prowler) - Essential for identifying configuration drifts and security events in AWS, Azure, and GCP. Checks against CIS benchmarks and other standardsresponse queries for osquery

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
* [JA3](https://github.com/salesforce/ja3) - A method for creating SSL/TLS client fingerprints that is easy to produce on any platform and share for threat intelligence.
  * Salesforce Guide: \*READ FIRST\* - [TLS F(Legacy) A method for creating SSL/TLS client fingerprints. *Note: The original repo is archived. See [JA4](https://github.com/FoxIO-LLC/ja4) for the modern successor.*
  * Salesforce Guide: \*READ FIRST\* - [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)
  * [Open Sourcing JA3: SSL/TLS Client Fingerprinting](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41)
  * [RDP Fingerprinting -rprinting Beyond JA3](https://www.ntop.org/ndpi/effective-tls-fingerprinting-beyond-ja3/)
* [HASSH](https://github.com/salesforce/hassh) - A network fingerprinting standard which can be used to identify specific Client and Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of a small MD5 fingerprint.&#x20;
* [FATT: Fingerprint All The Things](https://github.com/0x4D31/fatt) -A pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic&#x20;
* [RDFP](https://github.com/theparanoids/rdfp) - Zeek Remote desktop fingerprinting script based on FATT (Fingerprint All The Things)
* [Recog](https://github.com/rapid7/recog) - A framework for identifying products, services, operating systems, and hardware by matching fingerprints against data returned from various network probes. Recog makes it simple to extract useful information from web server banners, snmp system description fields, and a whole lot more.

## Threat Intelligence Platforms (TIP)

* [MISP (Malware Information Sharing Platform)](https://www.misp-project.org/) - The de facto open-source standard for storing and sharing threat intelligence. It allows organizations to collaborate by sharing Indicators of Compromise (IOCs) in a structured format.
* [OpenCTI](https://github.com/OpenCTI-Platform/opencti) - A unified platform for managing cyber threat intelligence. It helps organizations structure, store, organize, visualize, and share their knowledge about cyber threats.

## Attack Surface Monitoring and Asset Discovery

* [Awesome Lists Collection: Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
* [https://cheatsheetseries.owasp.org/cheatsheets/Attack\_Surface\_Analysis\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Attack\_Surface\_Analysis\_Cheat\_Sheet.html)

### [Amass](https://github.com/OWASP/Amass)&#x20;

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

* [Hakluke's Amass Guide](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
* [Dionach's Amass Guide](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [Amass Tutorial (Video)](https://www.youtube.com/watch?v=mEQnVkSG19M)

### [projectdiscovery.io](https://projectdiscovery.io/#/)

A collection of open source tools for attack surface management and bug bounties.

* [nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner based on a simple YAML-based DSL.
  * [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  * [https://github.com/projectdiscovery/nuclei-docs](https://github.com/projectdiscovery/nuclei-docs)
* [subfinder](https://github.com/projectdiscovery/subfinder) - Subfinder is a subdomain discovery tool that identifies valid subdomains for websites. Designed as a passive framework, it is useful for bug bounties and safe for penetration testing.
* [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in Go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests.
* [httpx](https://github.com/projectdiscovery/httpx) - A fast and multi-purpose HTTP toolkit that allows running multiple probers using the `retryablehttp` library. It is designed to maintain result reliability with increased threads.
* [proxify](https://github.com/projectdiscovery/proxify) - Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
* [dnsx](https://github.com/projectdiscovery/dnsx) - A fast and multi-purpose DNS toolkit that allows running multiple DNS queries of your choice with a list of user-supplied resolvers.

### Other tools

* [SecurityTrails](https://securitytrails.com/) - Powerful tools for third-party risk, attack surface management, and detailed intelligence.
* [WhoisXML API](https://www.whoisxmlapi.com/) - Domain & IP data intelligence for greater enterprise security.
* [RiskIQ](https://www.riskiq.com/) - RiskIQ Digital Footprint gives complete visibility beyond the firewall. Unlike scanners and IP-dependent data vendors, RiskIQ Digital Footprint is a solution with composite intelligence, code-level discovery, and automated threat detection and exposure monitoring—security intelligence mapped to your attack surface.
* [DeHashed](https://dehashed.com/) - Scan domains for indicators found in breaches.

### Network Diffing&#x20;

A simple but effective monitoring method, where regular port scans are run and then compared to previous scan results. This can be handy for detecting newly open ports on scanned devices. This action can be easily and quickly performed by [Masscan](https://github.com/robertdavidgraham/masscan).

* _The Hacker Playbook 3: Monitoring an Environment - pg.24_

## Deception Technology

* [OpenCanary](https://github.com/thinkst/opencanary) - A daemon that runs multiple "canary" versions of common services (SSH, HTTP, FTP, etc.). It acts as a lightweight, low-interaction honeypot that alerts on the first sign of interaction.
* [CanaryTokens](https://canarytokens.org/) - A free and simple way to drop "tripwires" into files, folders, or databases. Tokens (like a unique URL or DNS hostname) trigger an alert when accessed.

## File Integrity Monitoring

Persistence mechanisms often require attackers to interact with the target machine, such as creating or modifying files. This gives defenders the opportunity to detect them by monitoring for file creation or modification in critical files or directories.

* [AuditBeat's FIM](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-module-file\_integrity.html)
* [auditd](https://www.redhat.com/sysadmin/configure-linux-auditing-auditd)
* [Wazuh's FIM](https://documentation.wazuh.com/current/learning-wazuh/detect-fs-changes.html)

## File Analysis & Scanning

* [YARA](https://virustotal.github.io/yara/) - The industry standard for file-based pattern matching. YARA helps identify and classify malware samples by creating descriptions based on textual or binary patterns.
* [Loki](https://github.com/Neo23x0/Loki) - A free and simple IOC scanner that uses YARA rules and other indicators to scan endpoints for signs of compromise.

## Misc Tools

* [SAGAN](https://github.com/quadrantsec/sagan) - An open source (GNU/GPLv2) high performance, real-time log analysis & correlation engine that can be used with popular IDS tools and rules sets like Suricata and SNORT.
* [RITA](https://github.com/activecm/rita) - A tool that scans Zeek logs for beaconing detection and DNS tunneling.
* [dnstwist](https://github.com/elceef/dnstwist) - Tool for creation of potential typo-squatting domains by use of multi-character permutation and checking for registration of those domains.
  * [https://dnstwister.report/](https://dnstwister.report/) - Online Version and DNS monitoring service

## Deprecated / Archived Projects

The following tools were widely used or referenced in the past but are currently unmaintained, archived, or have been superseded. They are listed here for historical context or research purposes.

*   **[Intrigue Core](https://github.com/intrigueio/intrigue-core)** - Formerly a popular attack surface discovery framework, the project was archived following the acquisition by Mandiant (Google Cloud).
*   **[Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation)** - A legendary PowerShell obfuscation detection tool. While valuable for research, it is not actively maintained against modern PowerShell versions or evasion techniques.
*   **[Flare](https://github.com/austin-taylor/flare)** - A network analysis tool for Elastic Stack. Unmaintained.
*   **[OpenUBA](https://github.com/GACWR/OpenUBA)** - User & Entity Behavior Analytics framework. Unmaintained.
*   **[BlueSpawn](https://github.com/ION28/BLUESPAWN)** - EDR + Active Defense tool. Inactive/Dormant.
*   **[OpenEDR](https://github.com/ComodoSecurity/openedr)** - Open Source EDR monitoring. Inactive/Stagnant.
*   **[whids](https://github.com/0xrawsec/whids)** - Open Source EDR for Windows. Unmaintained.
*   **[ODIN](https://github.com/chrismaddalena/ODIN)** - Automated intelligence gathering tool. Unmaintained.
*   **[Asnip](https://github.com/harleo/asnip)** - Attack surface mapping tool. Unmaintained.
*   **[AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper)** - Reconnaissance tool. Unmaintained.
*   **[GQUIC Protocol Analyzer](https://github.com/salesforce/GQUIC\_Protocol\_Analyzer)** - Obsolete. Zeek now includes native [QUIC support](https://docs.zeek.org/en/current/scripts/base/protocols/quic/index.html).

## **Detection Use Cases**

{% content-ref url="detection-use-cases/" %}
[detection-use-cases](detection-use-cases/)
{% endcontent-ref %}
