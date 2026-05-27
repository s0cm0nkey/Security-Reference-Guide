---
description: Search-friendly index of cyber security resource topics across blue team, red team, DFIR, OSINT, cloud, containers, AppSec, logging, privacy, and training.
---

# Resource Index

This index points common search topics to their canonical page in the guide. It is intentionally high-level: detailed links and tool lists live on the section pages.

## Blue Team and SOC

* **Blue team resources, SOC operations, defensive security, hardening, threat hunting**: [Blue - Defensive Operations](blue-defense/README.md)
* **Detection engineering, SIEM rules, Sigma, Sysmon, IDS/IPS, detection use cases**: [Event Detection](blue-defense/event-detection/README.md)
* **Security query languages, KQL, Splunk SPL, Sigma, YARA-L, SIEM searches**: [Query Languages](blue-defense/query-languages.md)
* **Packet capture, PCAP analysis, Wireshark, Zeek, Suricata, network security monitoring**: [Packet Analysis](blue-defense/packet-analysis.md)
* **Vulnerability management, exposure management, code scanning, secret scanning**: [Asset and Vulnerability Management](blue-defense/vulnerability-management.md)

## Logging and Architecture

* **Security logging strategy, log collection, retention, log pipelines**: [Logging and Security Architecture](security-logging/README.md)
* **Endpoint logging, Windows Event Logs, Linux logs, Sysmon collection**: [Logging - Endpoint Logs](security-logging/logging-guide-windows-endpoint-logs.md)
* **Cloud audit logs, AWS CloudTrail, Azure activity logs, Microsoft 365 audit, Google Cloud logging**: [Logging - Cloud](security-logging/logging-cloud.md)
* **DNS logs, HTTP logs, SMTP logs, flow data, network service logs**: [Logging - Network Services](security-logging/logging-guide-network-services.md)
* **Asset inventory, device discovery, CMDB context, log source evaluation**: [Device Discovery and Asset Monitoring](security-logging/device-discovery-and-asset-inventory.md)

## DFIR and Malware Analysis

* **Incident response, DFIR tools, forensic triage, evidence collection**: [Blue - DFIR](dfir-digital-forensics-and-incident-response/README.md)
* **Windows DFIR commands, Windows event logs, process analysis, remediation commands**: [Windows DFIR Checks](dfir-digital-forensics-and-incident-response/windows-dfir-checks.md)
* **Linux DFIR commands, macOS DFIR commands, host investigation**: [Linux DFIR Commands](dfir-digital-forensics-and-incident-response/linux-dfir-commands.md) and [macOS DFIR Commands](dfir-digital-forensics-and-incident-response/macos-dfir-commands.md)
* **Memory forensics, Volatility, process memory, injected code**: [Memory Forensics](dfir-digital-forensics-and-incident-response/memory-forensics/README.md)
* **Malware analysis, sandboxing, file analysis, YARA, reverse engineering**: [Malware](dfir-digital-forensics-and-incident-response/malware.md)

## Cyber Intelligence and OSINT

* **Cyber threat intelligence, CTI, intelligence cycle, indicator enrichment**: [Cyber Intelligence](cyber-intelligence/README.md)
* **Threat feeds, blocklists, reputation sources, MISP, OpenCTI, TAXII/STIX**: [Intel Feeds and Sources](cyber-intelligence/intel-feeds-and-sources.md)
* **Threat data, hashes, URLs, domains, IP reputation, malware lookup**: [Threat Data](cyber-intelligence/threat-data.md)
* **OSINT tools, search engines, domain investigation, username and email investigation**: [OSINT](cyber-intelligence/osint/README.md)
* **Shodan, Censys, ZoomEye, FOFA, internet-exposed asset search**: [Cyber Search Engines](cyber-intelligence/osint/cyber-search.md)

## Offensive Security

* **Penetration testing, red team operations, offensive methodology**: [Red - Offensive Operations](red-offensive/README.md)
* **Active reconnaissance, Nmap, vulnerability scanning, recon frameworks**: [Reconnaissance and Scanning](red-offensive/scanning-active-recon/README.md)
* **Exploitation, Metasploit, payloads, shells, exploit research**: [Exploitation and Targets](red-offensive/exploitation-and-targets/README.md)
* **Post-exploitation, persistence, defense evasion, credential harvesting**: [Post Exploitation](red-offensive/testing-methodology/post-exploitation/README.md)
* **Active Directory attacks, lateral movement, password attacks, C2 frameworks**: [Attacking Active Directory](red-offensive/testing-methodology/active-directory.md)

## Web Application Security

* **Web application hacking, AppSec testing, bug bounty methodology, OWASP testing**: [Web App Hacking](web-app-hacking/README.md)
* **Burp Suite, Burp extensions, web proxy testing**: [Burp Suite](web-app-hacking/burp-suite.md)
* **Web app scanners, content discovery, API testing utilities**: [Web App Scanning Utilities](web-app-hacking/scanning-utilities.md)
* **OAuth, API security, TLS, certificates, WAF testing, web technologies**: [Web Technologies](web-app-hacking/web-technologies/README.md)
* **SQL injection, XSS, CSRF, XXE, request smuggling, IDOR, host header attacks**: [Attacks and Vulnerabilities](web-app-hacking/attacks-and-vulnerabilities/README.md)

## Platform and Engineering Fundamentals

* **Cloud security, AWS, Azure, Google Cloud, Microsoft 365, cloud testing**: [Cloud](cloud.md)
* **Docker, Kubernetes, container security, image scanning, runtime security**: [Containers](containers.md)
* **Networking, sysadmin, operating systems, Active Directory basics, protocols**: [Yellow - NetEng/SysAdmin](yellow-neteng-sysadmin.md)
* **Bash, PowerShell, command line, regex, scripting, data transformation**: [Yellow - Code and CLI](code-tools/README.md)
* **AI, machine learning, FOSS alternatives, security research datasets**: [Yellow - AI, Machine Learning, and FOSS](yellow-ai-machine-learning-and-foss.md)

## Privacy, OPSEC, and Training

* **Privacy, Tor, PGP, anonymity, secure communication, OPSEC**: [Grey - Privacy/TOR/OPSEC](grey-privacy-tor-opsec/README.md)
* **Cyber security training, courses, certifications, books, labs, CTF practice**: [Training and Resources](training/README.md)
* **Awesome lists, massive security resource collections, curated GitHub lists**: [The Awesome Lists](training/the-awesome-lists.md)
* **Practice labs, home labs, vulnerable environments, CTF platforms**: [Practice Lab](training/practice-lab.md)
