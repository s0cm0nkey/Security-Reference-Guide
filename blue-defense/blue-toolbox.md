# Blue Team Toolbox

This section collects useful tools and resources that don't fit neatly into the other specific categories but are essential for a robust defense strategy.

### Open Source AntiVirus/AntiMalware/AntiRootkit

* [ClamAV](https://www.clamav.net/) - An open source antivirus engine for detecting trojans, viruses, malware, and other malicious threats.
  * [ClamAV Documentation](https://docs.clamav.net/Introduction.html)
  * [On-Access Scanning](https://docs.clamav.net/manual/OnAccess.html) - For Linux users, ClamAV has an on-access scanning option. Ensure it is enabled for real-time protection.
* [YARA](https://virustotal.github.io/yara/) - The pattern matching swiss knife for malware researchers (and everyone else).
* [Rootkit Hunter (rkhunter)](https://rkhunter.sourceforge.net/) - A Unix-based tool that scans for rootkits, backdoors, and possible local exploits.
* [Chkrootkit](http://www.chkrootkit.org/) - A tool to locally check for signs of a rootkit.

### Secure Firmware

* [Coreboot](https://doc.coreboot.org/getting_started/index.html) - A replacement for your BIOS / UEFI with a strong focus on boot speed, security, and flexibility. Designed to boot the operating system as fast as possible without compromising security.
* [TianoCore](https://www.tianocore.org/) - A community project supporting an open source implementation of the Unified Extensible Firmware Interface (UEFI). EDK II is a modern, feature-rich, cross-platform firmware development environment for the UEFI and UEFI Platform Initialization (PI) specifications.

### Personal Firewall/Sandbox

* [PortMaster](https://safing.io/) - A free and open-source application firewall with adjustable defense profiles, white/blacklisting, and privacy features.
* [OpenSnitch](https://github.com/evilsocket/opensnitch) - A Linux Application Firewall.
* [FireJail](https://github.com/netblue30/firejail) - A SUID sandbox program that reduces the risk of security breaches by restricting the running environment of untrusted applications using Linux namespaces, seccomp-bpf, and Linux capabilities.
* [eBPF](https://ebpf.io/) - A technology that can run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.
* [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows) - An eBPF implementation that runs on top of Windows. eBPF is a well-known technology for providing programmability and agility, especially for extending an OS kernel, for use cases such as DoS protection and observability.

### OpenSource Email Security

* [Sublime Security](https://sublimesecurity.com/) - Sublime lets you write and run custom detection and response rules to block phishing attacks, hunt for threats, and more.

### Threat Intelligence Platforms (TIP)

* [MISP](https://www.misp-project.org/) - Malware Information Sharing Platform and Threat Sharing. Open source software for collecting, storing, distributing and sharing cyber security indicators.
* [OpenCTI](https://www.opencti.io/en/) - Open Cyber Threat Intelligence Platform. A unified platform to manage and analyze cyber threat intelligence.

### Malware Analysis & Sandboxing

* [CyberChef](https://gchq.github.io/CyberChef/) - The "Cyber Swiss Army Knife" - a web app for encryption, encoding, compression and data analysis.
* [Any.Run](https://any.run/) - Interactive online malware sandbox service.
* [Hybrid Analysis](https://www.hybrid-analysis.com/) - Free automated malware analysis service.
* [VirusTotal](https://www.virustotal.com/) - Analyze suspicious files, domains, IPs and URLs to detect malware and other breaches.
* [UrlScan.io](https://urlscan.io/) - A service to scan and analyse websites.

### Forensics & Incident Response

* [Velociraptor](https://docs.velociraptor.app/) - An advanced digital forensic and incident response tool that enhances your visibility into your endpoints.
* [Volatility](https://www.volatilityfoundation.org/) - The world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples.
* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) - A collection of highly regarded forensic tools for Windows (including KAPE, LECmd, etc.).
* [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - The classic suite of troubleshooting and security tools for Windows.

### Network Analysis

* [Wireshark](https://www.wireshark.org/) - The world’s foremost and widely-used network protocol analyzer.
* [Zeek](https://zeek.org/) - A powerful network analysis framework that is much different from the typical IDS you may know.
* [Suricata](https://suricata.io/) - A high performance Network IDS, IPS and Network Security Monitoring engine.
* [Zui (formerly Brim)](https://zui.brimdata.io/) - Desktop application to efficiently search and analyze super-structured network data (Zeek logs, PCAP).

### VMs/OSs

* [Security Onion](https://securityonionsolutions.com/) - A free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management.
* [SANS SIFT](https://www.sans.org/tools/sift-workstation/) - The SIFT Workstation is a collection of free and open-source incident response and forensic tools designed to perform detailed digital forensic examinations in a variety of settings.
* [Flare](https://github.com/mandiant/flare-vm) - A fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.
* [REMnux](https://remnux.org/) - A Linux toolkit for reverse-engineering and analyzing malicious software. REMnux provides a curated collection of free tools so analysts can investigate malware without having to find, install, and configure them individually.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - A “big data analytics” platform focused on the typical needs of computer forensic investigators/analysts and information security operations personnel. It is a customized build of the open source Elastic stack, pre-configured for forensic use.

### MacOS

* [Santa](https://github.com/google/santa) - A binary authorization system for macOS.
* [KnockKnock](https://objective-see.org/products/knockknock.html) - Uncovers persistently installed software to reveal malware.
* [LuLu](https://objective-see.org/products/lulu.html) - An open-source firewall that aims to block unknown outgoing connections, protecting your privacy and your Mac.
* *Operator Handbook: MacOS Defend - pg.162*

### Security Infrastructure Tools

* [Zuul](https://github.com/Netflix/zuul) - An [L7 application gateway](https://www.f5.com/services/resources/glossary/application-layer-gateway) providing dynamic routing, monitoring, resiliency, and security.
* [IPFire](https://www.ipfire.org/) - An open source firewall distribution.
* [pfSense](https://www.pfsense.org/) - A free and open source firewall and router featuring unified threat management, load balancing, and more.
* [Pi-hole](https://pi-hole.net/) - A [DNS sinkhole](https://en.wikipedia.org/wiki/DNS_Sinkhole) that protects devices from unwanted content without client-side software.

### Browser Security

* [uBlock Origin](https://github.com/gorhill/uBlock) - An efficient wide-spectrum content blocker.
* [Privacy Badger](https://privacybadger.org/) - Automatically learns to block invisible trackers.

### Misc Tools

* [SELinux](https://github.com/SELinuxProject/selinux) - A security enhancement to Linux providing mandatory access control (MAC) to support confidentiality and integrity requirements.
* [AppArmor](https://www.apparmor.net/) - A Linux application security system that proactively protects the OS and applications from threats by enforcing good behavior.
* [Veracrypt](https://veracrypt.fr/en/Home.html) - Open source disk encryption.
* [Network Tools](https://network-tools.com/) - Free online network toolset.
* [IP Location](https://lite.ip2location.com/ip-address-ranges-by-country) - IP address ranges by country.
* [TheHive](https://thehive-project.org/) - A scalable, open source Security Incident Response Platform.
* [Cortex](https://github.com/TheHive-Project/Cortex) - A tool for analyzing TheHive Observables at scale.
* [SANS Security Policy Templates](https://www.sans.org/information-security-policy/) - A collection of security policy templates.
* [CrowdSec](https://github.com/crowdsecurity/crowdsec/) - A collective behavior engine that analyzes behaviors to detect and block attacks.
* [Google Admin Toolbox](https://toolbox.googleapps.com/apps/main/) - Miscellaneous web-based utilities.
* [Grsecurity](https://grsecurity.net/) - Extensive security enhancement to the Linux kernel.
* **Graph and Charting Tools**
  * [Google Charts](https://developers.google.com/chart)
  * [Gnuplot](http://www.gnuplot.info/)

### Archived / Deprecated Projects

These tools are no longer actively maintained but remain here for reference or legacy compatibility.

* [Venator-Swift](https://github.com/richiercyrus/Venator-Swift) - (Archived) Proactive detection of malicious activity on macOS systems.
* [MADCert](https://github.com/NationalSecurityAgency/MADCert) - (Archived) Certificate generator and manager.
* [BLESS](https://github.com/Netflix/bless) - (Archived) Bastion's Lambda Ephemeral SSH Service.
* [D4 Project](https://d4-project.org/) - (Inactive) Distributed denial-of-service (DDoS) detection tool.
* [AfterGlow](http://afterglow.sourceforge.net/) - (Legacy) Network visualization tool.
