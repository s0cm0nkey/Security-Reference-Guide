# Blue Team Toolbox

This page collects defensive tools that do not fit cleanly into a narrower Blue page. If a tool belongs to a specific workflow, use the related section instead of duplicating the full entry here.

## Endpoint Protection and Local Security

* [Rootkit Hunter (rkhunter)](https://rkhunter.sourceforge.net/) - Unix-based tool that scans for rootkits, backdoors, and possible local exploits.
* [Chkrootkit](http://www.chkrootkit.org/) - Local rootkit checking tool.
* [PortMaster](https://safing.io/) - Free and open-source application firewall with adjustable defense profiles.
* [OpenSnitch](https://github.com/evilsocket/opensnitch) - Linux application firewall.
* [FireJail](https://github.com/netblue30/firejail) - SUID sandbox program that reduces risk by restricting application runtime environments with Linux namespaces, seccomp-bpf, and capabilities.
* [Santa](https://github.com/google/santa) - Binary authorization system for macOS.
* [KnockKnock](https://objective-see.org/products/knockknock.html) - macOS persistence discovery tool from Objective-See.
* [LuLu](https://objective-see.org/products/lulu.html) - Open-source macOS firewall for controlling outbound connections.

## Firmware and Platform Security

* [Coreboot](https://doc.coreboot.org/getting_started/index.html) - Open firmware project focused on boot speed, security, and flexibility.
* [TianoCore](https://www.tianocore.org/) - Open-source implementation of UEFI and UEFI Platform Initialization specifications.
* [eBPF](https://ebpf.io/) - Kernel programmability technology used for observability, networking, and security controls.
* [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows) - Microsoft implementation of eBPF for Windows.
* [SELinux](https://github.com/SELinuxProject/selinux) - Mandatory access control framework for Linux.
* [AppArmor](https://www.apparmor.net/) - Linux application confinement system.
* [Grsecurity](https://grsecurity.net/) - Linux kernel security enhancement project.

## Email, Browser, and User-Facing Defense

* [Sublime Security](https://sublimesecurity.com/) - Email detection and response platform with custom rule support.
* [uBlock Origin](https://github.com/gorhill/uBlock) - Efficient wide-spectrum browser content blocker.
* [Privacy Badger](https://privacybadger.org/) - Browser extension that learns to block invisible trackers.
* [Veracrypt](https://veracrypt.fr/en/Home.html) - Open-source disk encryption.

## Security Infrastructure Tools

* [Zuul](https://github.com/Netflix/zuul) - L7 application gateway for dynamic routing, monitoring, resiliency, and security.
* [IPFire](https://www.ipfire.org/) - Open-source firewall distribution.
* [pfSense](https://www.pfsense.org/) - Open-source firewall and router platform.
* [Pi-hole](https://pi-hole.net/) - DNS sinkhole for blocking unwanted domains at the network level.
* [CrowdSec](https://github.com/crowdsecurity/crowdsec/) - Collaborative behavior engine for detecting and blocking attacks.
* [SANS Security Policy Templates](https://www.sans.org/information-security-policy/) - Security policy templates for common organizational needs.

## Small Utilities

* [Network Tools](https://network-tools.com/) - Web-based network toolset.
* [Google Admin Toolbox](https://toolbox.googleapps.com/apps/main/) - Miscellaneous Google administration and diagnostic utilities.
* [Google Charts](https://developers.google.com/chart) - Charting library for visualizations.
* [Gnuplot](http://www.gnuplot.info/) - Command-line graphing utility.

## Related Tool Homes

* SIEM, IDS/IPS, endpoint detection, Sysmon, and detection engineering tools live in Event Detection.

{% content-ref url="event-detection/" %}
[event-detection](event-detection/)
{% endcontent-ref %}

* Packet capture, Zeek, Wireshark, Zui, and protocol analysis tools live in Packet Analysis.

{% content-ref url="packet-analysis.md" %}
[packet-analysis.md](packet-analysis.md)
{% endcontent-ref %}

* Threat intelligence platforms, indicator enrichment, URL reputation, VirusTotal, URLScan, MISP, and OpenCTI live in Cyber Intelligence.

{% content-ref url="../cyber-intelligence/" %}
[cyber-intelligence](../cyber-intelligence/)
{% endcontent-ref %}

* Incident response, forensics, malware analysis, sandboxing, YARA, SIFT, REMnux, FLARE VM, Velociraptor, Volatility, and Eric Zimmerman tools live in DFIR.

{% content-ref url="../dfir-digital-forensics-and-incident-response/" %}
[dfir-digital-forensics-and-incident-response](../dfir-digital-forensics-and-incident-response/)
{% endcontent-ref %}

* Deception, honeypots, canary tokens, Fail2Ban, CrowdSec, and active response live in Active Defense.

{% content-ref url="active-defense.md" %}
[active-defense.md](active-defense.md)
{% endcontent-ref %}

## Archived / Deprecated Projects

These tools are no longer actively maintained but remain here for reference or legacy compatibility.

* [Venator-Swift](https://github.com/richiercyrus/Venator-Swift) - Archived proactive detection project for macOS systems.
* [MADCert](https://github.com/NationalSecurityAgency/MADCert) - Archived certificate generator and manager.
* [BLESS](https://github.com/Netflix/bless) - Archived Lambda-based ephemeral SSH bastion.
* [D4 Project](https://d4-project.org/) - Inactive distributed denial-of-service detection project.
* [AfterGlow](http://afterglow.sourceforge.net/) - Legacy network visualization tool.
