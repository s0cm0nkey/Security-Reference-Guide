# Device Discovery and Asset Monitoring

Asset inventory gives logs context. A source IP, process name, or username is far more useful when analysts can tie it to an owner, role, location, criticality, and expected behavior.

## Minimum Inventory Data

### Devices

* MAC address
* IP address
* Hostname
* Operating system
* Installed software
* Running processes
* Scripting frameworks
* Primary user or owner
* Business role or criticality

### Users

* Name
* Username
* Email
* Groups
* Authentication status
* Permissions
* Privileges
* Typical workstation
* Typical location or region

## Active Discovery

Active discovery interacts with the device or service.

* **Network scanners** - Nmap and similar tools can identify hosts, ports, services, and sometimes operating systems.
* **Authenticated vulnerability scanners** - Can collect software, patch, configuration, and exposure data.
* **Inventory and endpoint management systems** - Often provide the cleanest software and ownership data.
* **Cloud APIs** - Provide resource inventories, tags, owners, and configuration details.

Vulnerability scanning depth belongs in Red Offensive or vulnerability management pages. This page focuses on using inventory data as logging context.

{% content-ref url="../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../red-offensive/scanning-active-recon/)
{% endcontent-ref %}

## Passive Discovery

Passive discovery uses logs and observed traffic.

* Active Directory requests
* DHCP logs
* DNS logs
* NetFlow/IPFIX
* Firewall logs
* Zeek/Corelight logs
* Switch CAM tables
* Wireless IDS
* NTP logs

Examples:

* `software.log` from Zeek can map IP addresses to observed software.
* DHCP logs can tie IP addresses to MAC addresses and hostnames.
* NTP requests can reveal unmanaged personal devices if corporate assets should only use internal time servers.
* Switch CAM data can support MAC-to-port and manufacturer lookup.

Useful resources:

* [HASecuritySolutions CAMTableExport](https://github.com/HASecuritySolutions/Logstash/blob/master/scripts/CAMTableExport.ps1)
* [Wireshark OUI manufacturer file](https://gitlab.com/wireshark/wireshark/raw/master/manuf)

## Software Monitoring

Software inventory helps define expected applications and identify unusual software. Process inventory is even more important because malware can hide on disk, but it must execute.

Sources:

* Client management tools
* Patch management
* Application control
* EDR tools
* Process monitoring
* Log agents

Application allowlisting and control:

* [NIST SP 800-167: Guide to Application Whitelisting](https://www.nist.gov/publications/guide-application-whitelisting)
* [AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)

Detection and threat hunting examples that use software rarity or long-tail analysis belong in Blue Defense.

{% content-ref url="../blue-defense/threat-hunting.md" %}
[threat-hunting.md](../blue-defense/threat-hunting.md)
{% endcontent-ref %}

## Device Baseline Monitoring

Baselines define normal configuration and activity so changes can be reviewed over time.

Useful baseline data:

* Active processes
* ARP cache
* Certificates
* Drivers
* Hosts file
* Registry keys
* Route table
* Scheduled tasks
* Host firewall, antivirus, and application control status
* Services
* Shares
* Software inventory
* USB devices
* Local users and groups

Example Windows checks:

```powershell
Get-WmiObject -Namespace root\Microsoft\SecurityClient -List
netsh.exe advfirewall show allprofiles
Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
```

## Baseline Tools

* [Log Campaign](https://github.com/HASecuritySolutions/LogCampaign) - PowerShell framework for creating device baselines and logging them to Windows channels or syslog.
* [Kansa](https://github.com/davehull/Kansa) - Incident-response collection framework. Useful for baselines in labs or IR workflows, but canonical DFIR coverage belongs in DFIR.

{% content-ref url="../dfir-digital-forensics-and-incident-response/" %}
[dfir-digital-forensics-and-incident-response](../dfir-digital-forensics-and-incident-response/)
{% endcontent-ref %}
