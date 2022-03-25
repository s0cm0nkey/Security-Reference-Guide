# Device Discovery and Asset Monitoring

## **“If you know the enemy and know yourself, you need not fear the result of a hundred battles." - Sun Tzu**

The first step in protecting your network from attackers is understanding it. You cannot defend what you do not know exists. [CIS Controls](https://www.cisecurity.org/controls/) list of 20 controls recommended for securing your network, has #1 and #2 all about inventorying devices and software within your environment.\
"If an organization does not know what each asset is for, then it is not a fair expectation that a managed security service provider (MSSP) will know. If the MSSP cannot know the business context of an asset, then monitoring and protection become more and more difficult. This is an area where end users of managed services can try to better integrate with their MSSP." - SANS SEC555

There are 2 asset layers we need to focus on for proper auditing within an environment. Below are the two layers and their minimum associated data points. (These are not exhaustive but should be the minimum known data points)

* **Devices**
  * Mac Address
  * IP address
  * Hostname
  * Operating System
  * Installed Software
  * Processes
  * Scripting frameworks
  * Associated User
* **Users**
  * Name
  * Username
  * Email
  * Groups
  * Authentication status
  * Permissions
  * Privileges
  * Geo-locations.
  * Associated workstation

The methodology for collecting these will come from both active and passive network detection abilities. The following sections will detail the tools and techniques used for these.

**Active Network Detection**

Active network detection is where there is an actual interaction with the device. This can happen with port scanning or any process that has authentication to the device in order to enumerate data about the device.

Active Network Detection Sources

* Network Scanners
  * [NMAP ](https://nmap.org)scanning is popular, easy, and can return a wealth of data including hostname, open ports, operating system and more. Uses a fingerprint database to identify device types, services, and the host operating system.
* Vulnerability Scanners
  * Can be unauthenticated which works similar to an NMAP scan
  * Can be authenticated which allows direct querying of the device and return significantly more data.
  * Typically will support SNMP, SSH, and SMB by default.
  * [VulnWhisperer](https://github.com/HASecuritySolutions/VulnWhisperer) - A handy script for exporting vuln scan data and importing it into Elastic Stack
  * [PoshNessus](https://github.com/tenable/Posh-Nessus) - Powershell module for automating Nessus functions.
* Inventory Systems

**Passive Network detection**

Passive network detection is where there is no interaction with the device, and the data is collected from passive logs or traffic seen within the network. Much of this will require detailed internal East-West Activity.

Passive Network Detection Sources

* Active Directory requests
* Zeek
  * software.log file maps IP to software usage without repetitive logging.
* DHCP
* NetFlow
* Firewall
* Switch CAM Tables
  * [https://github.com/HASecuritySolutions/Logstash/blob/master/scripts/CAMTableExport.ps1](https://github.com/HASecuritySolutions/Logstash/blob/master/scripts/CAMTableExport.ps1)
  * OUI lookup to determine manufacturer
    * Look for Invalid OUIs
    * Wireshark maintains a [free OUI file](https://gitlab.com/wireshark/wireshark/raw/master/manuf)
* Wireless IDS
* NTP
  * All corporate assets should be using an internal NTP server
  * Can identify  personal devices by how they request NTP from internet time servers
  * time.windows.com, time.apple.com, ntp.ubuntu.com, etc.

**Software Monitoring**

Inventory of both software installed as well as running as a process, is critical to determining what is allowed in your environment. Especially processes. "Malware can hide, but it must run" - SANS. Once the applications and software has been inventoried, you can create a highly effective strategy for detecting anomalies by creating a process for application whitelisting. [NIST 800-167](https://www.nist.gov/publications/guide-application-whitelisting) gives a great guide on this.

Determining what is installed can be done by leveraging the data from a few different sources.

* Client Management Tools
* Patch Management
* Application Control
  * [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) - Free app control solution for Windows.
    * Can perform blocking by Path, Hash, or Publisher.
* Process Monitoring

For using this software inventory as a basis for detections, we can perform long tail analysis on the inventory by looking at software by count, and looking for those with the lowest count. In a large environment, installed software and running processes shouldn't differ too much between devices.

**Asset Tagging**

A detailed asset inventory can be more than a simple lookup for enrichment. You can built simple detections around assets that have been tagged into groups. Powershell.exe use by the system admins group? Totally expected. Powershell.exe used by an accountant? Might want to look in to that.&#x20;

**Device Baseline Monitoring**

Device baselines are handy for defining "normal" configurations and acitivty, and then being able to compare them against future snapshots, looking for any significant discrepancies.&#x20;

Creating baselines starts with collection of various data points from your devices. This can come in the form of a script or a log agent that can forward the data on to your SIEM.

Baseline Data to capture

* Active Processes
  * Long Tail analysis on running processes accross the environment is very effective here.
* ARP Cache
  * Simple arp -a with long tail analysis can identify strange devices. Investigate one-off entries
* Certificates
  * Filter on trusted certificates and authorities
  * Alert on new entries
  * Powershell - Get-ChildItem in the certificate store
* Drivers
* Host Files
  * Local files take precendence over DNS
  * Should not change except by IT or developers
  * Typically has 0 entries
* Registry Keys
* Route Table
  * Check for number of gateways. There should typically one be one. There might be two if using a VPN, but no more than that. Investigate what you cannot account for.
* Scheduled Tasks
* Security Status
  * Check that your Host firewalls, AV, and App control is all enabled. When should this ever be disabled?
  * Get-WMIObject -namespace root\Microsoft\SecurityClient -list
    * Shows AV info and status
  * netsh.exe advfirewall show all profiles
    * Shows Windows firewall status per profile
* Services
* Shares
* Software inventory
* USB devices
* Users and Groups
  * Most systems are AD integrated. Local accoutns should be disabled, or at the very least be given random passwords.
  * Get-WMIObject -Class Win32\_UserAccount -Filter "LocalAccount='True'"
  * Can also extract the last password change to check for proper password rotation.

**Baseline Tools**

* [Log Campaign](https://github.com/HASecuritySolutions/LogCampaign) - A powershell script framework for automatically creating a device baseline.
  * Logs to Windows Channel or Syslog
  * Comes with built in baseline modules
  * Includes a module for checking [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns), and areas of persistence.
    * This works very well with Long Tail analysis.
* [Kansa](https://github.com/davehull/Kansa) - Designed for incident response, this tool can be used to easily create a baseline.
  * Does not easily export to SIEM

