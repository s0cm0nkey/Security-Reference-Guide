# Sysmon

### [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. It is a critical data source for Incident Response, Event Detection, and Threat Hunting.

## Configuration & Tools

* [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux) - Linux version of Sysmon. Installation guide for Ubuntu available on GitHub.
* [Sysmon-dfir](https://github.com/MHaggis/sysmon-dfir) - Sources, configuration, and detection logic utilizing Microsoft Sysmon.
* [Sysmon-modular](https://github.com/olafhartong/sysmon-modular) - A repository of Sysmon configuration modules for granular control.
* [Sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) - SwiftOnSecurity's Sysmon configuration file template with default high-quality event tracing.
* [SysmonSimulator](https://github.com/ScarredMonk/SysmonSimulator) - Sysmon event simulation utility used to simulate attacks and generate Sysmon Event logs for testing EDR detections and correlation rules.
* [SysmonView](https://github.com/nokeeko/SysmonView) - An off-line Sysmon log visualization tool.
* [SysmonShell](https://github.com/nokeeko/SysmonShell) - A GUI tool for creating and editing Sysmon configuration files.
* [Espy](https://github.com/activecm/espy/) - Endpoint detection for remote hosts for consumption by RITA and Elasticsearch.

## Legacy / Archived Projects

* [SysmonSearch](https://github.com/JPCERTCC/SysmonSearch) - Investigate suspicious activity by visualizing Sysmon's event log. (Note: Project appears unmaintained and may not support newer Sysmon schemas).
* [NXLog-Autoconfig](https://github.com/SMAPPER/NXLog-AutoConfig) - Script to install Sysmon with the [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) config. (Note: Project appears unmaintained).

## Guides & Resources

* [TrustedSec Sysmon Community Guide](https://www.trustedsec.com/tools/trustedsec-sysmon-community-guide/) - Comprehensive guide on Sysmon configuration and usage.
* [Sysmon Threat Analysis Guide](https://www.varonis.com/blog/sysmon-threat-detection-guide/) - Guide on using Sysmon for threat detection.
* [Splunking the Endpoint: Threat Hunting with Sysmon](https://haggis-m.medium.com/splunking-the-endpoint-threat-hunting-with-sysmon-9dd956e3e1bd) - Blog post on using Splunk and Sysmon for threat hunting.
* [Sysmon API MindMap](https://raw.githubusercontent.com/OTRF/API-To-Event/master/images/API-to-Sysmon.svg) - Visual map of Sysmon API to events.
* [Sysmon Cheatsheet](https://github.com/olafhartong/sysmon-cheatsheet/blob/master/Sysmon-Cheatsheet-dark.pdf) - A quick reference cheatsheet for Sysmon.

### Key Sysmon Event IDs

* **Event ID 1**: Process Creation
* **Event ID 3**: Network Connection
* **Event ID 7**: Image Loaded
* **Event ID 8**: CreateRemoteThread
* **Event ID 11**: File Create
* **Event ID 12, 13, 14**: Registry Events (Create/Delete, Value Set, Rename)
* **Event ID 15**: FileCreateStreamHash
* **Event ID 22**: DNS Query

### Sysmon Event Types and Fields

![](<../../.gitbook/assets/image (24).png>)
