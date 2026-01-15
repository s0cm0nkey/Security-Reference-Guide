---
description: Common Security Events, how to analyze them, and the tools to do so.
---

# Event and Log analysis

## Types of data we work with

Security professionals typically work with parsed and normalized versions of log information within a SIEM. This structured data enables field-specific searching, the creation of use cases that map across various log sources, and provides a deeper level of detail than what appears in a standard alert.

**Event data** is the data behind the alert. It consists of all available details from the reporting log file, normalized into a standard format. This normalization is key, as it allows searches to operate across multiple log types. Generally, if you are working within a SOAR or SIEM, you will be dealing with event data.

When investigating an event, alert, or incident, there are generally three levels of data to consider:


* Alert data - These are essentially searches made in your data to look for specific matches. If working out of an alert queue like most security analysts, this is what you will get first. The alert should show you the search logic as well as the data points that are matched in the search.
* Event data - These are the event logs that your searches and use cases work off of. They are typically normalized for processing by your SIEM, parsed so you know which fields you need, and possibly filtered to limit the scope of the data you might find relevant.
* Log data - This is the raw, unedited, un-normalized data, before it is processed by another tool. Generally if you are working with an EDR platform, application logs, or system logs, these will be giving you raw log data.

Alert data and Event data can vary depending on the platform in use. Log data and its format are specific to the type of log being generated.

Security analysts typically work from Alert or Event data, pivoting to Log data if further investigation is needed. Threat hunters and forensic investigators often utilize raw Log data for its granular level of detail.

## Log Analysis Techniques

While tools provide alerts, analysts often need to hunt through data manually. Here are core techniques for finding anomalies in event data:

*   **Stacking (Frequency Analysis):** Grouping data by a specific field (e.g., User Agent, Event ID, Process Name) and counting unique occurrences. The goal is often **Long Tail Analysis**—investigating the "least frequent" occurrences (outliers) which are mathematically more likely to be anomalies.
*   **Baselining:** Defining "normal" behavior for a specific environment (e.g., "The backup service account always runs from Server A at 02:00 AM"). Deviations from this known good state are potential indicators of compromise.
*   **Parent-Child Process Analysis:** Examining the relationship between a process and the process that spawned it. For example, `winword.exe` (Microsoft Word) spawning `cmd.exe` or `powershell.exe` is highly suspicious and often indicates a macro-based attack.

## **Understanding Log results and their contents**

Logging formats will change depending on the log, log source, application, and manufacturer. Most are dense with information and can be difficult to parse without any reference. Below are some collections of cheatsheets and tool outputs that can help you make sense of the various log types you might encounter during an investigation.

* Platform Logs
  * [SigmaHQ](https://github.com/SigmaHQ/sigma) - The "Snort" for log events. Sigma is a generic signature format that allows you to describe detection methods once and convert them for use in Splunk, Elastic, Microsoft Sentinel, and others.
  * [What2Log](https://what2log.com/platformselection/) - What2Log is an amazing platform that breaks down the different logs and data points found within those logs, and gives fantastic guidance on what exactly they mean.
  * [Cheat-Sheets — Malware Archaeology](https://www.malwarearchaeology.com/cheat-sheets) - Collection of logging cheatsheets for various windows log types.
  * [Linux Logs Explained - Full overview of Linux Log Files - Plesk](https://www.plesk.com/blog/featured/linux-logs-explained/) - Breakdown of the files and paths of the various logs created by Linux
  * [Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx) - Explanation of Windows Event IDs
  * Windows [Security Identifiers](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) - Describes security identifiers and how they work in regards to accounts and groups in the Windows operating system.
  * [What are Microsoft Entra reports? | Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/overview-reports) - Understanding Microsoft Entra ID (formerly Azure AD) Audit logs
  * [Sign-in log schema in Azure Monitor | Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema) - Understanding Azure sign-in logs
  * [Detailed properties in the audit log - Microsoft Purview | Microsoft Learn](https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties) - O365 Log breakdown
* Protocol Specific Logs
  * [The Importance of DNS Logging in Enterprise Security](https://nxlog.co/whitepapers/dns-logging) - DNS log fields and analysis
* Tool/Application Logs
  * [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) - Great collection of tool outputs collected by the JP-CERT.
  * [Microsoft Defender AV event IDs and error codes | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus) - Understanding Defender AV event codes and Defender logs
  * [Sysmon - Windows Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) - Breakdown of sysmon logging and reported events.
  * [Proxy server logs for incident response](https://www.vanimpe.eu/2016/10/21/proxy-server-logs-incident-response/) - Web Proxy log breakdown
  * [Zeek and Windows Logs](https://f.hubspotusercontent00.net/hubfs/8645105/Corelight_May2021/Pdf/002_CORELIGHT_080420_ZEEK_LOGS_US_ONLINE.pdf) - Comparison and correlation of Zeek logs with Windows event logs.
* File properties and metadata
  * [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries, Scripts and Libraries. A reference for legitimate Windows binaries that can be abused by attackers to download files, execute code, or bypass security controls.
  * [Strontic xCyclopedia](https://strontic.github.io/xcyclopedia/) - Huge encyclopedia of executables, dll files, scripts, even the file paths they are supposed to be under. Contains tons of metadata, file hashes, reputation scores, handles, and so much more!
  * [Winbindex](https://winbindex.m417z.com/) - Index of windows binaries with file hash, size, what update it was created with, and many more. Perfect for understanding more on a file.
  * [Echotrail.io](https://www.echotrail.io) - A super handy tool that maps Windows filenames to hashes, parent/child process, and much more. Great for determining if a file really is a Windows file, or is behaving in a way that it should.
  * [FileSec.io](https://filesec.io/) - Stay up-to-date with the latest file extensions being used by attackers.
* Misc
  * [CyberChef](https://gchq.github.io/CyberChef/) - The "Swiss Army Knife" for decoding and manipulating data. Essential for decoding Base64 strings, URL encoding, or hex dumps found in logs.
  * [jq](https://jqlang.github.io/jq/) - A lightweight and flexible command-line JSON processor. Critical for parsing and filtering modern structured logs (like AWS CloudTrail or JSON-formatted syslog) in the terminal.
  * [Wireshark's MAC address OUI manufacturer lookup](https://gitlab.com/wireshark/wireshark/raw/master/manuf)
  * [MalAPI.io](https://malapi.io/) - Cheatsheet for commands that could be potentially used for malicious activity.
* Reference
  * _BTFM: Log Auditing - pg. 51_
  * _Crafting the InfoSec Playbook: Logging Requirements - pg.48_
  * _Cyber Operations: Logging - pg. 455_

![](<../.gitbook/assets/image (17) (1).png>)

![](<../.gitbook/assets/image (18).png>)
