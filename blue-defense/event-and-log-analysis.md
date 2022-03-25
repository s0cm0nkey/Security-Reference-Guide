---
description: Common Security Events, how to analyze them, and the tools to do so
---

# Event and Log analysis

## Types of data we work with

These are the parsed and normalized version of the log information that comes into your SIEM. These will help you be able to search for data in specific fields, create use cases that map across log sources, and provide the next level of detail beyond what appears in an alert.Event data - This is the data behind the alert. This should be all of the available details found in the reporting log file, normalized/converted into a standard format. This normalization is key, as it is what allows your searches to work across multiple log types. Generally, if you are working out of a SOAR or SIEM, you will be dealing with event data.When investigating an event, alert, or incident, there will be three levels of data you will look at:&#x20;

* Alert data - These are essentially searches made in your data to look for specific matches. If working out of an alert queue like most security analysts, this is what you will get first. The alert should show you the search logic as well as the data points that are matched in the search.
* Event Data - These are the event logs that your searches and use cases work off of. They are typically normalized for processing by your SIEM, parsed so you know which fields you need, and possibly filtered to limit the scope of the data you might find relevant.
* Log data - This is the raw, unedited, un-normalized data, before it is processed by another tool. Generally if you are working with an EDR platform, application logs, or system logs, these will be giving you raw log data.

Alert data and Event data can change depending on the platform you are using. Log data and format will be specific to the type of log that is being generated. \
Security analysts will typically be working from Alert/Event data, and then pivot to log data if they need further investigation. Threat hunters and forensics investigators will typically use raw log data for its granular level of detail.

## **Understanding Log results**

Logging formats will change depending on the log, log source, application, and manufacturer. Most are super dense with information and can be difficult to parse with out any reference. Below are some collections of cheatsheets and tool outputs that can help you make sense of some of the log types you might deal with and part of an investigation.

* [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) - Great collection of tool outputs collected by the JP-CERT.
* [Cheat-Sheets — Malware Archaeology](https://www.malwarearchaeology.com/cheat-sheets) - Collection of logging cheatsheets for various windows log types.
* [Strontic xCyclopedia](https://strontic.github.io/xcyclopedia/) - Huge encyclopedia of executables, dll files, scripts, even the file paths they are supposed to be under. Contains tons of metadata, file hashes, reputation scores, handles, and so much more!
* [Winbindex](https://winbindex.m417z.com) - Index of windows binaries with file hash, size, what update it was created with, and many more. Perfect for understanding more on a file.
* [Echotrail.io](https://www.echotrail.io) - A super handy tool that maps windows file  to hashes, parent/child process, and much more. Great for determining if a file is really is a windows file, or is behaving in a way that it should.
* [https://filesec.io/](https://filesec.io) - Stay up-to-date with the latest file extensions being used by attackers.
* [Linux Logs Explained - Full overview of Linux Log Files - Plesk](https://www.plesk.com/blog/featured/linux-logs-explained/) - Breakdown of the files and paths of the various logs created by Linux
* [Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx) - Explanation of Windows Event IDs
* Windows [Security Identifiers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) - Describes security identifiers and how they work in regards to accounts and groups in the Windows operating system.
* [Microsoft Defender AV event IDs and error codes | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) - Understanding Defender AV event codes and Defender logs
* [Sysmon - Windows Sysinternals | Microsoft Docs](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - Breakdown of sysmon logging and reported events.
* [What are Azure Active Directory reports? | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/overview-reports)  - Understanding Azure AD Audit logs
* [Sign-in log schema in Azure Monitor | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema) - Understanding Azure sign-in logs
* [Detailed properties in the audit log - Microsoft 365 Compliance | Microsoft Docs](https://docs.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log?view=o365-worldwide) - O365 Log breakdown
* [Understanding DHCP Server Log File Format - ](https://www.serverbrain.org/network-planning-2003/understanding-dhcp-server-log-file-format.html)DHCP log breakdown
* [The Importance of DNS Logging in Enterprise Security](https://nxlog.co/whitepapers/dns-logging) - DNS log fields and analysis
* [Proxy server logs for incident response -](https://www.vanimpe.eu/2016/10/21/proxy-server-logs-incident-response/) Web Proxy log breakdown
* [Zeek and Windows Logs](https://f.hubspotusercontent00.net/hubfs/8645105/Corelight\_May2021/Pdf/002\_CORELIGHT\_080420\_ZEEK\_LOGS\_US\_ONLINE.pdf)
* [Wireshark's MAC address OUI manufacturer lookup](https://gitlab.com/wireshark/wireshark/raw/master/manuf)
* [https://malapi.io/](https://malapi.io) - Cheatsheet for commands that could be potentially used for malicious activity.
* _BTFM: Log Auditing - pg. 51_
* _Crafting the InfoSec Playbook: Logging Requirements - pg.48_
* _Cyber Operations: Logging - pg. 455_

![](<../.gitbook/assets/image (17).png>)

![](<../.gitbook/assets/image (18).png>)
