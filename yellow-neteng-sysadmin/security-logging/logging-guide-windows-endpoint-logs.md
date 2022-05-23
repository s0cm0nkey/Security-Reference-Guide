# Logging - Endpoint Logs

## Windows

### **Windows Log Sources**

Windows events have the ability to be exceedingly granular, but also produce more logs than we can handle. Determining the logging level is a critical first step for on-boarding windows log sources. Managing Windows logging can be easily managed by powershell commands and Group Policy Objects.&#x20;

* Windows Event Logs - (.EVT) The older standard format for windows OS event logging.
* Windows Event Logs XML - (.EVTX) An upgraded logging format with slightly smaller storage size, pre-parsed fields, and an expanded number of data fields. This format is now the primary Windows log source.
  * XML fields parsed into EventData and UserData
  * Allows applications to specify additional properties/fields.
  * Stored in binary format and uses Windows EvtRender API to convert binary and XML.
  * [https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt\_system\_property\_id](https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt\_system\_property\_id)
  * [https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt\_log\_property\_id](https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt\_log\_property\_id)
* [Windows Event Tracing](https://docs.microsoft.com/en-us/archive/blogs/ntdebugging/part-3-etw-methods-of-tracing) - (ETW) Created ETL: Event Trace Logs(.ETL file), commonly used for debugging or troubleshooting.&#x20;
  * Disabled by default due to shear volume of data.
  * [https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)

### **Windows Log Management**

Windows Event logs are typically broken out into what windows calls "[Channels](https://docs.microsoft.com/en-us/windows/win32/wes/defining-channels)" which specifies the category of Events such as Application, Security, System, etc. There are four types of channels that existing within Windows:

* Admin - Well known events. (evtx)
* Operational - Used for human analysis (evtx)
* Analytic and Debug - High volume of information for the most granular of analysis. (.etl)

Windows uses audit policies to control what is logged and can easily be defined by group policy. Policies can con in a basic format or an advanced format for more granular control over your logging. Remember: when using advanced audit policies, enable "Force audit policy subcategory settings". Sometimes we will have systems that are not joined to the domain. Since group policy is not available, we can use a handy utility called auditpol.exe to remotely fetch and set audit policy settings. \
Microsoft has a fantastic set of [recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) for how to set-up your audit policy. CIS also has a set of [configuration recommendations](https://www.cisecurity.org/benchmark/microsoft\_windows\_desktop/) that have tons of helpful detail on why their settings are recommended.

### **Windows Event Types**

* Account management - Used for tracking un authorized changes in the environment. Can track changes to:
  * Application Groups,
  * System Accounts
  * User Active Directory Distribution Groups
  * Security Groups
  * Account Management related events such as password change or account lockout.
* Logon/Logoff - The primary event type for detecting credential theft and reuse.&#x20;
  * Logon/logoff activity
  * Special group logons
  * Failed logins, and thier failure reason
  * Account lockouts.
* Detailed Tracking - Next level details of endpoint activity
  * Process creation and termination
  * RPC events
  * Token rights changes
  * Plug-N-Play activity (Requires Win10/Server 2016)
  * Command-line logging (Requires manual adjustment)
* Object Access - Event type for monitoring of network objects. Does not log all activity by default. You must place an ACL on the object or object group in order to tell the Audit Policy what to log.
  * File creation/deletion/modification
  * Registry key changes
  * Network access
  * Windows Firewall logging
  * Active Directory Objects: Users, Groups, Files, Folders, etc.
  * Certificates

### **Supplementary Windows logging**&#x20;

#### When Event logs are not enough

[Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon): A Sysinternals tool that provides detailed information about process creations, network connections, and changes to file creation time. It is a wealth of information that can be used for a variety of purposes in Incident Response, Event Detection, and Threat Hunting.\
Sysmon adds additional logging capabilities over standard windows event logs. It can provide logs for driver/dll loding activities, WMI monitoring, and can provide process hashes and parent processes for analysis.

* [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux) - Linux version of Sysmon. Installation guide for Ubuuntu available on Github.
* [Sysmon-dfir](https://github.com/MHaggis/sysmon-dfir) - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
* [Sysmon-modular](https://github.com/olafhartong/sysmon-modular) - A repository of Sysmon configuration modules that breaks out Sysmon's functions into subfolders. You can use powershell to combine each function file into one larger XML configuration file.
* [Sysmon-config ](https://github.com/SwiftOnSecurity/sysmon-config)- SwiftOnSecurity's Sysmon configuration file template with default high-quality event tracing. Advanced Sysmon configurations require the use of an XML configuration file.
* [SysmonSearch](https://github.com/JPCERTCC/SysmonSearch) -  Investigate suspicious activity by visualizing Sysmon's event log.
* [TrustedSec Sysmon Community Guide](https://www.trustedsec.com/tools/trustedsec-sysmon-community-guide/) - Everything Dave Kennedy writes/makes is gold. It is the way.
* [Sysmon Threat Analysis Guide](https://www.varonis.com/blog/sysmon-threat-detection-guide/) [Splunking the Endpoint: Threat Hunting with Sysmon](https://haggis-m.medium.com/splunking-the-endpoint-threat-hunting-with-sysmon-9dd956e3e1bd)
* [Espy](https://github.com/activecm/espy/): Endpoint detection for remote hosts for consumption by RITA and Elasticsearch&#x20;
* [Sysmon API MindMap](https://raw.githubusercontent.com/OTRF/API-To-Event/master/images/API-to-Sysmon.svg)
* [https://docplayer.net/19532221-Tracking-hackers-on-your-network-with-sysinternals-sysmon.html](https://docplayer.net/19532221-Tracking-hackers-on-your-network-with-sysinternals-sysmon.html)

Custom Powershell Log Creation: When you have a program that only outputs logs to a file, or if you have a reoccurring task that you would like to log the output from, you can use the powershell "Write-EventLog" to output the results to a log file.

### **Windows Log Collection**

To achieve the greatest utility and flexibility, it is preferred to use a log agent over agentless collection. Windows also has a great log agent built into the platform with the Windows Event Collector.&#x20;

* **Windows Event Forwarding** - The built-in log forwarding and collecting service within windows
  * Requires a Windows Event Collector  logging agent to be configured and running
  * The Collector will then pull events from the endpoint, or the endpoint will push them to the Collector.
  * GPO can be users to tell the endpoints which events to push.
  * This is intended to be sent from one windows host to a windows collector, NOT directly into a SIEM.
  * Does not support the forwarding of ETL files
  * Can manage event subscriptions via an intuitive GUI, or by a custom XML file.
  * [https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)
  * [https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
  * [https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem](https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem)
  * [https://petri.com/configure-event-log-forwarding-windows-server-2012-r2/](https://petri.com/configure-event-log-forwarding-windows-server-2012-r2/)
  * [https://blog.palantir.com/windows-event-forwarding-for-network-defense-cb208d5ff86f?gi=79f1178de0ae](https://blog.palantir.com/windows-event-forwarding-for-network-defense-cb208d5ff86f?gi=79f1178de0ae)
  * [https://github.com/palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding)
* **Blind Drop** - When certain applications or devices cannot output files, or your organization refuses to install an agent on a device, you can output available logs to a file and then share the log files with a file server then into your SIEM for processing.
  * Requires a single file server and a third party agent or powershell script
  * File server is set up to allow log files to be uploaded but never modified or viewed.

## Linux

### **Linux Log Sources**

Syslog - The original method of logging for Linux.&#x20;

* Linux devices listen using a local socket by default
* Syslog daemon stores in /var/log/ by default
* Only supports UDP port 514
* Common log files
  * /var/log/message - Global message (general activity)
  * /var/log/auth.log - Authentication related logs
  * /var/log/boot.log - Boot time events
  * /var/log/daemon.log - Background Process Events
  * /var/log/kern.log - Kernel messages (Used for trouble shooting)
  * /var/log/cron.log - Events related to scheduled tasks
  * /var/log/secure - su or sudo related events.
* Syslog codes - These are the digits in the log files that identify both the purpose of the log and the importance.
  * Facility Codes - Details the purpose of the log. (0-23)
  * Severity Codes - Details the urgency of the log. (0-7)
  * [https://www.ietf.org/rfc/rfc5424.txt](https://www.ietf.org/rfc/rfc5424.txt)
* Syslog Structure
  * PRI - Number that combines Severity and Faciltiy codes together. PRI= Severity + (Faciltiy\*8)

[Syslog-NG](https://www.syslog-ng.com/products/open-source-log-management/) - Syslog enhanced

* Created to fill in the capability gaps for original syslog
* Adds ability to transport over TCP and SSL/TLS
* Capable of logging higher volumes of up to 600k+ messages per second
* Can perform custom filtering and parsing
* Easier to use config file
* Can send logs to multiple locations simultaneously

[Rsyslog](https://www.rsyslog.com/) - Rocket-fast Syslog

* As the name implies, can handle a massing 1million+ messages per second to local logging.
* Similar in increase in function to Syslog-NG
* Supports RELP: Reliable Event Logging Protocol
* Uses liblognorm instead of Regex to parse

### Third party logging tools

* [Auditd](https://linux.die.net/man/8/auditd) - Logging system developed by Red Hat
  * Provides additional logging information including user activity and process activity.
  * Config file of audit.rules contains 3 rules types
    * Control rules - Defines config settings of the logs
    * System call rules - Monitors system calls for processes and users.
    * File monitor rules
  * [https://access.redhat.com/documentation/en-us/red\_hat\_enterprise\_linux/6/html/security\_guide/chap-system\_auditing](https://access.redhat.com/documentation/en-us/red\_hat\_enterprise\_linux/6/html/security\_guide/chap-system\_auditing)
* [Snoopy Logger](https://github.com/a2o/snoopy) - Utility designed to log command line execution to syslog
* [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux) - Linux version of Sysmon. Installation guide for Ubuuntu available on Github.

## **Command line and Scripting basics**

In both Windows and Linux, the command line is actually an interpreter for scripting. Commands can be scripted for both the native command line utilities such as cmd.exe and Bash, as well as more powerful languages like Powershell or Python. Powershell in particular is used heavily for administrative actions within a network, as well as being used maliciously in over 38% of all incidents.

When logging command line usage and script calls it is important to understand thier common usage. Script files are used for automation and are seen being used very commonly by defenders. Defenders will often have repetitive, complex tasks that  automation through a script will drastically increase their workflow. Now, all of those tasks can be put manually in the command line instead of a script, but they can be incredibly long commands. In order to bypass detection by antivirus, often times attackers will place their long commands directly into the command line or call remote code, rather than directly run a script. Remember: Antivirus cannot detect a signature, when there is no file.

### **Powershell Execution Policy and other security**

Powershell has a built in security setting called the Execution policy. It was originally designed to prevent admins from running code they didnt intend on running. There are 4 policy settings available in Powershell.

* Restricted - Interactive commands only. No scripts.
* AllSigned - Permits only scripts that are digitally assigned by approved publishers
* RemoteSigned - Permits only scripts that are signed by approved publishers or generated locally.
* Unrestricted - Permits all scripts.

Sadly, there are quite a few ways to bypass it. That being said, you can create detections for most of these techniques. [https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)

Applocker can be used to allow or deny powershell use based on powershell itself, or particular scripts through a feature called [JEA: Just Enough Administration](https://github.com/PowerShell/JEA).

### **Command Line Logging**

Command line logging is not typically enabled by default. For windows environments, even enabled, you must take one step further in order to log the command line parameters as well.

* Windows - Enable logging of process creations under Windows Audit Policy
  * Computer Configuration -> Policies -> Administrative Templates -> System -> Audit Process Creation.
* Powershell
  * Event logs under Application and service logs -> Microsoft -> Windows -> "Microsoft-Windows-Powershell/Operational"
  * Module Logging - Records when a function from a module is invoked. Extremely verbose.
    * Event ID 4103 - Powershell Module Loaded
    * Requires Powershell 3.0
  * Script Block Logging - Generates a log for each block of code executed.&#x20;
    * Recorded at time of execution. Data is decoded within the log. Combine with command line logging to get both the before and after data.
    * Contains extra field called Event Type. Can classify suspicious commands with a WARNING level log.
    * Event ID 4104 - Creation of Script Block
    * Event ID 4105 - Script Block Execution Start
    * Event ID 4106 - Script Block Execution Stop
    * Requires Powershell 5.0&#x20;
  * Transcription Logging - Contains both the input and output, only saves to a file.

### **Command line key words for detection**

* Powershell
  * "/ExecutionPolicy bypass"

### **Reference**

* [https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1\&viewFallbackFrom=powershell-6](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1\&viewFallbackFrom=powershell-6)

****

****
