# Logging - Endpoint Logs

Endpoint logs provide host-level visibility for authentication, process execution, file activity, PowerShell, system changes, and local security state. This page focuses on enabling and collecting endpoint logs from Windows and Linux systems.

Detection use cases that consume endpoint logs live in Blue Defense.

{% content-ref url="../blue-defense/event-detection/detection-use-cases/endpoint.md" %}
[endpoint.md](../blue-defense/event-detection/detection-use-cases/endpoint.md)
{% endcontent-ref %}

{% content-ref url="../blue-defense/event-detection/detection-use-cases/command-line.md" %}
[command-line.md](../blue-defense/event-detection/detection-use-cases/command-line.md)
{% endcontent-ref %}

## Windows

### Windows Log Sources

* **EVT** - Older Windows event log format.
* **EVTX** - Current Windows event log format with structured XML fields.
* **ETW / ETL** - Event Tracing for Windows and Event Trace Log files. Useful for high-volume tracing, debugging, and specialized telemetry.

Useful Microsoft references:

* [Windows Event Log API](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
* [EVT_SYSTEM_PROPERTY_ID](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_system_property_id)
* [EVT_LOG_PROPERTY_ID](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_log_property_id)
* [Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)

### Windows Log Management

Windows event channels include:

* **Admin** - Events intended for administrators.
* **Operational** - Events used for operational troubleshooting and analysis.
* **Analytic and Debug** - High-volume tracing channels, often disabled by default.

Windows audit policy controls what security events are logged. Use Group Policy for domain systems and `auditpol.exe` for local or remote inspection where appropriate.

* [Microsoft audit policy recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
* [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop/)

### Windows Event Types

* **Account management** - User, group, and account lifecycle changes.
* **Logon/Logoff** - Logon activity, failed logons, lockouts, and special logons.
* **Detailed tracking** - Process creation, process termination, RPC events, token changes, and plug-and-play activity.
* **Object access** - File, registry, network share, firewall, certificate, and Active Directory object access when auditing is configured.

### Supplementary Windows Logging

Sysmon is a supplementary log source for process creation, network connections, driver and DLL loading, WMI activity, hashes, parent process relationships, registry activity, and more. Keep Sysmon configuration and detection resources on the Sysmon page.

{% content-ref url="../blue-defense/event-detection/sysmon.md" %}
[sysmon.md](../blue-defense/event-detection/sysmon.md)
{% endcontent-ref %}

Custom PowerShell logging can also be useful when scripts or programs only write to local files. `Write-EventLog` can place custom operational output into Windows Event Logs.

### Windows Event Forwarding

Windows Event Forwarding (WEF) is the built-in Windows collection mechanism for forwarding Windows Event Logs to a Windows Event Collector.

* Uses WinRM.
* Can be configured by Group Policy.
* Supports source-initiated and collector-initiated subscriptions.
* Is intended for Windows endpoint-to-Windows collector forwarding, not direct SIEM ingestion.
* Does not forward ETL files.

References:

* [Microsoft: Use Windows Event Forwarding to help with intrusion detection](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
* [Windows Event Forwarding Survival Guide](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)
* [Monitoring What Matters: Windows Event Forwarding for Everyone](https://learn.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem)
* [Palantir Windows Event Forwarding](https://github.com/palantir/windows-event-forwarding)
* [Palantir: Windows Event Forwarding for Network Defense](https://blog.palantir.com/windows-event-forwarding-for-network-defense-cb208d5ff86f)

### Blind Drop Collection

Blind drop collection is useful when an application or device can write logs only to a file and an agent cannot be installed. A file server accepts log uploads, then a collector or agent forwards those files to the logging platform.

## Linux

### Syslog

Linux systems typically write local logs under `/var/log/` through a syslog daemon. Modern syslog implementations can forward over UDP, TCP, RELP, and TLS depending on the daemon and configuration.

Common log paths:

* `/var/log/messages` - General system messages on many distributions.
* `/var/log/auth.log` - Authentication events on Debian/Ubuntu-style systems.
* `/var/log/secure` - Authentication and sudo-related events on RHEL-style systems.
* `/var/log/boot.log` - Boot events.
* `/var/log/daemon.log` - Daemon and background process events.
* `/var/log/kern.log` - Kernel messages.
* `/var/log/cron.log` - Scheduled task events.

Syslog metadata:

* **Facility** - Message source category.
* **Severity** - Message importance.
* **PRI** - Facility and severity encoded together.

### Syslog Implementations

* [syslog-ng](https://www.syslog-ng.com/products/open-source-log-management/) - Enhanced syslog daemon with filtering, parsing, routing, TCP, and TLS support.
* [rsyslog](https://www.rsyslog.com/) - High-performance syslog daemon with RELP, TCP/TLS forwarding, queues, and parsing support.

### Linux Audit and Command Logging

* [auditd](https://linux.die.net/man/8/auditd) - Linux audit subsystem for system calls, file watches, and security-relevant activity.
  * [Red Hat System Auditing Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing)
* [Snoopy Logger](https://github.com/a2o/snoopy) - Logs command execution to syslog.
* [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux) - Linux Sysmon implementation.

## Command Line and Script Logging

Command lines and scripts provide high-value context for both administration and attacker activity. Enable enough detail to capture command intent, but plan for noise and sensitive data handling.

### Windows Command and PowerShell Logging

* Enable process creation auditing.
* Enable command-line parameter logging for process creation.
* Collect PowerShell Operational logs.
* Enable PowerShell module logging where useful.
* Enable PowerShell script block logging for decoded script content.
* Enable transcription logging when you need full input/output records and have storage controls in place.

PowerShell execution policy bypasses are offensive/defense-evasion techniques; keep bypass details in Red Offensive and detection ideas in Blue Defense command-line use cases.

{% content-ref url="../red-offensive/testing-methodology/post-exploitation/defense-evasion.md" %}
[defense-evasion.md](../red-offensive/testing-methodology/post-exploitation/defense-evasion.md)
{% endcontent-ref %}

{% content-ref url="../blue-defense/event-detection/detection-use-cases/command-line.md" %}
[command-line.md](../blue-defense/event-detection/detection-use-cases/command-line.md)
{% endcontent-ref %}

PowerShell reference:

* [PowerShell documentation](https://learn.microsoft.com/en-us/powershell/scripting/overview)
