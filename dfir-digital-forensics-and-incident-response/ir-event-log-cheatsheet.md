# IR Event Log Cheatsheet

## Security log information <a href="#security-log-information" id="security-log-information"></a>

Note: Logs and their event codes have evolved. References here primarily apply to Windows Vista / Server 2008 and newer (including Windows 10/11 and Server 2016/2019/2022).

### Retrieval Commands

**PowerShell (Recommended):**
```powershell
# Get last 10 security events
Get-WinEvent -LogName Security -MaxEvents 10

# Get specific event ID
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624}

# Filter using Hashtable (Faster)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}
```

**Command Line (wevtutil):**
```cmd
wevtutil qe security /f:text
wevtutil qe security /f:text /c:10
wevtutil qe security /f:text | findstr "Event ID"
```

**Sysinternals (psloglist):**
```cmd
psloglist -s -x security
```

### Critical Security Events

#### Account Management
* **4720**: A user account was created.
* **4722**: A user account was enabled.
* **4723**: An attempt was made to change an account's password.
* **4724**: An attempt was made to reset an account's password.
* **4725**: A user account was disabled.
* **4726**: A user account was deleted. (Note: 4736 is often cited but 4726 is standard for user deletion).
* **4738**: A user account was changed.
* **4781**: The name of an account was changed.
* **4732**: A member was added to a security-enabled local group.
* **4733**: A member was removed from a security-enabled local group.
* **4756**: A member was added to a security-enabled universal group.
* **4757**: A member was removed from a security-enabled universal group.
* **Range 4720-4764**: General account and group modifications.

#### Logon and Auth
* **4624**: An account was successfully logged on.
* **4625**: An account failed to log on.
* **4634**: An account was logged off.
* **4648**: A logon was attempted using explicit credentials (RunAs).
* **4672**: Special privileges assigned to new logon (Admin logon).
* **4740**: A user account was locked out.
* **4767**: A user account was unlocked.
* **4776**: The computer attempted to validate the credentials for an account (NTLM).
* **4778**: A session was reconnected to a Window Station (RDP Reconnect).
* **4779**: A session was disconnected from a Window Station (RDP Disconnect).

**Kerberos Events:**
* **4768**: A Kerberos authentication ticket (TGT) was requested.
  * `0x6`: Client not found (Bad Username).
  * `0xC`: Client time restriction.
  * `0x12`: Account revoked/disabled/locked.
  * `0x17`: Key expired (Password expired).
  * `0x18`: Pre-authentication information was invalid (Bad Password).
* **4769**: A Kerberos service ticket was requested.
* **4770**: A Kerberos service ticket was renewed.
* **4771**: Kerberos pre-authentication failed.

#### System and Service
* **1102**: The audit log was cleared.
* **4614**: A notification package has been loaded by the Security Account Manager.
* **4697**: A service was installed in the system. (Critical for persistence).
* **7045**: (System Log) A service was installed in the system.

#### Process and Task
* **4688**: A new process has been created. (Enable command line logging for full details).
* **4698**: A scheduled task was created.
* **4699**: A scheduled task was deleted.
* **4700**: A scheduled task was enabled.
* **4701**: A scheduled task was disabled.
* **4702**: A scheduled task was updated.

## Logon type information <a href="#logon-type-information" id="logon-type-information"></a>

* **Type 0**: System (Used only by System account authentications).
* **Type 2**: Interactive (User at keyboard).
* **Type 3**: Network (Accessing shared folder, printer, IIS).
* **Type 4**: Batch (Scheduled tasks).
* **Type 5**: Service (Service startup).
* **Type 7**: Unlock (Unlocking workstation).
* **Type 8**: NetworkCleartext (IIS Basic Auth - plain text password).
* **Type 9**: NewCredentials (RunAs using `/netonly`).
* **Type 10**: RemoteInteractive (RDP).
* **Type 11**: CachedInteractive (Login when domain is offline).
* **Type 12**: Cached Remote Interactive.
* **Type 13**: Cached Unlock Logon.

## Special logon information (4672) <a href="#special-logon-information-4672" id="special-logon-information-4672"></a>

| Privilege Name | Description | Notes |
| :--- | :--- | :--- |
| **SeAssignPrimaryTokenPrivilege** | Replace a process-level token | Required to assign the primary token of a process. With this privilege, the user can initiate a process to replace the default token associated with a started subprocess. |
| **SeAuditPrivilege** | Generate security audits | With this privilege, the user can add entries to the security log. |
| **SeBackupPrivilege** | Back up files and directories | Required to perform backup operations. Bypasses file and directory permissions for reading. |
| **SeCreateTokenPrivilege** | Create a token object | Allows a process to create a token which it can then use to get access to any local resources. Highly sensitive. |
| **SeDebugPrivilege** | Debug programs | Required to debug and adjust the memory of a process owned by another account. Allows complete access to sensitive components. |
| **SeEnableDelegationPrivilege** | Enable computer and user accounts to be trusted for delegation | Allows setting "Trusted for Delegation" on objects. |
| **SeImpersonatePrivilege** | Impersonate a client after authentication | With this privilege, the user can impersonate other accounts. |
| **SeLoadDriverPrivilege** | Load and unload device drivers | Required to load or unload a device driver into kernel mode. |
| **SeRestorePrivilege** | Restore files and directories | Required to perform restore operations. Bypasses write permissions. Can optionally set the owner of a file. |
| **SeSecurityPrivilege** | Manage auditing and security log | View/Clear security log and manage auditing options. |
| **SeSystemEnvironmentPrivilege** | Modify firmware environment values | Modify nonvolatile RAM (Boot details etc). |
| **SeTakeOwnershipPrivilege** | Take ownership of files or other objects | Take ownership of objects without discretionary access. |
| **SeTcbPrivilege** | Act as part of the operating system | Holder is part of the trusted computer base. Can impersonate any user. |

## System log information <a href="#system-log-information" id="system-log-information"></a>

**Command:**
```powershell
Get-WinEvent -LogName System -MaxEvents 10
wevtutil qe system /f:text
```

**Useful Events:**
* **1056**: DHCP Server service is running on a DC with credentials that have not been authorized.
* **7030**: The service is configured as interactive but the system is not.
* **7034**: Service crashed/terminated unexpectedly.
* **7036**: Service started or stopped.
* **7040**: The start type of a service was changed.
* **7045**: A service was installed in the system.
* **10000**: WLAN-AutoConfig detected.
* **20001**: Device driver installation.
* **20002**: Remote access.
* **20003**: Service installation.

## Application log information <a href="#application-log-information" id="application-log-information"></a>

Many applications output errors to the Windows Application Event Logs. For example an application crash may generate an event, or an error may generate an event of value. It’s worth looking for events with a source relating to a known vulnerable component that may have been exploited. For example the [Australian Cyber Security Centre](https://www.cyber.gov.au/acsc/view-all-content/advisories/advisory-2020-004-remote-code-execution-vulnerability-being-actively-exploited-vulnerable-versions-teleriktelerik-ui-sophisticated-actors) makes special note in one of their reports for the following event.

* **Event ID 1309** (Source: ASP.NET): Web application exception. Can indicate exploitation attempts (e.g., Telerik UI vulnerabilities).
* **1000**: Application Error (Crash).
* **1001**: Windows Error Reporting (Bucket info).

## PowerShell Log Information <a href="#powershell-log-information" id="powershell-log-information"></a>

Located in `Applications and Services Logs/Microsoft/Windows/PowerShell/Operational`.

**Command:**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"
```

**Events:**
* **4103**: Module Logging (Pipeline Execution Details). Shows what commands were executed.
* **4104**: Script Block Logging. Captures the full code of script blocks (handling de-obfuscation).

## Windows Defender Log Information <a href="#windows-defender-log-information" id="windows-defender-log-information"></a>

Located in `Applications and Services Logs/Microsoft/Windows/Windows Defender/Operational`.

**Events:**
* **1000**: Scan started.
* **1001**: Scan completed.
* **1116**: Malaria/Threat detection.
* **1117**: Threat action taken (cleaned/quarantined).
* **5001**: Real-time protection disabled.

## Sysmon log information <a href="#sysmon-log-information" id="sysmon-log-information"></a>

{% embed url="https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5eb3687f39d69d48c403a42a/1588816000014/Windows+Sysmon+Logging+Cheat+Sheet_Jan_2020.pdf" %}

Location: `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`

* **1**: Process create (CommandLine, Hashes).
* **2**: File creation time changed.
* **3**: Network connection detected.
* **4**: Sysmon service state changed.
* **5**: Process terminated.
* **6**: Driver loaded.
* **7**: GetHashed Image (Modules).
* **8**: CreateRemoteThread (Injection).
* **9**: RawAccessRead (Drive reading).
* **10**: ProcessAccess (Memory access, credential dumping).
* **11**: FileCreate (File created).
* **12**: RegistryEvent (Object create/delete).
* **13**: RegistryEvent (Value set).
* **14**: RegistryEvent (Key/Value rename).
* **15**: FileCreateStreamHash (ADS).
* **16**: SysmonConfigDatabase (Config change).
* **17**: PipeEvent (Pipe Created).
* **18**: PipeEvent (Pipe Connected).
* **19**: WmiEvent (WmiEventFilter).
* **20**: WmiEvent (WmiEventConsumer).
* **21**: WmiEvent (WmiEventConsumerToFilter).
* **22**: DNSEvent (DNS Query).
* **23**: FileDelete (File archiving).
* **24**: ClipboardChange.
* **25**: ProcessTampering (Hollow/Herpaderp).
* **26**: FileDeleteDetected.

## Legacy and Deprecated Tools <a href="#legacy-tools" id="legacy-tools"></a>

These tools or commands are largely deprecated or found only on older systems (XP/2003).

* **eventquery.vbs**: VBScript for querying logs on WinXP/2003.
  ```cmd
  eventquery.vbs /L security
  ```
