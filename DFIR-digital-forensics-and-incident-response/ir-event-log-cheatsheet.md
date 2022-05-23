# IR Event Log Cheatsheet

## Security log information <a href="#security-log-information" id="security-log-information"></a>

Note: Logs and their event codes have changed over time. Most of the references here are for Windows Vista and Server 2008 onwards rather than Windows 2000,XP,Server 2003. More information on them may be added in the future if required.

(psloglist requires psloglist.exe from systinternals):

```
wevtutil qe security /f:text
eventquery.vbs /L security
wevtutil qe security /f:text | Select-String -Pattern "Event ID: [EventCode]" -Context 2,20
wevtutil qe security /f:text | Select-String -Pattern "Event ID: [EventCode]" -Context 2,20 | findstr "Account Name:"
psloglist -s -x security
```

Note: Some suspicious events - “Event log service was stopped”, “Windows File Protection is not active on this system”, “The MS Telnet Service has started successfully”

* Security: 4720 (Account created)
* Security: 4722 (Account enabled)
* Security: 4724 (Password reset)
* Security: 4723 (User changed password)
* Security: 4736 (Account deleted)
* Security: 4781 (Account renamed)
* Security: 4738 (User account change)
* Security: 4688 (A new process has been created)
* Security: 4732 (Account added to a group)
* Security: 4733 (Account removed from a group)
* Security: 1102 (Audit log cleared)
* Security: 4614 (Security System Extension)
* Security: 4672 (Special privileges assigned to new logon)
* Security: 4624 (Account successfully logged on)
* Security: 4698 (Scheduled Task Creation)
* Security: 4702 (Scheduled Task Modified)
* Security: 4699 (Scheduled Task Deleted)
* Security: 4701 (Scheduled Task Disabled)
* Security: 4700 (Scheduled Task Enabled)
* Security: 4697 (Service Installation)
* Security: 4625 (Account failed to log on)
* Security: 4776 (The domain controller attempted to validate credentials for an account)
* Security: 4634 (Account successfully logged off)
* Security: 4740 (A user account was locked out)
* Security: 4767 (A user account was unlocked)
* Security: 4778 (Remote Desktop session reconnected)
* Security: 4779 (Remote desktop session disconnected)
* Security: 4625 (A user account failed to log on)
* Security: 4648 (A logon was attempted using explicit credentials)
* Security: 4768 (A Kerberos authentication ticket (TGT) was requested)
  * 0x6 (The username doesn’t exist) - Bad username or not yet replicated to DC
  * 0xC (Start time is later than end time - Restricted workstation)
  * 0x12 (Account locked out, disabled, expired, restricted, or revoked etc)
* Security: 4769 (A Kerberos service ticket was requested)
* Security: 4770 (A Kerberos service ticket was renewed)
* Security: 4771 (Kerberos pre-authentication failed)
  * 0x10 - Smart card logon is being attempted and the proper certificate cannot be located.
  * 0x17 - The user’s password has expired.
  * 0x18 - The wrong password was provided.
* Security: Greater than 4720 Eand less than 4764 (Account/group modifications)

## Logon type information <a href="#logon-type-information" id="logon-type-information"></a>

* Type: 0 (Used only by System account authentications)
* Type: 2 (Interactive Logon)
  * User is at the keyboard.
* Type: 3 (Network Authentication/SMB Auth Logon)
  * Auth over the network. Note: RDP can fall under this if Network Level Authentication is enabled.
* Type: 4 (Batch Logon)
  * More often than not from a Scheduled Task.
* Type: 5 (Service Logon)
  * More often than not from a Service.
* Type: 7 (Unlock Logon)
  * User is at the keyboard unlocking it after lunch.
* Type: 8 (Network Cleartext Logon)
  * Basically Logon Type 3 but creds are in the clear.
* Type: 9 (New Credentials Logon)
  * More often than not from using ‘RunAs’ with the ‘/netonly’ parameter.
* Type: 10 (Terminal/RDP Logon Type)
  * Logon via Terminal Services/RDP.
* Type: 11 (Cached Interactive)
  * Logon when unable to connect to domain (Cached Creds locally).
* Type: 12 (Cached Remote Interactive)
  * Same as RemoteInteractive. This is used for internal auditing.
* Type: 13 (Cached Unlock Logon)
  * Same as Unlock Logon except with cached creds.

## Special logon information (4672) <a href="#special-logon-information-4672" id="special-logon-information-4672"></a>

| Privilege Name                | Description                                                    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SeAssignPrimaryTokenPrivilege | Replace a process-level token                                  | Required to assign the primary token of a process. With this privilege, the user can initiate a process to replace the default token associated with a started subprocess.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| SeAuditPrivilege              | Generate security audits                                       | With this privilege, the user can add entries to the security log.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| SeBackupPrivilege             | Back up files and directories                                  | Required to perform backup operations. With this privilege, the user can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system. This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file. Any access request other than read is still evaluated with the ACL.                                                                                                                                                                               |
| SeCreateTokenPrivilege        | Create a token object                                          | Allows a process to create a token which it can then use to get access to any local resources when the process uses NtCreateToken() or other token-creation APIs. When a process requires this privilege, we recommend using the LocalSystem account (which already includes the privilege), rather than creating a separate user account and assigning this privilege to it.                                                                                                                                                                                                                         |
| SeDebugPrivilege              | Debug programs                                                 | Required to debug and adjust the memory of a process owned by another account.With this privilege, the user can attach a debugger to any process or to the kernel. We recommend that SeDebugPrivilege always be granted to Administrators, and only to Administrators. Developers who are debugging their own applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides complete access to sensitive and critical operating system components.                                                                      |
| SeEnableDelegationPrivilege   | Enable computer and user accounts to be trusted for delegation | With this privilege, the user can set the Trusted for Delegation setting on a user or computer object.The user or object that is granted this privilege must have write access to the account control flags on the user or computer object.                                                                                                                                                                                                                                                                                                                                                           |
| SeImpersonatePrivilege        | Impersonate a client after authentication                      | With this privilege, the user can impersonate other accounts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| SeLoadDriverPrivilege         | Load and unload device drivers                                 | Required to load or unload a device driver.With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers.                                                                                                                                                                                                                                                                                                                                                                              |
| SeRestorePrivilege            | Restore files and directories                                  | Required to perform restore operations. This privilege causes the system to grant all write access control to any file, regardless of the ACL specified for the file. Any access request other than write is still evaluated with the ACL. Additionally, this privilege enables you to set any valid user or group SID as the owner of a file. With this privilege, the user can bypass file, directory, registry, and other persistent objects permissions when restoring backed up files and directories and determines which users can set any valid security principal as the owner of an object. |
| SeSecurityPrivilege           | Manage auditing and security log                               | Required to perform a number of security-related functions, such as controlling and viewing audit events in security event log. With this privilege, the user can specify object access auditing options for individual resources, such as files, Active Directory objects, and registry keys.A user with this privilege can also view and clear the security log.                                                                                                                                                                                                                                    |
| SeSystemEnvironmentPrivilege  | Modify firmware environment values                             | Required to modify the nonvolatile RAM of systems that use this type of memory to store configuration information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| SeTakeOwnershipPrivilege      | Take ownership of files or other objects                       | Required to take ownership of an object without being granted discretionary access. This privilege allows the owner value to be set only to those values that the holder may legitimately assign as the owner of an object. With this privilege, the user can take ownership of any securable object in the system, including Active Directory objects, files and folders, printers, registry keys, processes, and threads.                                                                                                                                                                           |
| SeTcbPrivilege                | Act as part of the operating system                            | This privilege identifies its holder as part of the trusted computer base.This user right allows a process to impersonate any user without authentication. The process can therefore gain access to the same local resources as that user.                                                                                                                                                                                                                                                                                                                                                            |

## System log information: <a href="#system-log-information" id="system-log-information"></a>

```
wevtutil qe system /f:text
eventquery.vbs /L system
```

Note: Some useful events -

* System: 7030 (Basic Service Operations)
* System: 7040 (The start type of a service was changed from disabled to auto start)
* System: 7045 (Service Was Installed)
* System: 1056 (DHCP Server Oddities)
* System: 10000 (COM Functionality)
* System: 20001 (Device Driver Installation)
* System: 20002 (Remote Access)
* System: 20003 (Service Installation)

## Application log information <a href="#application-log-information" id="application-log-information"></a>

Many applications output errors to the Windows Application Event Logs. For example an application crash may generate an event, or an error may generate an event of value. It’s worth looking for events with a source relating to a known vulnerable component that may have been exploited. For example the [Australian Cyber Security Centre](https://www.cyber.gov.au/acsc/view-all-content/advisories/advisory-2020-004-remote-code-execution-vulnerability-being-actively-exploited-vulnerable-versions-teleriktelerik-ui-sophisticated-actors) makes special note in one of their reports for the following event.

* Event ID: 1309
* Source: ASP.NET

In particular instances of this event with reference to Telerik.Web.UI.IAsyncUploadConfiguration, one can help to identify successful exploitation of a vulnerable Telerik instance.

## Sysmon log information <a href="#sysmon-log-information" id="sysmon-log-information"></a>

{% embed url="https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5eb3687f39d69d48c403a42a/1588816000014/Windows+Sysmon+Logging+Cheat+Sheet_Jan_2020.pdf" %}

When installed and running the event log is located at: “Applications and Services Logs/Microsoft/Windows/Sysmon/Operational”

Note: A WMI consumer is a management application or script that interacts with the WMI infrastructure. [Microsoft Docs - WMI Architecture](https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/wmi-architecture)

* Sysmon: 1 (Process create)
* Sysmon: 2 (File creation time)
* Sysmon: 3 (Network connection detected)
* Sysmon: 4 (Sysmon service state changed)
* Sysmon: 5 (Process terminated)
* Sysmon: 6 (Driver loaded)
* Sysmon: 9 (Image loaded)
* Sysmon: 10 (Process accessed)
* Sysmon: 11 (File created)
* Sysmon: 12 (Registry object added or deleted)
* Sysmon: 13 (Registry value set)
* Sysmon: 14 (Registry object renamed)
* Sysmon: 15 (File stream created)
* Sysmon: 16 (Sysmon configuration changed)
* Sysmon: 17 (Named pipe created)
* Sysmon: 18 (Named pipe connected)
* Sysmon: 19 (WMI filter)
* Sysmon: 20 (WMI consumer)
* Sysmon: 21 (WMI consumer filter)
* Sysmon: 22 (DNS Query)
* Sysmon: 23 (File Delete)
* Sysmon: 24 (Clipboard Changed)
