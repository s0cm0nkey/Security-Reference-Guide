# Endpoint

**External media connected**

* Theory
  * CIS Critical Control 8 - "Limit use of external devices to those with an approved business documented need. Monitor for use and attempted use of external devices"
  * Not just thumb drives, but LAN devices and peripherals as well.
  * USB connections will create new events in the System log when connection, but not removed or plugged in a second time, by default.
* Detection Requirements
  * Logging of EventID 2003, 2010, 2100, and 2101
  * Enable Event IDs in the Microsoft\Windows\DriverFrameworks-UserMode Operations Channel to detect ALL USB plug and unplug events, not just the first time (Defualt). Will add device serial and unique session to log data.
    * Default is to be disabled
    *   Enable with Powershell

        * `$logName = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'`
        * `$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration`&#x20;

        `$logName`&#x20;

        * `$log.IsEnabled=$true # change to $false if disabling`
        * `$log.SaveChanges()`
  * \*Optional\* -[ NirSoft USBDeview](https://www.nirsoft.net/utils/usb\_devices\_view.html) tool can run regularly and export details USB logs to a CSV file for lookup and ingest. Power shell can be used to invoke the tool and create a Windows Event from it as well.
* Logic 1 - Windows USB Insertion events
  * Where
    * These events occur in succession with the same device
      * EventID 2003 - Host Process asked to load drivers for device
      * EventID 2010 - Successfully loaded drivers for device
    * OR Where these events occur in succession with the same device
      * EventID 2100 - Received Pnp or Power operation for device
      * EventID 2101 - Completed Pnp or Power operation for device
  * Exclude
    * Known approved peripheral devices
    * Removable device use by approved user list.
* Reference
  * [https://www.cisecurity.org/resources/?o=controls](https://www.cisecurity.org/resources/?o=controls)
  * [https://room362.com/post/2016/snagging-creds-from-locked-machines/](https://room362.com/post/2016/snagging-creds-from-locked-machines/)

**New Service Created**

* Theory
  * CIS v6 Critical Control 9: "Manage (track/control/correct) the ongoing operational use of ports, protocols, and services…"
  * Services are frequently used for persistence and privilege escalation.
  * Many offensive tools will create a high entropy service name when creating a service as part of persistence or privilege escalation
* Detection Requirements
  * Logging of EventID 4697 and 7045
  * Tool/function able to calculate string entropy. See [https://github.com/MarkBaggett/freq](https://github.com/MarkBaggett/freq)
* Logic 1 - New Service Installation
  * Where
    * The following event occurs on an endpoint
      * EventID 7045 - A service was installed on the system
      * OR
      * EventID 4697 - A service was installed on the system
    * AND
      * Service has not been seen within the past 30 days
      * OR
      * Service is present on a documented deny list
  * Exclude
    * Services on a documented allow list
    * Services installed on a device that has been granted exception to this rule.
* Logic 2 - New Service Installation with high entropy service name.
  * Where
    * The following event occurs on an endpoint
      * EventID 7045 - A service was installed on the system
      * OR
      * EventID 4697 - A service was installed on the system
    * AND
      * The service name has a high entropy value
* Reference
  * [h](https://www.rapid7.com/blog/post/2018/03/05/cis-critical-control-9-limitation-and-control-of-ports-protocols-and-services/)[ttps://www.rapid7.com/blog/post/2018/03/05/cis-critical-control-9-limitation-and-control-of-ports-protocols-and-services/](https://www.rapid7.com/blog/post/2018/03/05/cis-critical-control-9-limitation-and-control-of-ports-protocols-and-services/)

**New Scheduled task**

* Theory
  * Malware can create a schedule task to set up a C2 channel that would persist through a reboot.
  * Typically, new scheduled tasks are rare in a hardened environment.
  * These can typically be found in certain registry keys.
* Detection Requirements
  * Logging of EventID 4698 and 4657
  * Audit Policy must be set to audit object access
  * Enable the Audit Registry policy
* Logic 1 - New scheduled task created
  * Where
    * The following event occurs on an endpoint
      * EventID 4698
    * OR
    * The following event occurs on an endpoint
      * EventID 4657
      * AND
      * Manipulation of one fo the following target Registry key is one of the following:
        * HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run&#x20;
        * HKEY\_CURRENT\_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        * HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
        * HKEY\_CURRENT\_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
* Reference
  * [https://www.sans.org/blog/sans-dfir-windows-memory-forensics-training-for526-malware-can-hide-but-it-must-run/](https://www.sans.org/blog/sans-dfir-windows-memory-forensics-training-for526-malware-can-hide-but-it-must-run/)

**Potential Pass-The-Hash Activity**

* Theory
  * Pass-the-hash attacks often use local administrator accounts to log in to other devices using the local admin's NTLM password hash instead of the password itself. Local accounts are rarely seen/used for logging into another device. NTLM use for local accounts is disabled by default, but still enabled for RID 500 (Administrator) accounts. Best practice is to disable this account and provision a specific user account with administrator privileges.
  * Some offensive tools will create a random Workstation name when performing a Pass-The-Hash attack. By checking the entropy value of workstation names in EventID 4624 logs, we can potentially discover the use of these tools.
  * Local accounts should never be used to attempt to login to a second device. This activity could indicate a pass the hash attempt or other malcious activity.
* Detection Requirements
  * Logging of EventID 4624: Account was successfully logged on.
  * Logging of EventID 4625: An account failed to log in.
* Logic 1 - Default Administrator Account login
  * Where
    * The following event occurs on an endpoint
      * EventID 4624
      * AND
      * Account Name = "Administrator"
      * AND
      * Account domain = Hostname (Local Account)
* Logic 2 - Workstation Name login with High Entropy
  * Where
    * The following event occurs on an endpoint
      * EventID 4624
      * AND
      * Workstation Name has high entropy score
* Logic 3 - Logon/Attempt from local account on remote host.
  * Where
    * The following event occurs on an endpoint
      * EventID 4624 OR Event 4625
      * AND
      * Source device != Destination Device
      * AND
      * Source account domain = Hostname (Local Account)
* Reference

**New Account Created**

* Theory
  * Account creation is normal within an Active Directory Environment. New local accounts, not so much.
* Detection Requirements
  * Logging of EventID 4720: A user account was created
  * Monitoring of Linux events from /var/log/auth.log
* Logic 1 - New Local User Account Created
  * Where
    * The following event occurs on an endpoint
      * EventID 4720
      * AND
      * Account Domain = Hostname (Local Account)
    * OR
* Logic 2 - New Local User Account Created (Linux)
  * Where
    * Command= "\*useradd\*"
* Reference

**New Group Created/Deleted**

* Theory
  * Group creation and deletion should always be monitored for activity and verified against approved actions. These should not be too prevalent in your network.
* Detection Requirements
  * Logging of EventID 4727: A security-enabled global group was created
  * Logging of EventID 4730: A security-enabled global group was deleted
  * Logging of EventID 4731: A security-enabled local group was created
  * Logging of EventID 4734: A security-enabled local group was deleted
  * Logging of EventID 4754: A security-enabled universal group was created
  * Logging of EventID 4758: A security-enabled universal group was deleted
* Logic 1 - New Group Created/Deleted (Windows)
  * Where
    * The following event occurs on an endpoint
      *   EventID 4727 OR EventID 4730 OR EventID 4731 OR EventID 4734 OR EventID 4754 OR&#x20;

          EventID 4758
* Logic 2 - New group Created (Linux)
  * Where
    * Command="\*groupadd\*"
* Reference

**User added to Group**

* Theory
  * Certain groups that users can be added to are sensitive and should always be monitored. These can be noisy if set up as an alert, so consider running as a regularly scheduled report for easy reading and minimal labor.
* Detection Requirements
  * Logging of EventID 4728: A member was added to a security-enabled local group
  * Logging of EventID 4732: A member was added to a security-enabled global group
  * Logging of EventID 4756: A member was added to a security-enabled universal group
* Logic 1 - User added to security-enabled group
  * Where
    * The following event occurs on an endpoint
      * EventID 4728 OR EventID 4732 OR EventID 4756
* Reference

**Logs Cleared**

* Theory
  * Threat actors will typically try to delete logs in order to cover thier tracks and make analysis more difficult. Looking for these actions can alert to when a threat actor is in your environment.
* Detection Requirements
  * Logging of EventID 104: The System log file was cleared
  * Logging of EventID 1102 - The audit log was cleared
* Logic 1
  * Where
    * The following event occurs on an endpoint
      * EventID 104 OR EventID 1102
* Reference

**AppLocker Blocked Action**

* Theory
  * &#x20;AppLocker can log when and EXE, DLL, MSI, or script is allowed, blocked, or wouldhave been blocked but is in a pre-enforcement mode. Combined with a strong application whitelisting policy, this can greatly harden a device.
* Detection requirements
  * Logging of EventID 8002: Allowed EXE or DLL
  * Logging of EventID 8003: Would have blocked EXE or DLL
  * Logging of EventID 8004: Blocked EXE or DLL
  * Logging of EventID 8005: Allowed MSI or Script
  * Logging of EventID 8006: Would have blocked MSI or Script
  * Logging of EventID 8007: Blocked MSI or Script
* Logic 1 - Allowed Application generator search
  * Where
    * The following event occurs on an endpoint:
      * EventID 8002 OR EventID 8005
* Logic 2 - Applocker performed a blocking action
  * Where
    * The following event occurs on an endpoint:
      * EventID 8003 OR EventID 8004 OR EventID 8006 OR EventID 8007
