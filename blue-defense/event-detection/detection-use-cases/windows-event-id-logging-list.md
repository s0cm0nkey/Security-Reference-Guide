# Windows Event ID logging list

* EventID 104: The System log file was  cleared
  * Use Case - Clearing of logs
* EventID 400 - Powershell Engine state is changed
  * Use Case - Powershell Downgrade Attack
* EventID 1102 - The audit log was cleared
  * Use Case - Clearing of logs
* EventID 2003 - Host Process asked to load drivers for device
  * Use Case - External media connected
* EventID 2010 - Successfully loaded drivers for device
  * Use Case - External media connected
* EventID 2100 - Received Pnp or Power operation for device
  * Use Case - External media connected
* EventID 2101 - Completed Pnp or Power operation for device
  * Use Case - External media connected
* Event ID 4103 - Powershell Module Loaded
  * Use Case - Abnormal Command Line Length
  * Use Case - Commands Encoded with Base64
  * Use Case - Execution of Downloaded Code
  * Use Case - Suspicious Command Line String
* Event ID 4104 - Creation of Script Block
  * Use Case - Abnormal Command Line Length
  * Use Case - Commands Encoded with Base64
  * Use Case - Execution of Downloaded Code
  * Use Case - Suspicious Command Line String
* Event ID 4105 - Script Block Execution Start
  * Use Case - Abnormal Command Line Length
  * Use Case - Commands Encoded with Base64
  * Use Case - Execution of Downloaded Code
  * Use Case - Suspicious Command Line String
* Event ID 4106 - Script Block Execution Stop
  * Use Case - Abnormal Command Line Length
  * Use Case - Commands Encoded with Base64
  * Use Case - Execution of Downloaded Code
* EventID 4624 - Successful login result
  * Use Case - Local Administrator Sign-on
  * Use Case - Workstation Name login with High Entropy
  * Use Case - Logon/Attempt from local account on remote host.
  * Use Case - Suspicious Command Line String
* EventID 4625 - An account failed to log in.
  * Use Case - Logon/Attempt from local account on remote host.
* EventID 4648 - Login attempted using explicit credentials
  * Use Case - Use of Explicit Credentials
* EventID 4657 - A registry Value was modified
  * Use Case - New Scheduled Task
* EventID 4697 - A service was installed on the system
  * Use Case - New Service Created
  * Use Case - New Service Installation with high entropy service name.
* EventID 4698 - A scheduled task was created
  * Use Case - New Scheduled Task
* EventID 4720 - User Account
  * Use Case - New local account created
* EventID 4727: A security-enabled global group was created
  * Use Case - New Group Created/Deleted (Windows)
* EventID 4728: A member was added to a security-enabled local group
  * Use Case - User added to security-enabled group
* EventID 4730: A security-enabled global group was deleted
  * Use Case - New Group Created/Deleted (Windows)
* EventID 4731: A security-enabled local group was created
  * Use Case - New Group Created/Deleted (Windows)
* EventID 4732: A member was added to a security-enabled global group
  * Use Case - User added to security-enabled group
* EventID 4734: A security-enabled local group was deleted
  * Use Case - New Group Created/Deleted (Windows)
* EventID 4754: A security-enabled universal group was created
  * Use Case - New Group Created/Deleted (Windows)
* EventID 4756: A member was added to a security-enabled universal group
  * Use Case - User added to security-enabled group
* EventID 4758: A security-enabled universal group was deleted
  * Use Case - New Group Created/Deleted (Windows)
* EventID 7045 - A service was installed on the system
  * Use Case - New Service Created
  * Use Case - New Service Installation with high entropy service name.
* EventID 8002: Allowed EXE or DLL
  * Use Case - Allowed Application generator search
* EventID 8003: Would have blocked EXE or DLL
  * Use Case - Applocker performed a blocking action
* EventID 8004: Blocked EXE or DLL
  * Use Case - Applocker performed a blocking action
* EventID 8005: Allowed MSI or Script
  * Use Case - Allowed Application generator search
* EventID 8006: Would have blocked MSI or Script
  * Use Case - Applocker performed a blocking action
* EventID 8007: Blocked MSI or Script
  * Use Case - Applocker performed a blocking action

Reference

* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

#### AD Attack Detection

| Attack                        | Event ID                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Account and Group Enumeration | <p>4798: A user's local group membership was enumerated<br>4799: A security-enabled local group membership was enumerated</p>                                                                                      |
| AdminSDHolder                 | 4780: The ACL was set on accounts which are members of administrators groups                                                                                                                                       |
| Kekeo                         | <p>4624: Account Logon<br>4672: Admin Logon<br>4768: Kerberos TGS Request</p>                                                                                                                                      |
| Silver Ticket                 | <p>4624: Account Logon<br>4634: Account Logoff<br>4672: Admin Logon</p>                                                                                                                                            |
| Golden Ticket                 | <p>4624: Account Logon<br>4672: Admin Logon</p>                                                                                                                                                                    |
| PowerShell                    | <p>4103: Script Block Logging<br>400: Engine Lifecycle<br>403: Engine Lifecycle<br>4103: Module Logging<br>600: Provider Lifecycle<br></p>                                                                         |
| DCShadow                      | <p>4742: A computer account was changed<br>5137: A directory service object was created<br>5141: A directory service object was deleted<br>4929: An Active Directory replica source naming context was removed</p> |
| Skeleton Keys                 | <p>4673: A privileged service was called<br>4611: A trusted logon process has been registered with the Local Security Authority<br>4688: A new process has been created<br>4689: A new process has exited</p>      |
| PYKEK MS14-068                | <p>4672: Admin Logon<br>4624: Account Logon<br>4768: Kerberos TGS Request</p>                                                                                                                                      |
| Kerberoasting                 | 4769: A Kerberos ticket was requested                                                                                                                                                                              |
| S4U2Proxy                     | 4769: A Kerberos ticket was requested                                                                                                                                                                              |
| Lateral Movement              | <p>4688: A new process has been created<br>4689: A process has exited<br>4624: An account was successfully logged on<br>4625: An account failed to log on</p>                                                      |
| DNSAdmin                      | <p>770: DNS Server plugin DLL has been loaded<br>541: The setting serverlevelplugindll on scope . has been set to <code>&#x3C;dll path></code><br>150: DNS Server could not load or initialize the plug-in DLL</p> |
| DCSync                        | 4662: An operation was performed on an object                                                                                                                                                                      |
| Password Spraying             | <p>4625: An account failed to log on<br>4771: Kerberos pre-authentication failed<br>4648: A logon was attempted using explicit credentials</p>                                                                     |
