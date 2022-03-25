# Authentication/Logon

**Network Cleartext Logon**

* Theory
  * No login should be cleartext. Ever. No exceptions
* Requirements
  * Logging of EventID 4624: Account was successfully logged on.
  * Logging of EventID 4625: An account failed to log in.
* Logic
  * Where
    * One of the following events occurs
      * EventID 4624 OR EventID 4625
    * AND
    * Logon Type = 8 (NetworkCleartext)
* Reference
  * [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624)

**Successful login without connection from documented workstation**

* Theory
  * In a hardened environment where a user should only be connection to resources by using their company desktop, there should be a Logon type 7 (device unlock) logon within about 24 hours of a logon of any other kind for the user associated with that device.
  * If there is not a logon type 7 entry, that could indicate a users account being used NOT in association with a legitimate logon to their device, and there for an indication of a compromised account.
* Requirements
  * Logging of EventID 4624: Account was successfully logged on.
  * Logging of EventID 4625: An account failed to log in.
* Logic&#x20;
  * Where
    * One of the following events occurs
      * EventID 4624 OR EventID 4625
      * AND
      * NOT Logon Type = 7 (device unlock)
    * AND
      * EventID 4624 OR EventID 4624
      * AND
      * Logon Type = 7 (device unlock) NOT within the past 24 hours

**Anonymous Impersonation level**

* Theory
  * For proper tracking of user actions, Anonymous impersonation with logon events should be disabled. There should be little to no legitimate use of anonymous impersonations within a corporate environment.
* Logic
  * Where
    * One of the following events occurs
      * EventID 4624 OR EventID 4625
      * AND
      * Impersonation Level = Anonymous

**Suspicious change in Successful logon count vs Failure Logon count**

* Theory
  * The rate of successes vs failures when logging in should stay relatively static unless there is either a sizeable network issue (which still needs to be escalated) or an attacker is attempting to manipulate credentials
  * If we look at overall count for user accounts, we can see spikes that may indicate a passwords spraying attack.
* Requirements
  * Logging of EventID 4624: Account was successfully logged on.
  * Logging of EventID 4625: An account failed to log in.
* Logic 1 - Establish a per user baseline of a success/failure ratio. Compare the ratio of the past 24 hours to that ratio.
* Logic 2 - Establish a baseline ratio of total successes/failures within your network. Compare to the past 24 hours. Can also take an hourly approach

**Suspicious Impersonation Level**

* Theory
  * Of the Impersonation levels available in logons, a couple of them have trends that we can use as a baseline to highlight suspicious activity. Typically it is User Accounts that are performing Impersonation logins. This is for using account tokens on a local system. Conversely, Computer Accounts  take up the vast majority of delegation logons, which can be users on both remote and local systems.
  * After whitelisting noise in the network, this can be used to see accounts performing logons outside of their typical scope.
* Requirements
  * Logging of EventID 4624: Account was successfully logged on.
  * Logging of EventID 4625: An account failed to log in.
* Logic - Suspicious Impersonation Level
  * Where
    * One of the following events occurs
      * EventID 4624 OR EventID 4625
    * AND
    * Impersonation level = "Delegate"
      * AND
      * Account = "\*$"
    * OR
    * Impersonation level = "Impersonate"
      * AND
      * Account!= "svc\*" or "\*$"

**Use of Explicit Credentials**

* Theory
  * Only a limited selection of people should ever need to run a task as another user. These are typically admin tasks performed by a limited group. By creating an allow list for those users and monitoring and alerting on all other activity, we can detect actions like unauthorized use of privileged accounts, use of stolen credentials, and interactively changing into service accounts.
* Requirements
  * Logging of EventID 4648 - Login attempted using explicit credentials
  * Allow list of admin users
* Logic 1 - Global use of explicit credentials
  * Where
    * EventID 4648 occurs
    * AND
    * NOT in the allow list
* Logic 2 - Local use of explicit credentials
  * Where
    * EventID 4648 occurs
    * AND
    * NOT in the allow list
    * AND
    * Dest port=0 OR Dest IP=127.0.0.1

