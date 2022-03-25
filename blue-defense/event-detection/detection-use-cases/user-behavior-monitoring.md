# User Behavior monitoring

Service account on a non-service related system = Alert

* Unusual process by user
  * Start with Application Control
  * Machine learning can profile Powershell.exe use at startup vs a manual launch
* Unusual process by time
* New Login Locations
* Unusual Login Time
  * Separate by user group. Sys admins log in a crazy times. Accountants do not.
* Account/DNS Enumeration
  * Insider recon is done with native authorized tools
  * Can be locked down by security group
  * Can be profiled with machine learning
  * Most can be caught without machine learning
  * [https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html)
* Directory service lookups
* Unusual protocol use
* Account Sharing
  * Number of workstations logged into by user within time frame
  * login within 1 minute of process creation or login event on a different system
  * user logged in externally as well as internally
* Improper use of Privileged User Account
  * Domain admin account logging into a regular workstation = Alert

Brute force logins do not require behavioral analysis. It is either evil or misconfigured. Either way, it needs a ticket. 50 failed logons in a minute.

Compromised accounts are likely to generate more denied access logs. Least privilege helps make this easy to spot.

Look at using a controlled jumped box for all domain admin logins. Makes it easy to track sessions and look for any logins not from the Jump Box.
