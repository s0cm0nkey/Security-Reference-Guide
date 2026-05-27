# User Behavior Monitoring

Use this page for UEBA-style starter ideas: activity that may be individually legitimate but becomes suspicious when compared to the user, role, host, time, or normal business process.

## High-Value Patterns

* Service account used on a non-service system.
* Domain admin account logging into a regular workstation.
* New login location for a user.
* Unusual login time, separated by user group. System administrators and accountants usually have very different working patterns.
* Account sharing indicators, such as one user logging into many workstations in a short window.
* Internal account or DNS enumeration using native authorized tools.
* Unusual protocol use for a user's role or device.

## Process and Access Behavior

* Unusual process by user
  * Start with Application Control
  * Machine learning can profile Powershell.exe use at startup vs a manual launch
* Unusual process by time
* Account/DNS Enumeration
  * Insider recon is done with native authorized tools
  * Can be locked down by security group
  * Can be profiled with machine learning
  * Most can be caught without machine learning
  * [https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html)
* Directory service lookups

## Notes

* Brute force logins do not require behavioral analysis. They are either malicious or misconfigured, and either case needs a ticket.
* Compromised accounts are likely to generate more denied access logs. Least privilege helps make this easier to spot.
* A controlled jump box for all domain admin logins makes privileged sessions easier to track and makes off-path admin logons more visible.

For authentication and logon-specific detections, use the Authentication/Logon page.

{% content-ref url="authentication-logon.md" %}
[authentication-logon.md](authentication-logon.md)
{% endcontent-ref %}
