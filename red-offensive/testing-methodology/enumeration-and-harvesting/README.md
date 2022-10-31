---
description: All the ways to grab the goodies
---

# Enumeration and Harvesting

## **Post Exploitation Tasks**

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

## **Host Enumeration**

* [JAWS](https://github.com/411Hall/JAWS) - JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It
* [RedTeamScripts](https://github.com/threatexpress/red-team-scripts) - Red Team Scripts is a collection of red teaming related tools, scripts, techniques, and notes developed or discovered over time during engagements. Invoke-HostEnum is the tool within these scripts that can perform windows host enumeration for any valuable data.
* [https://www.ired.team/offensive-security/enumeration-and-discovery](https://www.ired.team/offensive-security/enumeration-and-discovery)

{% hint style="info" %}
Privilege escalation tools can also provide much of the enumeration that you need.
{% endhint %}

{% content-ref url="../privilege-escalation/" %}
[privilege-escalation](../privilege-escalation/)
{% endcontent-ref %}

##

## AD Enumeration

[https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf](https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf)

### Tools

* [ADExplorer by Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) - An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database, define favorite locations, view object properties and attributes without having to open dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute.
* [ADRecon](https://github.com/adrecon/ADRecon) - ADRecon is a tool which extracts and combines various artifacts (as highlighted below) out of an AD environment.
* [ACLight](https://github.com/cyberark/ACLight) -A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
* [TruffleSnout](https://github.com/dsnezhkov/TruffleSnout) - Iterative AD discovery toolkit for offensive operators. Situational awareness and targeted low noise enumeration.

### SPN Scanning

* [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)
* [Active Directory: PowerShell script to list all SPNs used](https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx)
* [Discovering Service Accounts Without Using Privileges](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)

### Data Mining

* [A Data Hunting Overview](https://thevivi.net/2018/05/23/a-data-hunting-overview/)
* [Push it, Push it Real Good](https://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
* [Finding Sensitive Data on Domain SQL Servers using PowerUpSQL](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)
* [Sensitive Data Discovery in Email with MailSniper](https://www.youtube.com/watch?v=ZIOw\_xfqkKM)
* [Remotely Searching for Sensitive Files](https://www.fortynorthsecurity.com/remotely-search/)
* [I Hunt Sysadmins - harmj0y](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)

### User Hunting

* [Active Directory Recon Without Admin Rights](https://adsecurity.org/?p=2535)
* [Gathering AD Data with the Active Directory PowerShell Module](https://adsecurity.org/?p=3719)
* [Using ActiveDirectory module for Domain Enumeration from PowerShell Constrained Language Mode](http://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html)
* [PowerUpSQL Active Directory Recon Functions](https://github.com/NetSPI/PowerUpSQL/wiki/Active-Directory-Recon-Functions)
* [Derivative Local Admin](https://medium.com/@sixdub/derivative-local-admin-cdd09445aac8)
* [Automated Derivative Administrator Search](https://wald0.com/?p=14)
* [Dumping Active Directory Domain Info – with PowerUpSQL!](https://blog.netspi.com/dumping-active-directory-domain-info-with-powerupsql/)
* [Local Group Enumeration](https://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
* [Situational Awareness](https://pentestlab.blog/2018/05/28/situational-awareness/)
* [Commands for Domain Network Compromise](https://www.javelin-networks.com/static/5fcc6e84.pdf)
* [A Pentester’s Guide to Group Scoping](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)

### LAPS

* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon](https://adsecurity.org/?p=3164)
* [Running LAPS with PowerView](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)

### AppLocker

* [Enumerating AppLocker Config](https://rastamouse.me/blog/applocker/)

### Active Directory Federation Services

* [118 Attacking ADFS Endpoints with PowerShell Karl Fosaaen](https://www.youtube.com/watch?v=oTyLdAUjw30)
* [Using PowerShell to Identify Federated Domains](https://blog.netspi.com/using-powershell-identify-federated-domains/)
* [LyncSniper: A tool for penetration testing Skype for Business and Lync deployments](https://github.com/mdsecresearch/LyncSniper)
* [Troopers 19 - I am AD FS and So Can You](https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you)

## **Harvesting Guides and Resources**

{% content-ref url="endpoint-harvesting.md" %}
[endpoint-harvesting.md](endpoint-harvesting.md)
{% endcontent-ref %}

{% content-ref url="ad-remote-harvesting.md" %}
[ad-remote-harvesting.md](ad-remote-harvesting.md)
{% endcontent-ref %}

{% content-ref url="meterpreter-post-auth-runbook.md" %}
[meterpreter-post-auth-runbook.md](meterpreter-post-auth-runbook.md)
{% endcontent-ref %}

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

* iRedTeam blog - [https://www.ired.team/offensive-security/credential-access-and-credential-dumping](https://www.ired.team/offensive-security/credential-access-and-credential-dumping)
* Copy a locked file - [https://github.com/GhostPack/Lockless](https://github.com/GhostPack/Lockless)
* Commands
  * General Enumeration
    * _RTFM: Linux System Info - pg. 5_
    * _BTFM: Linux System Info - pg. 71_
    * _RTFM: Windows System Info - pg. 15_
    * _BTFM: Windows System Info - pg. 60_
    * _RTFM: WMI  Info - pg. 20_
    * _RTFM: Powershell Info - pg. 22_
    * _RTFM: Registry Locations - pg. 26_
  * Host Enumeration
    * Browser Information
      * _PTFM: Browser Information- pg. 46_
    * Virtual Machine Detection
      * _PTFM: Windows VM Detection - pg. 47_
      * _PTFM: Linux VM Detection - pg. 106_
    * Searching for cleartext passwords
      * _PTFM: Windows Cleartext Passwords - pg. 40_
      * _PTFM: Linux Cleartext Passwords - pg. 102_
    * Credential Dumping
      * _PTFM: Windows Credential Dumping - pg. 41_
      * _PTFM: Linux Credential Dumping - pg. 102_
    * Firewall settings
      * _BTFM: Windows Firewall - pg. 22_
      * _BTFM: Linux Firewall - pg. 35_
  * Active Directory
    * _BTFM: AD Inventory - pg. 16_
  * Email collection
    * _PTFM: Email Collection - pg. 59_

## Misc

* [SlackPirate](https://github.com/emtunc/SlackPirate) - Slack Enumeration and Extraction Tool - extract sensitive information from a Slack Workspace
