---
description: All the ways to grab the goodies
---

# Enumeration and Harvesting

## **Post Exploitation Tasks**

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

{% content-ref url="meterpreter-post-auth-runbook.md" %}
[meterpreter-post-auth-runbook.md](meterpreter-post-auth-runbook.md)
{% endcontent-ref %}

## **Enumeration**

{% tabs %}
{% tab title="Guides" %}
* [https://www.ired.team/offensive-security/enumeration-and-discovery](https://www.ired.team/offensive-security/enumeration-and-discovery)
* [http://pwnwiki.io/#!presence/windows/blind.md](http://pwnwiki.io/#!presence/windows/blind.md) - Windows Blind files to search for as an attacker
* [http://pwnwiki.io/#!presence/linux/blind.md](http://pwnwiki.io/#!presence/linux/blind.md) - Linux Blind files
* [http://pwnwiki.io/#!presence/windows/windows\_cmd\_config.md](http://pwnwiki.io/#!presence/windows/windows\_cmd\_config.md) - Commands that display information about the configuration of the victim and are usually executed from the context of the `cmd.exe` or `command.exe` prompt.
* [http://pwnwiki.io/#!presence/windows/network.md](http://pwnwiki.io/#!presence/windows/network.md) - Windows commands to help you gather information about the victim system's network connections, devices and capabilities.
{% endtab %}

{% tab title="Endpoint Tools" %}
* [JAWS](https://github.com/411Hall/JAWS) - JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It
* [RedTeamScripts](https://github.com/threatexpress/red-team-scripts) - Red Team Scripts is a collection of red teaming related tools, scripts, techniques, and notes developed or discovered over time during engagements. Invoke-HostEnum is the tool within these scripts that can perform windows host enumeration for any valuable data.
* [HostRecon](https://github.com/dafthack/HostRecon) - Invoke-HostRecon runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase of an engagement. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.
{% endtab %}
{% endtabs %}

#### AD Enumeration

[https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf](https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf)

{% tabs %}
{% tab title="Tools" %}
* [ADExplorer by Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) - An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database, define favorite locations, view object properties and attributes without having to open dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute.
* [ADRecon](https://github.com/adrecon/ADRecon) - ADRecon is a tool which extracts and combines various artifacts (as highlighted below) out of an AD environment.
* [ACLight](https://github.com/cyberark/ACLight) -A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
* [TruffleSnout](https://github.com/dsnezhkov/TruffleSnout) - Iterative AD discovery toolkit for offensive operators. Situational awareness and targeted low noise enumeration.
{% endtab %}

{% tab title="SPN Scanning" %}
* [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)
* [Active Directory: PowerShell script to list all SPNs used](https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx)
* [Discovering Service Accounts Without Using Privilege](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
{% endtab %}

{% tab title="Data Mining" %}
* [A Data Hunting Overview](https://thevivi.net/2018/05/23/a-data-hunting-overview/)
* [Push it, Push it Real Good](https://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
* [Finding Sensitive Data on Domain SQL Servers using PowerUpSQL](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)
* [Sensitive Data Discovery in Email with MailSniper](https://www.youtube.com/watch?v=ZIOw\_xfqkKM)
* [Remotely Searching for Sensitive Files](https://www.fortynorthsecurity.com/remotely-search/)
* [I Hunt Sysadmins - harmj0y](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)
{% endtab %}

{% tab title="User Hunting" %}
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
* [A Pentester’s Guide to Group Scopin](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)
{% endtab %}

{% tab title="LAPS" %}
* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon](https://adsecurity.org/?p=3164)
* [Running LAPS with PowerView](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)
{% endtab %}

{% tab title="ADFS" %}
* [118 Attacking ADFS Endpoints with PowerShell Karl Fosaaen](https://www.youtube.com/watch?v=oTyLdAUjw30)
* [Using PowerShell to Identify Federated Domains](https://blog.netspi.com/using-powershell-identify-federated-domains/)
* [LyncSniper: A tool for penetration testing Skype for Business and Lync deployments](https://github.com/mdsecresearch/LyncSniper)
* [Troopers 19 - I am AD FS and So Can You](https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you)
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Privilege escalation tools can also provide much of the enumeration that you need.
{% endhint %}

{% content-ref url="../privilege-escalation/" %}
[privilege-escalation](../privilege-escalation/)
{% endcontent-ref %}

## **Harvesting and Credential Dumping**

iRedTeam blog - [https://www.ired.team/offensive-security/credential-access-and-credential-dumping](https://www.ired.team/offensive-security/credential-access-and-credential-dumping)

{% tabs %}
{% tab title="LaZagne" %}
### [LaZagne](https://github.com/AlessandroZ/LaZagne)&#x20;

LaZagne is an open-source tool used in post-exploitation to recover stored passwords on a system. Its modules support Windows, Linux, and OSX, but are primarily intended for Windows systems.\
Software uses different techniques to save credentials, such as saving them to a plaintext file, local databases or credential managers. LaZagne is able to search for these common methods and retrieve any passwords it finds.\
LaZagne is capable of extracting passwords from 87 different software applications from the following categories of software:\
Browsers, Chats, Databases, Games, Git, Mails, Maven, Dumps from memory, Multimedia, PHP, SVN, Sysadmin, WIFI, and  Internal mechanism password storage\
The LaZagne tool along with a full list of software that it supports is available in the [public GitHib repository](https://github.com/AlessandroZ/LaZagne).

[https://www.youtube.com/watch?v=AwFyiFOXrd0](https://www.youtube.com/watch?v=AwFyiFOXrd0)\
\
**Using LaZagne on Windows**

LaZagne's ability to retrieve stored credentials for Windows software is extensive and supports a large number of browsers including Chrome and Firefox, chat clients including Skype, databases, and mail clients including Outlook.\
The tool also supports credential retrieval for many sysadmin utilities like OpenVPN and OpenSSH, and password managers such as KeyPass, which could provide valuable credentials for moving to other hosts in a network.\
\
**Usage**

The Windows version comes with an executable (.exe) file that can be used as a standalone .exe; however, it is not able to detect some credentials such as Google Chrome passwords.\
Simply double clicking on the executable ‘Lazagne.exe' will cause a warning message which indicates that the executable is malicious.&#x20;

* To run the tool successfully, use the command prompt to execute LaZagne:
  * `> lazagne.exe`
  * &#x20;`# Run all modules`
    * `> lazagne.exe all`
  * `# Run the browser modules`
    * `lazagne.exe browsers`
* There is also a Python script in the Windows directory of the LaZagne repository that can run on systems with Python installed. There are a few requirements that may need to be installed first – check the requirements.txt file in the repository for more details.
  * `#python laZagne.py`
  * `# Run all modules`
    * `python laZagne.py all`
  * `# Run modules for Google Chrome. Add the -v flag for verbose output`
    * `python laZagne.py browsers -google -v`
{% endtab %}

{% tab title="Endpoint Tools" %}
* [PassHunt](https://github.com/Dionach/PassHunt) - PassHunt searches drives for documents that contain passwords or any other regular expression. It's designed to be a simple, standalone tool that can be run from a USB stick.
* [SessionGopher](https://github.com/Arvanaghi/SessionGopher) - SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It has WMI functionality built in so it can be run remotely. Its best use case is to identify systems that may connect to Unix systems, jump boxes, or point-of-sale terminals.
* [CredDump](https://github.com/moyix/creddump) - Tool for dumping credentials and secrets from Windows Registry Hives.
  * [https://www.kali.org/tools/creddump7/](https://www.kali.org/tools/creddump7/)
* [dumpsterdiver](https://www.kali.org/tools/dumpsterdiver/) - This package contains a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords.
* [polenum](https://www.kali.org/tools/polenum/) - polenum is a Python script which uses the Impacket Library from CORE Security Technologies to extract the password policy information from a windows machine.
* [powersploit](https://www.kali.org/tools/powersploit/) - PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.
* [pspy](https://github.com/DominicBreuker/pspy) - Monitor linux processes without root permissions
* [swap\_digger](https://github.com/sevagas/swap\_digger) - swap\_digger is a tool used to automate Linux swap analysis during post-exploitation or forensics. It automates swap extraction and searches for Linux user credentials, web forms credentials, web forms emails, http basic authentication, Wifi SSID and keys, etc.
* [https://highon.coffee/blog/linux-local-enumeration-script/](https://highon.coffee/blog/linux-local-enumeration-script/)
* [Masky](https://github.com/Z4kSec/Masky) - Python library with CLI allowing to remotely dump domain user credentials via an ADCS without dumping the LSASS process memory
  * [https://z4ksec.github.io/posts/masky-release-v0.0.3/](https://z4ksec.github.io/posts/masky-release-v0.0.3/)
{% endtab %}
{% endtabs %}

{% content-ref url="ad-remote-harvesting.md" %}
[ad-remote-harvesting.md](ad-remote-harvesting.md)
{% endcontent-ref %}

<details>

<summary>Command Reference</summary>

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

</details>

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

## Misc

* [SlackPirate](https://github.com/emtunc/SlackPirate) - Slack Enumeration and Extraction Tool - extract sensitive information from a Slack Workspace
* Copy a locked file - [https://github.com/GhostPack/Lockless](https://github.com/GhostPack/Lockless)
