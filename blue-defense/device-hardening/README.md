# Device Auditing and Hardening

The best way to understand what device hardening and how to do it, is to follow [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/). This organization has developed standards for hardening different operating systems and applications to a proper level in an enterprise environment. Not only do they have step by step walk-troughs of what to look for and how to do it, they also have scripts that can check and even automate the hardening for you. As a security analyst of any level or specialty, learning the available configuration based vulnerabilities of the platforms you work with on a daily basis, is one of the most valuable things you can do to improve you skillset.

[AuditScripts](https://www.auditscripts.com/) is another great set of tools that can perform configuration hardening audits based on different requirements, including the choice of those defined by CIS.

## Security Auditing Tools

* Auditing toolkits
  * [Lynis (Linux Security Auditing)](https://github.com/CISOfy/Lynis) - Lynis is a security auditing tool for systems based on UNIX like Linux, macOS, BSD, and others. It performs an in-depth security scan and runs on the system itself.
  * [Seatbelt (Windows Security Auditing) ](https://github.com/GhostPack/Seatbelt)- Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
  * [BTPS: Blue team Powershell Toolkit ](https://github.com/tobor88/BTPS-SecPack)- A collection of PowerShell tools that can be utilized to protect defend an environment based Microsoft's recommendations.
* [Bloodhound Enterprise ](https://bloodhoundenterprise.io/)- Enterprise grade attack path management solution
* [Purple Knight](https://www.purple-knight.com/) -  An enterprise grade Active Directory Defense solution with AD mapping, security reports, security indicators and remediation guides.
* [debsums](https://manpages.ubuntu.com/manpages/trusty/man1/debsums.1.html) - Utility for checking installed debian packages and comparing that hashes against a list of known good ones. Handy to run every once&#x20;
* [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) - PowerShell toolkit for auditing Active Directory Certificate Services (AD CS).
* [WDACTools](https://github.com/mattifestation/WDACTools) - A PowerShell module to facilitate building, configuring, deploying, and auditing Windows Defender Application Control (WDAC) policies

## Hardening Tools

* [Microsoft Attack Surface Analyzer](https://github.com/Microsoft/AttackSurfaceAnalyzer) - Attack Surface Analyzer is a [Microsoft](https://github.com/microsoft/) developed open source security tool that analyzes the attack surface of a target system and reports on potential security vulnerabilities introduced during the installation of software or system misconfiguration.
* [OSChameleon](https://github.com/mushorg/oschameleon) - OS Fingerprint Obfuscation for modern Linux Kernels.
  * [https://adhdproject.github.io/#!Tools/Annoyance/OsChameleon.md](https://adhdproject.github.io/#!Tools/Annoyance/OsChameleon.md)
* [Portspoof](https://github.com/drk1wi/portspoof) - A tool for confusing port scanners by returning false port information.
  * [https://www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/](https://www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/)
* [HardenTools](https://github.com/securitywithoutborders/hardentools) - a collection of simple utilities designed to disable a number of "features" exposed by operating systems (Microsoft Windows, for now), and primary consumer applications.
* [atc-mitigation](https://github.com/atc-project/atc-mitigation) - Actionable analytics designed to combat threats based on MITRE's ATT\&CK.
* [https://www.oo-software.com/en/shutup10](https://www.oo-software.com/en/shutup10) - Free anti-spy and telemetry logging tool for Windows 10 and 11
* [Google's Browser Info Checker](https://toolbox.googleapps.com/apps/browserinfo/) - Checks what info you might be sharing to others through your browser. Requires Javascript.
* [Googe's MXChecker](https://toolbox.googleapps.com/apps/checkmx/) - Checks for common MX domain security settings.
*   [cs-php-bouncer](https://github.com/crowdsecurity/cs-php-bouncer) - This bouncer leverages the PHP `auto_preprend` mechanism.

    New/unknown IP are checked against crowdsec API, and if request should be blocked, a **403** or a captcha can be returned to the user, and put in cache.
* [dev-sec](https://github.com/dev-sec/) - Security + DevOps: Automatic Server Hardening.
* [grapheneX](https://github.com/grapheneX/grapheneX) - Automated System Hardening Framework&#x20;
* [Legit-Labs/legitify](https://github.com/Legit-Labs/legitify) - Detect and remediate misconfigurations and security risks across all your GitHub assets
* [https://github.com/cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) - Automation to assess the state of your M365 tenant against CISA's baselines

### Linux

* [https://wiki.ubuntu.com/AppArmor](https://wiki.ubuntu.com/AppArmor) - proactively protects the operating system and applications from external or internal threats.
* [https://github.com/SELinuxProject](https://github.com/SELinuxProject) - provides a flexible Mandatory Access Control (MAC) system built into the Linux kernel.

### Apache Web Server

* [mod\_evasive](https://github.com/jzdziarski/mod\_evasive) - mod\_evasive module is an Apache web services module that helps your server stay running in the event of a DDOS or Brute Force attack.
  * [https://phoenixnap.com/kb/apache-mod-evasive](https://phoenixnap.com/kb/apache-mod-evasive)
* [ModSecurity-apache](https://github.com/SpiderLabs/ModSecurity-apache) - ModSecurity is a plug-in module for Apache that works like a firewall. It functions through rule sets, which allow you to customize and configure your [server security](https://phoenixnap.com/kb/server-security-tips).
  * [https://phoenixnap.com/kb/setup-configure-modsecurity-on-apache](https://phoenixnap.com/kb/setup-configure-modsecurity-on-apache)

## Hardening Resources

* [Awesome Lists Collection: Security Hardening](https://github.com/decalage2/awesome-security-hardening)
* [Awesome Lists Collection: Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
* [https://social.technet.microsoft.com/wiki/contents/articles/18931.security-hardening-tips-and-recommendations.aspx](https://social.technet.microsoft.com/wiki/contents/articles/18931.security-hardening-tips-and-recommendations.aspx)
* [Developing a Secure Baseline](https://adsecurity.org/?p=3299)
* [OWASP Cryptographic Storage Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html) - Guide and Reference for best standards for encrypting stored data.
* [https://cheatsheetseries.owasp.org/cheatsheets/Authorization\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authorization\_Cheat\_Sheet.html)
* [NSA's Secure Windows baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline)
* [https://www.securedyou.com/how-to-secure-linux-server-from-hackers-hardening-guide/](https://www.securedyou.com/how-to-secure-linux-server-from-hackers-hardening-guide/)
* [NSA\_NETWORK\_INFRASTRUCTURE\_SECURITY\_GUIDANCE\_20220301.PDF](https://media.defense.gov/2022/Mar/01/2002947139/-1/-1/0/CTR\_NSA\_NETWORK\_INFRASTRUCTURE\_SECURITY\_GUIDANCE\_20220301.PDF)
* [https://admx.help/](https://admx.help/) - Group Policy Administrative Templates Catalog
* _Defensive Securit Handbook: Microsoft Windows Infrastructure - pg. 81_
* _Defensive Securit Handbook: Hardening Endpoints - pg. 116_
* _Defensive Securit Handbook: Network Infrastructure - pg. 143_

### AD hardening

* [Active Directory Security Assessment Checklist](https://www.cert.ssi.gouv.fr/uploads/guide-ad.html) - CERT.FR
* [Active Directory Certificate Services](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831740\(v=ws.11\)) -  An often overlooked tool that should come with most Microsoft licenses, use AD certificates to sign scripts and docs made in your environment, to easily detect what is foreign. Detections, alerts, and all the fancy security tools are completely worthless, if the devices you are trying to protect are not properly hardened against the onslaught of attacks they might face day to day. Most if not all devices and even applications, in their factory fresh state, are not properly hardened for use in an enterprise environment. Many features that you might appreciate as a convenience in your home network, are actually a major vulnerability in a large scale network deployed at your company.
  * [ Locksmith](https://github.com/TrimarcJake/Locksmith) - A tool to identify and remediate common misconfigurations in Active Directory Certificate Services
    * [https://www.hub.trimarcsecurity.com/post/wild-west-hackin-fest-toolshed-talk-locksmith](https://www.hub.trimarcsecurity.com/post/wild-west-hackin-fest-toolshed-talk-locksmith)
* [Security Considerations for Domain Trusts - Microsoft](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321\(v=ws.10\)?redirectedfrom=MSDN#w2k3tr\_trust\_security\_zyzk)
* [Locking up your Domain Controllers - Microsoft](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc160936\(v=msdn.10\)?redirectedfrom=MSDN)
* Group Policies
  * [Active Directory and Group Policy Guidelines](https://www.grouppolicy.biz/2010/07/best-practice-active-directory-structure-guidelines-part-1/)
  * [https://www.blackhillsinfosec.com/webcast-group-policies-that-kill-kill-chains](https://www.blackhillsinfosec.com/webcast-group-policies-that-kill-kill-chains/)
  * [NIST Secure base set of GPOs](https://csrc.nist.gov/Projects/United-States-Government-Configuration-Baseline/USGCB-Content/Microsoft-Content)

### Certificate Pinning

* [https://www.hasecuritysolutions.com/the-trusted-evil-intranet-page/](https://www.hasecuritysolutions.com/the-trusted-evil-intranet-page/)

### Email Defense Hardening

* [https://www.cyber.gov.au/sites/default/files/2020-05/PROTECT%20-%20How%20to%20Combat%20Fake%20Emails%20%28September%202019%29.pdf](https://www.cyber.gov.au/sites/default/files/2020-05/PROTECT%20-%20How%20to%20Combat%20Fake%20Emails%20\(September%202019\).pdf)
* [https://www.m3aawg.org/sites/default/files/m3aawg\_parked\_domains\_bp-2015-12.pdf](https://www.m3aawg.org/sites/default/files/m3aawg\_parked\_domains\_bp-2015-12.pdf)
* [https://www.m3aawg.org/sites/default/files/m3aawg-email-authentication-recommended-best-practices-09-2020.pdf](https://www.m3aawg.org/sites/default/files/m3aawg-email-authentication-recommended-best-practices-09-2020.pdf)
* [https://www.m3aawg.org/sites/default/files/m3aawg-maliciousdomainregistratinos-2018-06.pdf](https://www.m3aawg.org/sites/default/files/m3aawg-maliciousdomainregistratinos-2018-06.pdf)
* [https://www.m3aawg.org/sites/default/files/m3aawg-reporting-phishing-urls-2018-12.pdf](https://www.m3aawg.org/sites/default/files/m3aawg-reporting-phishing-urls-2018-12.pdf)

## **Hardening Commands**

{% content-ref url="windows-hardening-commands.md" %}
[windows-hardening-commands.md](windows-hardening-commands.md)
{% endcontent-ref %}

Note: These may inadvertently break communication of devices and should be tested. It may also require a restart.
