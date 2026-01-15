# Device Auditing and Hardening

Detections, alerts, and all the "fancy" security tools are completely worthless if the devices you are trying to protect are not properly hardened against the onslaught of attacks they face day-to-day. Most, if not all, devices and applications in their "factory fresh" state are not properly hardened for use in an enterprise environment. Many features that you might appreciate as a convenience in your home network are actually a major vulnerability in a large-scale network deployed at your company.

The best way to understand device hardening and how to perform it is to follow [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/). This organization has developed standards for hardening different operating systems and applications to an appropriate level for enterprise environments. Not only do they have step-by-step walkthroughs of what to look for and how to remediate issues, but they also often have scripts that can check and even automate the hardening process. As a security analyst of any level or specialty, learning the available configuration-based vulnerabilities of the platforms you work with on a daily basis is one of the most valuable things you can do to improve your skillset.

[AuditScripts](https://crfsecure.org/auditscripts/) is another great set of tools that can perform configuration hardening audits based on different requirements, including the choice of those defined by CIS.

## Security Auditing Tools

* Auditing toolkits
  * [Lynis (Linux Security Auditing)](https://github.com/CISOfy/Lynis) - Lynis is a security auditing tool for systems based on UNIX like Linux, macOS, BSD, and others. It performs an in-depth security scan and runs on the system itself.
  * [Seatbelt (Windows Security Auditing)](https://github.com/GhostPack/Seatbelt) - Seatbelt is a C# project that performs a number of security-oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
  * [BTPS: Blue team Powershell Toolkit](https://github.com/tobor88/BTPS-SecPack) - A collection of PowerShell tools that can be utilized to protect and defend an environment based on Microsoft's recommendations.
* [Bloodhound Enterprise](https://bloodhoundenterprise.io/) - Enterprise-grade attack path management solution.
* [Purple Knight](https://www.semperis.com/purple-knight/) -  An enterprise-grade Active Directory Defense solution with AD mapping, security reports, security indicators, and remediation guides.
* [debsums](https://manpages.ubuntu.com/manpages/trusty/man1/debsums.1.html) - Utility for checking installed Debian packages and comparing their hashes against a list of known good ones. Handy to run periodically to detect file integrity changes.
* [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) - PowerShell toolkit for auditing Active Directory Certificate Services (AD CS).
* [WDACTools](https://github.com/mattifestation/WDACTools) - A PowerShell module to facilitate building, configuring, deploying, and auditing Windows Defender Application Control (WDAC) policies.
* [CSET](https://www.cisa.gov/stopransomware/cyber-security-evaluation-tool-csetr) - The Cyber Security Evaluation Tool (CSET®) is a stand-alone desktop application that guides asset owners and operators through a systematic process of evaluating Operational Technology and Information Technology.
* [OpenSCAP](https://www.open-scap.org/) - An ecosystem of open source software for implementing and enforcing NIST's Security Content Automation Protocol (SCAP) standards. It serves as a powerful tool for vulnerability assessment and compliance checking (STIG/CIS).

## Hardening Tools

* [Microsoft Attack Surface Analyzer](https://github.com/Microsoft/AttackSurfaceAnalyzer) - Attack Surface Analyzer is a [Microsoft](https://github.com/microsoft/) developed open source security tool that analyzes the attack surface of a target system and reports on potential security vulnerabilities introduced during the installation of software or system misconfiguration.
* [Portspoof](https://github.com/drk1wi/portspoof) - A tool for confusing port scanners by returning false port information.
  * [Black Hills Infosec: How to use Portspoof](https://www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/)
* [HardenTools](https://github.com/securitywithoutborders/hardentools) - A collection of simple utilities designed to disable a number of "features" exposed by operating systems (Microsoft Windows, for now), and primary consumer applications.
* [O&O ShutUp10++](https://www.oo-software.com/en/shutup10) - Free anti-spy and telemetry logging tool for Windows 10 and 11.
* [Google's Browser Info Checker](https://toolbox.googleapps.com/apps/browserinfo/) - Checks what info you might be sharing to others through your browser. Requires Javascript.
* [Google's MXChecker](https://toolbox.googleapps.com/apps/checkmx/) - Checks for common MX domain security settings.
*   [cs-php-bouncer](https://github.com/crowdsecurity/cs-php-bouncer) - This bouncer leverages the PHP `auto_prepend` mechanism.

    New/unknown IP are checked against crowdsec API, and if request should be blocked, a **403** or a captcha can be returned to the user, and put in cache.
* [dev-sec](https://github.com/dev-sec/) - Security + DevOps: Automatic Server Hardening.
* [grapheneX](https://github.com/grapheneX/grapheneX) - Automated System Hardening Framework.
* [Legit-Labs/legitify](https://github.com/Legit-Labs/legitify) - Detect and remediate misconfigurations and security risks across all your GitHub assets.
* [ScubaGear](https://github.com/cisagov/ScubaGear) - Automation to assess the state of your M365 tenant against CISA's baselines.
Cloud & Container Hardening

* [Prowler](https://github.com/prowler-cloud/prowler) - An Open Source security tool to perform AWS, Azure, and Google Cloud security best practices assessments, audits, incident response, continuous monitoring, hardening, and forensics readiness.
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - An open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.
* [kube-bench](https://github.com/aquasecurity/kube-bench) - Checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.
* [Checkov](https://github.com/bridgecrewio/checkov) - A static code analysis tool for infrastructure as code (IaC) and also a software composition analysis (SCA) tool for images and open source packages.

### Linux

* [Ubuntu Wiki: AppArmor](https://wiki.ubuntu.com/AppArmor) - Proactively protects the operating system and applications from external or internal threats.
* [GitHub: SELinuxProject](https://github.com/SELinuxProject) - Provides a flexible Mandatory Access Control (MAC) system built into the Linux kernel.

### macOS

* [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) - A NIST-led project to provide a programmatic approach to generating security configuration profiles for macOS.

## Hardening Resources

* [Awesome Lists Collection: Security Hardening](https://github.com/decalage2/awesome-security-hardening)
* [Awesome Lists Collection: Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
* [TechNet: Security Hardening Tips and Recommendations](https://social.technet.microsoft.com/wiki/contents/articles/18931.security-hardening-tips-and-recommendations.aspx)
* [DoD Cyber Exchange: STIGs](https://public.cyber.mil/stigs/) - The Security Technical Implementation Guides (STIGs) are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems.
* [Developing a Secure Baseline](https://adsecurity.org/?p=3299)
* [OWASP Cryptographic Storage Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) - Guide and Reference for best standards for encrypting stored data.
* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [NSA's Secure Windows Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline)
* [Top 20 Linux Security Tips](https://www.cyberciti.biz/tips/linux-security.html) - Classic guide for securing Linux servers.
* [NSA Network Infrastructure Security Guidance (2022)](https://media.defense.gov/2022/Mar/01/2002947139/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDANCE_20220301.PDF)
* [GPSearch](https://gpsearch.azurewebsites.net/) - A searchable database of Group Policy settings.
* _Defensive Security Handbook: Microsoft Windows Infrastructure - pg. 81_
* _Defensive Security Handbook: Hardening Endpoints - pg. 116_
* _Defensive Security Handbook: Network Infrastructure - pg. 143_

### AD hardening

* [Active Directory Security Assessment Checklist](https://www.cert.ssi.gouv.fr/uploads/guide-ad.html) - CERT.FR
* [Active Directory Certificate Services](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831740\(v=ws.11\)) -  An often overlooked tool that should come with most Microsoft licenses; use AD certificates to sign scripts and docs made in your environment to easily detect what is foreign.
  * [Locksmith](https://github.com/TrimarcJake/Locksmith) - A tool to identify and remediate common misconfigurations in Active Directory Certificate Services
    * [Trimarc Security: Locksmith Talk](https://www.hub.trimarcsecurity.com/post/wild-west-hackin-fest-toolshed-talk-locksmith)
* [Security Considerations for Domain Trusts - Microsoft](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321\(v=ws.10\)?redirectedfrom=MSDN#w2k3tr_trust_security_zyzk)
* [Locking up your Domain Controllers - Microsoft](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc160936\(v=msdn.10\)?redirectedfrom=MSDN)
* Group Policies
  * [Active Directory and Group Policy Guidelines](https://www.grouppolicy.biz/2010/07/best-practice-active-directory-structure-guidelines-part-1/)
  * [Black Hills Infosec: Group Policies that Kill Kill Chains](https://www.blackhillsinfosec.com/webcast-group-policies-that-kill-kill-chains/)
  * [NIST Secure Base Set of GPOs](https://csrc.nist.gov/Projects/United-States-Government-Configuration-Baseline/USGCB-Content/Microsoft-Content)

### Email Defense Hardening

* [Cyber.gov.au: Combat Fake Emails](https://www.cyber.gov.au/sites/default/files/2020-05/PROTECT%20-%20How%20to%20Combat%20Fake%20Emails%20%28September%202019%29.pdf)
* [M3AAWG: Parked Domains Best Practices](https://www.m3aawg.org/sites/default/files/m3aawg_parked_domains_bp-2015-12.pdf)
* [M3AAWG: Email Authentication Best Practices](https://www.m3aawg.org/sites/default/files/m3aawg-email-authentication-recommended-best-practices-09-2020.pdf)
* [M3AAWG: Malicious Domain Registrations](https://www.m3aawg.org/sites/default/files/m3aawg-maliciousdomainregistratinos-2018-06.pdf)
* [M3AAWG: Reporting Phishing URLs](https://www.m3aawg.org/sites/default/files/m3aawg-reporting-phishing-urls-2018-12.pdf)

## Archived / Deprecated Tools

*   [OSChameleon](https://github.com/mushorg/oschameleon) - **(Archived/Legacy)** OS Fingerprint Obfuscation for Linux. Requires Python 2.7.
    *   [ADHD Project - OsChameleon](https://adhdproject.github.io/#!Tools/Annoyance/OsChameleon.md)
*   [atc-mitigation](https://github.com/atc-project/atc-mitigation) - **(Deprecated)** Analytics for combatting threats based on MITRE ATT&CK. No longer actively maintained.
*   [mod_evasive](https://github.com/jzdziarski/mod_evasive) - **(Legacy)** Apache module for DoS/Brute Force protection. Not updated in many years; consider modern WAF solutions.
*   [ModSecurity-apache](https://github.com/SpiderLabs/ModSecurity-apache) - **(Legacy)** Traditional ModSecurity 2.x for Apache. For modern deployments, consider ModSecurity v3 (libmodsecurity).

## **Hardening Commands**

{% content-ref url="windows-hardening-commands.md" %}
[windows-hardening-commands.md](windows-hardening-commands.md)
{% endcontent-ref %}

Note: These may inadvertently break communication of devices and should be tested. It may also require a restart.
