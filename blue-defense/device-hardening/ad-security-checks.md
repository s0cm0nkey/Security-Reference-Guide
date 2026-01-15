# AD Security Checks

### Defensive/Hardening Tools

* [PingCastle](https://www.pingcastle.com/) - A tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework
* [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) - Uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Defenders can use it to identify and eliminate highly complex attack paths.
* [Purple Knight](https://www.purple-knight.com/) - A security assessment tool that scans your Active Directory environment for indicators of exposure (IOEs) and provides a report with a security score.
* [SpoolerScanner](https://github.com/vletoux/SpoolerScanner) - Check if MS-RPRN is remotely available using PowerShell or C#.
* [DCSYNCMonitor](https://github.com/shellster/DCSYNCMonitor) - Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.

### Deprecated / Archive Tools
*The following tools may be unmaintained but contain useful concepts or scripts.*
* [jackdaw](https://github.com/skelsec/jackdaw) - AD visualization tool (similar goal to BloodHound) focusing on object interactions. 
* [RiskySPN](https://github.com/cyberark/RiskySPN) - PowerShell scripts focused on detecting and abusing accounts associated with SPNs.
* [Deploy-Deception](https://github.com/samratashok/Deploy-Deception) - A PowerShell module to deploy active directory decoy objects.
* [dcept](https://github.com/secureworks/dcept) - A tool for deploying and detecting use of Active Directory honeytokens.

## General Recommendations

* Manage local Administrator passwords using Windows LAPS (built-in) or Legacy LAPS.
* Implement RDP Restricted Admin mode (as needed).
* Remove unsupported OSs from the network.
* Monitor scheduled tasks on sensitive systems (DCs, etc.).
* Scan SYSVOL for legacy GPP Passwords (MS14-025) in fragments (groups.xml, scheduledtasks.xml).
* Ensure that OOB management passwords (DSRM) are changed regularly & securely stored.
* Disable SMBv1 and enforce SMB v2/v3 signing.
* Default domain Administrator password should be changed every year & when an AD admin leaves. The KRBTGT password should be rotated twice annually and when an AD admin leaves.
* Remove trusts that are no longer necessary & enable SID filtering as appropriate.
* Enforce LDAP Signing and Channel Binding to prevent relay attacks.
* All domain authentications should be set (when possible) to: "Send NTLMv2 response only. Refuse LM & NTLM."
* Block internet access for DCs, servers, & all administration systems.

## Protect Admin Credentials

* No "user" or computer accounts in admin groups.
* Ensure all admin accounts are "sensitive & cannot be delegated".
* Add admin accounts to "Protected Users" group (requires Windows Server 2012 R2 Domain Controllers, 2012R2 DFL for domain protection).
* Disable all inactive admin accounts and remove from privileged groups.

## Protect AD Admin Credentials

* Limit AD admin membership (DA, EA, Schema Admins, etc.) & only use custom delegation groups.
* Tiered Administration to mitigate credential theft impact.
* Ensure admins only logon to approved admin workstations & servers.
* Leverage time-based, temporary group membership for all admin accounts

## Protect Service Account Credentials

* Limit to systems of the same security level.
* Leverage “(Group) Managed Service Accounts” (or password >20 characters) to mitigate credential theft (kerberoast).
* Implement Fine-Grained Password Policies (FGPP) (starting at DFL 2008) to increase password requirements for SAs and administrators.
* Logon restrictions – prevent interactive logon & limit logon capability to specific computers.
* Disable inactive SAs & remove from privileged groups.

## Protect Resources

* Segment network to protect admin & critical systems.
* Deploy IDS to monitor the internal corporate network.
* Network device & OOB management on separate network.

## Protect Domain Controllers

* Only run software & services to support AD.
* Minimal groups (& users) with DC admin/logon rights.
* Disable the Print Spooler service on all Domain Controllers (to mitigate PrintNightmare and coercion attacks).
* Ensure critical patches are applied before running DCPromo (e.g., Zerologon [CVE-2020-1472]).
* Validate scheduled tasks & scripts.

## Protect AD CS (Certificate Services)

* Treat Certificate Authorities (CAs) as Tier 0 assets (same security level as Domain Controllers).
* Regularly audit Certificate Templates for misconfigurations (e.g., ESC1-ESC8 vulnerabilities).
* Remove "Enroll" permissions for "Domain Users" on sensitive templates.
* Prevent "Enrollee Supplies Subject" flag on templates that allow authentication.
* Monitor for new certificate requests and template changes.

## Protect Workstations (& Servers)

* Patch quickly, especially privilege escalation vulnerabilities.
* Set WDigest `UseLogonCredential` registry value to 0:
    *   Path: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest`
    *   Value Name: `UseLogonCredential`
    *   Type: `DWORD`
    *   Value: `0`
* Deploy workstation whitelisting (Microsoft AppLocker or Windows Defender Application Control) to block code execution in user folders – home directory & profile path.
* Deploy workstation app sandboxing technology (Windows Defender Exploit Guard) to mitigate application memory exploits (0-days).

## Logging

* Enable enhanced auditing.Creation Events" enabled
* “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings”
* Enable PowerShell module logging (“\*”) & forward logs to central log server (WEF or other method).
* Enable CMD Process logging & enhancement (KB3004375) and forward logs to central log server.
* SIEM or equivalent to centralize as much log data as possible.
* User Behavior Analysis system for enhanced knowledge of user activity (such as Microsoft Defender for Identity).

## Security Pro’s Checks

* Identify who has AD admin rights (domain/forest).
* Identify who can logon to Domain Controllers (& admin rights to virtual environment hosting virtual DCs).
* Scan Active Directory Domains, OUs, AdminSDHolder, & GPOs for inappropriate custom permissions.
* Ensure AD admins (aka Domain Admins) protect their credentials by not logging into untrusted systems (workstations).
* Limit service account rights that are currently DA (or equivalent).
