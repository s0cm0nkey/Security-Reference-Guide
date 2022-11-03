# AD Privilege Escalation

## Harvested Credentials

{% content-ref url="../post-exploitation/enumeration-and-harvesting/ad-remote-harvesting.md" %}
[ad-remote-harvesting.md](../post-exploitation/enumeration-and-harvesting/ad-remote-harvesting.md)
{% endcontent-ref %}

## Constrained Delegation

### Abusing Constrained Delegation

* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
* [Kerberos Resource-based Constrained Delegation: Computer Object Take Over](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
* [Resource Based Constrained Delegation](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)
* [A Case Study in Wagging the Dog: Computer Takeover](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
* [BloodHound 2.1's New Computer Takeover Attack](https://www.youtube.com/watch?v=RUbADHcBLKg)

### Abusing Unconstrained Delegation

* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest](https://adsecurity.org/?p=4056)
* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Exploiting Unconstrained Delegation](https://www.riccardoancarani.it/exploiting-unconstrained-delegation/)
* [https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/abusing\_unconstrained\_delegation/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/abusing\_unconstrained\_delegation/)

## Attacking Domain Trusts

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

## Privileges and Permissions

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

## Misconfigurations

### Misconfigured MSSQL Access Control

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfgured\_access\_control\_of\_mssql/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfgured\_access\_control\_of\_mssql/)

### Misconfigured GPO

* [https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [A Redteamer's Guide to GPO's and OU's](https://wald0.com/?p=179)
* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
* [GPO Abuse - Part 1](https://rastamouse.me/blog/gpo-abuse-pt1/)
* [GPO Abuse - Part 2](https://rastamouse.me/blog/gpo-abuse-pt2/)
* [SharpGPOAbuse](https://github.com/mwrlabs/SharpGPOAbuse)
* [Grouper](https://github.com/l0ss/Grouper) - A PowerShell script for helping to find vulnerable settings in AD Group Policy.
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_gpo/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_gpo/)

### Misconfigured Forest or Domain Trust

* [https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d?gi=43aabaf65628](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d?gi=43aabaf65628)
* [https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/attacking\_windows\_domain\_domain\_trust/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/attacking\_windows\_domain\_domain\_trust/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/incorrectly\_configured\_forest\_or\_domain\_trust/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/incorrectly\_configured\_forest\_or\_domain\_trust/)
* [https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

### Misconfigured ACLs

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/misconfigured\_access\_control\_lists/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/misconfigured\_access\_control\_lists/)
* [aclpwn.py](https://github.com/fox-it/aclpwn.py) - Active Directory ACL exploitation with BloodHound
* [ADACLScanner](https://github.com/canix1/ADACLScanner) - A tool with GUI or command linte used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory
* [RACE](https://github.com/samratashok/RACE) - RACE is a PowerShell module for executing ACL attacks against Windows targets.

### Misconfigured LAPS

* [Exploiting Weak Active Directory Permissions With Powersploit](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
* [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [Abusing Active Directory Permissions with PowerView](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_laps/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_misconfigured\_laps/)

### Misconfigured RODC

* [https://adsecurity.org/?p=3592](https://adsecurity.org/?p=3592)

## Unsupported OS

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_unsupported\_os/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_unsupported\_os/)

## Kerberos Attacks and Vulns

### Golden Ticket

* [AD-001 - Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)

### Kerberoasting

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

### Kerberos Delegation

* [Constructing Kerberos Attacks with Delegation Primitives](https://shenaniganslabs.io/media/Constructing%20Kerberos%20Attacks%20with%20Delegation%20Primitives.pdf)
* [No Shells Required - a Walkthrough on Using Impacket and Kerberos to Delegate Your Way to DA](http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Overview](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-overview/)

### Kerberos Relay Attacks

* [KrbRelay](https://github.com/cube0x0/KrbRelay) - Framework for Kerberos relaying
  * [https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
* [https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html](https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html)
* [https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)

### MS14-068 Kerberos Vulnerability

* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege](https://adsecurity.org/?p=525)
* [Digging into MS14-068, Exploitation and Defence](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
* [From MS14-068 to Full Compromise – Step by Step](https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/)

## DCShadow

* [Privilege Escalation With DCShadow](https://blog.stealthbits.com/privilege-escalation-with-dcshadow/)
* [DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)
* [DCShadow explained: A technical deep dive into the latest AD attack technique](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
* [DCShadow - Silently turn off Active Directory Auditing](http://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html)
* [DCShadow - Minimal permissions, Active Directory Deception, Shadowception and more](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)
* [AD-003 - DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)

## Abusing AD Certificate Signing

* [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

## Specific Vulnerabilities and Attacks

### Remote Potato

* [https://github.com/antonioCoco/RemotePotato0](https://github.com/antonioCoco/RemotePotato0)

### PetitPotam

* [https://github.com/topotam/PetitPotam/](https://github.com/topotam/PetitPotam/)
* [https://threatpost.com/microsoft-petitpotam-poc/168163/](https://threatpost.com/microsoft-petitpotam-poc/168163/)
* [https://blog.truesec.com/2021/08/05/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory/](https://blog.truesec.com/2021/08/05/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory/)

### Zerologon

* [Cobalt Strike ZeroLogon-BOF](https://github.com/rsmudge/ZeroLogon-BOF)
* [CVE-2020-1472 POC](https://github.com/dirkjanm/CVE-2020-1472)
* [Zerologon: instantly become domain admin by subverting Netlogon cryptography (CVE-2020-1472)](https://www.secura.com/blog/zero-logon)

### Skeleton Key

* [AD-002 - Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)



