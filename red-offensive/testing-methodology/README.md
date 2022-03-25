# Testing Methodology

## Passive Reconnaissance

This section focuses on the very first part of a penetration test: Passive Reconnaissance. This is where you use all the tools and resources at your disposal to gather up all of the information you can on your target, without interacting with the target in anyway (no scanning).

For more tools and resources on intelligence gathering outside of the below frameworks, please see the OSINT section under Cyber Intelligence.

{% content-ref url="../../cyber-intelligence/osint/" %}
[osint](../../cyber-intelligence/osint/)
{% endcontent-ref %}

{% content-ref url="../offensive-toolbox/recon-frameworks.md" %}
[recon-frameworks.md](../offensive-toolbox/recon-frameworks.md)
{% endcontent-ref %}

{% content-ref url="../../web-app-hacking/mapping-the-site.md" %}
[mapping-the-site.md](../../web-app-hacking/mapping-the-site.md)
{% endcontent-ref %}

{% hint style="info" %}
Note: Many Recon Frameworks have both passive and active reconnaissance capabilities.
{% endhint %}

* [https://tryhackme.com/room/passiverecon](https://tryhackme.com/room/passiverecon)
* [https://tryhackme.com/room/redteamrecon](https://tryhackme.com/room/redteamrecon)
* _Penetration Testing: Information Gathering - pg.113_

## **Active Recon and Scanning**

After your passive reconnaissance phase, the next step is active scanning of your target. This usually involves port scanning and scanning for any vulnerabilities that your target might have, preferably with out them noticing. Active scanning does have direct interaction with your target and does run the risk of being detected. There are ways to subtle scan your target and not draw too much attention. This can include slowing the rate of your scanning or performing them in such a way as to not create a full connection request that would trigger any defensive alerts.

The following section will contain scanning tools and resources such as port scanners, vulnerability scanners, and so much more!

* [https://tryhackme.com/room/activerecon](https://tryhackme.com/room/activerecon)

{% content-ref url="scanning-active-recon/" %}
[scanning-active-recon](scanning-active-recon/)
{% endcontent-ref %}

## Exploitation

### Exploit Research

{% content-ref url="exploit-research.md" %}
[exploit-research.md](exploit-research.md)
{% endcontent-ref %}

### Attacking your target

After finding your target and enumerating it, its now time for your initial access. This step is usually focused around exploiting a port/service open to you. There are tons of different ways to do this as you can see with the guides and list below. \
Keep in mind that just because you cannot completely exploit one service does not mean it wont be helpful. Certain services may have interesting intel that might help you exploit something else, such as an open FTP server with anonymous auth, that contains a few docs with valid usernames in it (you will find worse things).

Once you have your initial exploitation, you will essentially attempt a second round of it to escalate your privileges in the target box. Some times that can be done by getting initial access on another trusted box, or even by a service that is running internally on the loopback. Check everything, look everywhere, and dont forget the OSCP catch phrase, "try harder!"

For reference on exploiting specific services please see the Exploitation section.

{% content-ref url="exploitation.md" %}
[exploitation.md](exploitation.md)
{% endcontent-ref %}

### Payloads and Obfuscation tools

{% content-ref url="payloads-and-obfuscation/" %}
[payloads-and-obfuscation](payloads-and-obfuscation/)
{% endcontent-ref %}

### Exploit Development/Buffer Overflow

For details on creating your own exploits, and the dreaded topic of buffer overflows, please see the Exploit Dev section.

{% content-ref url="exploit-dev-buffer-overflow.md" %}
[exploit-dev-buffer-overflow.md](exploit-dev-buffer-overflow.md)
{% endcontent-ref %}

## Actions on Target

* _Penetration Testing: Post Exploitation - pg.277_

### Endpoint Enumeration and Harvesting

{% content-ref url="enumeration-and-harvesting/" %}
[enumeration-and-harvesting](enumeration-and-harvesting/)
{% endcontent-ref %}

### Network Harvesting and MITM

{% content-ref url="network-attacks-harvesting-mitm.md" %}
[network-attacks-harvesting-mitm.md](network-attacks-harvesting-mitm.md)
{% endcontent-ref %}

### Privilege Escalation

{% content-ref url="privilege-escalation/" %}
[privilege-escalation](privilege-escalation/)
{% endcontent-ref %}

### Active Directory

{% content-ref url="active-directory/" %}
[active-directory](active-directory/)
{% endcontent-ref %}

### Persistence

{% content-ref url="persistence.md" %}
[persistence.md](persistence.md)
{% endcontent-ref %}

## Offensive Utility

### File Transfer

{% content-ref url="file-transfer.md" %}
[file-transfer.md](file-transfer.md)
{% endcontent-ref %}

### Lateral Movement

{% content-ref url="lateral-movement.md" %}
[lateral-movement.md](lateral-movement.md)
{% endcontent-ref %}

### Pivot/Proxy/Tunnel/Redirect

{% content-ref url="pivot-proxy-tunnel-redirect.md" %}
[pivot-proxy-tunnel-redirect.md](pivot-proxy-tunnel-redirect.md)
{% endcontent-ref %}

### Defense Evasion

{% content-ref url="defense-evasion.md" %}
[defense-evasion.md](defense-evasion.md)
{% endcontent-ref %}

### Password Attacks

{% content-ref url="password-attacks.md" %}
[password-attacks.md](password-attacks.md)
{% endcontent-ref %}

## Cloud

{% content-ref url="../../yellow-neteng-sysadmin/cloud.md" %}
[cloud.md](../../yellow-neteng-sysadmin/cloud.md)
{% endcontent-ref %}

## Containers

{% content-ref url="../../yellow-neteng-sysadmin/containers.md" %}
[containers.md](../../yellow-neteng-sysadmin/containers.md)
{% endcontent-ref %}

## Special Targets

{% content-ref url="special-targets.md" %}
[special-targets.md](special-targets.md)
{% endcontent-ref %}

