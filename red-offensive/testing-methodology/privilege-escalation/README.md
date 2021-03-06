---
description: Shellin's for show, Rootin's for dough
---

# Privilege Escalation

![](<../../../.gitbook/assets/image (2).png>)

## **PrivEsc General Guides**

* [HackTricks](https://book.hacktricks.xyz). If I had to take one link with me into a pentest, this would be it. Written by the creator of WinPEAS and LinPEAS, it is THE guide for PrivEsc, and one of the best for everything else.&#x20;
* [Vulnhub PrivEsc Cheatsheet](https://github.com/Ignitetechnologies/Privilege-Escalation) -&#x20;
* PrivEsc for MySQL [https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/](https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/)
* [https://toshellandback.com/2015/11/24/ms-priv-esc/](https://toshellandback.com/2015/11/24/ms-priv-esc/)
* [https://www.ired.team/offensive-security/code-execution](https://www.ired.team/offensive-security/code-execution)
* [https://www.ired.team/offensive-security/code-injection-process-injection](https://www.ired.team/offensive-security/code-injection-process-injection)
* [https://www.ired.team/offensive-security/privilege-escalation](https://www.ired.team/offensive-security/privilege-escalation)
* [Conda's Priv Esc Video Playlist](https://www.youtube.com/playlist?list=PLDrNMcTNhhYrBNZ\_FdtMq-gLFQeUZFzWV)
* Metasploit/Empire PrivEsc - _PTFM pg. 31_

{% hint style="info" %}
Dont forget to to try any harvested credentials!
{% endhint %}

{% content-ref url="../enumeration-and-harvesting/" %}
[enumeration-and-harvesting](../enumeration-and-harvesting/)
{% endcontent-ref %}

## **Windows**

### **Guides and Reference**

* [HackTricks: Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
* [PayloadsAllTheThings/Windows-PrivilegeEscalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [https://medium.com/bugbountywriteup/privilege-escalation-in-windows-380bee3a2842](https://medium.com/bugbountywriteup/privilege-escalation-in-windows-380bee3a2842)
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
* [https://rahmatnurfauzi.medium.com/windows-privilege-escalation-scripts-techniques-30fa37bd194](https://rahmatnurfauzi.medium.com/windows-privilege-escalation-scripts-techniques-30fa37bd194)
* [https://www.fuzzysecurity.com/tutorials/16.html](https://www.fuzzysecurity.com/tutorials/16.html)
* [https://www.greyhathacker.net/?p=738](https://www.greyhathacker.net/?p=738)
* [http://www.bhafsec.com/wiki/index.php/Windows\_Privilege\_Escalation](http://www.bhafsec.com/wiki/index.php/Windows\_Privilege\_Escalation)
* [https://www.sans.org/blog/kerberos-in-the-crosshairs-golden-tickets-silver-tickets-mitm-and-more/](https://www.sans.org/blog/kerberos-in-the-crosshairs-golden-tickets-silver-tickets-mitm-and-more/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/local\_privilege\_escalation/local\_privilege\_escalation/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/local\_privilege\_escalation/local\_privilege\_escalation/)



### **Windows PrivEsc Tools**

* [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) (The Go-To) - These tools search for possible local privilege escalation paths that you could exploit and print them to you with nice colors so you can recognize the misconfigurations easily.
* [SeatBelt](https://github.com/GhostPack/Seatbelt) - Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
* [Windows Exploit Suggester Next Gen ](https://github.com/bitsadmin/wesng)- WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities.
* [Sherlock](https://github.com/rasta-mouse/Sherlock) and [Watson](https://github.com/rasta-mouse/Watson) - look for missing patches and KBs         &#x20;
* [Accesschk.exe ](https://xor.cat/2017/09/05/sysinternals-accesschk-accepteula/)with the accept EULA flag - a [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) tool that is great for auditing privileges on your systems, and for auditing privileges on _others???_ systems. This version is a standalone utiltility with the older code that allows you to auto accept the EULA flag.
* [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) - From LOCAL/NETWORK SERVICE to SYSTEM by abusing `SeImpersonatePrivilege` on Windows 10 and Server 2016/2019.
* [Rattler](https://github.com/sensepost/rattler) - Rattler is a tool that automates the identification of DLL's which can be used for DLL preloading attacks.
* [SharpImpersonation](https://github.com/S3cur3Th1sSh1t/SharpImpersonation) - A User Impersonation tool - via Token or Shellcode injection
  * [https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/](https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/)

### Potato Exploits

* [Rotten Potato](https://github.com/breenmachine/RottenPotatoNG) - New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools. Leverages the privilege escalation chain based on [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges.
* [Juicy Potato](https://github.com/ohpe/juicy-potato) - Upgraded and Weaponized verison of RottenPotatoNG
* [Sweet Potato](https://github.com/CCob/SweetPotato) - A collection of various native Windows privilege escalation techniques from service accounts to SYSTEM
* [Rogue Potato](https://github.com/antonioCoco/RoguePotato) - Just another Windows Local Privilege Escalation from Service Account to System.&#x20;
  * [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
* [RemotePotato0](https://github.com/antonioCoco/RemotePotato0) - Just another "Won't Fix" Windows Privilege Escalation from User to Domain Admin.

### **Windows Methodology**

{% content-ref url="windows-methodology.md" %}
[windows-methodology.md](windows-methodology.md)
{% endcontent-ref %}

## **Linux**&#x20;

### **Guides and Reference**

* [HackTricks - Linux](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
* [https://in.security/lin-security-practise-your-linux-privilege-escalation-foo/](https://in.security/lin-security-practise-your-linux-privilege-escalation-foo/)
* [https://www.hackingarticles.in/linux-for-pentester-find-privilege-escalation/](https://www.hackingarticles.in/linux-for-pentester-find-privilege-escalation/)
* [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)
* [https://www.youtube.com/watch?v=dk2wsyFiosg](https://www.youtube.com/watch?v=dk2wsyFiosg)
* [https://resources.infosecinstitute.com/topic/privilege-escalation-linux-live-examples/#gref](https://resources.infosecinstitute.com/topic/privilege-escalation-linux-live-examples/#gref)
* [https://sushant747.gitbooks.io/total-oscp-guide/content/privilege\_escalation\_-\_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege\_escalation\_-\_linux.html)
* [https://xapax.github.io/security/#post\_exploitation/privilege\_escalation\_-\_linux/](https://xapax.github.io/security/#post\_exploitation/privilege\_escalation\_-\_linux/)

### **Linux PrivEsc Tools**

* [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) - These tools search for possible local privilege escalation paths that you could exploit and print them to you with nice colors so you can recognize the misconfigurations easily.
* [LinEnum](https://github.com/rebootuser/LinEnum) - Scripted Local Linux Enumeration & Privilege Escalation Checks
* [LSE](https://github.com/diego-treitos/linux-smart-enumeration) - Linux Smart enumeration, Linux enumeration tools for pentesting and CTFs
* [Unix Privesc Check](http://pentestmonkey.net/tools/audit/unix-privesc-check) - Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivilged users to escalate privileges to other users or to access local apps (e.g. databases).
* [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2) - Next-Generation Linux Kernel Exploit Suggester
* [SUDO Killer ](https://github.com/TH3xACE/SUDO\_KILLER)- Linux Privilege Escalation through SUDO abuse.

### **Linux Methodology**

{% content-ref url="linux-methodology.md" %}
[linux-methodology.md](linux-methodology.md)
{% endcontent-ref %}
