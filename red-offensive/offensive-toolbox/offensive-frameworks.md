# Offensive Frameworks

## **Metasploit**

The one offensive framework to rule them all. By far the most popular, Metasploit has become a staple for penetration testers everywhere. Metasploit contains 3 basic components you need to know.\
Metasploit modules are the exploit commands and code needed to exploit a specific vulnerability. There are tons of them and more are constantly added to the database when new exploit code is developed. For those looking to take the infamous OSCP exam, the exploit code itself can be used on the exam, but can only be used once through Metasploit itself for auto-exploitation.\
Merterpreter is the advanced shell that comes with Metasploit. It comes with a slew of added commands you would not be able to use in a traditional shell, including easy privilege escalation. This shell has become easier and easier to detect with AV and EDR solutions, so advanced encoding is usually required, but well worth the effort.\
MSVenom is a tool that can encode your payloads to bypass detection by your targets defenses. You will quickly get used to encoding everything you use. You can even chain encodings together

### Metasploit guides

* [https://www.offensive-security.com/metasploit-unleashed/](https://www.offensive-security.com/metasploit-unleashed/)
* [Metasploit | No Starch Press](https://nostarch.com/metasploit)&#x20;
* [https://tryhackme.com/room/metasploitintro](https://tryhackme.com/room/metasploitintro)
* [https://tryhackme.com/room/rpmetasploit](https://tryhackme.com/room/rpmetasploit)
* [https://www.tunnelsup.com/metasploit-cheat-sheet/](https://www.tunnelsup.com/metasploit-cheat-sheet/)
* __[Metasploit-Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Metasploit%20-%20Cheatsheet.md)
* [Metasploit for Pentester: Creds](https://www.hackingarticles.in/metasploit-for-pentester-creds/)
* [Metasploit for Pentester: Windows Hidden Bind Shell](https://www.hackingarticles.in/metasploit-for-pentester-windows-hidden-bind-shell/)
* [Metasploit for Pentester: Migrate](https://www.hackingarticles.in/metasploit-for-pentester-migrate/)
* [Metasploit for Pentester: Inject Payload into Executable](https://www.hackingarticles.in/metasploit-for-pentester-inject-payload-into-executable/)
* [Metasploit for Pentester: Clipboard](https://www.hackingarticles.in/metasploit-for-pentester-clipboard/)
* [Metasploit for Pentester: Database & Workspace](https://www.hackingarticles.in/metasploit-for-pentester-database-workspace/)
* [Metasploit for Pentester: Sessions](https://www.hackingarticles.in/metasploit-for-pentester-sessions/)
* _Penetration Testing: Using Metasploit Framework - pg.88_

### Metasploit  Modules

* &#x20;[Modules | Metasploit Documentation](https://docs.rapid7.com/metasploit/modules/)&#x20;
* [Metasploit Module Library](https://www.infosecmatter.com/metasploit-module-library/)
* [Metasploit Auxiliary Modules (Detailed Spreadsheet)](https://www.infosecmatter.com/metasploit-auxiliary-modules-detailed-spreadsheet/)
* [Post Exploitation Metasploit Modules (Reference)](https://www.infosecmatter.com/post-exploitation-metasploit-modules-reference/)
* [Honeybadger](https://github.com/trustedsec/HoneyBadger) modules&#x20;

### Metasploit Exploits and Attacks

* [List of Metasploit Windows Exploits (Detailed Spreadsheet) ](https://www.infosecmatter.com/list-of-metasploit-windows-exploits-detailed-spreadsheet/)
* [List of Metasploit Linux Exploits (Detailed Spreadsheet)](https://www.infosecmatter.com/list-of-metasploit-linux-exploits-detailed-spreadsheet/)
* [Client Side Attacks - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/client-side-attacks/)&#x20;
* [PSExec Pass the Hash - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)&#x20;

### [Armitage](https://tools.kali.org/exploitation-tools/armitage): The Metasploit GUI&#x20;

* [https://www.offensive-security.com/metasploit-unleashed/armitage/](https://www.offensive-security.com/metasploit-unleashed/armitage/)
* [Cortana-scripts](https://github.com/rsmudge/cortana-scripts) -  A collection of Cortana scripts that you may use with Armitage and Cobalt Strike 2.x. Cortana Scripts are not compatible with Cobalt Strike 3.x. Cobalt Strike 3.x uses a variant of Cortana called Aggressor Script.&#x20;

### Metasploit payloads

* Metasploit Payloads - [https://github.com/rapid7/metasploit-payloads](https://github.com/rapid7/metasploit-payloads)
* Creating Metasploit Payloads - [https://netsec.ws/?p=331](https://netsec.ws/?p=331)
* Converting a Metasploit module into a standalone binary - [https://netsec.ws/?p=262](https://netsec.ws/?p=262)

### [MSFVenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) - The Metasploit Payload Encoder

* msfvenom cheatsheet - [https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/](https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/)
* msfvenom payloads - [https://github.com/Shiva108/CTF-notes/blob/master/msfvenom.html](https://github.com/Shiva108/CTF-notes/blob/master/msfvenom.html)
* msfvenom basic guide - [https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
* Blackhills Infosec. msfvenom advanced payload guide - [https://www.blackhillsinfosec.com/advanced-msfvenom-payload-generation/](https://www.blackhillsinfosec.com/advanced-msfvenom-payload-generation/)
* msfvenom payload calculator - [https://github.com/g0tmi1k/msfpc](https://github.com/g0tmi1k/msfpc)

### Meterpreter

* [Meterpreter](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/) - The multi-function, super flexible, auto escalating shell by Metasploit
  * [Mettle](https://github.com/rapid7/mettle) **-** Meterpreter portable version! This is an implementation of a native-code Meterpreter, designed for portability, embedability, and low resource utilization. It can run on the smallest embedded Linux targets to big iron, and targets Android, iOS, macOS, Linux, and Windows, but can be ported to almost any POSIX-compliant environment.
* [https://xapax.github.io/security/#post\_exploitation/getting\_meterpreter\_shell/](https://xapax.github.io/security/#post\_exploitation/getting\_meterpreter\_shell/)
* [https://www.netscylla.com/blog/2018/09/26/MSF-Meterpreter-and-Railgun.html](https://www.netscylla.com/blog/2018/09/26/MSF-Meterpreter-and-Railgun.html)

{% content-ref url="../testing-methodology/post-exploitation/meterpreter-post-auth-runbook.md" %}
[meterpreter-post-auth-runbook.md](../testing-methodology/post-exploitation/meterpreter-post-auth-runbook.md)
{% endcontent-ref %}

{% embed url="https://youtu.be/xsyeL6xWWy4" %}

### Reference

* _RTFM:  Metasploit - pg. 56_
* _PTFM: Metasploit Commands - pg. 160_
* _PTFM:  Persistence with Metasploit/Empire - pg. 26_
* _PTFM: Host Enumeration with Metasploit/Empire - pg. 46_
* _PTFM: Metasploit/Emipre Pass-the-hash - pg. 52_
* _Operator Handbook: Metasploit - pg.198_
* _Operator Handbook: MSFVenom - pg.208_

## ****[**PowerShell Empire**](https://github.com/BC-SECURITY/Empire)****

Empire 3 is a post-exploitation framework that includes a pure-PowerShell Windows agent, and compatibility with Python 3.x Linux/OS X agents. It is the merger of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and flexible architecture.\
Empire was formerly an abandoned project that BC-Securty has revived. Please be aware when reading old posts or guides about Emipre that they may not be completely accurate to the new version of the project.

### Resources

* [https://www.powershellempire.com/](https://www.powershellempire.com/) - Legacy site
* [https://www.bc-security.org/post/overview-of-empire-4-0-and-c/](https://www.bc-security.org/post/overview-of-empire-4-0-and-c/)
* [DeathStar](https://github.com/byt3bl33d3r/DeathStar) - A Python script that uses [Empire's](https://github.com/BC-SECURITY/Empire) RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs.
* [Starkiller](https://github.com/BC-SECURITY/Starkiller) - Starkiller is a Frontend for [Powershell Empire](https://github.com/BC-SECURITY/Empire/). It is an Electron application written in VueJS.
* [https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993) - Tricks write up from one of the original authors of Emipre.
* [https://www.ired.team/offensive-security/red-team-infrastructure/powershell-empire-101](https://www.ired.team/offensive-security/red-team-infrastructure/powershell-empire-101)
* [https://www.hackingarticles.in/empire-for-pentester-active-directory-enumeration/](https://www.hackingarticles.in/empire-for-pentester-active-directory-enumeration/)
* [https://www.youtube.com/watch?v=zFlsxrGMScE](https://www.youtube.com/watch?v=zFlsxrGMScE)
* [https://tryhackme.com/room/rppsempire](https://tryhackme.com/room/rppsempire)
* _PTFM: Empire Commands - pg. 162_
* _PTFM:  Persistence with Metasploit/Empire - pg. 26_
* _PTFM: Host Enumeration with Metasploit/Empire - pg. 46_
* Can be incorporated in Empire:
  * [https://github.com/threatexpress/red-team-scripts](https://github.com/threatexpress/red-team-scripts)
* _PTFM: Metasploit/Emipre Pass-the-hash - pg. 52_
* _PTFM: C2 Obfuscation- pg. 64_
* _PTFM: Data Exfiltration via Web Services - pg. 68_
* _Advanced Penetration Testing - pg. 50_

{% embed url="https://youtu.be/52xkWbDMUUM" %}

## **All-in-one Penetration Testing Toolkits**

* [Sn1per](https://github.com/1N3/Sn1per) - Discover the attack surface and prioritize risks with our continuous Attack Surface Management (ASM) platform - Sn1per Professional. For more information, go to [https://xerosecurity.com](https://xerosecurity.com).
* [legion](https://github.com/carlospolop/legion) - Legion is a tool that uses several well-known opensource tools to automatically, semi-automatically or _manually_ enumerate the most frequent found services running in machines that you could need to pentest. Written by Carlos Pollop, the creator of [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), and [book.hacktricks](https://book.hacktricks.xyz/), everything this guy makes is gold. Highest of recommendations
* [celerystalk](https://github.com/sethsec/celerystalk) - celerystalk helps you automate your network scanning/enumeration process with asynchronous jobs (aka _tasks_) while retaining full control of which tools you want to run. Super handy for stringing together all your favorite tools
* [lscript](https://github.com/arismelachroinos/lscript) - Lazy Script: This is a script for Kali Linux that automates many procedures about wifi penetration and hacking.
* [KatanaFramework](https://github.com/PowerScript/KatanaFramework/) - Katana is a framework written in python for penetration testing, based on a simple and comprehensive structure for anyone to use, modify, and share.
* [Osmedeus](https://github.com/j3ssie/Osmedeus) - Osmedeus allows you automated run the collection of awesome tools to reconnaissance and vulnerability scanning against the target.
* [OWASP/Nettacker](https://github.com/OWASP/Nettacker) - OWASP Nettacker project is created to automate information gathering, vulnerability scanning and eventually generating a report for networks, including services, bugs, vulnerabilities, misconfigurations, and other information.
* [sifter](https://github.com/s1l3nt78/sifter/) - Sifter is a fully stocked Op Centre for Pentesters. It combines a pleothara of OSINT, recon and vulnerability analysis tools within categorized modsets in order to quickly perform recon tasks, check network firewalling, enumerate remote and local hosts, and scan for the 'blue' vulnerabilities within microsoft and if unpatched, exploit them.
* [jok3r](https://github.com/koutto/jok3r/) - Jok3r is a Python3 CLI application which is aimed at helping penetration testers for network infrastructure and web black-box security tests.
* [Xerror](https://github.com/Chudry/Xerror) - Xerror is an automated penetration tool , which will help security professionals and non professionals to automate their pentesting tasks.
* [WinPwn](https://github.com/S3cur3Th1sSh1t/WinPwn) - Powershell based recon and exploitation script with automatic proxy recognition and integration.
* [axiom](https://github.com/pry0cc/axiom) - The dynamic infrastructure framework for everybody! Distribute the workload of many different scanning tools with ease, including nmap, ffuf, masscan, nuclei, meg and many more!
