# Windows Hardening Commands

### Harden System from Lateral Movement and Privilege Escalation <a href="#harden-system-from-lateral-movementprivesc" id="harden-system-from-lateral-movementprivesc"></a>

**Note:** modifications may disrupt device communication. Test thoroughly before deploying to production. May also require a restart.

### **Disable remote interaction with services**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
```

### **Disable remote interaction with scheduled tasks**

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
```

### **Disable RDP access**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f 
```

### **Disable DCOM**

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Ole" /v EnableDCOM /t REG_SZ /d N /f
```

### **Disable Admin Shares**

Note: This disables the automatic creation of C$, ADMIN$, etc. `net share` commands can remove them immediately without a reboot, but they will return unless the registry key is set.

**Registry (Persistent):**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d 0 /f
```

**Runtime (Temporary/Immediate):**
```cmd
net share C$ /delete
net share IPC$ /delete
net share ADMIN$ /delete
```

### **Disable Printer Spooler Service (PrintNightmare RCE & LPE Mitigation)**

Note: [Flow chart](https://twitter.com/gentilkiwi/status/1412483747321192451) kindly provided by Benjamin Delpy

```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /t REG_DWORD /d 4 /f
```

### **Prevent SYSTEM from writing new print DLL (PrintNightmare RCE & LPE Mitigation)**

Special thanks to [truesec](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/)

```powershell
$Path = "C:\Windows\System32\spool\drivers"
$Acl = (Get-Item $Path).GetAccessControl('Access')
$Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
$Acl.AddAccessRule($Ar)
Set-Acl $Path $Acl
```

### **Disable Remote Printing (PrintNightmare RCE mitigation)**

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f
```

### **Enable Warning for Point and Print and UAC (PrintNightmare LPE mitigation)**

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```

### **Deny vulnerable Netlogon connections (Prevent ZeroLogon CVE-2020-1472)**

Note: This should be run on a DC or relevant policy applied. It requires the August 11, 2020 update. Full mitigation advice can be found [here](https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc)

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
```

It should be noted the following System events relate to this and should be reviewed:

* Event IDs 5827 and 5828 in the System event log, if ZeroLogon connections are denied.
* Event IDs 5830 and 5831 in the System event log, if ZeroLogon connections are allowed by “Domain controller: Allow vulnerable Netlogon secure channel connections” group policy.
* Event ID 5829 in the System event log, if ZeroLogon vulnerable Netlogon secure channel connection is allowed.

### **Stop Server Responsible for Inter-process Communication Calls**

```cmd
net stop server
```

**Disable Anonymous Access to Named Pipes**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t "REG_DWORD" /d 1 /f
```

Notes on named pipes:

* Named pipes are used for communication between processes, this includes a process from a remote system.
* A named pipe can be created by anyone.
* By enabling ‘RestrictNullSessAccess’ you stop anonymous network logons from accessing named pipes on your system.
* If a process has the ‘SeImpersonatePrivilege’ (or equivalent) privilege assigned and creates a named pipe, it may be able to impersonate the user context of anyone who connects to its named pipe if it then acts as the named pipe server.
  * The client of a named pipe, RPC, or DDE connection can control the impersonation level that the server of the named pipe can impersonate, ref: [Microsoft](https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
    * This doesn’t apply if the connection is remote, in that instance the permissions are set by the server.
* Any service running through the Service Control Manager (SCM), or Component Object Model (COM) specified to run under a certain account, automatically has impersonate privileges.
* When creating a child process using ‘CreateProcessWithToken’ the secondary logon service ‘seclogon’ needs to be running or else this will fail.

**Disable OLE objects in Office**

```powershell
Set-ItemProperty HKCU:\Software\Microsoft\Office\*\*\Security -Name PackagerPrompt -Type DWORD -Value 2
Set-ItemProperty Registry::HKEY_USERS\*\Software\Microsoft\Office\*\*\Security -Name PackagerPrompt -Type DWORD -Value 2
```

### **Disable LLMNR (Mitigates Responder/Poisoning)**

```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
```

### **Enable LSA Protection (RunAsPPL)**

Note: Prevents non-protected processes from interacting with LSASS (mitigates Mimikatz dumping).

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

### **Disable WDigest Authentication**

Note: Prevents LSASS from storing credentials in cleartext.

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
```

### **Limit Cached Logons**

Note: Sets the number of previous user credential hashes stored locally to 0. **Warning:** This effectively prevents login if the Domain Controller is unreachable.

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f
```

### **Disable PowerShell v2**

Note: Removes the legacy PowerShell version to prevent downgrade attacks.

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
```

### **Enable PowerShell Logging**

Note: Enables ScriptBlock logging and Transcription.

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\TRANSCRIPTION" /v EnableTranscripting /t REG_DWORD /d 1 /f
```

## Deprecated / Legacy Mitigations

These techniques were used as temporary workarounds for specific vulnerabilities (CVEs) before patches were available. They should generally be replaced by applying official security updates.

### **Rename mshtml.dll (CVE-2021-40444 Mitigation)**

Note: This will render any application which leverages mshtml.dll for rendering HTML content unable to do so (including mshta.exe - yay). At this stage the MSHTML (Trident) engine should not be leveraged by many applications and [Microsoft recommends future app development not use the MSHTML (Trident) engine](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/internet-explorer-11-desktop-app-retirement-faq/ba-p/2366549). Some examples of what do use it include .chm files and software mentioned [here](https://en.wikipedia.org/wiki/Trident\_\(layout\_engine\))

*   Run cmd.exe as Administrator.

```cmd
takeown /F mshtml.dll
icacls mshtml.dll /grant administrators:F
move mshtml.dll mshtml2.dll
cd ../SysWOW64
takeown /F mshtml.dll
icacls mshtml.dll /grant administrators:F
move mshtml.dll mshtml2.dll
```

## References

* **Windows**
  * _BTFM: Windows Hardening_ - pg. 22
  * _Operator Handbook: Windows\_Defend_ - pg. 334
  * Enforce Safe DLL Search Mode - _PTFM_ - pg. 28
  * Disable Run Once - _PTFM_ - pg. 28
  * Enable Windows Credential Guard - _PTFM_ - pg. 44
  * _Operator Handbook: Mimikatz\_Defend_ - pg. 206
  * _Cyber Operations: Defending the Windows Domain_ - pg. 567
* **Linux**
  * _BTFM: Linux Hardening_ - pg. 34
  * _Operator Handbook: Linux\_Defend_ - pg. 123
* **Misc Guides**
  * [Repository of Hardening guides](https://github.com/ernw/hardening)
  * _Operator Handbook: MacOS\_Defend_ - pg. 162
