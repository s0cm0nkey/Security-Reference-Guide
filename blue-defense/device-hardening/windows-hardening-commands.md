# Windows Hardening Commands

## Windows Commands

### Harden System from Lateral Movement/privesc <a href="#harden-system-from-lateral-movementprivesc" id="harden-system-from-lateral-movementprivesc"></a>

Note: These may inadvertently break communication of devices and should be tested. It may also require a restart.

### **Disable remote interaction with services**

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
```

### **Disable remote interaction with scheduled tasks**

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
```

### **Disable RDP access**

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f 
```

### **Disable DCOM**

```
reg add "HKLM\SOFTWARE\Microsoft\Ole" /v EnableDCOM /t REG_SZ /d N /f
```

### **Disable Admin Shares**

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d 0 /f
```

### **Disable Printer Spooler Service (PrintNightmare RCE & LPE Mitigation)**

Note: [Flow chart](https://twitter.com/gentilkiwi/status/1412483747321192451) kindly provided by Benjamin Delpy

```
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /t REG_DWORD /d 4 /f
```

### **Prevent SYSTEM from writing new print DLL (PrintNightmare RCE & LPE Mitigation)**

Special thanks to [truesec](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/)

```
$Path = "C:\Windows\System32\spool\drivers"
$Acl = (Get-Item $Path).GetAccessControl('Access')
$Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
$Acl.AddAccessRule($Ar)
Set-Acl $Path $Acl
```

### **Disable Remote Printing (PrintNightmare RCE mitigation)**

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f
```

### **Enable Warning on PointAndPrint and UAC (PrintNightmare LPE mitigation)**

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
```

### **Deny vulnerable Netlogon connections (Prevent ZeroLogon CVE-2020-1472)**

Note: This should be run on a DC or relevant policy applied. It requires the August 11, 2020 update. Full mitigation advice can be found [here](https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc)

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
```

It should be noted the following System events relate to this and should be reviewed:

* Event IDs 5827 and 5828 in the System event log, if ZeroLogon connections are denied.
* Event IDs 5830 and 5831 in the System event log, if ZeroLogon connections are allowed by “Domain controller: Allow vulnerable Netlogon secure channel connections” group policy.
* Event ID 5829 in the System event log, if ZeroLogon vulnerable Netlogon secure channel connection is allowed.

### **Rename mshtml.dll (CVE-2021-40444 Mitigation)**

Note: This will render any application which leverages mshtml.dll for rendering HTML content unable to do so (including mshta.exe - yay). At this stage the MSHTML (Trident) engine should not be leveraged by many applications and [Microsoft recommends future app development not use the MSHTML (Trident) engine](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/internet-explorer-11-desktop-app-retirement-faq/ba-p/2366549). Some examples of what do use it include .chm files and software mentioned [here](https://en.wikipedia.org/wiki/Trident\_\(layout\_engine\))

*   Run cmd.exe as Administrator.

    takeown /F mshtml.dll icacls mshtml.dll /grant administrators:F move mshtml.dll mshtml2.dll cd ../SysWOW64 takeown /F mshtml.dll icacls mshtml.dll /grant administrators:F move mshtml.dll mshtml2.dll

### **Stop Server Responsible for Inter-process Communication Calls**

```
net stop server
```

### **Delete Admin Shares**

Note: This may break some application communication and admin functionality. It may also be temporary as Windows has been known to recreate them. Always test.

* C$ = Default share on systems ‘C’ drive.
* IPC$ = Default Inter-process communication share (used by named pipes)
*   ADMIN$ = Default share for remote administration (used by PsExec)

    net share C$ /delete net share IPC$ /delete net share ADMIN$ /delete

**Disable Anonymous Access to Named Pipes**

```
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

**Disable OLE objects in**

```
Set-ItemProperty HKCU:\Software\Microsoft\Office\*\*\Security -Name PackagerPrompt -Type DWORD -Value 2
Set-ItemProperty REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security -Name PackagerPrompt -Type DWORD -Value 2
```

* Windows
  * _BTFM: Windows Hardening - pg. 22_
  * _Operator Handbook: Windows\_Defend - pg. 334_
  * Enforce Safe DLL Search Mode - _PTFM - pg. 28_
  * Disable Run Once - _PTFM - pg. 28_
  * Enable WIndows Credential Guard - _PTFM - pg.44_
  * _Operator Handbook: Mimikatz\_Defend - pg. 206_
  * _Cyber Operations: Defending the Windows Domain - pg. 567_
* Linux
  * _BTFM: Linux Hardening - pg. 34_
  * _Operator Handbook: Linux\_Defend - pg. 123_
* Misc Guides
  * Repository of Hardening guides - [https://github.com/ernw/hardening](https://github.com/ernw/hardening)__
  * _Operator Handbook: MacOS\_Defend - pg. 162_
