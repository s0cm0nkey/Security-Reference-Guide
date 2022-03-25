# Windows DFIR Check by MITRE Tactic

## T1015 Accessibility Features <a href="#t1015-accessibility-features" id="t1015-accessibility-features"></a>

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AtBroker.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v "Debugger"
sfc /VERIFYFILE=C:\Windows\System32\sethc.exe
sfc /VERIFYFILE=C:\Windows\System32\utilman.exe
sfc /VERIFYFILE=C:\Windows\System32\AtBroker.exe
sfc /VERIFYFILE=C:\Windows\System32\Narrator.exe
sfc /VERIFYFILE=C:\Windows\System32\Magnify.exe
sfc /VERIFYFILE=C:\Windows\System32\DisplaySwitch.exe
sfc /VERIFYFILE=C:\Windows\System32\osk.exe
```

## T1098 Account Manipulation <a href="#t1098-account-manipulation" id="t1098-account-manipulation"></a>

```
N/A
```

## T1182 AppCert DLLs <a href="#t1182-appcert-dlls" id="t1182-appcert-dlls"></a>

```
reg query "HKLM\System\CurrentControlSet\Control\Session Manager" /v AppCertDlls
```

## T1103 AppInit DLLs <a href="#t1103-appinit-dlls" id="t1103-appinit-dlls"></a>

```
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v Appinit_Dlls
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v Appinit_Dlls
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v Appinit_Dlls
reg query "HKU\{SID}\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v Appinit_Dlls
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='11'} | FL TimeCreated,Message
```

## T1138 Application Shimming <a href="#t1138-application-shimming" id="t1138-application-shimming"></a>

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"
dir %WINDIR%\AppPatch\custom
dir %WINDIR%\AppPatch\AppPatch64\Custom
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-ShimEngine/Operational';}|FL
```

Note: Some other similar methods exist such as abusing the ‘Command’ value of [Windows Telemetry Controller - Special Thanks to TrustedSec](https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/).

Hint: Look for a Command not pointing to “CompatTelRunner.exe” or which has ‘-cv’, ‘-oobe’, or ‘-fullsync’ in the command line.

```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /s
```

## T1197 BITS Jobs <a href="#t1197-bits-jobs" id="t1197-bits-jobs"></a>

```
bitsadmin /list /allusers /verbose
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Bits-Client/Operational'; Id='59'} | FL TimeCreated,Message
ls 'C:\ProgramData\Microsoft\Network\Downloader\qmgr.db'
```

## T1067 Bootkit <a href="#t1067-bootkit" id="t1067-bootkit"></a>

Note: This exists below the OS in the Master Boot Record or Volume Boot Record. The system must be booted through Advanced Startup Options with a Command Prompt, or through a recovery cd.

```
bootrec /FIXMBR
bootrec /FIXBOOT
```

Extra: If your boot configuration data is missing or contains errors the below can fix this.

```
bootrec /REBUILDBCD
```

If you’re thinking of a bootkit more as a rootkit (malicious system drivers) you can go with the below.

### **General Driver Enumeration**

```
gci C:\Windows\*\DriverStore\FileRepository\ -recurse -include *.inf | FL FullName,LastWriteTime,LastWriteTimeUtc
gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue
sc.exe query type=driver state=all
```

### **Unsigned Drivers**

```
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id='3001'} | FL TimeCreated,Message
gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | where {$_.status -ne 'Valid'}
```

### **Previous Unusual Loaded Filter Drivers (Often used by rootkits)**

Note: This will likely have false positives, particularly relating to filter drivers which are used by AV products, EDR solutions, or otherwise.

```
$FilterEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName="Microsoft-Windows-FilterManager"} | ForEach-Object {
	[PSCustomObject] @{
		TimeCreated = $_.TimeCreated
		MachineName = $_.MachineName
		UserId = $_.UserId
		FilterDriver = $_.Properties[4].Value
        Message = $_.Message
	}
}
echo "Scanning for suspicious filter drivers. Any found will be displayed below:"
$FilterEvents | where-object {$_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "WdFilter" -AND $_.FilterDriver -ine "storqosflt" -AND $_.FilterDriver -ine "wcifs" -AND $_.FilterDriver -ine "CldFlt" -AND $_.FilterDriver -ine "FileCrypt" -AND $_.FilterDriver -ine "luafv" -AND $_.FilterDriver -ine "npsvctrig" -AND $_.FilterDriver -ine "Wof" -AND $_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "bindflt" -AND $_.FilterDriver -ine "PROCMON24" -AND $_.FilterDriver -ine "FsDepends"}
```

### **Unusual Loaded Filter Drivers (No longer present or filtering registry keys)**

```
$FilterEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName="Microsoft-Windows-FilterManager"} | ForEach-Object {
	[PSCustomObject] @{
		TimeCreated = $_.TimeCreated
		MachineName = $_.MachineName
		UserId = $_.UserId
		FilterDriver = $_.Properties[4].Value
        Message = $_.Message
	}
}
echo "Scanning for suspicious filter drivers. Any found will be compared against existing services:"
$SuspectDrivers = $($FilterEvents | where-object {$_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "WdFilter" -AND $_.FilterDriver -ine "storqosflt" -AND $_.FilterDriver -ine "wcifs" -AND $_.FilterDriver -ine "CldFlt" -AND $_.FilterDriver -ine "FileCrypt" -AND $_.FilterDriver -ine "luafv" -AND $_.FilterDriver -ine "npsvctrig" -AND $_.FilterDriver -ine "Wof" -AND $_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "bindflt" -AND $_.FilterDriver -ine "PROCMON24" -AND $_.FilterDriver -ine "FsDepends"} | select -exp FilterDriver)
$SuspectDrivers
foreach ($driver in $SuspectDrivers){
echo "Checking services for relevant drivers. Any which aren't present may indicate a filter driver which has since been removed, or an active rootkit filtering service registry keys."
gci REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\$driver
}
```

### **Safe Boot registry keys**

Special Thanks - [Didier Stevens](https://blog.didierstevens.com/2007/02/19/restoring-safe-mode-with-a-reg-file/), [multiple times](https://blog.didierstevens.com/2006/06/22/save-safeboot/)

Note: These keys specify what services are run in Safe Mode. Sometimes they’ll be modified by malware to ensure rootkits can still function in Safe Mode.

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal /s
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network /s
```

### **Unload malicious filter driver**

```
fltmc filters
fltmc volumes
fltmc instances
fltmc unload <filtername>
fltmc detach <filtername> <volumeName> <instanceName>
```

Note: Common legitimate filter drivers include

* WdFilter – Windows Defender Filter
* storqosflt - Storage QoS Filter
* wcifs - Windows Container Isolation File System Filter
* CldFlt - Windows Cloud Files Filter
* FileCrypt - Windows Sandboxing and Encryption Filter
* luafv – LUA File Virtualization Filter (UAC)
* npsvctrig – Named Pipe Service Trigger Provider Filter
* Wof – Windows Overlay Filter
* FileInfo – FileInfo Filter (SuperFetch)
* bindflt - Windows Bind Filter system driver
* FsDepends - File System Dependency Minifilter
* PROCMON24 - Procmon Process Monitor Driver

## T1176 Browser Extensions <a href="#t1176-browser-extensions" id="t1176-browser-extensions"></a>

### **Chrome**

```
Get-ChildItem -path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -recurse -erroraction SilentlyContinue
Get-ChildItem -path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions' -recurse -erroraction SilentlyContinue -include manifest.json | cat
reg query "HKLM\Software\Google\Chrome\Extensions" /s
reg query "HKLM\Software\Wow6432Node\Google\Chrome\Extensions" /s
```

### **Firefox**

```
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions" -recurse -erroraction SilentlyContinue
Get-ChildItem -path "C:\Program Files\Mozilla Firefox\plugins\" -recurse -erroraction SilentlyContinue
Get-ChildItem -path registry::HKLM\SOFTWARE\Mozilla\*\extensions
```

### **Edge**

```
Get-ChildItem -Path C:\Users\*\AppData\Local\Packages\ -recurse -erroraction SilentlyContinue
```

### **Internet Explorer**

```
Get-ChildItem -path "C:\Program Files\Internet Explorer\Plugins\" -recurse -erroraction SilentlyContinue
reg query 'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
reg query 'HKLM\Software\Microsoft\Internet Explorer\Toolbar'
reg query 'HKLM\Software\Microsoft\Internet Explorer\URLSearchHooks'
reg query 'HKLM\Software\Microsoft\Internet Explorer\Explorer Bars'
reg query 'HKU\{SID}\Software\Microsoft\Internet Explorer\Explorer Bars'
reg query 'HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions'
```

## T1109 Component Firmware <a href="#t1109-component-firmware" id="t1109-component-firmware"></a>

Note: This is incredibly rare, and doesn’t have an easy detection/remediation mechanism. Using the Windows CheckDisk utility, System File Checker, or Deployment Image Servicing and Management may assist but isn’t guaranteed.

```
chkdsk /F
sfc /scannow
dism /Online /Cleanup-Image /ScanHealth
dism /Online /Cleanup-Image /RestoreHealth
dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```

## T1122 Component Object Model (COM) Hijacking <a href="#t1122-component-object-model-com-hijacking" id="t1122-component-object-model-com-hijacking"></a>

Note: This involves replacing legitimate components with malicious ones, and as such the legitimate components will likely no longer function. If you have a detection based on DLLHost.exe with /Processid:{xyz}, you can match xyz with the CLSID (COM Class Object) or AppID mentioned below to check for any malicious EXE or DLL.

```
HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{abc} /v AppID /t REG_SZ /d {xyz}
HKLM\SOFTWARE\Classes\CLSID\{abc} /v AppID /t REG_SZ /d {xyz}
HKLM\SOFTWARE\Classes\AppID\{xyz}
HKLM\SOFTWARE\Classes\WOW6432Node\AppID\{xyz}
HKLM\SOFTWARE\WOW6432Node\Classes\AppID\{xyz}
```

Example analysis:

```
reg query "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID" /s /f "{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}"
reg query "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{178167bc-4ee3-403e-8430-a6434162db17}" /s
reg query "HKLM\SOFTWARE\Classes\AppID\{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}"
```

Queries:

```
reg query HKLM\SOFTWARE\Classes\CLSID\ /s /f ".dll"
reg query HKLM\SOFTWARE\Classes\CLSID\ /s /f ".exe"
reg query HKLM\SOFTWARE\Classes\AppID\ /s /f DllSurrogate
gci -path REGISTRY::HKLM\SOFTWARE\Classes\*\shell\open\command 
reg query HKU\{SID}\SOFTWARE\Classes\CLSID\ /s /f ".dll"
reg query HKU\{SID}\SOFTWARE\Classes\CLSID\ /s /f ".exe"
gci 'REGISTRY::HKU\*\Software\Classes\CLSID\*\TreatAs'
gci 'REGISTRY::HKU\*\Software\Classes\Scripting.Dictionary'
gci "REGISTRY::HKU\*\SOFTWARE\Classes\CLSID\*\LocalServer32" -ea 0
gci "REGISTRY::HKU\*\SOFTWARE\Classes\CLSID\*\InprocServer32" -ea 0
gci "REGISTRY::HKU\*\SOFTWARE\Classes\CLSID\*\InprocHandler*" -ea 0
gci "REGISTRY::HKU\*\SOFTWARE\Classes\CLSID\*\*Server32" -ea 0
gci "REGISTRY::HKU\*\SOFTWARE\Classes\CLSID\*\ScriptletURL" -ea 0
reg query HKU\{SID}\SOFTWARE\Classes\CLSID\ /s /f "ScriptletURL"
```

### **Get list of all COM Objects**

[Original by Jeff Atwood](https://stackoverflow.com/questions/660319/where-can-i-find-all-of-the-com-objects-that-can-be-created-in-powershell)

```
gci HKLM:\Software\Classes -ea 0| ? {$_.PSChildName -match '^\w+\.\w+$' -and(gp "$($_.PSPath)\CLSID" -ea 0)} | select -ExpandProperty PSChildName
```

## T1136 Create Account <a href="#t1136-create-account" id="t1136-create-account"></a>

```
net user
net user /domain
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts" /s
```

## T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking <a href="#t1038-dll-search-order-hijacking" id="t1038-dll-search-order-hijacking"></a>

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
gci -path C:\Windows\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid"
gci -path C:\Windows\System32\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid"
gps | FL ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
gps | ? {$_.Modules -like '*{DLLNAME}*'} | FL ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
$dll = gps | Where {$_.Modules -like '*{DLLNAME}*' } | Select Modules;$dll.Modules;
(gps).Modules.FileName
(gps).Modules | FL FileName,FileVersionInfo
(gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid"
```

### Locate Possible [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038/) <a href="#locate-possible-dll-search-order-hijacking" id="locate-possible-dll-search-order-hijacking"></a>

Note: A legitimate clean executable can be used to run malicious DLLs based on how the software searches for them.

More information on [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode"
```

### **Search order for desktop applications:**

If SafeDllSearchMode is enabled (is by default), the search order is as follows:

* The same directory from which the executable is run.
* The System Directory (Usually C:\Windows\System32).
* The 16-bit System Directory.
* The Windows Directory (Usually C:\Windows).
* The Current Directory (From the process which executed the executable).
* The directories that are listed in the PATH environment variable.

If SafeDllSearchMode is disabled (SafeDllSearchMode has a reg value of 0), the search order is as follows:

* The same directory from which the executable is run.
* The Current Directory (From the process which executed the executable).
* The System Directory (Usually C:\Windows\System32).
* The 16-bit System Directory.
* The Windows Directory (Usually C:\Windows).
* The directories that are listed in the PATH environment variable.

## T1133 External Remote Services <a href="#t1133-external-remote-services" id="t1133-external-remote-services"></a>

```
N/A
```

## T1044 File System Permissions Weakness <a href="#t1044-file-system-permissions-weakness" id="t1044-file-system-permissions-weakness"></a>

```
Get-WmiObject win32_service | FL name,PathName
get-acl "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" | FL | findstr "FullControl"
```

## T1158 Hidden Files and Directories <a href="#t1158-hidden-files-and-directories" id="t1158-hidden-files-and-directories"></a>

```
dir /S /A:H
```

## T1179 Hooking <a href="#t1179-hooking" id="t1179-hooking"></a>

### **Finding EasyHook Injection**

```
tasklist /m EasyHook32.dll;tasklist /m EasyHook64.dll;tasklist /m EasyLoad32.dll;tasklist /m EasyLoad64.dll;
```

More Material:

* [GetHooks](https://github.com/jay/gethooks/releases/tag/1.01)

## T1062 Hypervisor <a href="#t1062-hypervisor" id="t1062-hypervisor"></a>

```
N/A
```

## T1183 Image File Execution Options Injection <a href="#t1183-image-file-execution-options-injection" id="t1183-image-file-execution-options-injection"></a>

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s /f "MonitorProcess"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /f "Debugger"
```

## T1037 Logon Scripts <a href="#t1037-logon-scripts" id="t1037-logon-scripts"></a>

```
reg query "HKU\{SID}\Environment" /v UserInitMprLogonScript
```

## T1177 LSASS Driver <a href="#t1177-lsass-driver" id="t1177-lsass-driver"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4614';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3033';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3063';} | FL TimeCreated,Message
```

## T1031 Modify Existing Service <a href="#t1031-modify-existing-service" id="t1031-modify-existing-service"></a>

```
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ImagePath"
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ServiceDLL"
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "FailureCommand"
Get-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\*\* -ea 0 | where {($_.ServiceDll -ne $null)} | foreach {filehash $_.ServiceDll}
Get-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\*\* -ea 0 | where {($_.ServiceDll -ne $null)} | select -uniq ServiceDll -ea 0 | foreach {filehash $_.ServiceDll} | select -uniq -exp hash
```

## T1128 Netsh Helper DLL <a href="#t1128-netsh-helper-dll" id="t1128-netsh-helper-dll"></a>

```
reg query HKLM\SOFTWARE\Microsoft\Netsh
```

## T1050 New Service <a href="#t1050-new-service" id="t1050-new-service"></a>

```
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ImagePath"
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ServiceDLL"
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "FailureCommand"
Get-WmiObject win32_service | FL Name, DisplayName, PathName, State
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | FL TimeCreated,Message
```

Note: If not examining the registry directly and looking at services in a ‘live’ capacity you may encounter ‘hidden services’ which aren’t shown due to a SDDL applied to them. You can find solely these services using the following ([Special thanks - Josh Wright](https://gist.github.com/joswr1ght/c5d9773a90a22478309e9e427073fd30))

```
Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}
```

Some common legitimate hidden services are:

```
WUDFRd
WUDFWpdFs
WUDFWpdMtp
```

## T1137 Office Application Startup <a href="#t1137-office-application-startup" id="t1137-office-application-startup"></a>

```
Get-ChildItem -path C:\Users\*\Microsoft\*\STARTUP\*.dotm -force
Get-ChildItem -path C:\Users\*\AppData\Roaming\Microsoft\*\STARTUP\* -force
reg query "HKU\{SID}\Software\Microsoft\Office test\Special\Perf" /s
reg query "HKLM\Software\Microsoft\Office test\Special\Perf" /s
Get-ChildItem -path registry::HKLM\SOFTWARE\Microsoft\Office\*\Addins\*
Get-ChildItem -path registry::HKLM\SOFTWARE\Wow6432node\Microsoft\Office\*\Addins\*
Get-ChildItem -path registry::HKLM\SOFTWARE\Wow6432node\Microsoft\Office\*\Addins\*
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Templates\*" -erroraction SilentlyContinue
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Excel\XLSTART\*" -erroraction SilentlyContinue
Get-ChildItem -path C:\ -recurse -include Startup -ea 0
ls 'C:\Program Files\Microsoft Office\root\*\XLSTART\*'
ls 'C:\Program Files\Microsoft Office\root\*\STARTUP\*'
reg query HKCU\Software\Microsoft\Office\<Outlook Version>\Outlook\WebView\Inbox
reg query HKCU\Software\Microsoft\Office\<Outlook Version>\Outlook\Security
reg query HKCU\Software\Microsoft\Office\<Outlook Version>\Outlook\Today\UserDefinedUrl
reg query HKCU\Software\Microsoft\Office\<Outlook Version>\Outlook\WebView\Calendar\URL
Get-WinEvent -FilterHashtable @{ LogName='Microsoft Office Alerts'; Id='300';} | FL TimeCreated,Message
```

## T1034 Path Interception <a href="#t1034-path-interception" id="t1034-path-interception"></a>

```
N/A
```

## T1013 Port Monitors <a href="#t1013-port-monitors" id="t1013-port-monitors"></a>

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors" /s /v "Driver"
```

## T1504 PowerShell Profile <a href="#t1504-powershell-profile" id="t1504-powershell-profile"></a>

```
ls C:\Windows\System32\WindowsPowerShell\v1.0\Profile.ps1
ls C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.*Profile.ps1
ls C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.*Profile.ps1
gci -path "C:\Users\*\Documents\PowerShell\Profile.ps1"
gci -path "C:\Users\*\Documents\PowerShell\Microsoft.*Profile.ps1"
```

## T1108 Redundant Access <a href="#t1108-redundant-access" id="t1108-redundant-access"></a>

```
N/A
```

## T1060 Registry Run Keys / Startup Folder <a href="#t1060-registry-run-keys--startup-folder" id="t1060-registry-run-keys--startup-folder"></a>

```
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Windows"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute
gci -path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" -include *.lnk,*.url
gci -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -include *.lnk,*.url
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Shell-Core/Operational'; Id='9707'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Shell-Core/Operational'; Id='9708'} | FL TimeCreated,Message
```

## T1053 Scheduled Task <a href="#t1053-scheduled-task" id="t1053-scheduled-task"></a>

```
gci -path C:\windows\system32\tasks | Select-String Command | FT Line, Filename
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | Select-String Command | FL Filename,Line
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | where {$_.CreationTime.hour -ge (get-date).hour-2}| Select-String Command | FL Line,Filename
gci -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\'
gci -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\'
ls 'C:\Windows\System32\WptsExtensions.dll'
```

Note: thanks to [Markus Piéton](https://twitter.com/markus\_pieton/status/1189559716453801991) for the WptsExtensions.dll one.

## T1180 Screensaver <a href="#t1180-screensaver" id="t1180-screensaver"></a>

```
reg query "HKU\{SID}\Control Panel\Desktop" /s /v "ScreenSaveActive"
reg query "HKU\{SID}\Control Panel\Desktop" /s /v "SCRNSAVE.exe"
reg query "HKU\{SID}\Control Panel\Desktop" /s /v "ScreenSaverIsSecure"
```

## T1101 Security Support Provider <a href="#t1101-security-support-provider" id="t1101-security-support-provider"></a>

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages"
```

## T1505 Server Software Component <a href="#t1505-server-software-component" id="t1505-server-software-component"></a>

```
N/A
```

## T1058 Service Registry Permissions Weakness <a href="#t1058-service-registry-permissions-weakness" id="t1058-service-registry-permissions-weakness"></a>

```
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\* |FL
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\servicename |FL
```

## T1023 Shortcut Modification <a href="#t1023-shortcut-modification" id="t1023-shortcut-modification"></a>

```
Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "exe"
Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "dll"
Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "dll"
Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "exe"
gci -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "exe" | FL
gci -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "dll" | FL
```

## T1198 SIP and Trust Provider Hijacking <a href="#t1198-sip-and-trust-provider-hijacking" id="t1198-sip-and-trust-provider-hijacking"></a>

```
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg" /s /v "Dll"
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData" /s /v "Dll"
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy" /s /v "`$DLL"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg" /s /v "Dll"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData" /s /v "Dll"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy" /s /v "`$DLL"
```

## T1019 System Firmware <a href="#t1019-system-firmware" id="t1019-system-firmware"></a>

```
reg query HKLM\HARDWARE\DESCRIPTION\System\BIOS
Confirm-SecureBootUEFI
Get-WmiObject win32_bios
```

## T1209 Time Providers <a href="#t1209-time-providers" id="t1209-time-providers"></a>

```
reg query "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders" /s /f "Dll"
```

## T1078 Valid Accounts <a href="#t1078-valid-accounts" id="t1078-valid-accounts"></a>

```
net users
net group /domain "Domain Admins"
net users /domain <name>
```

## T1100 Web Shell <a href="#t1100-web-shell" id="t1100-web-shell"></a>

Note: The presence of files with these values isn’t necessarily indicative of a webshell, review output.

```
gci -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "runat" | FL
gci -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "eval" | FL
```

[ProxyShell](https://www.thezdi.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell) - May reveal evidence of mailbox exfil or Web Shell being dropped:

```
Get-WinEvent -FilterHashtable @{LogName='MSExchange Management';} | ? {$_.Message -match 'MailboxExportRequest'} | FL TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='MSExchange Management';} | ? {$_.Message -match 'aspx'} | FL TimeCreated, Message
```

## T1084 Windows Management Instrumentation Event Subscription <a href="#t1084-windows-management-instrumentation-event-subscription" id="t1084-windows-management-instrumentation-event-subscription"></a>

### **Get WMI Namespaces**

```
Function Get-WmiNamespace ($Path = 'root')
{
	foreach ($Namespace in (Get-WmiObject -Namespace $Path -Class __Namespace))
	{
		$FullPath = $Path + "/" + $Namespace.Name
		Write-Output $FullPath
		Get-WmiNamespace -Path $FullPath
	}
}
Get-WMINamespace -Recurse
```

### **Query WMI Persistence**

```
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription
Get-WmiObject -Class __EventFilter -Namespace root\subscription
Get-WmiObject -Class __EventConsumer -Namespace root\subscription
```

## T1004 Winlogon Helper DLL <a href="#t1004-winlogon-helper-dll" id="t1004-winlogon-helper-dll"></a>

```
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" /s
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" /s
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
reg query "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /s
```

## T1574.002 Hijack Execution Flow: DLL Side-Loading

### Locate Possible [Dll Side Loading](https://attack.mitre.org/techniques/T1073/) <a href="#locate-possible-dll-side-loading" id="locate-possible-dll-side-loading"></a>

Note: A legitimate clean executable can be used to run malicious DLLs based on issues with a manifest file used by the application to load DLLs.

```
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners"
```

By placing a malicious DLL in the below locations legitimate binaries may have been used to sideload these malicious DLLs.

* C:\Windows\WinSxS
* C:\Windows\SXS

### **Unique Sideload DLL hashes (may take some time)**

```
(gci -path C:\Windows\WinSxS -recurse -include *.dll|gi -ea SilentlyContinue|filehash).hash|sort -u
```

### **Unsigned or Invalid Sideload DLLs (there will be a lot)**

```
gci -path C:\Windows\WinSxS -recurse -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid"
```

### **Unsigned Sideload DLLs (Less noise)**

```
gci -path C:\Windows\WinSxS -recurse -include *.dll | Get-AuthenticodeSignature | Where-Object Status -E "NotSigned"
gci -path C:\Windows\WinSxS -recurse -include *.ocx | Get-AuthenticodeSignature | Where-Object Status -NE "Valid"
```

### **Hash of Unsigned Sideload DLLs**

```
gci -path C:\Windows\WinSxS -recurse -include *.dll | Get-AuthenticodeSignature | Where-Object Status -E "NotSigned" | Select Path | gi -ea SilentlyContinue | filehash | sort -u
gci -path C:\Windows\WinSxS -recurse -include *.ocx | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | Select Path | gi -ea SilentlyContinue | filehash | sort -u
```

