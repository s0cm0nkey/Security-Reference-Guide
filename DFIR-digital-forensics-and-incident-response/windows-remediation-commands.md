# Windows Remediation Commands



### Set logging on all success/failure events <a href="#set-logging-on-all-successfailure-events" id="set-logging-on-all-successfailure-events"></a>

(WARNING THIS WILL PRODUCE A LOT OF NOISE, TAILOR TO YOUR NEEDS)

```
auditpol /set /category:* /success:enable /failure:enable
```

### Enable logging of process creation <a href="#enable-logging-of-process-creation" id="enable-logging-of-process-creation"></a>

```
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

### Enable logging of non non-Windows module loads via WDAC code integrity <a href="#enable-logging-of-non-non-windows-module-loads-via-wdac-code-integrity" id="enable-logging-of-non-non-windows-module-loads-via-wdac-code-integrity"></a>

Note 1: Special thanks to [Matt Graeber](https://twitter.com/mattifestation/status/1366435525272481799) for this.

Note 2: This is based off of a [Windows Defender Application Control system integrity policy](https://gist.github.com/mgraeber-rc/7b9f4d497d75967afc58209df611508b) which has been converted on an enterprise system.

On an enterprise system enable it by creating a module load audit policy: https://twitter.com/mattifestation/status/1366435525272481799

```
ConvertFrom-CIPolicy Non_Microsoft_UserMode_Load_Audit.xml C:\Windows\System32\CodeIntegrity\SIPolicy.p7b
```

Store the converted policy on a Win10 system to be monitored at: Windows\System32\CodeIntegrity\SIPolicy.p7b

### Kill “Unstoppable” Service/Process <a href="#kill-unstoppable-serviceprocess" id="kill-unstoppable-serviceprocess"></a>

```
reg add HKLM\SYSTEM\CurrentControlSet\Services\{SERVICENAME}\XblAuthManager\Parameters /V start /T reg_dword /D 4 /f
sc.exe sdset {SERVICENAME} "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
Get-Service -Name {SERVICENAME} | Set-Service -Status Paused
sc.exe config {SERVICENAME} start= disabled
Get-Service -Name {SERVICENAME} | Set-Service -Status Stopped
tasklist /FI "IMAGENAME eq {SERVICEEXENAME}"
taskkill /F /t /IM "{SERVICEEXENAME}"
```

### Kill malicious process <a href="#kill-malicious-process" id="kill-malicious-process"></a>

```
wmic process where name="malware.exe" call terminate
wmic process where processid=[PID] delete
taskkill /IM malware.exe
taskkill /PID [PID] /T
```

Note: Call terminate allows you to specify an exit status in terms of a signed integer or a quoted negative value. Both methods essentially function the same by calling TerminateProcess.



**Locate Possible Shellcode within process via Injected Thread**

```
Import-Module .\Get-InjectedThread.ps1
Get-InjectedThread
```

**Obtain Possible Shellcode within process as Hex**

```
(Get-InjectedThread|Select -exp Bytes|ForEach-Object ToString X2) -join ''
(Get-InjectedThread|? {$_.ThreadId -match '{PID}'}|Select -exp Bytes|ForEach-Object ToString X2) -join ''
```

**Obtain Possible Shellcode within process as Hex**

```
(Get-InjectedThread|Select -exp Bytes|ForEach-Object ToString X2) -join '\x'
(Get-InjectedThread|? {$_.ThreadId -match '{PID}'}|Select -exp Bytes|ForEach-Object ToString X2) -join '\x'
```

### **Remove ACE entries for “everyone”**

```
icacls "C:\{DESIREDFOLDERPATH}" /remove everyone /T
```

#### Disable unwanted windows binaries (via Base64 encoding and removal) <a href="#disable-unwanted-windows-binaries-via-base64-encoding-and-removal" id="disable-unwanted-windows-binaries-via-base64-encoding-and-removal"></a>

Note: This is one method, not the only way.

```
certutil -encode C:\windows\system32\mshta.exe C:\windows\system32\mshta.disabled
Get-Acl -Path C:\windows\system32\mshta.exe | Set-Acl -Path C:\windows\system32\mshta.disabled
takeown /f C:\windows\system32\mshta.exe
icacls C:\windows\system32\mshta.exe /grant administrators:F
rm C:\windows\system32\mshta.exe
```

### Enable windows binaries (via Base64 decoding and removal) <a href="#enable-windows-binaries-via-base64-decoding-and-removal" id="enable-windows-binaries-via-base64-decoding-and-removal"></a>

```
certutil -decode C:\windows\system32\mshta.disabled C:\windows\system32\mshta.exe
Get-Acl -Path C:\windows\system32\mshta.disabled | Set-Acl -Path C:\windows\system32\mshta.exe
takeown /f C:\windows\system32\mshta.disabled
icacls C:\windows\system32\mshta.disabled /grant administrators:F
rm C:\windows\system32\mshta.disabled
```

### Make multiple files visible and remove ‘superhidden’ <a href="#make-multiple-files-visible-and-remove-superhidden" id="make-multiple-files-visible-and-remove-superhidden"></a>

```
gci C:\{DESIREDFOLDERPATH} -force -recurse -ea 0 | foreach {$_.attributes = 'Normal'};
attrib -s -h C:\{DESIREDFOLDERPATH}\*.*
```

### Enable Date Accessed Timestamps <a href="#enable-date-accessed-timestamps" id="enable-date-accessed-timestamps"></a>

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /d 0 /t REG_DWORD /f
```

### Remove BITSAdmin Persistence <a href="#remove-bitsadmin-persistence" id="remove-bitsadmin-persistence"></a>

```
bitsadmin /reset /allusers
import-module bitstransfer
Get-BitsTransfer -AllUsers | Remove-BitsTransfer
```

### Delete Windows Defender excluded files <a href="#delete-windows-defender-excluded-files" id="delete-windows-defender-excluded-files"></a>

```
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "[RegkeyValue]"
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' -Name "Paths"
```

### Open File Extension (e.g. scripts) with certain application (elevated cmd) <a href="#open-file-extension-eg-scripts-with-certain-application-elevated-cmd" id="open-file-extension-eg-scripts-with-certain-application-elevated-cmd"></a>

```
FTYPE Custom=Notepad.exe "%1"
ASSOC .wsf=Custom
```

### Disable Command Prompt <a href="#disable-command-prompt" id="disable-command-prompt"></a>

```
reg add "HKCU\SOFTWARE\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 0 /f
```

### Remediate malicious files <a href="#remediate-malicious-files" id="remediate-malicious-files"></a>

```
rmdir %localappdata%\maliciousdirectory\ /s
del /F %localappdata%\maliciousdirectory\malware.exe
```

Powershell:

```
Remove-Item [C:\Users\Public\*.exe]
Remove-Item -Path [C:\Users\Public\malware.exe] -Force
Get-ChildItem * -Include *.exe -Recurse | Remove-Item
```

### Remediate Persistent WMI Subscriptions <a href="#remediate-persistent-wmi-subscriptions" id="remediate-persistent-wmi-subscriptions"></a>

The most important aspect is to locate and remove the CommandLineEventConsumer. This has the malicious command stored within the value ‘CommandLineTemplate’. The below example searches for commands that contain ‘powershell’.

```
Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name like '%%[Name]%%'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "CommandLineTemplate like '%%powershell%%'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "__Path like '%%[Name]%%'" | Remove-WmiObject 
```

## Malicious scheduled tasks <a href="#remediate-malicious-scheduled-tasks" id="remediate-malicious-scheduled-tasks"></a>

```
schtasks /Delete /TN [taskname] /F
```

Powershell:

```
Unregister-ScheduledTask -TaskName [taskname]
Unregister-ScheduledTask -TaskPath [taskname]
```

## Registry Keys <a href="#unload-all-users-registry-keys" id="unload-all-users-registry-keys"></a>

### Unload all users registry keys <a href="#unload-all-users-registry-keys" id="unload-all-users-registry-keys"></a>

```
Foreach ($UserProfile in $UserProfiles) {reg unload HKU\$($UserProfile.SID)};
```

### Remediate Automatic Load/Run Reg Keys <a href="#remediate-automatic-loadrun-reg-keys" id="remediate-automatic-loadrun-reg-keys"></a>

```
reg delete [keyname] /v [ValueName] /f
reg delete [keyname] /f
Foreach ($UserProfile in $UserProfiles) {reg delete HKU\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /f}
Foreach ($UserProfile in $UserProfiles) {reg delete HKU\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f}
```

Powershell:

```
Remove-ItemProperty -Path "[Path]" -Name "[name]"
```

### Prevent Executable from Running. <a href="#prevent-executable-from-running" id="prevent-executable-from-running"></a>

Note: Load in hives and add particular SID to prevent users running named files, helps prevent for example your IIS service account from running cmd.exe or powershell.exe

```
reg add "HKU\{SID}\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisallowRun /t REG_DWORD /d "00000001" /f
reg add "HKU\{SID}\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v malware.exe /t REG_SZ /d "malware.exe" /f
```

