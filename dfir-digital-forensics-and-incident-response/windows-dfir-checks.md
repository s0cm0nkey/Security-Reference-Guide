# Windows DFIR Checks

## Malware Activity <a href="#check-disabled-task-manager-often-from-malware" id="check-disabled-task-manager-often-from-malware"></a>

### Check disabled task manager (often from malware) <a href="#check-disabled-task-manager-often-from-malware" id="check-disabled-task-manager-often-from-malware"></a>

```
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr
```

### Mimikatz/Credential Extraction Detection <a href="#mimikatzcredential-extraction-detection" id="mimikatzcredential-extraction-detection"></a>

The below represent registry keys which make it more difficult for Mimikatz to work. Modification of these keys may indicate an attacker trying to execute Mimikatz within an environment if they were set to their more secure state. Always test prior to changing registry keys such as these in a production environment to ensure nothing breaks.

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
	- “UseLogonCredential” should be 0 to prevent the password in LSASS/WDigest
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
	- “RunAsPPL” should be set to dword:00000001 to enable LSA Protection which prevents non-protected processes from interacting with LSASS. 
	- Mimikatz can remove these flags using a custom driver called mimidriver.
		- This uses the command **!+** and then **!processprotect /remove /process:lsass.exe** by default so tampering of this registry key can be indicative of Mimikatz activity.
```

The [Mimikatz Yara rule](https://github.com/gentilkiwi/mimikatz/blob/master/kiwi\_passwords.yar) may also prove useful.

Some techniques may involve loading lsasrv.dll or wdigest.dll to extract credentials and may be caught if this is loaded legitimately using:

```
tasklist /m wdigest.dll
tasklist /m lsasrv.dll
```

You may be able to detect changes to the below registry keys which can be used to load an arbitrary DLL and extract credentials, more information from [Adam Chester](https://blog.xpnsec.com/exploring-mimikatz-part-1/)

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS /v LsaDbExtPt
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt
```

An adversary may also tamper with the number of cached logons a system holds (default of 10).

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount
```

### NetNTLM Downgrade Attack Detection <a href="#netntlm-downgrade-attack-detection" id="netntlm-downgrade-attack-detection"></a>

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LMCompatibilityLevel
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictSendingNTLMTraffic 
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NTLMMinClientSec
```

[DanderSpritz eventlogedit](https://github.com/fox-it/danderspritz-evtx)

### Putty Detection <a href="#putty-detection" id="putty-detection"></a>

```
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
```

### Locate Possible Trickbot <a href="#locate-possible-trickbot" id="locate-possible-trickbot"></a>

```
gci -path C:\Users\*\AppData\Roaming\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Roaming\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Roaming\*\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Roaming\*\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Windows\System32\config\systemprofile\appdata\roaming -recurse -force -include *.exe
schtasks /query /fo LIST /v | findstr "appdata"	
schtasks /query /fo LIST /v | findstr "programdata"	
schtasks /query /fo LIST /v | findstr "public"	
tasklist /svc | findstr "svchost"
```

### Check running executables for malware via VirusTotal <a href="#check-running-executables-for-malware-via-virustotal" id="check-running-executables-for-malware-via-virustotal"></a>

**Note: VT Has a rate limit for the Public API so this won’t work if you are using the Public API. All 1 liners require VTAPIKey to be set as your VirusTotal API key**

```
foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{ resource =(Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash); apikey = "[VTAPIKey]"}}
```

**This query uses a 15 second timeout to ensure only 4 queries are submitted a minute**

```
foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{ resource =(Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash); apikey = "[VTAPIKey]"};Start-Sleep -Seconds 15;}
```

**This query uses a 15 second timeout to ensure only 4 queries are submitted a minute and only unique hashes are queried**

```
$A = $( foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}) |Sort-Object| Get-Unique -AsString; foreach ($process in $A) {Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{ resource =($process); apikey = "[VTAPIKey]"};Start-Sleep -Seconds 15;} 
```

## Registry Indicators

### Check Registry for IE Enhanced Security Modification <a href="#check-registry-for-ie-enhanced-security-modification" id="check-registry-for-ie-enhanced-security-modification"></a>

```
gci 'REGISTRY::HKU\*\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
gci 'REGISTRY::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
```

### Check Registry for disabling of UAC (1=UAC Disabled) <a href="#check-registry-for-disabling-of-uac-1uac-disabled" id="check-registry-for-disabling-of-uac-1uac-disabled"></a>

```
gci REGISTRY::HKU\*\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA 
gci REGISTRY::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA 
```

### Review Software Keys for malicious entries <a href="#review-software-keys-for-malicious-entries" id="review-software-keys-for-malicious-entries"></a>

```
gci registry::HKLM\Software\*
gci registry::HKU\*\Software\*
```

### Scan Registry keys for specified text <a href="#scan-registry-keys-for-specified-text" id="scan-registry-keys-for-specified-text"></a>

```
Get-ChildItem -path HKLM:\ -Recurse -ea SilentlyContinue | where {$_.Name -match 'notepad' -or $_.Name -match 'sql'}
Get-ChildItem -path HKLM:\ -Recurse -ea SilentlyContinue | get-itemproperty | where {$_ -match 'notepad' -or $_ -match 'sql'}
reg query HKLM\SOFTWARE /s /f ".exe"
reg query HKLM\SYSTEM /s /f ".exe"
reg query HKLM\SECURITY /s /f ".exe"
reg query HKLM /s /f ".exe"
```

## Suspicious Files <a href="#check-registry-for-ie-enhanced-security-modification" id="check-registry-for-ie-enhanced-security-modification"></a>

### Find files without extensions <a href="#find-files-without-extensions" id="find-files-without-extensions"></a>

```
Get-ChildItem -Path C:\Users\[user]\AppData -Recurse -Exclude *.* -File -Force -ea SilentlyContinue
```

### Persistent file locations of interest <a href="#persistent-file-locations-of-interest" id="persistent-file-locations-of-interest"></a>

```
%localappdata%\<random>\<random>.<4-9 file ext>
%localappdata%\<random>\<random>.lnk
%localappdata%\<random>\<random>.bat
%appdata%\<random>\<random>.<4-9 file ext>
%appdata%\<random>\<random>.lnk
%appdata%\<random>\<random>.bat
%appdata%\<random>\<random>.bat
%SystemRoot%\<random 4 chars starting with digit>
%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*
"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*"
%SystemRoot%\System32\<randomnumber>\
%SystemRoot%\System32\tasks\<randomname>
%SystemRoot%\\<randomname>
C:\Users\[user]\appdata\roaming\[random]
C:\Users\[user]\appdata\roaming\[random]
C:\Users\Public\*
```

You can scan these directories for items of interest e.g. unusual exe, dll, bat, lnk etc files with:

```
dir /s /b %localappdata%\*.exe | findstr /e .exe
dir /s /b %appdata%\*.exe | findstr /e .exe
dir /s /b %localappdata%\*.dll | findstr /e .dll
dir /s /b %appdata%\*.dll | findstr /e .dll
dir /s /b %localappdata%\*.bat | findstr /e .bat
dir /s /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\" | findstr /e .lnk
dir /s /b "C:\Users\Public\" | findstr /e .exe
dir /s /b "C:\Users\Public\" | findstr /e .lnk
dir /s /b "C:\Users\Public\" | findstr /e .dll
dir /s /b "C:\Users\Public\" | findstr /e .bat
ls "C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | findstr /e .lnk
```

### Locate LNK Files with a particular string (Special thanks to the notorious) <a href="#locate-lnk-files-with-a-particular-string-special-thanks-to-the-notorious" id="locate-lnk-files-with-a-particular-string-special-thanks-to-the-notorious"></a>

```
Select-String -Path 'C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk' -Pattern "powershell" | Select Path
```

#### Master File Table <a href="#master-file-table" id="master-file-table"></a>

The Master File Table is an incredibly important artifact; however, this can only be read or obtained using low level disk reading. This contains an entry for every file or directory on the filesystem including metadata about these files, and may provide evidence on files which have been removed (MFT entries marked as ‘free’). More information can be found on [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)

### Determine Timestomping <a href="#determine-timestomping" id="determine-timestomping"></a>

Within the Master File Table (Located at the Win root) there are 2 elements, $STANDARD\_INFORMATION and $FILE\_NAME, both of which have values for a file being created, modified, accessed and written.

These are known as MACB times (Modified, Accessed, Changed, Birth). The $STANDARD\_INFORMATION element can be modified from a malicious process, but the $FILE\_NAME element is left intact and cannot without some extra trickery.

These discrepancies generally indicate Timestomping with the $FILE\_NAME entry being the source of truth. This can be determined by obtaining the MFT (e.g. using a tool such as Rawcopy), and comparing timestamps on the file (e.g. using a tool such as MFTExplorer).

[Rawcopy](https://github.com/jschicht/RawCopy)

```
RawCopy.exe /FileNamePath:C:0 /OutputPath:C:\Audit /OutputName:MFT_C.bin
```

[MFTExplorer](https://ericzimmerman.github.io/#!index.md)

### Check system directories for executables not signed as part of an operating system release <a href="#check-system-directories-for-executables-not-signed-as-part-of-an-operating-system-release" id="check-system-directories-for-executables-not-signed-as-part-of-an-operating-system-release"></a>

```
gci C:\windows\*\*.exe -File -force |get-authenticodesignature|?{$_.IsOSBinary -notmatch 'True'}
```

Note: Don’t forget tice Utilities load in user hives.

```
reg query 'HKU\[SID]\Software\Microsoft\Office\[versionnumber]\Word\Security\Trusted Documents\TrustRecords';
gci 'REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords' -ea 0 | foreach {reg query $_.Name}
```

Note: This will show the file name/location and metadata in Hex. If the last lot of hex is FFFFFF7F then the user enabled the macro.



Note: Don’t forget to load in user hives.

```
reg query 'HKU\[SID]\Software\Microsoft\Office\[versionnumber]\Word\Security\Trusted Documents\TrustRecords';
gci 'REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords' -ea 0 | foreach {reg query $_.Name}
```

Note: This will show the file name/location and metadata in Hex. If the last lot of hex is FFFFFF7F then the user enabled the macro.



### Check all Appdata files for unsigned or invalid executables <a href="#check-all-appdata-files-for-unsigned-or-invalid-executables" id="check-all-appdata-files-for-unsigned-or-invalid-executables"></a>

```
Get-ChildItem -Recurse $env:APPDATA\..\*.exe -ea SilentlyContinue| ForEach-object {Get-AuthenticodeSignature $_ -ea SilentlyContinue} | Where-Object {$_.status -ine "Valid"}|Select Status,Path
```

### Check for execuables in Local System User Profile and Files <a href="#check-for-execuables-in-local-system-user-profile-and-files" id="check-for-execuables-in-local-system-user-profile-and-files"></a>

```
Get-ChildItem C:\Windows\*\config\systemprofile -recurse -force -ea 0 -include *.exe, *.dll *.lnk
```

### Find executables and scripts in Path directories ($env:Path) <a href="#find-executables-and-scripts-in-path-directories-envpath" id="find-executables-and-scripts-in-path-directories-envpath"></a>

```
Get-Command * -Type Application | FT -AutoSize
Get-Command -Name * | FL FileVersionInfo
```

### Find files created/written based on date <a href="#find-files-createdwritten-based-on-date" id="find-files-createdwritten-based-on-date"></a>

```
Get-ChildItem C:\ -recurse -ea SilentlyContinue -force | where-object { $_.CreationTime.Date -match "12/25/2014"}
Get-ChildItem C:\ -recurse -ea SilentlyContinue -force | where-object { $_.LastWriteTime -match "12/25/2014"}
Get-ChildItem C:\ -recurse -ea SilentlyContinue -force | where-object { $_.CreationTime.Hour -gt 2 -and $_.CreationTime.Hour -lt 15}
```

### Programs specifically set to run as admin <a href="#programs-specifically-set-to-run-as-admin" id="programs-specifically-set-to-run-as-admin"></a>

```
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /s /f RUNASADMIN
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /s /f RUNASADMIN
```

**Windows Indexing Service**

```
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\windows.edb
```

* [ESE Database View](https://www.nirsoft.net/utils/ese\_database\_view.html)
* [View ESE Database](http://www.edgemanage.emmet-gray.com/Articles/ViewESE.html)
*

## DNS Logs

### Scan DNS Logs <a href="#scan-dns-logs" id="scan-dns-logs"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Id='3010';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Id='3020';} | FL TimeCreated,Message
```

### Scan DNS Logs and output unique DNS Queries <a href="#scan-dns-logs-and-output-unique-dns-queries" id="scan-dns-logs-and-output-unique-dns-queries"></a>

```
$events=Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Id='3020';};
$output = @();
foreach ($Event in $events){
$data = New-Object -TypeName PSObject;
$XML = [xml]$Event.ToXml();
$query=$XML.Event.EventData.Data|?{$_.Name -eq 'QueryName'} | Select -exp InnerText;
$result=$XML.Event.EventData.Data|?{$_.Name -eq 'QueryResults'} | Select -exp InnerText;
$data `
| Add-Member NoteProperty Query "$query" -PassThru `
| Add-Member NoteProperty QueryResults "$result" -PassThru | Out-Null
$output += $data;
}
$output = $output | sort Query | unique -AsString;
$output
```

## WMI

### Detect Persistent WMI Subscriptions <a href="#detect-persistent-wmi-subscriptions" id="detect-persistent-wmi-subscriptions"></a>

These will appear as children spawning from wmiprvse.

```
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription
Get-WmiObject -Class __EventFilter -Namespace root\subscription
Get-WmiObject -Class __EventConsumer -Namespace root\subscription
```

### Investigate WMI Usage <a href="#investigate-wmi-usage" id="investigate-wmi-usage"></a>

Note: Requires [Strings](https://docs.microsoft.com/en-us/sysinternals/downloads/strings)

```
strings -q C:\windows\system32\wbem\repository\objects.data
```

## WIndows Defender <a href="#delete-windows-defender-excluded-files" id="delete-windows-defender-excluded-files"></a>

### Check Windows Defender Block/Quarantine Logs <a href="#delete-windows-defender-excluded-files" id="delete-windows-defender-excluded-files"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Data='Severe'} | FL TimeCreated,Messag
```

## ACLs and ACE <a href="#check-and-set-access-control-lists" id="check-and-set-access-control-lists"></a>

### Check and Set Access Control Lists <a href="#check-and-set-access-control-lists" id="check-and-set-access-control-lists"></a>

```
Get-Acl -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'|FL
Get-Acl -Path [FileWithRequiredAccess] | Set-Acl -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
```

#### Change ACE for “everyone” on folder and subfiles/folders <a href="#change-ace-for-everyone-on-folder-and-subfilesfolders" id="change-ace-for-everyone-on-folder-and-subfilesfolders"></a>

**Grant everyone full access**

```
icacls "C:\{DESIREDFOLDERPATH}" /grant everyone:(CI)(OI)F /T
```

### Check Security Descriptor Definition Language (SDDL) and Access Control Entries (ACE) for services <a href="#check-security-descriptor-definition-language-sddl-and-access-control-entries-ace-for-services" id="check-security-descriptor-definition-language-sddl-and-access-control-entries-ace-for-services"></a>

```
sc sdshow <servicename>
$A=get-service;foreach ($service in $A){$service;sc.exe sdshow $service.Name}
$A=get-service;foreach ($service in $A){$service;sc.exe sdshow $service.Name|Select-String "A;*DC"}
$A=get-service;foreach ($service in $A){$service;sc.exe sdshow $service.Name|Select-String "A;*WD"}
$A=get-service;foreach ($service in $A){$service;sc.exe sdshow $service.Name|Select-String "A;*WO"}
```

## Logging Checks

### Check audit policies <a href="#check-audit-policies" id="check-audit-policies"></a>

```
auditpol /get /category:*
```

### Check for Windows Security Logging Bypass <a href="#check-for-windows-security-logging-bypass" id="check-for-windows-security-logging-bypass"></a>

Special thanks to [Grzegorz Tworek - 0gtweet](https://twitter.com/0gtweet/status/1182516740955226112)

```
reg query HKLM\System\CurrentControlSet\Control\MiniNt
```

## Vulnerability Checks

### Verify EternalBlue Patch (MS17-010) is installed - [Microsoft](https://support.microsoft.com/en-us/help/4023262/how-to-verify-that-ms17-010-is-installed) <a href="#verify-eternalblue-patch-ms17-010-is-installed---microsoft" id="verify-eternalblue-patch-ms17-010-is-installed---microsoft"></a>

Note: This impacts the SMB 1.0 Server Driver, if you don’t have the below, then it’s not installed. If you do you can use the above to determine patch level.

```
get-item C:\Windows\system32\drivers\srv.sys | FL VersionInfo
get-hotfix -id KB<111111>
```

More information on [ACE Strings](https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings) and the level of access they can provide.

## Lateral Movement Checks

### Map Network Shares Lateral Movement Detection (Destinations) <a href="#map-network-shares-lateral-movement-detection-destinations" id="map-network-shares-lateral-movement-detection-destinations"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4776';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4768';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4769';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\C$'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5145';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | FL TimeCreated,Message
```

### PsExec Lateral Movement Detection (Destinations) <a href="#psexec-lateral-movement-detection-destinations" id="psexec-lateral-movement-detection-destinations"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='2'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\ADMIN$'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'; Data='PSEXESVC'} | FL TimeCreated,Message
reg query HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC
reg query HKLM\SYSTEM\CurrentControlSet\Services\
ls C:\Windows\Prefetch\psexesvc.exe*.pf
```

### Scheduled Tasks Lateral Movement Detection (Destinations) <a href="#scheduled-tasks-lateral-movement-detection-destinations" id="scheduled-tasks-lateral-movement-detection-destinations"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4698';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4702';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4699';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4700';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4701';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='106';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='140';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='141';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='200';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='201';} | FL TimeCreated,Message
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" /s /v Actions
Get-ChildItem -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\' | Get-ItemProperty | FL Path, Actions
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
gci -path C:\Windows\System32\Tasks\ -recurse -File
```

### Services Lateral Movement Detection (Destinations) <a href="#services-lateral-movement-detection-destinations" id="services-lateral-movement-detection-destinations"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4697';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7034';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7035';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7036';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7040';} | FL TimeCreated,Message 
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | FL TimeCreated,Message
reg query 'HKLM\SYSTEM\CurrentControlSet\Services\'
```

### WMI/WMIC Lateral Movement Detection (Destinations) <a href="#wmiwmic-lateral-movement-detection-destinations" id="wmiwmic-lateral-movement-detection-destinations"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5857';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5860';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5861';} | FL TimeCreated,Message
C:\Windows\System32\wbem\Repository
ls C:\Windows\Prefetch\wmiprvse.exe*.pf
ls C:\Windows\Prefetch\mofcomp.exe*.pf
```

### PowerShell Lateral Movement Detection (Destinations) <a href="#powershell-lateral-movement-detection-destinations" id="powershell-lateral-movement-detection-destinations"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4103';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4104';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='53504';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='400';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='403';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='91';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='168';} | FL TimeCreated,Message
ls C:\Windows\Prefetch\wsmprovhost.exe*.pf
```
