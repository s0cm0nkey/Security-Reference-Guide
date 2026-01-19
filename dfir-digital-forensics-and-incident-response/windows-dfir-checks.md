# Windows DFIR Checks

## Malware Activity

### Check for Disabled Task Manager <a href="#check-disabled-task-manager" id="check-disabled-task-manager"></a>

Malware often disables Task Manager to prevent users from terminating malicious processes.

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr
```

### Mimikatz/Credential Extraction Detection <a href="#credential-extraction-detection" id="credential-extraction-detection"></a>

The following registry keys control security providers and LSA protection. If these are set to insecure values, it may indicate an attacker attempting to dump credentials (e.g., using Mimikatz).

*Note: Always test prior to changing registry keys to ensure system stability.*

```powershell
# Check WDigest (UseLogonCredential should be 0)
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential

# Check LSA Protection (RunAsPPL should be 1)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

*   **WDigest**: `UseLogonCredential` should be `0` to prevent storing cleartext passwords in LSASS.
*   **LSA Protection**: `RunAsPPL` should be `1` to prevent non-protected processes from interacting with LSASS.
*   **Tampering**: Mimikatz can remove these flags using a custom driver (`mimidriver`), often via commands like `!+` and `!processprotect /remove`.

The [Mimikatz Yara rule](https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar) may also prove useful.

Adversaries may load `lsasrv.dll` or `wdigest.dll` to extract credentials. Check if these are loaded in unexpected processes:

```powershell
tasklist /m wdigest.dll
tasklist /m lsasrv.dll
```

Check for registry keys used to load arbitrary DLLs into LSASS (forcing credential dumps):
More information from [Adam Chester](https://blog.xpnsec.com/exploring-mimikatz-part-1/)

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS /v LsaDbExtPt
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt
```

Check for modification of Cached Logons count (Adversaries may increase this to cache more credentials):

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount
```

### NetNTLM Configuration Checks <a href="#netntlm-config-checks" id="netntlm-config-checks"></a>

Checks if the system is configured to allow weak NTLM authentication/traffic (Downgrade Attacks).

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LMCompatibilityLevel
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictSendingNTLMTraffic 
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NTLMMinClientSec
```

### Putty Detection <a href="#putty-detection" id="putty-detection"></a>

Checks for saved Putty sessions which implies SSH usage and potential lateral movement targets or persistence.

```powershell
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
```

### Check Common AppData Locations (Trickbot-style paths) <a href="#check-common-appdata-locations" id="check-common-appdata-locations"></a>

Scans common user directories where malware (like Trickbot) often hides executables or data.

```powershell
# Scan AppData Roaming and Local for suspicious folders/modules
Get-ChildItem -path C:\Users\*\AppData\Roaming\*\Data -recurse -force -ErrorAction SilentlyContinue
Get-ChildItem -path C:\Users\*\AppData\Roaming\*\Modules -recurse -force -ErrorAction SilentlyContinue
Get-ChildItem -path C:\Users\*\AppData\Local\*\Data -recurse -force -ErrorAction SilentlyContinue
Get-ChildItem -path C:\Users\*\AppData\Local\*\Modules -recurse -force -ErrorAction SilentlyContinue

# Nested levels
Get-ChildItem -path C:\Users\*\AppData\Roaming\*\*\Data -recurse -force -ErrorAction SilentlyContinue
Get-ChildItem -path C:\Users\*\AppData\Roaming\*\*\Modules -recurse -force -ErrorAction SilentlyContinue

# System Profile AppData
Get-ChildItem -path C:\Windows\System32\config\systemprofile\appdata\roaming -recurse -force -include *.exe

# Scheduled Tasks referencing AppData/ProgramData (Common persistence)
schtasks /query /fo LIST /v | findstr "appdata"	
schtasks /query /fo LIST /v | findstr "programdata"	
schtasks /query /fo LIST /v | findstr "public"	

# Check services hosted in svchost (Look for anomalies)
tasklist /svc | findstr "svchost"
```

### Check running executables for malware via VirusTotal <a href="#check-running-executables-for-malware-via-virustotal" id="check-running-executables-for-malware-via-virustotal"></a>

**Note: This script uses the VirusTotal API v3. It requires an API Key.**

```powershell
$APIKey = "[VTAPIKey]"
$Header = @{ "x-apikey" = $APIKey }

# Get Unique Hashes from Running Processes
$Processes = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath }
$Hashes = $Processes | ForEach-Object { (Get-FileHash $_.ExecutablePath -Algorithm SHA256).Hash } | Select-Object -Unique

foreach ($Hash in $Hashes) {
    $Uri = "https://www.virustotal.com/api/v3/files/$Hash"
    Try {
        $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Header -ErrorAction Stop
        $Stats = $Response.data.attributes.last_analysis_stats
        Write-Output "Hash: $Hash | Malicious: $($Stats.malicious) | Suspicious: $($Stats.suspicious)"
    } Catch {
        # 404 means file not known to VT
        if ($_.Exception.Response.StatusCode.value__ -ne 404) {
             Write-Warning "Error querying $Hash : $($_.Exception.Message)"
        }
    }
    Start-Sleep -Seconds 15 # Respect Public API Rate Limits (4/min)
}
```

## Registry Indicators

### Check Registry for IE Enhanced Security Modification <a href="#check-registry-for-ie-enhanced-security-modification" id="check-registry-for-ie-enhanced-security-modification"></a>

```powershell
Get-ChildItem 'REGISTRY::HKU\*\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
Get-ChildItem 'REGISTRY::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
```

### Check Registry for disabling of UAC (1=UAC Disabled) <a href="#check-registry-for-disabling-of-uac-1uac-disabled" id="check-registry-for-disabling-of-uac-1uac-disabled"></a>

```powershell
Get-ChildItem REGISTRY::HKU\*\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA 
Get-ChildItem REGISTRY::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA 
```

### Review Software Keys for malicious entries <a href="#review-software-keys-for-malicious-entries" id="review-software-keys-for-malicious-entries"></a>

```powershell
Get-ChildItem registry::HKLM\Software\*
Get-ChildItem registry::HKU\*\Software\*
```

### Scan Registry keys for specified text <a href="#scan-registry-keys-for-specified-text" id="scan-registry-keys-for-specified-text"></a>

```powershell
Get-ChildItem -path HKLM:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'notepad' -or $_.Name -match 'sql'}
Get-ChildItem -path HKLM:\ -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$_ -match 'notepad' -or $_ -match 'sql'}

# Consider using reg query for speed in deep searches
reg query HKLM\SOFTWARE /s /f ".exe"
reg query HKLM\SYSTEM /s /f ".exe"
reg query HKLM\SECURITY /s /f ".exe"
reg query HKLM /s /f ".exe"
```

## Suspicious Files <a href="#suspicious-files" id="suspicious-files"></a>

### Find files without extensions <a href="#find-files-without-extensions" id="find-files-without-extensions"></a>

```powershell
Get-ChildItem -Path C:\Users\[user]\AppData -Recurse -Exclude *.* -File -Force -ErrorAction SilentlyContinue
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

```powershell
Get-ChildItem $env:LOCALAPPDATA -Recurse -Include *.exe,*.dll,*.bat -ErrorAction SilentlyContinue
Get-ChildItem $env:APPDATA -Recurse -Include *.exe,*.dll,*.bat -ErrorAction SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Include *.lnk -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\Public\" -Recurse -Include *.exe,*.lnk,*.dll,*.bat -ErrorAction SilentlyContinue
```

### Locate LNK Files with a particular string (Special thanks to the notorious) <a href="#locate-lnk-files-with-a-particular-string-special-thanks-to-the-notorious" id="locate-lnk-files-with-a-particular-string-special-thanks-to-the-notorious"></a>

```powershell
Select-String -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "powershell" | Select-Object Path
```

#### Master File Table <a href="#master-file-table" id="master-file-table"></a>

The Master File Table (MFT) is an incredibly important artifact; however, this can only be read or obtained using low-level disk reading. This contains an entry for every file or directory on the filesystem including metadata about these files, and may provide evidence on files which have been removed (MFT entries marked as ‘free’). More information can be found on [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Determine Timestomping <a href="#determine-timestomping" id="determine-timestomping"></a>

Within the Master File Table (located at the Windows root, e.g. `C:\$MFT`) there are two timestamp attributes: `$STANDARD_INFORMATION` and `$FILE_NAME`. Both have values for file Creation, Modification, Access, and Birth (MFT modification).

These are known as MACB times. The `$STANDARD_INFORMATION` attribute can be easily modified by user-level processes (and malware), but the `$FILE_NAME` attribute is generally read-only and cannot be modified without significant effort (kernel-level or direct disk access).

Discrepancies between these two attributes generally indicate "Timestomping", with the `$FILE_NAME` entry often being the source of truth. This can be determined by obtaining the MFT (using a tool such as Rawcopy) and comparing timestamps (using a tool such as MFTExplorer).

[Rawcopy](https://github.com/jschicht/RawCopy)

```powershell
RawCopy.exe /FileNamePath:C:0 /OutputPath:C:\Audit /OutputName:MFT_C.bin
```

[MFTExplorer](https://ericzimmerman.github.io/#!index.md)

### Check system directories for executables not signed as part of an operating system release <a href="#check-system-dirs-unsigned" id="check-system-dirs-unsigned"></a>

```powershell
Get-ChildItem C:\windows\*\*.exe -File -force | Get-AuthenticodeSignature | Where-Object {$_.IsOSBinary -notmatch 'True'}
```

### Office Trusted Documents (Macro Usage)

Note: This checks user hives for trusted documents, which can indicate if a user enabled macros on a malicious document.

```
reg query 'HKU\[SID]\Software\Microsoft\Office\[versionnumber]\Word\Security\Trusted Documents\TrustRecords';
gci 'REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords' -ea 0 | foreach {reg query $_.Name}
```

Note: This will show the file name/location and metadata in Hex. If the last lot of hex is FFFFFF7F then the user likely enabled the macro.



### Check all Appdata files for unsigned or invalid executables <a href="#check-all-appdata-files-for-unsigned-or-invalid-executables" id="check-all-appdata-files-for-unsigned-or-invalid-executables"></a>

```powershell
Get-ChildItem -Recurse $env:APPDATA\..\*.exe -ea SilentlyContinue | ForEach-Object {Get-AuthenticodeSignature $_ -ea SilentlyContinue} | Where-Object {$_.status -ine "Valid"} | Select-Object Status,Path
```

### Check for executables in Local System User Profile and Files <a href="#check-for-executables-in-local-system-user-profile-and-files" id="check-for-executables-in-local-system-user-profile-and-files"></a>

```powershell
Get-ChildItem C:\Windows\*\config\systemprofile -Recurse -Force -ErrorAction SilentlyContinue -Include *.exe, *.dll, *.lnk
```

### Find executables and scripts in Path directories ($env:Path) <a href="#find-executables-and-scripts-in-path-directories-envpath" id="find-executables-and-scripts-in-path-directories-envpath"></a>

```powershell
Get-Command -Name * | Format-List FileVersionInfo
```

### Find files created/written based on date <a href="#find-files-createdwritten-based-on-date" id="find-files-createdwritten-based-on-date"></a>

```
Get-ChildItem C:\ -recurse -ea SilentlyContinue -force | where-object { $_.CreationTime.Date -match "12/25/2014"}
Get-ChildItem C:\ -recurse -ea SilentlyContinue -force | where-object { $_.LastWriteTime -match "12/25/2014"}
Get-ChildItem C:\ -recurse -ea SilentlyContinue -force | where-object { $_.CreationTime.Hour -gt 2 -and $_.CreationTime.Hour -lt 15}
```

### Programs specifically set to run as admin <a href="#programs-specifically-set-to-run-as-admin" id="programs-specifically-set-to-run-as-admin"></a>

```powershell
reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /s /f RUNASADMIN
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /s /f RUNASADMIN
```

## Program Execution Artifacts

These artifacts help determine if a specific program was executed on the system.

### ShimCache (AppCompatCache) <a href="#shimcache" id="shimcache"></a>

Tracks executable file metadata and whether it was executed.

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
```
*Note: Parsing this key requires specialized tools (like Zimmerman's AppCompatCacheParser) due to its binary structure.*

### AmCache <a href="#amcache" id="amcache"></a>

Tracks applications usage and installation.

```powershell
Get-ChildItem -Path C:\Windows\appcompat\Programs\Amcache.hve
```

### UserAssist (GUI Execution) <a href="#userassist" id="userassist"></a>

Tracks programs executed via the GUI (Explorer). Values are Rot-13 encoded.

```powershell
Get-ChildItem "REGISTRY::HKU\*\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
```

### Background Activity Moderator (BAM/DAM) <a href="#bam-dam" id="bam-dam"></a>

Tracks execution on Windows 10+.

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
```

### Windows Indexing Service <a href="#windows-indexing-service" id="windows-indexing-service"></a>

Contains a database of indexed files.

```text
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\windows.edb
```

*   [ESE Database View](https://www.nirsoft.net/utils/ese_database_view.html)
*   [View ESE Database](http://www.edgemanage.emmet-gray.com/Articles/ViewESE.html)

## DNS Logs

**Note: DNS Client Operational logs (Microsoft-Windows-DNS-Client) are often disabled by default on client OS versions.**

### Scan DNS Logs <a href="#scan-dns-logs" id="scan-dns-logs"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Id='3010';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Id='3020';} | Format-List TimeCreated,Message
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

These will appear as children spawning from `wmiprvse.exe`.

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
```

### Investigate WMI Usage <a href="#investigate-wmi-usage" id="investigate-wmi-usage"></a>

Note: Requires [Strings](https://docs.microsoft.com/en-us/sysinternals/downloads/strings)

```
strings -q C:\windows\system32\wbem\repository\objects.data
```

## Windows Defender <a href="#windows-defender-checks" id="windows-defender-checks"></a>

### Check Windows Defender Block/Quarantine Logs <a href="#check-windows-defender-block-quarantine-logs" id="check-windows-defender-block-quarantine-logs"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Data='Severe'} | FL TimeCreated,Message
```

### Check Defender Exclusions ACLs <a href="#check-defender-exclusions-acls" id="check-defender-exclusions-acls"></a>

```powershell
Get-Acl -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' | FL
```

## ACLs and ACE <a href="#check-and-set-access-control-lists" id="check-and-set-access-control-lists"></a>

### Change ACE for “everyone” on folder and subfiles/folders <a href="#change-ace-for-everyone-on-folder-and-subfilesfolders" id="change-ace-for-everyone-on-folder-and-subfilesfolders"></a>

**Grant everyone full access**

```powershell
icacls "C:\{DESIREDFOLDERPATH}" /grant everyone:(CI)(OI)F /T
```

### Check Security Descriptor Definition Language (SDDL) and Access Control Entries (ACE) for services <a href="#check-sddl-and-ace-for-services" id="check-sddl-and-ace-for-services"></a>

```powershell
# In PowerShell, 'sc' is an alias for Set-Content, so use sc.exe
sc.exe sdshow <servicename>

$Services = Get-Service
foreach ($Service in $Services) {
    $Service.Name
    sc.exe sdshow $Service.Name
}

# Check for risky permissions: DC (Delete Child), WD (Write DAC), WO (Write Owner)
foreach ($Service in $Services) { $Service.Name; sc.exe sdshow $Service.Name | Select-String "A;*DC" }
foreach ($Service in $Services) { $Service.Name; sc.exe sdshow $Service.Name | Select-String "A;*WD" }
foreach ($Service in $Services) { $Service.Name; sc.exe sdshow $Service.Name | Select-String "A;*WO" }
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

### Event Log Tampering Utilities

[DanderSpritz eventlogedit](https://github.com/fox-it/danderspritz-evtx) - Tool for evtx manipulation.

## Vulnerability Checks

### Verify EternalBlue Patch (MS17-010) is installed - [Microsoft](https://support.microsoft.com/en-us/help/4023262/how-to-verify-that-ms17-010-is-installed) <a href="#verify-eternalblue-patch-ms17-010-is-installed---microsoft" id="verify-eternalblue-patch-ms17-010-is-installed---microsoft"></a>

Note: This impacts the SMB 1.0 Server Driver, if you don’t have the below, then it’s not installed. If you do you can use the above to determine patch level.

```
get-item C:\Windows\system32\drivers\srv.sys | FL VersionInfo
get-hotfix -id KB<111111>
```

More information on [ACE Strings](https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings) and the level of access they can provide.

## Lateral Movement Checks

### Remote Access / RDP Valid Logons <a href="#remote-access-rdp" id="remote-access-rdp"></a>

```powershell
# RDP Logons (Type 10)
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='10'} | Format-List TimeCreated,Message

# Network Logons (Type 3) - Common in lateral movement
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
```

### Map Network Shares Lateral Movement Detection (Destinations) <a href="#map-network-shares-lateral-movement-detection-destinations" id="map-network-shares-lateral-movement-detection-destinations"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4776';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4768';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4769';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\C$'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5145';} | Format-List TimeCreated,Message
```

### PsExec Lateral Movement Detection (Destinations) <a href="#psexec-lateral-movement-detection-destinations" id="psexec-lateral-movement-detection-destinations"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='2'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\ADMIN$'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'; Data='PSEXESVC'} | Format-List TimeCreated,Message
reg query HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC
reg query HKLM\SYSTEM\CurrentControlSet\Services\
Get-ChildItem C:\Windows\Prefetch\psexesvc.exe*.pf
```

### Scheduled Tasks Lateral Movement Detection (Destinations) <a href="#scheduled-tasks-lateral-movement-detection-destinations" id="scheduled-tasks-lateral-movement-detection-destinations"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4698';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4702';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4699';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4700';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4701';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='106';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='140';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='141';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='200';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='201';} | Format-List TimeCreated,Message
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" /s /v Actions
Get-ChildItem -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\' | Get-ItemProperty | Format-List Path, Actions
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
Get-ChildItem -path C:\Windows\System32\Tasks\ -recurse -File
```

### Services Lateral Movement Detection (Destinations) <a href="#services-lateral-movement-detection-destinations" id="services-lateral-movement-detection-destinations"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4697';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7034';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7035';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7036';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7040';} | Format-List TimeCreated,Message 
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | Format-List TimeCreated,Message
reg query 'HKLM\SYSTEM\CurrentControlSet\Services\'
```

### WMI/WMIC Lateral Movement Detection (Destinations) <a href="#wmiwmic-lateral-movement-detection-destinations" id="wmiwmic-lateral-movement-detection-destinations"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5857';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5860';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5861';} | Format-List TimeCreated,Message
# WMI Repository Path
Get-Item C:\Windows\System32\wbem\Repository
Get-ChildItem C:\Windows\Prefetch\wmiprvse.exe*.pf
Get-ChildItem C:\Windows\Prefetch\mofcomp.exe*.pf
```

### PowerShell Lateral Movement Detection (Destinations) <a href="#powershell-lateral-movement-detection-destinations" id="powershell-lateral-movement-detection-destinations"></a>

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4103';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4104';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='53504';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='400';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='403';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='91';} | Format-List TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='168';} | Format-List TimeCreated,Message
Get-ChildItem C:\Windows\Prefetch\wsmprovhost.exe*.pf
```

