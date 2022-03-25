# Windows System Enumeration

## Gather artifacts <a href="#gather-artifacts" id="gather-artifacts"></a>

```
reg save HKLM\SAM [LOCATION]\SAM 
reg save HKLM\SYSTEM [LOCATION]\SYSTEM
reg save HKLM\SECURITY [LOCATION]\SECURITY
reg save HKLM\SOFTWARE [LOCATION]\SOFTWARE
```

## System and User information <a href="#system-information" id="system-information"></a>

```
get-computerinfo
echo %DATE% %TIME%
date /t
time /t
reg query "HKLM\System\CurrentControlSet\Control\TimeZoneInformation"
systeminfo
wmic computersystem list full
wmic /node:localhost product list full /format:csv
wmic softwarefeature get name,version /format:csv
wmic softwareelement get name,version /format:csv
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /s
echo %PATH%
(gci env:path|Select -exp Value).split(';')
SET
wmic bootconfig get /all /format:List
wmic computersystem get name, domain, manufacturer, model, numberofprocessors,primaryownername,username,roles,totalphysicalmemory /format:list
wmic timezone get Caption, Bias, DaylightBias, DaylightName, StandardName
wmic recoveros get /all /format:List
wmic os get /all /format:list
wmic partition get /all /format:list
wmic logicaldisk get /all /format:list
wmic diskdrive get /all /format:list
fsutil fsinfo drives
```

(psinfo requires sysinternals psinfo.exe):

```
psinfo -accepteula -s -h -d
```

### Model of motherboard and hardware information: <a href="#model-of-motherboard-and-hardware-information" id="model-of-motherboard-and-hardware-information"></a>

```
wmic baseboard get product,manufacturer
wmic desktopmonitor get /all /format:list
wmic baseboard get /all /format:list
wmic bios get /all /format:list
wmic cpu get /all /format:list
```

### Installed Updates <a href="#installed-updates" id="installed-updates"></a>

(WMI Quick Fix Engineering)

```
wmic qfe
```

### Installed Software/Packages <a href="#installed-softwarepackages" id="installed-softwarepackages"></a>

```
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s /f DisplayName
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\ /s /f DisplayName
wmic product get name,version /format:csv
wmic product get /ALL
dism /online /get-packages
get-WmiObject -Class Win32_Product
get-package
```

Powershell: Full List for all users using uninstall keys in registry

```
$(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*; Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*;New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;$UserInstalls += gci -Path HKU: | where {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | foreach {$_.PSChildName };$(foreach ($User in $UserInstalls){Get-ItemProperty HKU:\$User\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*});$UserInstalls = $null;try{Remove-PSDrive -Name HKU}catch{};)|where {($_.DisplayName -ne $null) -and ($_.Publisher -ne $null)} | Select DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString |FT
```

### User and admin information <a href="#user-and-admin-information" id="user-and-admin-information"></a>

```
whoami
whoami /user
net users
net localgroup administrators
net group /domain [groupname]
net user /domain [username]
wmic sysaccount
wmic useraccount get name,SID
wmic useraccount list
```

### User accounts and logon information <a href="#user-accounts-and-logon-information" id="user-accounts-and-logon-information"></a>

```
Get-WmiObject Win32_UserProfile
```

### Logon information <a href="#logon-information" id="logon-information"></a>

```
wmic netlogin list /format:List
Get-WmiObject Win32_LoggedOnUser
Get-WmiObject win32_logonsession
query user
qwinsta
klist sessions
klist -li
```

### NT Domain/Network Client Information <a href="#nt-domainnetwork-client-information" id="nt-domainnetwork-client-information"></a>

```
wmic ntdomain get /all /format:List
wmic netclient get /all /format:List
nltest /trusted_domains
```

### Group and access information <a href="#group-and-access-information" id="group-and-access-information"></a>

(Accesschk requires accesschk64.exe or accesschk.exe from sysinternals):

```
net localgroup
accesschk64 -a *
```

### Hosts file and service>port mapping <a href="#hosts-file-and-serviceport-mapping" id="hosts-file-and-serviceport-mapping"></a>

```
type %SystemRoot%\System32\drivers\etc\hosts
type %SystemRoot%\System32\drivers\etc\services
```

### cmd history <a href="#cmd-history" id="cmd-history"></a>

```
doskey /history
```

Linux Subsystem for Windows 10 may have history in a location such as:

```
C:\Users\[User]\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\home\[user]
```

### Check group policies <a href="#check-group-policies" id="check-group-policies"></a>

```
gpresult /Z /SCOPE COMPUTER
gpresult /Z /SCOPE USER
gpresult /R /SCOPE COMPUTER
gpresult /R /SCOPE USER
gpresult /r /z
ls C:\Users\[username]\AppData\Local\GroupPolicy\DataStore
ls C:\Windows\system32\GroupPolicy\DataStore
```

### Obtain mode settings for ports <a href="#obtain-mode-settings-for-ports" id="obtain-mode-settings-for-ports"></a>

```
mode
```

### Service information <a href="#service-information-1" id="service-information-1"></a>

```
Get-WmiObject win32_service | select Name, DisplayName, State, PathName
Get-Service
```

#### View Named Pipes <a href="#view-named-pipes" id="view-named-pipes"></a>

```
[System.IO.Directory]::GetFiles("\\.\\pipe\\")
get-childitem \\.\pipe\
dir \\.\pipe\\
```

## File Information

### Obtain list of all files on a computer <a href="#obtain-list-of-all-files-on-a-computer" id="obtain-list-of-all-files-on-a-computer"></a>

```
tree C:\ /F > output.txt
dir C:\ /A:H /-C /Q /R /S /X
```

### Share information <a href="#share-information" id="share-information"></a>

```
Get-WmiObject Win32_Share
net share
wmic share list brief
wmic netuse get Caption, DisplayType, LocalName, Name, ProviderName, Status
```

### Pagefile information <a href="#pagefile-information" id="pagefile-information"></a>

```
wmic pagefile
```

### Cookies <a href="#cookies" id="cookies"></a>

```
C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies
C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies
C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\Low
```

### RecentDocs Information <a href="#recentdocs-information" id="recentdocs-information"></a>

[Special thanks Barnaby Skeggs](https://twitter.com/barnabyskeggs)

\*Note: Run with Powershell, get SID and user information with ‘wmic useraccount get name,SID’

```
$SID = "S-1-5-21-1111111111-11111111111-1111111-11111"; $output = @(); Get-Item -Path "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" | Select-Object -ExpandProperty property | ForEach-Object {$i = [System.Text.Encoding]::Unicode.GetString((gp "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name $_).$_); $i = $i -replace '[^a-zA-Z0-9 \.\-_\\/()~ ]', '\^'; $output += $i.split('\^')[0]}; $output | Sort-Object -Unique
```

More information on recent documents may be found:

```
C:\Users\[username]\AppData\Local\Microsoft\Windows\FileHistory\Data
gci "REGISTRY::HKU\*\Software\Microsoft\Office\*\Word\Reading Locations\*"
```

### Recent execution of programs <a href="#recent-execution-of-programs" id="recent-execution-of-programs"></a>

* Prefetch Located at : %SystemRoot%\Prefetch\\
* RecentFileCache.bcf Located at : %SystemRoot%\AppCompat\Programs\\
* Amcache.hve (reg hive) Located at : %SystemRoot%\AppCompat\Programs\\

Or query a lot of run programs from program compatibility assistant:

```
Get-ItemProperty "REGISTRY::HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
Get-ItemProperty "REGISTRY::HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
```

### Show known file extensions and hidden files (excluding OS hidden files) <a href="#show-known-file-extensions-and-hidden-files-excluding-os-hidden-files" id="show-known-file-extensions-and-hidden-files-excluding-os-hidden-files"></a>

```
reg add "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d "1" /f
reg add "HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d "0" /f
Stop-Process -processname explorer
```

### Files greater than a 10mb <a href="#files-greater-than-a-10mb" id="files-greater-than-a-10mb"></a>

```
FOR /R C:\ %i in (*) do @if %~zi gtr 10000000 echo %i %~zi
```

### Temp files greater than 10mb <a href="#temp-files-greater-than-10mb" id="temp-files-greater-than-10mb"></a>

```
FOR /R C:\Users\[User]\AppData %i in (*) do @if %~zi gtr 10000000 echo %i %~zi
```

## Alternate Data Streams

### List Alternate Data Streams in current Dir and view them <a href="#list-alternate-data-streams-in-current-dir-and-view-them" id="list-alternate-data-streams-in-current-dir-and-view-them"></a>

```
gi * -s *
gc [FILENAME] -s [ADSNAME]
```

### List Alternate Data Streams in text files within AppData <a href="#list-alternate-data-streams-in-text-files-within-appdata" id="list-alternate-data-streams-in-text-files-within-appdata"></a>

```
Get-ChildItem -Recurse -Path $env:APPDATA\..\ -include *.txt -ea SilentlyContinue|gi -s *|Select Stream -ea SilentlyContinue| Where-Object {$_.Stream -ine ":`$DATA"}
```

### Use Alternate Data Streams to find download location <a href="#use-alternate-data-streams-to-find-download-location" id="use-alternate-data-streams-to-find-download-location"></a>

```
get-item * -stream *|Where-Object {$_.Stream -ine ":`$DATA"}|cat
get-item C:\Users\Username\Downloads\* -stream *|Where-Object {$_.Stream -ine ":`$DATA"}|cat
$a=(gci -rec -path C:\users\user\downloads -ea 0 | gi -s Zone.Identifier -ea 0 | ? {$_.Length -ge '27'});foreach ($b in $a){$b.FileName;$b|cat}
$a=(get-item * -stream Zone.Identifier -ea 0 | ? {$_.Length -ge '27'});foreach ($b in $a){$b.FileName;$b|cat}
gci -Recurse -Path $env:APPDATA\..\ -include *.txt -ea SilentlyContinue |gi -s *| Where-Object {$_.Stream -ine ":`$DATA"}|cat
```

## Firewall and AV

### Firewall Information <a href="#firewall-information" id="firewall-information"></a>

```
netsh Firewall show state
netsh advfirewall firewall show rule name=all dir=in type=dynamic
netsh advfirewall firewall show rule name=all dir=out type=dynamic
netsh advfirewall firewall show rule name=all dir=in type=static
netsh advfirewall firewall show rule name=all dir=out type=static
```

```
netsh firewall show config
advfirewall firewall show rule name=all verbose
```

### Firewall Changes <a href="#firewall-changes" id="firewall-changes"></a>

```
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';} | FL TimeCreated, Message
```

## Start-up/Autoruns <a href="#cookies" id="cookies"></a>

### Startup process information <a href="#startup-process-information" id="startup-process-information"></a>

```
wmic startup list full
wmic startup list brief
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | FL
```

### Startup process information by path/file name <a href="#startup-process-information-by-pathfile-name" id="startup-process-information-by-pathfile-name"></a>

Note: This will search common persistence areas but not all of them, change the $Malware variable value to a term of your choosing.

```
$Malware = "appdata";
$Processes = gps |?{$_.Path -match $Malware -or $_.Name -match $Malware} | FL Name,Path,Id;
$Tasks = schtasks /query /fo csv /v | ConvertFrom-Csv | ?{"$_.Task To Run" -match $Malware}| FL "Taskname","Task To Run","Run As User";
$Services = gwmi win32_service | ? {$_.PathName -match $Malware}| FL Name,PathName;
$ServiceDLL = reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ServiceDLL" | findstr "$Malware";
$RunKey1 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run*' | ?{$_ -match $Malware};
$RunKey2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*' | ?{$_ -match $Malware};
$UserProfiles = (gwmi Win32_UserProfile | ? { $_.SID -notmatch 'S-1-5-(18|19|20).*' }); $paths = $UserProfiles.localpath; $sids = $UserProfiles.sid; for ($counter=0; $counter -lt $UserProfiles.length; $counter++){$path = $UserProfiles[$counter].localpath; $sid = $UserProfiles[$counter].sid; reg load hku\$sid $path\ntuser.dat};
$RunKey3 = Get-ItemProperty -Path Registry::HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run* | ?{$_ -match $Malware};
$Startup = Select-String -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*' -Pattern $Malware | Select Path;
$Startup2 = Select-String -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*' -Pattern $Malware | Select Path;
if ($Processes) {echo "Process Found!";$Processes} else {echo "No Running Processes Found."};
if ($Tasks) {echo "Tasks Found!";$Tasks} else {echo "No Tasks Found."};
if ($Services) {echo "Services Found!";$Services} else {echo "No Services Found."};
if ($ServiceDLL) {echo "ServiceDLL Found!";$ServiceDll} else {echo "No Service Dlls Found."};
if ($RunKey1) {echo "Wow6432Node Run Key Found!";$RunKey1} else {echo "No Local Machine Wow6432Node Run Key Found."};
if ($RunKey2) {echo "Local Machine Run Key Found!";$RunKey2} else {echo "No Local Machine Run Key Found."};
if ($RunKey3) {echo "User Run Key Found!";$RunKey3} else {echo "No User Run Key Found."};
if ($Startup) {echo "AppData Startup Link Found!";$Startup} else {echo "No AppData Startups Found."};
if ($Startup2) {echo "ProgramData Startup Link Found!";$Startup2} else {echo "No ProgramData Startups Found."};
```

### Scheduled task/job information <a href="#scheduled-taskjob-information" id="scheduled-taskjob-information"></a>

```
at (For older OS)
schtasks
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr "Task To Run:"
schtasks /query /fo LIST /v | findstr "appdata"
schtasks /query /fo LIST /v | select-string "Enabled" -CaseSensitive -Context 10,0 | findstr "exe"
schtasks /query /fo LIST /v | select-string "Enabled" -CaseSensitive -Context 10,0 | findstr "Task"
schtasks /query /fo LIST /v | Select-String "exe" -Context 2,27 
gci -path C:\windows\system32\tasks -recurse | Select-String Command | ? {$_.Line -match "EXENAME"} | FL Line, Filename
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)}|Select-String Command|FL Filename,Line
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | where {$_.CreationTime.hour -ge (get-date).hour-2}|Select-String Command|FL Line,Filename
schtasks /query /fo csv /v | ConvertFrom-Csv | ?{"$_.Task To Run" -match "MALICIOUS"}| FL "Taskname","Task To Run"
schtasks /query /fo csv /v | ConvertFrom-Csv | ?{$_.Taskname -ne "TaskName"} | FL "Taskname","Task To Run"
wmic job get Name, Owner, DaysOfMonth, DaysOfWeek, ElapsedTime, JobStatus, StartTime, Status
```

Powershell:

```
Get-ScheduledTask
gci -path C:\windows\system32\tasks -recurse | Select-String Command | FL Filename, Line
gci -path C:\windows\system32\tasks -recurse | Select-String "<Command>",Argument | FT Filename,Command,Line
gci -path C:\windows\system32\tasks -recurse | Select-String Command | ? {$_.Line -match "MALICIOUSNAME"} | FL Filename, Line
(gci -path C:\windows\system32\tasks -recurse | Select-String "<Command>" | select -exp Line).replace("<Command>","").trim("</Command>").replace("`"","").trim();
```

### File hash and location of all scheduled tasks <a href="#file-hash-and-location-of-all-scheduled-tasks" id="file-hash-and-location-of-all-scheduled-tasks"></a>

```
$a=((gci C:\windows\system32\tasks -rec | Select-String "<Command>" | select -exp Line).replace("<Command>","").trim("</Command>").replace("`"","").trim());foreach ($b in $a){filehash ([System.Environment]::ExpandEnvironmentVariables($b))}
```

From System32 Directory:

```
$a=((gci tasks -rec | Select-String "<Command>" | select -exp Line).replace("<Command>","").trim("</Command>").replace("`"","").trim());foreach ($b in $a){filehash ([System.Environment]::ExpandEnvironmentVariables($b))}
```

### UAC Bypass Fodhelper <a href="#uac-bypass-fodhelper" id="uac-bypass-fodhelper"></a>

```
reg query HKCU\Software\Classes\ms-settings\shell\open\command
reg query HKU\{SID}\Software\Classes\ms-settings\shell\open\command
```

#### [Quick overview of persistent locations (AutoRuns)](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) <a href="#quick-overview-of-persistent-locations-autoruns" id="quick-overview-of-persistent-locations-autoruns"></a>

```
autorunsc.exe -accepteula -a * -c -h -v -m > autoruns.csv
autorunsc.exe -accepteula -a * -c -h -v -m -z 'E:\Windows' > autoruns.csv
```

### Persistence and Automatic Load/Run Reg Keys <a href="#persistence-and-automatic-loadrun-reg-keys" id="persistence-and-automatic-loadrun-reg-keys"></a>

_Replace: “reg query” with “Get-ItemProperty -Path HK_:" in Powershell\*

e.g.: Get-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

**User Registry (NTUSER.DAT HIVE)** - Commonly located at:

```
C:\Users\[username]
```

\*Note: These are setup for querying the current users registry only (HKCU), to query others you will need to load them from the relevant NTUSER.DAT file and then query them.

```
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f run
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f load
reg query "HKCU\Environment" /v UserInitMprLogonScript
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v RESTART_STICKY_NOTES
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\Scripts"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RecentDocs"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunMRU"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
reg query "HKCU\SOFTWARE\AcroDC"
reg query "HKCU\SOFTWARE\Itime"
reg query "HKCU\SOFTWARE\info"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\User Shell Folders"
reg query "HKCU\SOFTWARE\Microsoft\Command Processor"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\RegEdit" /v LastKey
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKCU\SOFTWARE\Microsoft\Windows\currentversion\run"
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\[Random]\StubPath" /s
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\[Random]\StubPath" /s
reg query "HKCU\SOFTWARE\Microsoft\Office\[officeversion]\[word/excel/access etc]\Security\AccessVBOM"
reg query "HKCU\SOFTWARE\Microsoft\IEAK\GroupPolicy\PendingGPOs" /s
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\CPLs"
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Control Panel\CPLs"
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security\AccessVBOM
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security\AccessVBOM
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Powerpoint\Security\AccessVBOM
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Access\Security\AccessVBOM
```

### **Local Machine (SOFTWARE HIVE)**

```
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s
reg query "HKLM\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\policies\explorer\run"
reg query "HKLM\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\run"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
reg query "HKLM\SOFTWARE\Microsoft\Office\[officeversion]\[word/excel/access etc]\Security\AccessVBOM"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\[Random]\StubPath" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\[Random]\StubPath" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Control Panel\CPLs"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\CPLs"
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Excel\Security\AccessVBOM
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Word\Security\AccessVBOM
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Powerpoint\Security\AccessVBOM
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Access\Security\AccessVBOM
```

Don’t be afraid to use “findstr” or ‘/f’ to find entries of interest, for example file extensions which may also invoke malicious executables when run, or otherwise.

```
reg query "HKLM\SOFTWARE\Classes" | findstr "file"
reg query "HKLM\SOFTWARE\Classes" /f "file"
reg query HKCR\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5} /s
reg query HKCR\AppID\ /s | findstr "exe"
```

### **Local Machine (SYSTEM HIVE)**

Note: This not only contains services, but also malicious drivers which may run at startup (these are in the form of “.sys” files and are generally loaded from here: \SystemRoot\System32\drivers)

```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\[Random_name]\imagePath"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ /s /f "*.exe"
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath /f "*.exe"
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath /f "*.sys"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute
Get-Service -Name "*MALICIOUSSERVICE*"
gwmi win32_service | ? {$_.PathName -match "MALICIOUSSERVICE"}|FL Name,PathName
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | FL DisplayName,ImagePath,ObjectName
gci -Path C:\Windows\system32\drivers -include *.sys -recurse -ea 0 -force | Get-AuthenticodeSignature
gci -Path C:\Windows\system32\drivers -include *.sys -recurse -ea 0 -force | Get-FileHash
```

Note: Some useful commands to show relevant service information

```
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ImagePath"
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ServiceDLL"
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "FailureCommand"
```

## Registry

### Powershell: Query Registry Keys <a href="#query-registry-keys" id="query-registry-keys"></a>

```
Invoke-Command -ScriptBlock {Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run} -Session $s1
```

### Review Hivelist <a href="#review-hivelist" id="review-hivelist"></a>

```
gp REGISTRY::HKLM\SYSTEM\CurrentControlSet\Control\hivelist | Select *USER*
```

### Locate all user registry keys <a href="#locate-all-user-registry-keys" id="locate-all-user-registry-keys"></a>

```
$UserProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\ntuser.dat"}}
```

### Load all users registry keys from their ntuser.dat file (perform above first) <a href="#load-all-users-registry-keys-from-their-ntuserdat-file-perform-above-first" id="load-all-users-registry-keys-from-their-ntuserdat-file-perform-above-first"></a>

```
Foreach ($UserProfile in $UserProfiles) {If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {reg load HKU\$($UserProfile.SID) $($UserProfile.UserHive) | echo "Successfully loaded: $($UserProfile.UserHive)"}}
```

### Query all users run key <a href="#query-all-users-run-key" id="query-all-users-run-key"></a>

```
Foreach ($UserProfile in $UserProfiles) {reg query HKU\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run};
```

## [Enumerate WMI Namespaces](https://learn-powershell.net/2014/05/09/quick-hits-list-all-available-wmi-namespaces-using-powershell/) <a href="#enumerate-wmi-namespaces" id="enumerate-wmi-namespaces"></a>

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

## Network Connections <a href="#obtain-hash-for-all-running-executables" id="obtain-hash-for-all-running-executables"></a>

### Network connections <a href="#network-connections" id="network-connections"></a>

(tcpvcon requires sysintenals tcpvcon.exe):

```
ipconfig /all
netstat –anob
netstat -ano
Tcpvcon -a
```

### Routing table and ARP cache <a href="#routing-table-and-arp-cache" id="routing-table-and-arp-cache"></a>

```
route print
arp -a
Get-NetNeighbor
```

### Obtain hash and established network connections for running executables with dns cache <a href="#obtain-hash-and-established-network-connections-for-running-executables-with-dns-cache" id="obtain-hash-and-established-network-connections-for-running-executables-with-dns-cache"></a>

```
Get-NetTCPConnection -State Established | Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress -ea 0).Entry}}|sort|gu -AS|FT
```

### Obtain hash and listening network connections for running executables <a href="#obtain-hash-and-listening-network-connections-for-running-executables" id="obtain-hash-and-listening-network-connections-for-running-executables"></a>

```
Get-NetTCPConnection -State LISTEN | Select LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT
```

### Obtain hash and possible tunneled network connections for running executables <a href="#obtain-hash-and-possible-tunneled-network-connections-for-running-executables" id="obtain-hash-and-possible-tunneled-network-connections-for-running-executables"></a>

```
Get-NetTCPConnection -State ESTABLISHED |? LocalAddress -Like "::1" | Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress).Entry}}|sort|gu -AS|FT
Get-NetTCPConnection -State Established |? LocalAddress -Like "127.0.0.1"| Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress).Entry}}|sort|gu -AS|FT
Get-NetTCPConnection -State LISTEN |? LocalAddress -Like "127.0.0.1" | Select LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT
```

### Obtain workstation name for tunneled authentication <a href="#obtain-workstation-name-for-tunneled-authentication" id="obtain-workstation-name-for-tunneled-authentication"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='::';} | FL TimeCreated,Message
```



### Contents of DNS resolver <a href="#contents-of-dns-resolver" id="contents-of-dns-resolver"></a>

(useful for recent web history)

```
ipconfig /displaydns
Get-DnsClientCache | FT -AutoSize
```

### Currently connected Access Point name (WiFi) <a href="#currently-connected-access-point-name-wifi" id="currently-connected-access-point-name-wifi"></a>

```
reg query HKLM\system\CurrentControlSet\Services\Dnscache\Parameters\DnsActiveIfs\ /s
netsh wlan show interfaces
```

### Previously connected Access Point names (WiFi) <a href="#previously-connected-access-point-names-wifi" id="previously-connected-access-point-names-wifi"></a>

```
netsh wlan show profile
```

### Current surrounding Access Point names (WiFi) <a href="#current-surrounding-access-point-names-wifi" id="current-surrounding-access-point-names-wifi"></a>

```
netsh wlan show network mode=bssid 
```

### Extended network adapter configuration information <a href="#extended-network-adapter-configuration-information" id="extended-network-adapter-configuration-information"></a>

```
reg query HKLM\system\CurrentControlSet\Services\Tcpip\Parameters\ /s
reg query HKLM\system\CurrentControlSet\Services\Tcpip6\Parameters\ /s
```

## RDP

### RDP Cache images <a href="#rdp-cache-images" id="rdp-cache-images"></a>

This can be used to display some fragments of images which a user could see when operating on a server using the Windows RDP. The cache files are located: %USERPROFILE%\AppData\Local\Microsoft\Terminal Server Client\Cache\\

These can be parsed using [BMC-Tools](https://github.com/ANSSI-FR/bmc-tools)

```
bmc-tools.py -s ./ -d ./output
bmc-tools.py -s ./ -d ./output -o -b 	
```

### RDP (Terminal Services) Activity <a href="#rdp-terminal-services-activity" id="rdp-terminal-services-activity"></a>

```
reg query 'HKU\{SID}\Software\Microsoft\Terminal Server Client' /s
```

### RDP (Terminal Services) Configuration <a href="#rdp-terminal-services-configuration" id="rdp-terminal-services-configuration"></a>

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /s
```

### **Check if Terminal Services Enabled**

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
```

### **Check if one session per user has been modified**

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser
```

### **Check if port number has been modified**

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp" /v PortNumber
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber
```

## DLL Information <a href="#enable-logging-of-non-non-windows-module-loads-via-wdac-code-integrity" id="enable-logging-of-non-non-windows-module-loads-via-wdac-code-integrity"></a>

### Extract Module (DLL, SYS and EXE) information from WDAC Audit Events <a href="#extract-module-dll-sys-and-exe-information-from-wdac-audit-events" id="extract-module-dll-sys-and-exe-information-from-wdac-audit-events"></a>

```
# Extract relevant properties from 3076 events
# Modified by Jai Minton @CyberRaiju, based from original work by Matt Graeber @mattifestation 

# On an enterprise system enable it by creating a module load audit policy: https://twitter.com/mattifestation/status/1366435525272481799
	# ConvertFrom-CIPolicy Non_Microsoft_UserMode_Load_Audit.xml C:\Windows\System32\CodeIntegrity\SIPolicy.p7b
# Store the converted policy on a Win10 system to be monitored at: Windows\System32\CodeIntegrity\SIPolicy.p7b
# If you don't have one available you can use a pre-converted one found [here](https://github.com/JPMinty/Misc-Tools/blob/main/Windows-Defender-Application-Control-WDAC/SIPolicy.p7b)

# More information:
# https://gist.githubusercontent.com/mattifestation/de140831d47e15370ba35c1877f39082/raw/8db18ab36723cc9eaf9770c2cadafe46460ff80e/3076EventExtractor.ps1
# https://posts.specterops.io/threat-detection-using-windows-defender-application-control-device-guard-in-audit-mode-602b48cd1c11
# https://github.com/mattifestation/WDACTools

$SigningLevelMapping = @{
[Byte] 0 = 'Unchecked'
[Byte] 1 = 'Unsigned'
[Byte] 2 = 'Enterprise'
[Byte] 3 = 'Custom1'
[Byte] 4 = 'Authenticode'
[Byte] 5 = 'Custom2'
[Byte] 6 = 'Store'
[Byte] 7 = 'Antimalware'
[Byte] 8 = 'Microsoft'
[Byte] 9 = 'Custom4'
[Byte] 0xA = 'Custom5'
[Byte] 0xB = 'DynamicCodegen'
[Byte] 0xC = 'Windows'
[Byte] 0xD = 'WindowsProtectedProcessLight'
[Byte] 0xE = 'WindowsTcb'
[Byte] 0xF = 'Custom6'
}

$CIEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3076} | ForEach-Object {
	$ScenarioValue = $_.Properties[16].Value.ToString()
	$Scenario = $ScenarioValue
		switch ($Scenario) {
		'0' { $Scenario = 'Kernel-Mode' }
		'1' { $Scenario = 'User-Mode' }
	}
	[PSCustomObject] @{
		TimeCreated = $_.TimeCreated
		MachineName = $_.MachineName
		UserId = $_.UserId
		FileName = $_.Properties[1].Value
		ProcessName = $_.Properties[3].Value
		CertificateSHA1AuthentiCodeHash = [BitConverter]::ToString($_.Properties[8].Value).Replace('-', '')
		CertificateSHA256AuthentiCodeHash = [BitConverter]::ToString($_.Properties[10].Value).Replace('-', '')
		ModuleSHA1Hash = [BitConverter]::ToString($_.Properties[12].Value).Replace('-', '')
		ModuleSHA256Hash = [BitConverter]::ToString($_.Properties[14].Value).Replace('-', '')
		OriginalFileName = $_.Properties[24].Value
		InternalName = $_.Properties[26].Value
		FileDescription = $_.Properties[28].Value
		ProductName = $_.Properties[30].Value
		FileVersion = $_.Properties[31].Value
		SISigningScenario = $Scenario
		RequestedSigningLevel = $SigningLevelMapping[$_.Properties[4].Value]
		ValidatedSigningLevel = $SigningLevelMapping[$_.Properties[5].Value]
		PolicyHash = [BitConverter]::ToString($_.Properties[22].Value).Replace('-', '')
	}
}
$CIEvents
```

### Obtain DLL information [ListDLLs](https://docs.microsoft.com/en-us/sysinternals/downloads/listdlls) <a href="#obtain-dll-information-listdlls" id="obtain-dll-information-listdlls"></a>

```
listdlls [-r] [-v | -u] [processname|pid]
listdlls [-r] [-v] [-d dllname]
```

### Obtain unsigned DLL information loaded by processes <a href="#obtain-unsigned-dll-information-loaded-by-processes" id="obtain-unsigned-dll-information-loaded-by-processes"></a>

```
listdlls -u
```

### Obtain DLLs in use by processes <a href="#obtain-dlls-in-use-by-processes" id="obtain-dlls-in-use-by-processes"></a>

```
listdlls -v processname -accepteula
listdlls -v -d dllname.dll -accepteula
listdlls -v PID -accepteula
```

### Determine handles on a file <a href="#determine-handles-on-a-file" id="determine-handles-on-a-file"></a>

```
handle [[-a] [-u] | [-c <handle> [-l] [-y]] | [-s]] [-p <processname>|<pid>> [name]
handle -a -u -s -p exp
handle windows\system
```

## DNS <a href="#verify-eternalblue-patch-ms17-010-is-installed---microsoft" id="verify-eternalblue-patch-ms17-010-is-installed---microsoft"></a>

### Obtain TXT records from recently resolved domains <a href="#obtain-txt-records-from-recently-resolved-domains" id="obtain-txt-records-from-recently-resolved-domains"></a>

```
foreach ($domains in Get-DnsClientCache){Resolve-DnsName $domains.Entry -Type "TXT"|Select Strings|? Strings -NotLike ""};
```

## Active Directory

### Active Directory Investigation <a href="#active-directory-investigation" id="active-directory-investigation"></a>

Note: Live information can be found using [DSQuery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732952\(v=ws.11\)) or [Netdom](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc772217\(v=ws.11\)).

```
dsquery computer
dsquery user
dsquery contact
dsquery domainroot -inactive 4
dsquery group
dsquery ou
dsquery site
dsquery server
dsquery quota
dsquery *
	- dsquery * -limit 999999999
netdom query fsmo
netdom query trust
netdom query pdc
netdom query DC
netdom query server
netdom query workstation
netdom query OU
```

### **NT Directory Services Directory Information Tree File (ntds.dit)**

Active Directory Database file containing all schema, domain, configuration information (e.g. users, IP, computers, domain trusts etc)

* %SystemRoot%\NTDS\ntds.dit
* %SystemRoot%\System32\ntds.dit
  * File created only when promoting certain OS to a DC, and seldom used.

**Edb.log**

10MB transaction log used to store temporary data before it is sent to the ntds.dit database.

* %SystemRoot%\NTDS\Edb.log

**Edbxxxxx.log**

Additional transaction log files if the main edb.log file gets larger than 10MB without being flushed to ntds.dit.

* %SystemRoot%\NTDS\edbxxxxx.log

**Edb.chk**

Checkpoint file used to determine how much of the transaction logs have been sent to the ntdis.dit database.

* %SystemRoot%\NTDS\edb.chk

**Resx.log/Resx.jrs**

Reserved log files in case the hard drive fills up, at which point these files will be used (ideally they should never be used).

* %SystemRoot%\NTDS\res1.log
* %SystemRoot%\NTDS\res2.log

**Temp.edb**

Temporary file to store information during in progress transactions.

* %SystemRoot%\NTDS\temp.edb

**Schema.ini**

Initialises the ntds.dit file when the domain controller is created, and is then never used again.

* %SystemRoot%\NTDS\schema.ini

**Investigation of ntds.dit**

Obtaining this file can be done using any of the following and also requires the SYSTEM hive to decrypt (note: ntdsutil may not work on older AD servers).

(Output will be under C:\Audit)

ntdsutil

```
ntdsutil "activate instance ntds" ifm "create full C:\Audit" quit quit
```

vssadmin

```
vssadmin create shadow /for=C:
mkdir C:\Audit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[Number]\Windows\ntds\ntds.dit C:\Audit\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[Number]\Windows\System32\config\SYSTEM C:\Audit\SYSTEM
vssadmin delete shadows /shadow=[ShadowCopyID]
```

Other ‘less legitimate’ replication methods can be found detailed on the [AD Security Blog by Sean Metcalf](https://adsecurity.org/?p=2398#MimikatzDCSync)

* Or by using [Invoke-NinjaCopy](https://github.com/clymb3r/PowerShell/blob/master/Invoke-NinjaCopy/Invoke-NinjaCopy.ps1)

Repair the file if required:

```
esentutl /p /o C:\Audit\ntds.dit
```

Analyzing this file offline can be done with tactics such as:

* [Ropnop - Extract Hashes and Domain Info](https://blog.ropnop.com/extracting-hashes-and-domain-info-from-ntds-dit/)
