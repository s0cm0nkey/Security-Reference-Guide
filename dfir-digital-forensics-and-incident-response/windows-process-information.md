# Windows Process Information

## Process information <a href="#process-information" id="process-information"></a>

(pslist requires sysinternals pslist.exe):

```
tasklist -v
wmic process list full /format:csv
wmic process get name,parentprocessid,processid /format:csv
wmic process get ExecutablePath,processid /format:csv
wmic process get name,ExecutablePath,processid,parentprocessid /format:csv | findstr /I "appdata"
wmic process where processid=[PID] get parentprocessid
wmic process where processid=[PID] get commandline
wmic process where "commandline is not null and commandline!=''" get name,commandline /format:csv
gwmi win32_process -Filter "name like 'powershell.exe'" | select name,processId,commandline|FL
gwmi win32_process | select name,processId,path,commandline|FL
gwmi win32_process |FL ProcessID,ParentProcessID,CommandLine,@{e={$_.GetOwner().User}}
gwmi win32_process | Sort-Object -Property ProcessID | FL ProcessID,Path,CommandLine,ParentProcessID,@{n="User";e={$_.GetOwner().User}},@{n="ParentProcessPath";e={gps -Id $_.ParentProcessID|Select -exp Path}}
pslist
```

[PowerShell Module to show Process Tree](https://gist.github.com/JPMinty/f4d60adafdfbc12b0e4226a27bf1dcb0)

```
import-module .\Get-ProcessTree.ps1
Get-ProcessTree -Verbose | FT Id, Level, IndentedName, ParentId,Path,CommandLine
```

### Checking for running processes <a href="#checking-for-running-processes" id="checking-for-running-processes"></a>

```
Invoke-Command -ScriptBlock {Get-Process} -Session $s1
```

### Baseline processes and services <a href="#baseline-processes-and-services" id="baseline-processes-and-services"></a>

(Used to compare new process/services)

```
Get-Process | Export-Clixml -Path C:\Users\User\Desktop\process.xml
Get-Service | Export-Clixml -Path C:\Users\User\Desktop\service.xml
$edproc = Import-Clixml -Path C:\Users\User\Desktop\process.xml
$edproc1 = Import-Clixml -Path C:\Users\User\Desktop\process1.xml
$edservice = Import-Clixml -Path C:\Users\User\Desktop\service.xml
$edservice1 = Import-Clixml -Path C:\Users\User\Desktop\service1.xml
Compare-Object $edproc $edproc1 -Property processname
Compare-Object $edservice $edservice1 -Property servicename
```

### Current Process execution or module loads from temporary directories <a href="#current-process-execution-or-module-loads-from-temporary-directories" id="current-process-execution-or-module-loads-from-temporary-directories"></a>

Note: This will likely have some false positives as it’s just a wildcard. So in this case using ‘temp’ can come up in words such as ‘ItemProvider’.

```
(gps -Module -ea 0).FileName|Select-String "Appdata","ProgramData","Temp","Users","public"|unique
```

### Current Process execution or module loads from temporary directories + hash <a href="#current-process-execution-or-module-loads-from-temporary-directories--hash" id="current-process-execution-or-module-loads-from-temporary-directories--hash"></a>

```
$A=((gps -Module -ea 0).FileName|Select-String "Appdata","ProgramData","Temp","Users","public"|sort|unique);foreach ($B in $A) {filehash $B};
$A=((gps).Path|Select-String "Appdata","ProgramData","Temp","Users","public"|sort|unique);foreach ($B in $A) {filehash $B};
```

## Process Handles <a href="#locate-process-handles-eg-files-open-by-process" id="locate-process-handles-eg-files-open-by-process"></a>

### Locate process handles (e.g. files open by process) <a href="#locate-process-handles-eg-files-open-by-process" id="locate-process-handles-eg-files-open-by-process"></a>

_Note: Requires handles/handles64.exe from sysinternals_

```
handle64.exe -p [PID/name] -nobanner
handle64.exe -a -p [PID/name] -nobanner
handle64.exe -a -l -p [PID/name] -nobanner
handle64.exe -a -l -u -p keepass -nobanner
```

### Close process handles (e.g. files open by process) <a href="#close-process-handles-eg-files-open-by-process" id="close-process-handles-eg-files-open-by-process"></a>

_Note: Requires handles/handles64.exe from sysinternals_

```
handle64.exe -c [hexhandleref] -p [PID] -nobanner
handle64.exe -c [hexhandleref] -y -p [PID] -nobanner
```

## Hashes of Processes and Artifacts

### Obtain hash for all running executables <a href="#obtain-hash-for-all-running-executables" id="obtain-hash-for-all-running-executables"></a>

**Issues with spaces in names but supports CMD.exe**

```
FOR /F %i IN ('wmic process where "ExecutablePath is not null" get ExecutablePath') DO certutil -hashfile %i SHA256 | findstr -v : >> output.txt
```

**Powershell (Special thanks Lee Holmes)**

```
(gps|gi -ea SilentlyContinue|filehash).hash|sort -u
```

**My less efficient powershell**

```
foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | Format-List}

foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}

$A = $( foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}) |Sort-Object| Get-Unique;$A
```

### Obtain hash of DLLs currently loaded by processes <a href="#obtain-hash-of-dlls-currently-loaded-by-processes" id="obtain-hash-of-dlls-currently-loaded-by-processes"></a>

```
$A = $(foreach ($dll in gps|select -ExpandProperty modules -ea SilentlyContinue|? FileName -NotLike "C:\Windows\SYSTEM32\*"){Get-FileHash $dll.FileName| select Hash -ExpandProperty Hash})|Sort-Object| Get-Unique;$A
(gps).Modules.FileName | sort -uniq | foreach {filehash $_ -ea 0}
```

### Obtain processes where binaries file version doesn’t match OS Release <a href="#obtain-processes-where-binaries-file-version-doesnt-match-os-release" id="obtain-processes-where-binaries-file-version-doesnt-match-os-release"></a>

```
gps -FileVersionInfo -ea 0|? {$_.ProductVersion -notmatch $([System.Environment]::OSVersion.Version|Select -exp Build)}
```

### Obtain process binary file external names <a href="#obtain-process-binary-file-external-names" id="obtain-process-binary-file-external-names"></a>

```
gps -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | FL *name,*version
```

### Obtain processes running which are running a DLL <a href="#obtain-processes-running-which-are-running-a-dll" id="obtain-processes-running-which-are-running-a-dll"></a>

```
$A=(gps|select -ExpandProperty modules -ea SilentlyContinue | where {$_.ModuleName -Like 'sechost.dll' -or $_.ModuleName -Like 'ntdll.dll'} | sort -u);if($A[0].Size -ge -1) {foreach ($Module in $A){tasklist /m $Module.ModuleName}};
gps | FL ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
```

### Obtain hash of unsigned or invalid DLLs currently loaded by processes <a href="#obtain-hash-of-unsigned-or-invalid-dlls-currently-loaded-by-processes" id="obtain-hash-of-unsigned-or-invalid-dlls-currently-loaded-by-processes"></a>

```
$A=$(foreach ($dll in gps|select -ExpandProperty modules -ea SilentlyContinue){Get-AuthenticodeSignature $dll.FileName |Where-Object Status -NE "Valid"|Select Path});$B=$(foreach ($dll in $A){Get-FileHash $dll.Path| select Hash -ExpandProperty Hash})|Sort-Object| Get-Unique;$B
```

### Obtain list of unsigned DLLs currently loaded by processes <a href="#obtain-list-of-unsigned-dlls-currently-loaded-by-processes" id="obtain-list-of-unsigned-dlls-currently-loaded-by-processes"></a>

```
gps | select -exp modules -ea 0 | Select -exp FileName | Get-AuthenticodeSignature|Where-Object Status -NE "Valid"
gps | select -exp modules -ea 0 | Select -exp FileName | Get-AuthenticodeSignature | ? Status -NE "Valid" | FL Path
```

## Process Scanning

### Scan process creation logs for ‘appdata’ <a href="#scan-process-creation-logs-for-appdata" id="scan-process-creation-logs-for-appdata"></a>

```
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4688';}| ? {$_.Message -match 'appdata'}|FL TimeCreated, Message
```
