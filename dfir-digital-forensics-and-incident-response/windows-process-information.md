# Windows Process Information

This section covers commands and techniques for gathering information about running processes on Windows systems using native tools (CMD, PowerShell) and Sysinternals.

## Process Enumeration

### Command Prompt (CMD)

Native Windows commands to list process details.

```cmd
tasklist -v
```

### PowerShell

PowerShell commands for detailed process analysis. `Get-CimInstance` is preferred in modern PowerShell versions, while `Get-WmiObject` (gwmi) is legacy.

```powershell
# Modern (CIM)
Get-CimInstance Win32_Process -Filter "name like 'powershell.exe'" | Select-Object Name, ProcessId, CommandLine | FL

# Legacy (WMI)
gwmi win32_process -Filter "name like 'powershell.exe'" | select name,processId,commandline|FL

# Other Examples
gwmi win32_process | select name,processId,path,commandline|FL
gwmi win32_process |FL ProcessID,ParentProcessID,CommandLine,@{e={$_.GetOwner().User}}
gwmi win32_process | Sort-Object -Property ProcessID | FL ProcessID,Path,CommandLine,ParentProcessID,@{n="User";e={$_.GetOwner().User}},@{n="ParentProcessPath";e={gps -Id $_.ParentProcessID|Select -exp Path}}
```

### Network and Services

Identify network connections and services tied to processes.

```cmd
# Network to Process (CMD)
netstat -ano | findstr [PID]

# Network to Process (PowerShell)
Get-NetTCPConnection -OwningProcess [PID] | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime

# Services hosted in a process (e.g., svchost)
tasklist /svc /fi "imagename eq svchost.exe"
```

### Sysinternals

*Note: `pslist` is part of the [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/).*

```cmd
pslist
```

### Process Tree Visualization

[PowerShell Module to show Process Tree](https://gist.github.com/JPMinty/f4d60adafdfbc12b0e4226a27bf1dcb0)

```powershell
import-module .\Get-ProcessTree.ps1
Get-ProcessTree -Verbose | FT Id, Level, IndentedName, ParentId,Path,CommandLine
```

### Checking for Running Processes (Remote)

```powershell
Invoke-Command -ScriptBlock {Get-Process} -Session $s1
```

## Baseline Processes and Services

Technique to compare current state against a known good baseline.

```powershell
# Create Baseline
Get-Process | Export-Clixml -Path C:\Users\User\Desktop\process.xml
Get-Service | Export-Clixml -Path C:\Users\User\Desktop\service.xml

# Import and Compare
$edproc = Import-Clixml -Path C:\Users\User\Desktop\process.xml
$edproc1 = Import-Clixml -Path C:\Users\User\Desktop\process1.xml
$edservice = Import-Clixml -Path C:\Users\User\Desktop\service.xml
$edservice1 = Import-Clixml -Path C:\Users\User\Desktop\service1.xml

Compare-Object $edproc $edproc1 -Property processname
Compare-Object $edservice $edservice1 -Property servicename
```

## Suspicious Locations

### Current Process Execution or Module Loads from Temporary Directories

*Note: This search checks for keywords like "Appdata", "Temp", etc. Be aware of false positives (e.g., 'ItemProvider' matches 'temp').*

```powershell
(gps -Module -ea 0).FileName|Select-String "Appdata","ProgramData","Temp","Users","public"|unique
```

### Suspicious Locations + File Hash

Calculates the hash of files found in suspicious locations for further verification.

```powershell
# Check loaded modules
$A=((gps -Module -ea 0).FileName|Select-String "Appdata","ProgramData","Temp","Users","public"|sort|unique);foreach ($B in $A) {filehash $B};

# Check running process paths
$A=((gps).Path|Select-String "Appdata","ProgramData","Temp","Users","public"|sort|unique);foreach ($B in $A) {filehash $B};
```

## Process Handles

Locate files or resources opened by a specific process.

*Note: Requires `handle.exe`/`handle64.exe` from Sysinternals.*

### Locate Process Handles

```cmd
handle64.exe -p [PID/name] -nobanner
handle64.exe -a -p [PID/name] -nobanner
handle64.exe -a -l -p [PID/name] -nobanner
handle64.exe -a -l -u -p keepass -nobanner
```

### Close Process Handles

Forcefully close a handle (use with caution).

```cmd
handle64.exe -c [hexhandleref] -p [PID] -nobanner
handle64.exe -c [hexhandleref] -y -p [PID] -nobanner
```

## Hashes of Processes and Artifacts

### Obtain Hash for All Running Executables

**PowerShell (Pipeline)**
*Credit: Lee Holmes*

```powershell
(gps|gi -ea SilentlyContinue|filehash).hash|sort -u
```

**Alternative PowerShell Method**

```powershell
foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | Format-List}

foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}

$A = $( foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}) |Sort-Object| Get-Unique;$A
```

### Obtain Hash of DLLs Currently Loaded by Processes

### Processes Where Binary Version Doesn’t Match OS Release

Useful for finding misplaced or outdated system binaries.

```powershell
gps -FileVersionInfo -ea 0|? {$_.ProductVersion -notmatch $([System.Environment]::OSVersion.Version|Select -exp Build)}
```

### Obtain Process Binary Original Names (Masquerading Check)

Compare `OriginalFilename` with the running `Filename` to detect renamed binaries (e.g., `svchost.exe` running as `notmalware.exe`).

```powershell
gps -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | FL *name,*version
```

### Obtain Processes Loading Specific DLLs

Example: checking for `sechost.dll` or `ntdll.dll`.

```powershell
$A=(gps|select -ExpandProperty modules -ea SilentlyContinue | where {$_.ModuleName -Like 'sechost.dll' -or $_.ModuleName -Like 'ntdll.dll'} | sort -u);if($A[0].Size -ge -1) {foreach ($Module in $A){tasklist /m $Module.ModuleName}};
gps | FL ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
```

### Obtain Hash of Unsigned or Invalid DLLs

Checks loaded modules for digital signature status and hashes invalid ones.

```powershell
$A=$(foreach ($dll in gps|select -ExpandProperty modules -ea SilentlyContinue){Get-AuthenticodeSignature $dll.FileName |Where-Object Status -NE "Valid"|Select Path});$B=$(foreach ($dll in $A){Get-FileHash $dll.Path| select Hash -ExpandProperty Hash})|Sort-Object| Get-Unique;$B
```

### List Unsigned DLLs

```powershell
gps | select -exp modules -ea 0 | Select -exp FileName | Get-AuthenticodeSignature|Where-Object Status -NE "Valid"
gps | select -exp modules -ea 0 | Select -exp FileName | Get-AuthenticodeSignature | ? Status -NE "Valid" | FL Path
```

## Process Scanning (Event Logs)

### Scan Process Creation Logs for Keywords

Scans Security Log Event ID 4688 (Process Creation) for keywords like 'appdata'.
*Note: Requires Process Creation Auditing to be enabled.*

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4688';}| ? {$_.Message -match 'appdata'}|FL TimeCreated, Message
```

## Deprecated / Legacy Tools

### WMIC (Windows Management Instrumentation Command-line)

*Note: WMIC is deprecated in Windows 10 and 11 and is being removed. Use PowerShell (CIM/WMI) instead.*

**Process Enumeration:**

```cmd
wmic process list full /format:csv
wmic process get name,parentprocessid,processid /format:csv
wmic process get ExecutablePath,processid /format:csv
wmic process get name,ExecutablePath,processid,parentprocessid /format:csv | findstr /I "appdata"
wmic process where processid=[PID] get parentprocessid
wmic process where commandline is not null get name,commandline /format:csv
```

**Hash Running Executables (Loop):**

```cmd
FOR /F %i IN ('wmic process where "ExecutablePath is not null" get ExecutablePath') DO certutil -hashfile %i SHA256 | findstr -v : >> output.txt
```

## Recommended Functional Resources

*   **[Sysinternals Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)**: Advanced Task Manager replacement.
*   **[Sysinternals Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)**: Real-time file system, Registry, and process/thread activity.
*   **[System Informer](https://systeminformer.sourceforge.io/)** (formerly Process Hacker): A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
