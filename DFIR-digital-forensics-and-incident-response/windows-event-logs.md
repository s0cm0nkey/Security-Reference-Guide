# Windows Event Logs

## Get available Logs

### Powershell logs <a href="#powershell-logs" id="powershell-logs"></a>

```
Get-WinEvent -LogName "Windows Powershell"
```

### Event logs available <a href="#event-logs-available" id="event-logs-available"></a>

```
Get-EventLog -list
Get-WinEvent -Listlog * | Select RecordCount,LogName 
Get-WinEvent -Listlog *operational | Select RecordCount,LogName
wmic nteventlog list brief
```

### Event Logs per Application Source <a href="#event-logs-per-application-source" id="event-logs-per-application-source"></a>

```
Get-EventLog Application | Select -Unique Source
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='Outlook'}
Get-WinEvent -FilterHashtable @{ LogName='OAlerts';} | FL TimeCreated, Message
```

### Event Logs per Severity Source <a href="#event-logs-per-severity-source" id="event-logs-per-severity-source"></a>

**Critical Logs**

```
Get-WinEvent -FilterHashtable @{ LogName='Application'; Level='1';}
```

**Error Logs**

```
Get-WinEvent -FilterHashtable @{ LogName='Application'; Level='2';}
```

**Warning Logs**

```
Get-WinEvent -FilterHashtable @{ LogName='Application'; Level='3';}
```

**Information Logs**

```
Get-WinEvent -FilterHashtable @{ LogName='Application'; Level='4';}
```

## Event Logs for offline analysis <a href="#event-logs-for-offline-analysis" id="event-logs-for-offline-analysis"></a>

Event logs can be found: %SystemRoot%\System32\winevt\Logs

```
wevtutil epl System [Location]\System.evtx
wevtutil epl Security [Location]\Security.evtx
wevtutil epl Application [Location]\Application.evtx
wevtutil epl "Windows PowerShell" [Location]\Powershell.evtx
```

OR:

```
esentutl.exe /y /vss C:\Windows\System32\winevt\Logs\Security.evtx /d [Location]\Security.evtx
```

Copy all event logs:

```
XCOPY C:\Windows\System32\winevt\Logs [Location] /i
XCOPY C:\WINDOWS\system32\LogFiles\ [Location] /i
```

### [User Access Logging (UAL) KStrike Parser](https://github.com/brimorlabs/KStrike) <a href="#user-access-logging-ual-kstrike-parser" id="user-access-logging-ual-kstrike-parser"></a>

Note: More information can be found [here](https://docs.microsoft.com/en-us/windows-server/administration/user-access-logging/manage-user-access-logging). Special thanks to Brimor Labs.

```
KStrike.py SYSTEMNAME\Current.mdb > Current_mdb.txt
```

mdb Files are found at the below:

```
%SystemRoot%\Windows\System32\Logfiles\SUM
```

More information available on the [CrowdStrike Blog - Patrick Bennett](https://www.crowdstrike.com/blog/user-access-logging-ual-overview/)

### Quickly scan event logs with [DeepblueCLI](https://github.com/sans-blue-team/DeepBlueCLI) <a href="#quickly-scan-event-logs-with-deepbluecli" id="quickly-scan-event-logs-with-deepbluecli"></a>

```
.\DeepBlue.ps1 .\evtx\psattack-security.evtx | FL
```

### Event Tracing for Windows (ETW). <a href="#event-tracing-for-windows-etw" id="event-tracing-for-windows-etw"></a>

Event tracing is how a Provider (an application that contains event tracing instrumentation) creates items within the Windows Event Log for a consumer. This is how event logs are generated, and is also a way they can be tampered with. More information on this architecture can be found below.

[Event Tracing Architecture](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)

A great [post by Matt Graeber](https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63) goes into some depth on how this works and some common ways of interacting with ETW Traces.

### **List Running Trace Sessions**

```
logman query -ets
```

### **List Providers That a Trace Session is Subscribed to**

```
logman query "EventLog-System" -ets
```

### **List all ETW Providers**

```
logman query providers
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\
```

### **View providers process is sending events to**

```
logman query providers -pid {PID}
```

### Setup Custom Log Tracing <a href="#setup-custom-log-tracing" id="setup-custom-log-tracing"></a>

Special thanks to [Spotless](https://twitter.com/spotheplanet) for his [crash course](https://www.ired.team/miscellaneous-reversing-forensics/etw-event-tracing-for-windows-101)

### **Query Providers Available and their keyword values**

```
logman query providers
logman query providers Microsoft-Windows-WinHttp
```

Note: Take note of wanted values.

### **Initiate Tracing Session**

```
logman create trace <TRACENAMEHERE> -ets
logman query <TRACENAMEHERE> -ets
```

### Update trace with wanted providers <a href="#update-trace-with-wanted-providers" id="update-trace-with-wanted-providers"></a>

Note: the mask is the combined values wanted. For example if a keyword was 0x1 and another 0x16 and you wanted both you’d use 0x17.

```
logman update <TRACENAMEHERE> -p Microsoft-Windows-WinHttp 0x100000000 -ets
```

### Delete Subscription and Providers <a href="#delete-subscription-and-providers" id="delete-subscription-and-providers"></a>

```
logman update trace <TRACENAMEHERE> --p Microsoft-Windows-WinHttp 0x100000000 -ets
logman stop <TRACENAMEHERE> -ets
```

#### Event Log/Tracing Tampering Detection <a href="#event-logtracing-tampering-detection" id="event-logtracing-tampering-detection"></a>

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\EventLog\ /s /v File
reg query HKLM\SYSTEM\CurrentControlSet\Services\EventLog\ /s /v MaxSize
reg query HKLM\SYSTEM\CurrentControlSet\Services\EventLog\ /s /v Retention
sc.exe query eventlog
gci REGISTRY::HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ -recurse
reg query HKLM\SYSTEM\CurrentControlSet\control\WMI\AutoLogger\ /s /v enable*
```

### Timeline Windows Event Logs. <a href="#timeline-windows-event-logs" id="timeline-windows-event-logs"></a>

An easy way to explore Windows event logs is to dump them into a normalized csv format using EvtxExplorer.

[EvtxExplorer:](https://ericzimmerman.github.io/#!index.md)

```
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv C:\ --csvf AllEvtx.csv
```

From here you can analyse the CSV using Timeline explorer to view relevant information and group by MAPs.

[TimelineExplorer:](https://ericzimmerman.github.io/#!index.md)

### Super Timeline a host: <a href="#super-timeline-a-host" id="super-timeline-a-host"></a>

This can be done using [Plaso (Log2Timeline)](https://plaso.readthedocs.io/en/latest/)

Common IIS logs can often be found in the below locations:

* %SystemDrive%\inetpub\logs\LogFiles
* %SystemRoot%\System32\LogFiles\W3SVC1
* %SystemDrive%\inetpub\logs\LogFiles\W3SVC1
  * Note: replace 1 with the number for your IIS website ID
* %SystemDrive%\Windows\System32\LogFiles\HTTPERR

Common Apache logs can often be found in the below locations:

* /var/log
* /var/log/httpd/access.log
* /var/log/apache/access.log
* /var/log/apache2/access.log
* /var/log/httpd-access.log

Other logs can be found in the below, often using the Event Trace Log (ETL) format:

* C:\Windows\System32\LogFiles
* C:\Windows\Panther

ETL format can be parsed using tracerpt which is included in Windows, some examples below.

```
tracerpt C:\Windows\System32\LogFiles\WMI\Terminal-Services-RPC-Client.etl
tracerpt logfile1.etl logfile2.etl -o logdump.xml -of XML
tracerpt logfile.etl -o logdmp.xml -of XML -lr -summary logdmp.txt -report logrpt.xml
tracerpt logfile1.etl logfile2.etl -o -report
tracerpt logfile.etl counterfile.blg -report logrpt.xml -df schema.xml
tracerpt -rt "NT Kernel Logger" -o logfile.csv -of CSV
```

Software specific logs are often stored in readable formats at any of the following locations.

```
%AppData%\[softwarename] (e.g. C:\Users\[username]\AppData\Roaming\[softwarename]\)
%LocalAppData%\[softwarename] (e.g. C:\Users\[username]\AppData\Local\[softwarename]\)
%programfiles%\[softwarename] (e.g. C:\Program Files\[softwarename]\)
%programfiles(x86)%\[softwarename] (e.g. C:\Program Files (x86)\[softwarename]\)
```

You may also find useful memory crashdumps at the below:

```
C:\Users\[username]\AppData\Local\CrashDumps
C:\Users\[username]\AppData\Local\Microsoft\Windows\WER\
```
