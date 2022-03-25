# Memory Forensics

## Guides and Theory

### Dump full process memory <a href="#dump-full-process-memory" id="dump-full-process-memory"></a>

(procdump requires systinternals procdump.exe)

```
procdump -ma [processID]
```

### Powershell Memory Capture

Where the Microsoft Storage namespace is available (known not to be available in Win7), PowerShell can be used to invoke a native live memory dump.

```
$ss = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage;
Invoke-CimMethod -InputObject $ss -MethodName "GetDiagnosticInfo" -Arguments @{DestinationPath="[LOCATION]\dmp"; IncludeLiveDump=$true};
```

* [https://twitter.com/0gtweet/status/1273264867382788096?s=20](https://twitter.com/0gtweet/status/1273264867382788096?s=20)

## Live Triage of Memory <a href="#live-triage-of-memory" id="live-triage-of-memory"></a>

Shout-out to Matt Graeber, Jared Atkinson and Joe Desimone for the awesome work that has gone into these scripts. Note: Not all tested, appears to work with a standard Meterpreter payload, and by default with Cobalt Strike.

* [PowerShellArsenal](https://github.com/JPMinty/PowerShellArsenal)
* [Get-InjectedThread](https://gist.github.com/JPMinty/beffcd18d8ec06b73643c2f38cde384d)

### **Locate Possible Shellcode within process via Injected Thread**

```
Import-Module .\Get-InjectedThread.ps1
Get-InjectedThread
```

### **Obtain Possible Shellcode within process as Hex**

```
(Get-InjectedThread|Select -exp Bytes|ForEach-Object ToString X2) -join ''
(Get-InjectedThread|? {$_.ThreadId -match '{PID}'}|Select -exp Bytes|ForEach-Object ToString X2) -join ''
```

### **Obtain Possible Shellcode within process as Hex**

```
(Get-InjectedThread|Select -exp Bytes|ForEach-Object ToString X2) -join '\x'
(Get-InjectedThread|? {$_.ThreadId -match '{PID}'}|Select -exp Bytes|ForEach-Object ToString X2) -join '\x'
```

### **Basic Memory Analysis via PowerShellArsenal**

```
import-module .\PowerShellArsenal.psd1
Find-ProcessPEs
Get-ProcessStrings
Get-ProcessMemoryInfo -ProcessID {PID}
Get-VirtualMemoryInfo
```

### **Locate Possible Shellcode Address Space**

```
Get-ProcessMemoryInfo {PID} | ? {$_.AllocationProtect -eq "PAGE_EXECUTE_READWRITE"}
```

### **Find Meterpreter in Process Memory:**

Ref: [Meterpreter Wiki](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter)

```
Find-ProcessPEs {PID} | ?{$_.ModuleName -eq "metsrv.dll" -OR $_.ModuleName -eq "ext_server_stdapi.dll" -OR $_.ModuleName -like "ext_server_*.dll"} | FL ProcessID,ModuleName,Imports;
$A=$(gps | Select -exp Id); foreach ($process in $A){Find-ProcessPEs $process | ?{$_.ModuleName -eq "metsrv.dll"} | FL ProcessID,ModuleName,Imports};
$A=$(gps | Select -exp Id);	foreach ($process in $A){Find-ProcessPEs $process | ?{$_.ModuleName -eq "metsrv.dll" | FL ProcessID,ModuleName,Imports};
$A=$(gps | Select -exp Id);	foreach ($process in $A){Find-ProcessPEs $process | ?{$_.ModuleName -eq "metsrv.dll" -OR $_.ModuleName -eq "ext_server_stdapi.dll" -OR $_.ModuleName -like "ext_server_*.dll"} | FL ProcessID,ModuleName,Imports};
```

### **Find Cobalt Strike in Process Memory:**

```
Find-ProcessPEs {PID} | ?{$_.ModuleName -eq "beacon.dll" -OR $_.ModuleName -eq "beacon x64.dll" -OR $_.ModuleName -eq "beacon.x64.dll"} | FL ProcessID,ModuleName,Imports;
$A=$(gps | Select -exp Id); foreach ($process in $A){Find-ProcessPEs $process | ?{$_.ModuleName -eq "beacon.dll"} | FL ProcessID,ModuleName,Imports};
```

### In memory files locked by OS

To obtain these files while they’re in use you can use a low level file extractor such as [RawCopy](https://github.com/jschicht/RawCopy)

hiberfil.sys (RAM stored during machine hibernation)

* %SystemRoot%\hiberfil.sys

pagefile.sys (Virtual memory used by Windows)

* %SystemDrive%\pagefile.sys

swapfile.sys (Virtual memory used by Windows Store Apps)

* %SystemDrive%\swapfile.sys

## Volatility

{% content-ref url="volatility.md" %}
[volatility.md](volatility.md)
{% endcontent-ref %}

## Other Tools

* [LiME, Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)
* [https://github.com/jschicht/RawCopy](https://github.com/jschicht/RawCopy) - Commandline low level file extractor for NTFS
* [Belkasoft Live RAM Capture Tool](https://belkasoft.com/get?product=ram) - Belkasoft Live RAM Capturer is a tiny free forensic tool that allows to reliably extract the entire contents of computer’s volatile memory—even if protected by an active anti-debugging or anti-dumping system.
* [Redline](https://www.fireeye.com/services/freeware/redline.html) - Redline®, FireEye's premier free endpoint security tool, provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis and the development of a threat assessment profile.
  * [https://resources.infosecinstitute.com/topic/memory-analysis-using-redline/](https://resources.infosecinstitute.com/topic/memory-analysis-using-redline/)
* [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - Mandiant’s Memoryze™ is free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images and on live systems can include the paging file in its analysis.
* [MAGNET RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/) - MAGNET RAM Capture is a free imaging tool designed to capture the physical memory of a suspect’s computer, allowing investigators to recover and analyze valuable artifacts that are often only found in memory.
* [Volexity Surge](https://www.volexity.com/products-overview/surge/) - Volexity’s Surge Collect offers flexible storage options and an intuitive interface that any responder can run to eliminate the issues associated with the corrupt data samples, crashed target computers, and ultimately, unusable data that commonly results from using other tools.
  * [https://www.volexity.com/blog/2018/06/12/surge-collect-provides-reliable-memory-acquisition-across-windows-linux-and-macos/](https://www.volexity.com/blog/2018/06/12/surge-collect-provides-reliable-memory-acquisition-across-windows-linux-and-macos/)
* [LiveKD](https://docs.microsoft.com/en-us/sysinternals/downloads/livekd) - Written by the Legendary Mark Russinovich, _LiveKD_ allows you to run the Kd and Windbg Microsoft kernel debuggers, which are part of the [Debugging Tools for Windows package](https://www.microsoft.com/whdc/devtools/debugging/default.mspx), locally on a live system. Execute all the debugger commands that work on crash dump files to look deep inside the system.
* [aeskeyfind](https://www.kali.org/tools/aeskeyfind/) - Illustrates automatic techniques for locating 128-bit and 256-bit AES keys in a captured memory image.
* [WinPMem](https://github.com/Velocidex/WinPmem/releases) - The Memory forensics utility found within the [Velociraptor](https://github.com/Velocidex/velociraptor) toolset.
  * [https://winpmem.velocidex.com/docs/memory/](https://winpmem.velocidex.com/docs/memory/)
* [rsakeyfind](https://www.kali.org/tools/rsakeyfind/) - rsakeyfind is a tool that locates BER-encoded RSA private keys in MEMORY-IMAGE. If a MODULUS-FILE is specified, it will locate private and public keys matching the hex-encoded modulus read from this file.

```
winpmem.exe -o test.aff4 -dd
winpmem.exe -o test.raw --format raw -dd
```

## **Resources**

* [MemLabs](https://github.com/stuxnet999/MemLabs) - Educational, CTF-styled labs for individuals interested in Memory Forensics&#x20;
* [https://www.howtogeek.com/196672/windows-memory-dumps-what-exactly-are-they-for/](https://www.howtogeek.com/196672/windows-memory-dumps-what-exactly-are-they-for/)
* SANS Memory Forensics CheatSheet

![](<../../.gitbook/assets/image (32).png>)
