# Memory Forensics

## Guides and Theory

### Key Concepts

* **VAD (Virtual Address Descriptor)**: Data structure used by the Windows Memory Manager to describe memory ranges used by a process as they are allocated. Critical for spotting injected code affecting memory permissions (e.g., PAGE_EXECUTE_READWRITE).
* **DKOM (Direct Kernel Object Manipulation)**: A technique used by malware to hide processes/threads by unlinking them from OS lists (like the EPROCESS list) without modifying the actual objects, making them invisible to standard tools.
* **Pool Memory**: Kernel memory allocation. "Pool Tagging" helps identify which driver allocated a chunk of memory.

### Dump Full Process Memory <a href="#dump-full-process-memory" id="dump-full-process-memory"></a>

(Requires **Sysinternals ProcDump**)

```
procdump -ma [processID]
```

### Powershell Memory Capture

On systems where the `Microsoft.Windows.Storage` namespace is available (Windows 8/Server 2012 and later), PowerShell can be used to invoke a native live memory dump.

```
$ss = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage;
Invoke-CimMethod -InputObject $ss -MethodName "GetDiagnosticInfo" -Arguments @{DestinationPath="[LOCATION]\dmp"; IncludeLiveDump=$true};
```

* [Reference Tweet (@0gtweet)](https://twitter.com/0gtweet/status/1273264867382788096?s=20)

## Live Triage of Memory <a href="#live-triage-of-memory" id="live-triage-of-memory"></a>

> **Note:** Most of these commands, especially those interacting with other processes or system memory, require **Administrative** or **SYSTEM** privileges.

Credits to Matt Graeber, Jared Atkinson, and Joe Desimone for these scripts. Note: These techniques are effective against standard Meterpreter payloads and default Cobalt Strike configurations, though heavily dependent on the specific environment and EDR solutions present.

* [PowerShellArsenal](https://github.com/JPMinty/PowerShellArsenal)
* [Get-InjectedThread](https://gist.github.com/JPMinty/beffcd18d8ec06b73643c2f38cde384d)

### **Locate Possible Shellcode within process via Injected Thread**

```powershell
. .\Get-InjectedThread.ps1
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

```powershell
# Check a specific PID
Find-ProcessPEs -ProcessID {PID} | Where-Object {$_.ModuleName -eq "metsrv.dll" -or $_.ModuleName -eq "ext_server_stdapi.dll" -or $_.ModuleName -like "ext_server_*.dll"} | Format-List ProcessID,ModuleName,Imports

# Check all processes
Get-Process | ForEach-Object {
    Find-ProcessPEs -ProcessID $_.Id | Where-Object {
        $_.ModuleName -eq "metsrv.dll" -or 
        $_.ModuleName -eq "ext_server_stdapi.dll" -or 
        $_.ModuleName -like "ext_server_*.dll"
    } | Format-List ProcessID,ModuleName,Imports
}
```

### **Find Cobalt Strike in Process Memory:**

```powershell
# Check a specific PID
Find-ProcessPEs -ProcessID {PID} | Where-Object {$_.ModuleName -eq "beacon.dll" -or $_.ModuleName -eq "beacon x64.dll" -or $_.ModuleName -eq "beacon.x64.dll"} | Format-List ProcessID,ModuleName,Imports

# Check all processes
Get-Process | ForEach-Object {
    Find-ProcessPEs -ProcessID $_.Id | Where-Object {
        $_.ModuleName -eq "beacon.dll" -or 
        $_.ModuleName -eq "beacon x64.dll" -or 
        $_.ModuleName -eq "beacon.x64.dll"
    } | Format-List ProcessID,ModuleName,Imports
}
```

### In memory files locked by OS

To obtain these files while they’re in use you can use a low level file extractor such as [RawCopy](https://github.com/jschicht/RawCopy)

hiberfil.sys (Stores RAM contents during system hibernation)

* %SystemRoot%\hiberfil.sys

pagefile.sys (Paging file used for virtual memory)

* %SystemDrive%\pagefile.sys

swapfile.sys (Used by Windows Store (UWP) apps for swapping)

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
* [LiveKD](https://docs.microsoft.com/en-us/sysinternals/downloads/livekd) - Written by Mark Russinovich, _LiveKD_ allows you to run the Kd and Windbg Microsoft kernel debuggers locally on a live system.
* [WinPMem](https://github.com/Velocidex/WinPmem/releases) - The Memory forensics utility found within the [Velociraptor](https://github.com/Velocidex/velociraptor) toolset.
  * [https://winpmem.velocidex.com/docs/memory/](https://winpmem.velocidex.com/docs/memory/)
* [dumpscan](https://github.com/daddycocoaman/dumpscan) - **Dumpscan** is a command-line tool designed to extract and dump secrets from kernel and Windows Minidump formats. Kernel-dump parsing is provided by [volatility3](https://github.com/volatilityfoundation/volatility3).
* [MemProcFS](https://github.com/ufrisk/MemProcFS) - The Memory Process File System. Visualizes memory as a virtual file system for easy mounting and analysis.
* [PE-sieve](https://github.com/hasherezade/pe-sieve) - A light-weight tool that scans processes for hollowed processes, shellcode, and hooks.
* [FTK Imager](https://www.exterro.com/ftk-imager) - Widely used simplified tool for creating forensic images (including memory) without altering evidence.

## Legacy / Specialized Utils

* [aeskeyfind](https://www.kali.org/tools/aeskeyfind/) - Illustrates automatic techniques for locating 128-bit and 256-bit AES keys in a captured memory image (2008).
* [rsakeyfind](https://www.kali.org/tools/rsakeyfind/) - Locates BER-encoded RSA private keys in memory images (2010). Modern Volatility plugins often handle this.

```
winpmem.exe -o test.aff4 -dd
winpmem.exe -o test.raw --format raw -dd
```

## **Resources**

* [MemLabs](https://github.com/stuxnet999/MemLabs) - Educational, CTF-styled labs for individuals interested in Memory Forensics&#x20;
* [https://www.howtogeek.com/196672/windows-memory-dumps-what-exactly-are-they-for/](https://www.howtogeek.com/196672/windows-memory-dumps-what-exactly-are-they-for/)
* SANS Memory Forensics CheatSheet

![](<../../../.gitbook/assets/image (8) (1) (1).png>)
