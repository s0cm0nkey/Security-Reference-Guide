# Volatility

## [Volatility](https://github.com/volatilityfoundation/volatility)

Volatility is a memory forensics framework for extracting and analyzing data from volatile memory (RAM) dumps.

* [Volatility Foundation](https://www.volatilityfoundation.org/)
* [Volatility samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)

### Volatility 3 Resources
* [Volatility 3 Source Code](https://github.com/volatilityfoundation/volatility3/)
* [Volatility 3 Documentation](https://volatility3.readthedocs.io/en/latest/basics.html)
* [Memory Forensics R Illustrated](https://volatility-labs.blogspot.com/2021/10/memory-forensics-r-illustrated.html)

### Volatility 2 (Legacy) Resources
* [Volatility 2 Source Code](https://github.com/volatilityfoundation/volatility)
* [Command Reference (V2 Wiki)](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
* [Evolve](https://github.com/JamesHabben/evolve): Volatility Web UI (for Volatility 2)
* [volatility-autoruns](https://github.com/tomchop/volatility-autoruns/) - Automates most of the tasks you would need to run when trying to find out where malware is persisting from. (for Volatility 2)
* [Memory Forensics and Analysis Using Volatility (InfoSec Institute)](https://resources.infosecinstitute.com/topic/memory-forensics-and-analysis-using-volatility/)
* _Operator Handbook: Volatility - pg. 315_

## Volatility 3.x Basics

[Volatility 3](https://github.com/volatilityfoundation/volatility3/) was released in November 2019 and introduces significant changes to usage and syntax compared to Volatility 2. It is written in Python 3 and no longer requires strict profile selection, instead using symbol tables to automatically detect the OS and profile.

### Common Plugins

#### Linux
* `linux.bash.Bash`
* `linux.check_afinfo.Check_afinfo`
* `linux.check_syscall.Check_syscall`
* `linux.elfs.Elfs`
* `linux.lsmod.Lsmod`
* `linux.lsof.Lsof`
* `linux.malfind.Malfind`
* `linux.proc.Maps`
* `linux.pslist.PsList`
* `linux.pstree.PsTree`

#### macOS
* `mac.bash.Bash`
* `mac.check_syscall.Check_syscall`
* `mac.check_sysctl.Check_sysctl`
* `mac.check_trap_table.Check_trap_table`
* `mac.ifconfig.Ifconfig`
* `mac.lsmod.Lsmod`
* `mac.lsof.lsof`
* `mac.malfind.Malfind`
* `mac.netstat.Netstat`
* `mac.proc_maps.Maps`
* `mac.psaux.Psaux`
* `mac.pslist.PsList`
* `mac.pstree.PsTree`
* `mac.tasks.Tasks`
* `mac.timers.Timers`
* `mac.trustedbsd.trustedbsd`

#### Windows
* `windows.cmdline.CmdLine`
* `windows.dlldump.DllDump`
* `windows.dlllist.DllList`
* `windows.driverirp.DriverIrp`
* `windows.driverscan.DriverScan`
* `windows.filescan.FileScan`
* `windows.handles.Handles`
* `windows.info.Info`
* `windows.malfind.Malfind`
* `windows.moddump.ModDump`
* `windows.modscan.ModScan`
* `windows.modules.Modules`
* `windows.mutantscan.MutantScan`
* `windows.netscan.NetScan`
* `windows.netstat.NetStat`
* `windows.poolscanner.PoolScanner`
* `windows.procdump.ProcDump`
* `windows.pslist.PsList`
* `windows.psscan.PsScan`
* `windows.pstree.PsTree`
* `windows.registry.certificates.Certificates`
* `windows.registry.hivedump.HiveDump`
* `windows.registry.hivelist.HiveList`
* `windows.registry.hivescan.HiveScan`
* `windows.registry.printkey.PrintKey`
* `windows.registry.userassist.UserAssist`
* `windows.ssdt.SSDT`
* `windows.statistics.Statistics`
* `windows.strings.Strings`
* `windows.symlinkscan.SymlinkScan`
* `windows.vaddump.VadDump`
* `windows.vadinfo.VadInfo`
* `windows.virtmap.VirtMap`
* `windows.yarascan.YaraScan`
* `timeliner.Timeliner`

### Usage Examples

Assuming `vol.py` is the Volatility 3 executable and `memory.dmp` is the target memory image.

**Check Memory Image Information**

```bash
python3 vol.py -f memory.dmp windows.info
```

**Check List of Kernel Drivers**

```bash
python3 vol.py -f memory.dmp windows.modules
```

**Check List of Kernel Drivers (incl previously unloaded and hidden)**

```bash
python3 vol.py -f memory.dmp windows.modscan
```

**Dump List of Kernel Drivers to Files**

```bash
python3 vol.py -f memory.dmp windows.moddump
```

**Dump List of Running Processes to Files**

```bash
python3 vol.py -f memory.dmp windows.procdump
```

**Check Process List of Running Processes**

```bash
python3 vol.py -f memory.dmp windows.pslist
```

**Check Process Tree of Running Processes**

```bash
python3 vol.py -f memory.dmp windows.pstree
```

**Check Running Processes from EPROCESS blocks**

```bash
python3 vol.py -f memory.dmp windows.psscan
```

**Check Running Processes for possible shellcode/injection via PAGE_EXECUTE_READWRITE**

```bash
python3 vol.py -f memory.dmp windows.malfind
```

**Check processes and their command lines**

```bash
python3 vol.py -f memory.dmp windows.cmdline
```

**Check for files which exist in memory**

```bash
python3 vol.py -f memory.dmp windows.filescan
```

**Check for network connections**

```bash
python3 vol.py -f memory.dmp windows.netscan
```

**Scan memory with YARA rules**

```bash
python3 vol.py -f memory.dmp windows.yarascan --yara-file /path/to/rules.yar
```
