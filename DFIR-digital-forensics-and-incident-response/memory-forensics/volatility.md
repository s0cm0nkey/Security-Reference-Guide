# Volatility

## [Volatility](https://github.com/volatilityfoundation/volatility)&#x20;

Memory forensics framework for extracting data from RAM.

* [https://www.volatilityfoundation.org/](https://www.volatilityfoundation.org/26)
* [Evolve](https://github.com/JamesHabben/evolve): Volatility Web UI
* [Volatility samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)&#x20;
* [volatility-autoruns](https://github.com/tomchop/volatility-autoruns/) - Automates most of the tasks you would need to run when trying to find out where malware is persisting from. Once all the autostart locations are found, they are matched with running processes in memory.
* [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
* [https://resources.infosecinstitute.com/topic/memory-forensics-and-analysis-using-volatility/](https://resources.infosecinstitute.com/topic/memory-forensics-and-analysis-using-volatility/)
* [https://volatility-labs.blogspot.com/2021/10/memory-forensics-r-illustrated.html](https://volatility-labs.blogspot.com/2021/10/memory-forensics-r-illustrated.html)
* _Operator Handbook: Volatility - pg. 315_

## Volatility 3.x Basics <a href="#volatility-3x-basics" id="volatility-3x-basics"></a>

Note: [Version 3 of Volatility](https://github.com/volatilityfoundation/volatility3/) was released in November 2019 which changes the Volatility usage and syntax. More information on V3 of Volatility can be found on [ReadTheDocs](https://volatility3.readthedocs.io/en/latest/basics.html).

A list of common plugins are:

* linux.bash.Bash
* linux.check\_afinfo.Check\_afinfo
* linux.check\_syscall.Check\_syscall
* linux.elfs.Elfs
* linux.lsmod.Lsmod
* linux.lsof.Lsof
* linux.malfind.Malfind
* linux.proc.Maps
* linux.pslist.PsList
* linux.pstree.PsTree
* mac.bash.Bash
* mac.check\_syscall.Check\_syscall
* mac.check\_sysctl.Check\_sysctl
* mac.check\_trap\_table.Check\_trap\_table
* mac.ifconfig.Ifconfig
* mac.lsmod.Lsmod
* mac.lsof.lsof
* mac.malfind.Malfind
* mac.netstat.Netstat
* mac.proc\_maps.Maps
* mac.psaux.Psaux
* mac.pslist.PsList
* mac.pstree.PsTree
* mac.tasks.Tasks
* mac.timers.Timers
* mac.trustedbsd.trustedbsd
* windows.cmdline.CmdLine
* windows.dlldump.DllDump
* windows.dlllist.DllList
* windows.driverirp.DriverIrp
* windows.driverscan.DriverScan
* windows.filescan.FileScan
* windows.handles.Handles
* windows.info.Info
* windows.malfind.Malfind
* windows.moddump.ModDump
* windows.modscan.ModScan
* windows.modules.Modules
* windows.mutantscan.MutantScan
* windows.poolscanner.PoolScanner
* windows.procdump.ProcDump
* windows.pslist.PsList
* windows.psscan.PsScan
* windows.pstree.PsTree
* windows.registry.certificates.Certificates
* windows.registry.hivedump.HiveDump
* windows.registry.hivelist.HiveList
* windows.registry.hivescan.HiveScan
* windows.registry.printkey.PrintKey
* windows.registry.userassist.UserAssist
* windows.ssdt.SSDT
* windows.statistics.Statistics
* windows.strings.Strings
* windows.symlinkscan.SymlinkScan
* windows.vaddump.VadDump
* windows.vadinfo.VadInfo
* windows.virtmap.VirtMap
* timeliner.Timeliner

**Check Memory Image Information**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.info.Info
```

**Check List of Kernel Drivers**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.modules.Modules
```

**Check List of Kernel Drivers (incl previously unloaded and hidden)**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.modscan.ModScan
```

**Dump List of Kernel Drivers to Files**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.moddump.ModDump
```

**Dump List of Running Processes to Files**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.procdump.ProcDump
```

**Check Process List of Running Processes**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.pslist.PsList
```

**Check Process Tree of Running Processes**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.pstree.PsTree
```

**Check Running Processes from EPROCESS blocks**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.psscan.PsScan
```

**Check Running Processes for possible shellcode/injection via PAGE\_EXECUTE\_READWRITE**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.malfind.Malfind
```

**Check processes and their command lines**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.cmdline.CmdLine
```

**Check for files which exist in memory**

```
/usr/bin/python3.6 vol.py -f /home/user/samples/mem.bin windows.filescan.FileScan
```
