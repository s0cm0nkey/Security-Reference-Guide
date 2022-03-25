# Blue - DFIR: Digital Forensics and Incident Response

DFIR: Digital Forensics and Incident Response is a hugely important important sector of cyber security, where your everyday security analysis is take to the next level. While most security analysts will work out of a SIEM or SOAR platform, Incident Responders and Forensic analysts typically work directly with a potentially compromised device. With this, they are required to not only be familiar with a larger array of tools for analysis, but also a much stricter set of process and procedures as their actions are often subject to legal requirements.

## **DFIR Resource Collections**

* [DFIR Compendium ](https://aboutdfir.com)- The Definitive Compendium Project Digital Forensics & Incident Response
* [Infosec Reference: DFIR](https://github.com/rmusser01/Infosec\_Reference/blob/master/Draft/DFIR.md) - Massive collection of DFIR guides, articles, and tools
* [https://start.me/p/jj0B26/dfir](https://start.me/p/jj0B26/dfir) - Collection of more DFIR resources
* [https://www.jaiminton.com/cheatsheet/DFIR/](https://www.jaiminton.com/cheatsheet/DFIR/) - Huge collection of DFIR commands  and methodology
* Training
  * [DFIR Tra](https://www.dfir.training)[ning](https://www.dfir.training) - Tools, resources, and training classes for DFIR professionals
  * [https://dfirmadness.com/](https://dfirmadness.com) - Collection of training use cases to hone your DFIR skills

## **Incident Response**

### **Resources**

* [Awesome Lists Collection: Incident Response](https://github.com/meirwah/awesome-incident-response)
* Guides and Frameworks
  * [ATC React](https://atc-project.github.io/atc-react/) - The RE\&CT Framework is designed for accumulating, describing and categorizing actionable Incident Response techniques. It can be used for prioritization of Incident Response capabilities development, including skills development, technical measures acquisition/deployment, internal procedures development, etc, as well as gap analysis to determine "coverage" of existing Incident Response capabilities.
    * [https://github.com/atc-project/atc-react](https://github.com/atc-project/atc-react)
    * [https://github.com/atc-project/atc-data](https://github.com/atc-project/atc-data)
  * [SANS Incident Handlers Handbook](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901)
  * [Exabeam Incident Response Guide](https://www.exabeam.com/incident-response/steps/)
  * [NIST 61 R2 - ](./#tools-and-frameworks)[Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
  * [https://zeltser.com/ddos-incident-cheat-sheet/](https://zeltser.com/ddos-incident-cheat-sheet/)
  * [https://gitlab.com/syntax-ir/playbooks#ir-playbooks](https://gitlab.com/syntax-ir/playbooks#ir-playbooks) - Public IR playbooks
  * _BTFM: Incident Response checklist - pg. 109_
  * _BTFM: Remediation Tasks - pg. 112_
  * _(BTHb: INRE): Incident Response Steps - pg. 5_
* Report Templates and Guides
  * [https://github.com/cyb3rfox/Aurora-Incident-Response](https://github.com/cyb3rfox/Aurora-Incident-Response) - Incident Response Documentation made easy. Developed by Incident Responders for Incident Responders
  * [PagerDuty Incident Response processes and document templates](https://response.pagerduty.com)
  * [Zeltser Incident Survey CheatSheet](https://zeltser.com/security-incident-survey-cheat-sheet/)
  * [https://zeltser.com/cyber-threat-intel-and-ir-report-template/](https://zeltser.com/cyber-threat-intel-and-ir-report-template/)
  * _(BTHb: INRE): Incident Response Template - pg. 24_
* Misc
  * DNSDB for Incident Response - [https://info.farsightsecurity.com/passive-dns-incident-response-ebook](https://info.farsightsecurity.com/passive-dns-incident-response-ebook)
  * [Let's Defend: Build your own IR tool guide ](https://letsdefend.io/blog/build-your-own-simple-data-collection-tool-from-endpoint/)
  * [https://training.fema.gov/is/courseoverview.aspx?code=IS-100.c](https://training.fema.gov/is/courseoverview.aspx?code=IS-100.c) - Introduction to the Incident Command System, introduces the Incident Command System (ICS) and provides the foundation for higher level ICS training.
* Training
  * [Incident Response Challange](https://incident-response-challenge.com) - IR CTF Style Training Scenarios&#x20;

### IR/Malware Scanners

* [https://www.nextron-systems.com/thor/](https://www.nextron-systems.com/thor/) - IR scanner with more than 12,000 handcrafted YARA signatures, 400 Sigma rules, numerous anomaly detection rules and thousands of IOCs.
  * [Loki Scanner](https://github.com/Neo23x0/Loki)

```
loki-upgrader.exe
loki.exe -p [Directory]
```

* [MalwareBytes IR Scanner](https://www.malwarebytes.com/business/incident-response)
  * [https://www.malwarebytes.com/pdf/datasheets/mbirdatasheet.pdf](https://www.malwarebytes.com/pdf/datasheets/mbirdatasheet.pdf)
* [ClamAV](https://www.clamav.net/downloads) - ClamAV is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats. Can be used with a USB for portable scanning of devices.
* [Microsoft Safety Scanner ](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)- Microsoft Safety Scanner is a scan tool designed to find and remove malware from Windows computers. Simply download it and run a scan to find malware and try to reverse changes made by identified threats.
* [gmer Rootkit scanner](https://www.gmer.net) - An application that detects and removes [rootkits](http://en.wikipedia.org/wiki/Rootkit)
* [chkrootkit](http://www.chkrootkit.org) - A tool to locally check for signs of a [rootkit](http://www.chkrootkit.org/links/).&#x20;
  * [https://www.kali.org/tools/chkrootkit/](https://www.kali.org/tools/chkrootkit/)
* [RKHunter](https://github.com/installation/rkhunter) - scans systems for known and unknown rootkits, backdoors, sniffers and exploits.
  * [https://www.kali.org/tools/rkhunter/](https://www.kali.org/tools/rkhunter/)
* [hashlookup-forensic-analyser](https://github.com/hashlookup/hashlookup-forensic-analyser) - Analyse a forensic target (such as a directory) to find and report files found and not found from CIRCL hashlookup public service - [https://circl.lu/services/hashlookup/](https://circl.lu/services/hashlookup/)
* [pe-sieve](https://github.com/hasherezade/pe-sieve) - Scans a given process. Recognizes and dumps a variety of potentially malicious implants (replaced/injected PEs, shellcodes, hooks, in-memory patches).
  * [https://hshrzd.wordpress.com/pe-sieve/](https://hshrzd.wordpress.com/pe-sieve/)
* [Redline by Fireeye ](https://www.fireeye.com/services/freeware/redline.html)- Redline®, FireEye's premier free endpoint security tool, provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis and the development of a threat assessment profile.
* [https://www.herdprotect.com/](https://www.herdprotect.com) - herdProtect is a second line of defense malware scanning platform powered by [68 anti-malware engines](https://www.herdprotect.com/engines.aspx) in the cloud. Since no single anti-malware program is perfect 100% of the time, herdProtect utilizes a 'herd' of multiple engines to guarantee the widest coverage and the earliest possible detection. As a second line of defense anti-malware solution, herdProtect is designed to run with any existing anti-virus program already installed on a user's PC. herdProtect is a free service to help user's find and remove malicious software.
  * [https://www.herdprotect.com/knowledgebase.aspx](https://www.herdprotect.com/knowledgebase.aspx)
*   Windows Defender Scan

    ```
    "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
    "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
    "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\[username]\AppData\Local\Temp
    ```

    Note: Types are as follows

    * 1: Quick scan
    * 2: Full system scan
    * 3: File and directory custom scan

    #### Check Windows Defender for excluded files and default actions <a href="#check-windows-defender-for-excluded-files-and-default-actions" id="check-windows-defender-for-excluded-files-and-default-actions"></a>

    ```
    reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    Get-MpPreference | Select Exclusion*
    Get-MpPreference | Select *DefaultAction
    ```
* [Crowdstrike's CrowdResponse Scanner ](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)- Static Host Data Collection Tool

```
CrowdResponse -v -i config.txt -o out.xml
```

* [Binalyze IREC Tactical ](https://www.binalyze.com/tactical)- Standalone evidence collector for traditional DFIR situations. Can scan target with set YARA rules

```
IREC.exe --triage-memory
IREC.exe -ad "\\MACHINE\IREC-DIR" --triage-ruleset MyYaraRules --triage-memory 
```

* [Yara](https://github.com/virustotal/yara/releases/latest)

```
yara32.exe -d filename=[file defined in ruleset.yar] [ruleset.yar] [file to scan]
yara32.exe -d filename=[svchost.exe] [ruleset.yar] -r [directory to scan]
yara64.exe yararule.yar -r C:
yara64.exe yararule.yar -r C: -f 2> $null
```

* Yara Linux

Note: -s shows matching yara strings.

```
yara rule.yara malware.exe -s
yara rule.yara [Directory] -s
```

{% content-ref url="yara.md" %}
[yara.md](yara.md)
{% endcontent-ref %}

Depreciated Tools

### Other Tools

* Frameworks and Collections
  * [Kansa (Powershell)](https://github.com/davehull/kansa) - A modular incident response framework in Powershell. It uses Powershell Remoting to run user contributed, ahem, user contri- buted modules across hosts in an enterprise to collect data for use during incident response, breach hunts, or for building an environmental baseline.
  * [Windows Forensic Toolchest](https://www.foolmoon.net/security/wft/) - The Windows Forensic Toolchest™ (WFT) is designed to provide a structured and repeatable automated Live Forensic Response, Incident Response, or Audit on a Windows system while collecting security-relevant information from the system.
  * [Veliciraptor](https://github.com/Velocidex/velociraptor) - A tool for collecting host based state information.
    * [Velociraptor Deep Dive Video training](https://www.youtube.com/watch?app=desktop\&v=PiYPLEjYXnw)
  * [Meerkat](https://github.com/TonyPhipps/Meerkat) - Meerkat is collection of PowerShell modules designed for artifact gathering and reconnaisance of Windows-based endpoints without requiring a pre-deployed agent.
* Utility
  * [AWS\_IR](https://github.com/ThreatResponse/aws\_ir) - Python installable command line utility for mitigation of instance and key compromises.
  * [https://processhacker.sourceforge.io/](https://processhacker.sourceforge.io) - A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
  * [ADTimeline](https://github.com/ANSSI-FR/ADTimeline) - The ADTimeline script generates a timeline based on Active Directory replication metadata for objects considered of interest.

## DFIR Commands

{% content-ref url="interact-with-remote-machine.md" %}
[interact-with-remote-machine.md](interact-with-remote-machine.md)
{% endcontent-ref %}

{% content-ref url="windows-system-enumeration.md" %}
[windows-system-enumeration.md](windows-system-enumeration.md)
{% endcontent-ref %}

{% content-ref url="windows-process-information.md" %}
[windows-process-information.md](windows-process-information.md)
{% endcontent-ref %}

{% content-ref url="windows-dfir-checks.md" %}
[windows-dfir-checks.md](windows-dfir-checks.md)
{% endcontent-ref %}

{% content-ref url="windows-dfir-check-by-mitre-tactic.md" %}
[windows-dfir-check-by-mitre-tactic.md](windows-dfir-check-by-mitre-tactic.md)
{% endcontent-ref %}

{% content-ref url="windows-event-logs.md" %}
[windows-event-logs.md](windows-event-logs.md)
{% endcontent-ref %}

{% content-ref url="windows-remediation-commands.md" %}
[windows-remediation-commands.md](windows-remediation-commands.md)
{% endcontent-ref %}

{% content-ref url="ir-event-log-cheatsheet.md" %}
[ir-event-log-cheatsheet.md](ir-event-log-cheatsheet.md)
{% endcontent-ref %}

{% content-ref url="linux-dfir-commands.md" %}
[linux-dfir-commands.md](linux-dfir-commands.md)
{% endcontent-ref %}

{% content-ref url="macos-dfir-commands.md" %}
[macos-dfir-commands.md](macos-dfir-commands.md)
{% endcontent-ref %}

## **Forensics**

### **Guides and Resources**

* [Awesome Lists Collection: Forensics](https://github.com/Cugu/awesome-forensics)
* [DFIR artifact repository](https://github.com/ForensicArtifacts/artifacts)
* [https://tryhackme.com/room/windowsforensics1](https://tryhackme.com/room/windowsforensics1)
* Cheatsheets
  * [Zeltser Critical Log Cheatsheet](https://zeltser.com/security-incident-log-review-checklist/)
  * [SANS Forensics Cheatsheets](https://digital-forensics.sans.org/community/cheat-sheets)
* Triage and Order of Volatility
  * [RFC - 3227: Order of Volatility](https://datatracker.ietf.org/doc/html/rfc3227)
  * _(BTHb: INRE): Order of Volatility - pg. 29_
  * _BTFM: Live Triage - pg. 60_

### Tools&#x20;

* Forensic OS/VM
  * [https://www.sans.org/tools/sift-workstation](https://www.sans.org/tools/sift-workstation) - The SIFT Workstation is a collection of free and open-source incident response and forensic tools designed to perform detailed digital forensic examinations in a variety of settings. It can match any current incident response and forensic tool suite.
    * [SANS DFIR Posters and Cheat Sheets](https://www.sans.org/security-resources/posters/dfir/?msc=tool-sift)
    * [How To Mount a Disk Image In Read-Only Mode](https://www.sans.org/blog/digital-forensic-sifting-how-to-perform-a-read-only-mount-of-filesystem-evidence/?msc=tool-sift)
    * [How To Create a Filesystem and Registry Timeline](https://www.sans.org/blog/digital-forensic-sifting-registry-and-filesystem-timeline-creation/?msc=tool-sift)
    * [How To Create a Super Timeline](https://www.sans.org/blog/digital-forensic-sifting-super-timeline-creation-using-log2timeline/?msc=tool-sift)
    * [SIFT Workstation YouTube Series](https://www.youtube.com/playlist?list=PL60DFAE759FCDF36A)
    * [FOR508 - Advanced Incident Response](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/?msc=tool-sift)
  * [https://tsurugi-linux.org/](https://tsurugi-linux.org) - 64 bit Linux version to perform digital forensics analysis and OSINT research.
    * [tsurugi\_acquire](https://tsurugi-linux.org/tsurugi\_acquire.php) - a lightweight and streamlined version of Tsurugi Linux \[LAB], aimed at providing the basic tools needed to boot a PC and acquire mass storage devices.
    * [bento](https://tsurugi-linux.org/bento.php) - a portable toolkit designed for live forensics and incident response activities.
    * [https://tsurugi-linux.org/documentation\_tsurugi\_linux\_tools\_listing\_2021.php](https://tsurugi-linux.org/documentation\_tsurugi\_linux\_tools\_listing\_2021.php)
* Forensic Frameworks
  * [Autopsy forensic framework](https://www.autopsy.com/community/) - Autopsy is the premier open source forensics platform which is fast, easy-to-use, and capable of analyzing all types of mobile devices and digital media
    * [https://dfir-training.basistech.com/](https://dfir-training.basistech.com)
    * [https://www.aldeid.com/wiki/Autopsy](https://www.aldeid.com/wiki/Autopsy)
    * [https://tryhackme.com/room/autopsy2ze0](https://tryhackme.com/room/autopsy2ze0)
  * [X-Ways Forensic Toolkit](https://www.x-ways.net/forensics/) - X-Ways Forensics is an advanced work environment for computer forensic examiners
    * [https://www.x-ways.net/forensics/x-tensions/](https://www.x-ways.net/forensics/x-tensions/) - X-Ways plugin tools
    * [https://github.com/CrowdStrike/xwf-yara-scanner](https://github.com/CrowdStrike/xwf-yara-scanner) - YARA Scanner Plugin
    * [X-ways Imager](https://www.x-ways.net/imager/index-m.html) - Forensic disk imaging tool. Stripped down version of the [X-Ways Forensics](https://www.x-ways.net/forensics/index-m.html) computer forensics software with just the disk imaging functionality and little more
  * [Forensic Tool Kit (FTK)](https://www.exterro.com/forensic-toolkit) - Premium forensics suite that can perform imaging, file decryption, registry parsing, and much more.
    * [FTK Imager by AccessData](https://www.exterro.com/ftk-imager) - Create forensic images of local hard drives, CDs and DVDs, thumb drives or other USB devices, entire folders, or individual files from various places within the media.
  * [sleuthkit](https://www.kali.org/tools/sleuthkit/) - The Sleuth Kit, also known as TSK, is a collection of UNIX-based command line file and volume system forensic analysis tools. The filesystem tools allow you to examine filesystems of a suspect computer in a non-intrusive fashion. Because the tools do not rely on the operating system to process the filesystems, deleted and hidden content is shown.
    * [http://www.sleuthkit.org/sleuthkit/](http://www.sleuthkit.org/sleuthkit/)
  * [NTDSxtract](https://github.com/csababarta/ntdsxtract) - Active Directory forensic framework
  * [linux-explorer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints
    * [Installation and Configuration Video](https://youtu.be/NAOtGYBG-QY)
  * [GRR](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics.
  * [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - An all inclusive framework for hard drive forensic analysis. PowerForensics currently supports NTFS and FAT file systems, and work has begun on Extended File System and HFS+ support.
    * [https://powerforensics.readthedocs.io/en/latest/](https://powerforensics.readthedocs.io/en/latest/)&#x20;
    * [https://devblogs.microsoft.com/powershell/powershell-the-blue-team/](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)
  * [Eric Zimmerman's toolset](https://ericzimmerman.github.io/#!index.md) - SANS instructor and former FBI Forensics expert Eric Zimmerman has created a list of his favorite tools for public use and reference.
    * [https://cyberforensicator.com/2017/04/04/a-guide-to-eric-zimmermans-command-line-tools/](https://cyberforensicator.com/2017/04/04/a-guide-to-eric-zimmermans-command-line-tools/)

{% file src="../.gitbook/assets/EricZimmermanCommandLineToolsCheatSheet-v1.0 (2).pdf" %}

* Extraction Tools
  * [bulk-extractor](https://www.kali.org/tools/bulk-extractor/) - bulk\_extractor is a C++ program that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures.
  * [dumpzilla](https://www.kali.org/tools/dumpzilla/) - Dumpzilla application is developed in Python 3.x and has as purpose extract all forensic interesting information of Firefox, Iceweasel and Seamonkey browsers to be analyzed.
  * [regripper](https://www.kali.org/tools/regripper/) - RegRipper is an open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.
  * [safecopy](https://www.kali.org/tools/safecopy/) - safecopy tries to get as much data from SOURCE as possible, even resorting to device specific low level operations if applicable.
* Browser Tools
  * [galleta](https://www.kali.org/tools/galleta/) - Galleta is a forensics tool that examines the content of cookie files produced by Microsoft Internet Explorer (MSIE). It parses the file and outputs a field separated that can be loaded in a spreadsheet.
  * [pasco](https://www.kali.org/tools/pasco/) - Pasco is a forensic tool that examines the content of cache files (index.dat) produced by Microsoft Internet Explorer.
* Misc Utility
  * [XOR Tool](https://github.com/hellman/xortool) - A tool to do some xor analysis: Guess the key length (based on count of equal chars) and Guess the key (base on knowledge of most frequent char)
  * [forensics-colorize](https://www.kali.org/tools/forensics-colorize/) - forensics-colorize is a set of tools to visually compare large files, as filesystem images, creating graphics of them. It is intuitive because the produced graphics provide a quick and perfect sense about the percentage of changes between two files.
  * [dislocker](https://www.kali.org/tools/dislocker/) - Dislocker has been designed to read BitLocker encrypted partitions under a Linux system
  * [mac-robber](https://www.kali.org/tools/mac-robber/) - mac-robber is a digital investigation tool (digital forensics) that collects metadata from allocated files in a mounted filesystem. This is useful during incident response when analyzing a live system or when analyzing a dead system in a lab.
  * [testdisk](https://www.kali.org/tools/testdisk/) - TestDisk checks the partition and boot sectors of your disks. It is very useful in forensics, recovering lost partitions.
  * [unhide](https://www.kali.org/tools/unhide/) - Unhide is a forensic tool to find processes and TCP/UDP ports hidden by rootkits, Linux kernel modules or by other techniques. It includes two utilities: unhide and unhide-tcp.

### **File Carving/Recovery**

* [Foremost](https://github.com/korczis/foremost): Foremost is a console program to recover files based on their headers, footers, and internal data structures.
* [ext4magic](https://www.kali.org/tools/ext4magic/) - ext4magic can extract the information from the journal and restore files in an entire directory tree, if the information in the journal are sufficient.
* [ext3grep](https://www.kali.org/tools/ext3grep/) - ext3grep is a simple tool intended to aid anyone who accidentally deletes a file on an ext3 filesystem, only to find that they wanted it shortly thereafter.
* [extundelete](https://www.kali.org/tools/extundelete/) - extundelete uses the information stored in the partition’s journal to attempt to recover a file that has been deleted.
* [magicrescue](https://www.kali.org/tools/magicrescue/) - Magic Rescue scans a block device for file types it knows how to recover and calls an external program to extract them.
* [myrescue](https://www.kali.org/tools/myrescue/) - myrescue is a program to rescue the still-readable data from a damaged harddisk, CD-ROM, DVD, flash drives, etc. It is similar in purpose to dd\_rescue (or ddrescue), but it tries to quickly get out of damaged areas to first handle the not yet damaged part of the disk and return later.
* [recoverdm](https://www.kali.org/tools/recoverdm/) - recoverdm recover disks with bad sectors. You can recover files as well complete devices. In case it finds sectors which simply cannot be recovered, it writes an empty sector to the output file and continues.
* [recoverjpeg](https://www.kali.org/tools/recoverjpeg/) - recoverjpeg tries to recover JFIF (JPEG) pictures and MOV movies from a peripheral. This may be useful if you mistakenly overwrite a partition or if a device such as a digital camera memory card is bogus.
* [rifiuti2](https://www.kali.org/tools/rifiuti2/) - Rifiuti2 analyses recycle bin files from Windows. Analysis of Windows recycle bin is usually carried out during Windows computer forensics.
* [scalpel](https://www.kali.org/tools/scalpel/) - scalpel is a fast file carver that reads a database of header and footer definitions and extracts matching files from a set of image files or raw device files.
* [scrounge-ntfs](https://www.kali.org/tools/scrounge-ntfs/) - Scrounge NTFS is a data recovery program for NTFS filesystems. It reads each block of the hard disk and try to rebuild the original filesystem tree into a directory.
* [undbx](https://www.kali.org/tools/undbx/) - UnDBX is a tool to extract, recover and undelete e-mail messages from MS Outlook Express .dbx files

### Forensic Imaging

* [FTK Imager by AccessData](https://www.exterro.com/ftk-imager) - Create forensic images of local hard drives, CDs and DVDs, thumb drives or other USB devices, entire folders, or individual files from various places within the media.

```
ftkimager --list-drives
ftkimager \\.\PHYSICALDRIVE0 "[Location]\Case" --e01
ftkimager [source] [destination]
ftkimager \\.\PHYSICALDRIVE0 "[Location]\Case" --e01 --outpass securepasswordinsertedhere 
```

* [DD utility](https://man7.org/linux/man-pages/man1/dd.1.html) - Unix disk manipulation tool
  * [dc3dd](https://www.kali.org/tools/dc3dd/) - dc3dd is a patched version of GNU dd with added features for computer forensics
  * [dcfldd](https://www.kali.org/tools/dcfldd/) - Enhanced version of dd for forensics and security
  * [ddrescue](https://www.kali.org/tools/ddrescue/) - Data recovery and protection tool

```
dd.exe --list
dd.exe if=/dev/<drive> of=Image.img bs=1M
dd.exe if=\\.\<OSDrive>: of=<drive>:\<name>.img bs=1M --size --progress
(LINUX) sudo dd if=/dev/<OSDrive> of=/mnt/<name>.ddimg bs=1M conv=noerror,sync
```

* [X-ways Imager](https://www.x-ways.net/imager/index-m.html) - Forensic disk imaging tool. Stripped down version of the [X-Ways Forensics](https://www.x-ways.net/forensics/index-m.html) computer forensics software with just the disk imaging functionality and little more
* [guymager](https://www.kali.org/tools/guymager/) - The forensic imager contained in this package, guymager, was designed to support different image file formats, to be most user-friendly and to run really fast.

### Memory Forensics

{% content-ref url="memory-forensics/" %}
[memory-forensics](memory-forensics/)
{% endcontent-ref %}

### **USB Analysis**

* [https://gbhackers.com/usb-forensics/](https://gbhackers.com/usb-forensics/)
* [USB Descriptors](https://www.beyondlogic.org/usbnutshell/usb5.shtml)
* [USB Data Transfer Types](https://www.jungo.com/st/support/documentation/windriver/10.2.1/wdusb\_manual.mhtml/USB\_data\_transfer\_types.html)
* [USB WIreshark Filters](https://www.wireshark.org/docs/dfref/u/usb.html)

### MacOS&#x20;

* [Mac OS X 10.9 Forensics Wiki](https://forensicswiki.org/wiki/Mac\_OS\_X\_10.9\_-\_Artifacts\_Location)
* [Mac OS X 10.11 Forensics Wiki](https://forensicswiki.org/wiki/Mac\_OS\_X\_10.11\_\(ElCapitan\)\_-\_Artifacts\_Location)
* [Mac OS X Forensics Artifacts Spreadsheet](https://docs.google.com/spreadsheets/d/1X2Hu0NE2ptdRj023OVWIGp5dqZOw-CfxHLOW\_GNGpX8/edit#gid=1317205466)&#x20;
* [osxcollector](https://github.com/Yelp/osxcollector) -  A forensic evidence collection & analysis toolkit for OS X
* [automactc](https://github.com/CrowdStrike/automactc) - This is a modular forensic triage collection framework designed to access various forensic artifacts on macOS, parse them, and present them in formats viable for analysis. The output may provide valuable insights for incident response in a macOS environment. Automactc can be run against a live system or dead disk (as a mounted volume.)
* [Mac4n6](https://www.mac4n6.com) - Great blog on Mac OS forensics
* [mac\_apt](https://github.com/ydkhatri/mac\_apt) - macOS (& ios) Artifact Parsing Tool&#x20;
* [https://themittenmac.com/tools/](https://themittenmac.com/tools/)
  * [https://themittenmac.com/the-truetree-concept/](https://themittenmac.com/the-truetree-concept/)
  * [https://themittenmac.com/monitorui-tool-release/](https://themittenmac.com/monitorui-tool-release/)
  * [https://themittenmac.com/the-esf-playground/](https://themittenmac.com/the-esf-playground/)

## **Malware Analysis**

In incident response, phishing, or security monitoring scenarios, you will encounter potentially malicious files that will require in depth analysis to certify the nature of the file. These files can be as overt as an executable labeled "virus.exe" or as covert as "resume.doc". There will be instances where even after all of your analysis, you still cannot verify the nature of the document, and therefore should be considered malicious until proven otherwise.

### Malware Analysis Toolsets and multi-engine scanners

* [https://remnux.org/](https://remnux.org) - REMnux® is a Linux toolkit for reverse-engineering and analyzing malicious software. REMnux provides a curated collection of free tools created by the community. Analysts can use it to investigate malware without having to find, install, and configure the tools.
  * [https://zeltser.com/remnux-malware-analysis-tips/](https://zeltser.com/remnux-malware-analysis-tips/)
* [https://github.com/fireeye/flare-vm](https://github.com/fireeye/flare-vm) - A fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.
* [MalwareUnicorn's tool collection](https://malwareunicorn.org/#/resources) - Tools used by one of the best malware analysts in the field.
* [https://github.com/mindcollapse/MalwareMultiScan](https://github.com/mindcollapse/MalwareMultiScan) - Self-hosted [VirusTotal](https://www.virustotal.com) / [OPSWAT MetaDefender](https://metadefender.opswat.com) wannabe API for scanning URLs and files by multiple antivirus solutions.
* [RATDecoders](https://github.com/kevthehermit/RATDecoders) - Python Decoders for Common Remote Access Trojans
* [mal\_unpack](https://github.com/hasherezade/mal\_unpack) - Dynamic unpacker based on PE-sieve
  * [https://www.youtube.com/watch?v=8LZ6ksoytpU](https://www.youtube.com/watch?v=8LZ6ksoytpU)
* [CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser) - Python parser for CobaltStrike Beacon's configuration

### **Sandboxing**

{% content-ref url="sandboxing.md" %}
[sandboxing.md](sandboxing.md)
{% endcontent-ref %}

Outside of sandboxing, there are a host of other tools available that can perform different types of analysis on malware. There are even a few virtual machine distributions that are dedicated to malware analysis. The foremost of them are Flare-VM and Remnux. These will usually include sandboxing tools like cuckoo, code analysis tools like Snyk and Ghidra, and a host of other handy options.&#x20;

{% hint style="info" %}
Remember: it is always advised to perform your malware analysis on a virtual machine, in order to prevent unwanted accidents.
{% endhint %}

### **File Analysis**

{% content-ref url="file-analysis.md" %}
[file-analysis.md](file-analysis.md)
{% endcontent-ref %}

### **Resources**

* [https://nostarch.com/malware](https://nostarch.com/malware)
  * [https://www.jaiminton.com/Tutorials/PracticalMalwareAnalysis/](https://www.jaiminton.com/Tutorials/PracticalMalwareAnalysis/)
* [Awesome Lists Collection: Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
* [https://malwareunicorn.org/#/](https://malwareunicorn.org/#/) - Malware Blog, tools, and training
* [https://www.sans.org/security-resources/posters/dfir/remnux-usage-tips-malware-analysis-linux-400](https://www.sans.org/security-resources/posters/dfir/remnux-usage-tips-malware-analysis-linux-400)
* [https://www.sans.org/security-resources/posters/dfir/malware-analysis-reverse-engineering-cheat-sheet-395](https://www.sans.org/security-resources/posters/dfir/malware-analysis-reverse-engineering-cheat-sheet-395)
* [SANS Malware Analysis Cheatsheet](https://sansorg.egnyte.com/dl/GpsbKAhkQo/?)
* [https://zeltser.com/malware-analysis-cheat-sheet/](https://zeltser.com/malware-analysis-cheat-sheet/)
* [https://www.infosecinstitute.com/skills/learning-paths/malware-analysis-reverse-engineering/](https://www.infosecinstitute.com/skills/learning-paths/malware-analysis-reverse-engineering/)
* [Hackersploit's Malware Analaysis Bootcamp](https://hackersploit.org/malware-analysis-tutorials/)
* [https://tryhackme.com/room/malresearching](https://tryhackme.com/room/malresearching)
* _BTFM: Malware Analysis - pg. 77_
* _BTFM: Identifying Malware - pg. 80_
* _PTFM: Malware Analysis - pg. 149_
* _BTFM: Malware Attributes Checklist - pg.115_

## Reverse Engineering

{% content-ref url="binary-analysis-reverse-engineering.md" %}
[binary-analysis-reverse-engineering.md](binary-analysis-reverse-engineering.md)
{% endcontent-ref %}
