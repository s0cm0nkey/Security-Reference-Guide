---
description: DFIR resources for incident response, forensic triage, Windows and Linux commands, memory forensics, malware analysis, and evidence collection.
---

# Blue - DFIR: Digital Forensics and Incident Response

DFIR focuses on evidence, timelines, containment, eradication, and recovery after suspicious activity or a confirmed compromise. This section is for hands-on incident response and forensic analysis: remote triage, host commands, event logs, evidence collection, memory forensics, sandboxing, file analysis, malware analysis, and reverse engineering.

For detection engineering, SIEM rules, and Sysmon configuration, use Event Detection. For reputation and enrichment lookups, use Threat Data.

{% content-ref url="../blue-defense/event-detection/" %}
[event-detection](../blue-defense/event-detection/)
{% endcontent-ref %}

{% content-ref url="../cyber-intelligence/threat-data.md" %}
[threat-data.md](../cyber-intelligence/threat-data.md)
{% endcontent-ref %}

## DFIR Resource Collections

* [DFIR Compendium](https://aboutdfir.com/) - Broad DFIR tool and reference collection.
* [Infosec Reference: DFIR](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/DFIR.md) - Large collection of DFIR guides, articles, and tools.
* [DFIR start.me](https://start.me/p/jj0B26/dfir) - Curated DFIR bookmark collection.
* [Jaiminton DFIR Cheatsheet](https://www.jaiminton.com/cheatsheet/DFIR/) - DFIR commands and methodology.
* [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)
* [Awesome Forensics](https://github.com/Cugu/awesome-forensics)
* [Awesome KAPE](https://github.com/AndrewRathbun/Awesome-KAPE)
* [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)

Training, CTFs, labs, and course links have moved to Training.

{% content-ref url="../training/" %}
[training](../training/)
{% endcontent-ref %}

## Incident Response Process

* [RE&CT Framework](https://atc-project.github.io/atc-react/) - Actionable incident response techniques and capability mapping.
  * [atc-react GitHub](https://github.com/atc-project/atc-react)
  * [atc-data GitHub](https://github.com/atc-project/atc-data)
* [CERT Société Générale IRM](https://github.com/certsocietegenerale/IRM) - Public incident response methodologies.
* [SANS Incident Handler's Handbook](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901)
* [SANS Incident Response Process](https://www.sans.org/posters/incident-response-cycle/) - Preparation, identification, containment, eradication, recovery, and lessons learned.
* [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) - Computer Security Incident Handling Guide.
* [Exabeam Incident Response Guide](https://www.exabeam.com/incident-response/steps/)
* [Zeltser DDoS Incident Cheat Sheet](https://zeltser.com/ddos-incident-cheat-sheet/)
* [Syntax IR Playbooks](https://gitlab.com/syntax-ir/playbooks#ir-playbooks)
* [Microsoft Incident Response Playbooks](https://learn.microsoft.com/en-us/security/compass/incident-response-playbooks)
  * [Azure AD Incident Response PowerShell Module](https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module)
  * [Incident Response in a Microsoft Cloud Environment](https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/)

## Report Writing and Documentation

* [Aurora Incident Response](https://github.com/cyb3rfox/Aurora-Incident-Response) - IR documentation templates.
* [PagerDuty Incident Response Templates](https://response.pagerduty.com/)
* [Zeltser Incident Survey Cheat Sheet](https://zeltser.com/security-incident-survey-cheat-sheet/)
* [Zeltser CTI and IR Report Template](https://zeltser.com/cyber-threat-intel-and-ir-report-template/)

## Host Collection and IR Frameworks

* [Kansa](https://github.com/davehull/kansa) - PowerShell-based incident response framework for collecting data across Windows hosts.
* [Windows Forensic Toolchest](https://www.foolmoon.net/security/wft/) - Structured live forensic response and audit collection.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Endpoint visibility, collection, and response platform.
  * [Velociraptor Deep Dive](https://www.youtube.com/watch?app=desktop&v=PiYPLEjYXnw)
* [Meerkat](https://github.com/TonyPhipps/Meerkat) - PowerShell modules for Windows artifact gathering and reconnaissance.
* [Cado Community Edition](https://www.cadosecurity.com/cado-community-edition/) - Cloud-focused investigation and evidence processing.
* [AWS_IR](https://github.com/ThreatResponse/aws_ir) - Command-line utility for AWS incident response.
* [ADTimeline](https://github.com/ANSSI-FR/ADTimeline) - Active Directory replication metadata timeline generator.
* [GRR Rapid Response](https://github.com/google/grr) - Remote live forensics framework.
* [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerShell framework for disk forensic analysis.
  * [PowerForensics Docs](https://powerforensics.readthedocs.io/en/latest/)

## Malware and IR Scanners

* [Malwarebytes Incident Response](https://www.malwarebytes.com/business/incident-response)
* [ClamAV](https://www.clamav.net/downloads) - Open-source antivirus engine.
* [Microsoft Safety Scanner](https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download) - On-demand malware removal scanner.
* [hashlookup-forensic-analyser](https://github.com/hashlookup/hashlookup-forensic-analyser) - Analyze files against CIRCL hashlookup.
* [CobaltStrikeScan](https://github.com/Apr4h/CobaltStrikeScan) - Cobalt Strike beacon scanning and config parsing.
* [System Informer](https://systeminformer.sourceforge.io/) - Successor to Process Hacker for process, handle, service, and module investigation.
* [Windows Defender MpCmdRun](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) - Defender command-line scanner.

```cmd
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\[username]\AppData\Local\Temp
```

YARA, Loki, THOR Lite, Fenrir, and Binalyze IREC are maintained on the YARA page.

{% content-ref url="yara.md" %}
[yara.md](yara.md)
{% endcontent-ref %}

Memory scanners such as `pe-sieve` are maintained with memory forensics.

{% content-ref url="memory-forensics/" %}
[memory-forensics](memory-forensics/)
{% endcontent-ref %}

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

{% content-ref url="ir-event-log-cheatsheet.md" %}
[ir-event-log-cheatsheet.md](ir-event-log-cheatsheet.md)
{% endcontent-ref %}

{% content-ref url="windows-remediation-commands.md" %}
[windows-remediation-commands.md](windows-remediation-commands.md)
{% endcontent-ref %}

{% content-ref url="linux-dfir-commands.md" %}
[linux-dfir-commands.md](linux-dfir-commands.md)
{% endcontent-ref %}

{% content-ref url="macos-dfir-commands.md" %}
[macos-dfir-commands.md](macos-dfir-commands.md)
{% endcontent-ref %}

## Forensic Workstations and Frameworks

* [SIFT Workstation](https://www.sans.org/tools/sift-workstation) - SANS forensic workstation for detailed digital forensic examinations.
  * [SANS DFIR Posters and Cheat Sheets](https://www.sans.org/security-resources/posters/dfir/?msc=tool-sift)
  * [Read-Only Mounting with SIFT](https://www.sans.org/blog/digital-forensic-sifting-how-to-perform-a-read-only-mount-of-filesystem-evidence/?msc=tool-sift)
  * [Filesystem and Registry Timeline Creation](https://www.sans.org/blog/digital-forensic-sifting-registry-and-filesystem-timeline-creation/?msc=tool-sift)
  * [Super Timeline Creation](https://www.sans.org/blog/digital-forensic-sifting-super-timeline-creation-using-log2timeline/?msc=tool-sift)
* [Tsurugi Linux](https://tsurugi-linux.org/) - DFIR Linux distribution with OSINT tooling.
  * [tsurugi_acquire](https://tsurugi-linux.org/tsurugi_acquire.php)
  * [bento](https://tsurugi-linux.org/bento.php)
  * [Tsurugi Tools Listing](https://tsurugi-linux.org/documentation_tsurugi_linux_tools_listing_2021.php)
* [Autopsy](https://www.autopsy.com/community/) - Open-source forensic platform.
* [X-Ways Forensics](https://www.x-ways.net/forensics/) - Commercial forensic suite.
  * [X-Ways X-Tensions](https://www.x-ways.net/forensics/x-tensions/)
  * [CrowdStrike X-Ways YARA Scanner](https://github.com/CrowdStrike/xwf-yara-scanner)
  * [X-Ways Imager](https://www.x-ways.net/imager/index-m.html)
* [FTK](https://www.exterro.com/forensic-toolkit) - Commercial forensic suite.
  * [FTK Imager](https://www.exterro.com/ftk-imager)
* [The Sleuth Kit](https://www.kali.org/tools/sleuthkit/)
  * [sleuthkit.org](http://www.sleuthkit.org/sleuthkit/)
* [NTDSxtract](https://github.com/csababarta/ntdsxtract) - Active Directory forensic framework.
* [linux-explorer](https://github.com/intezer/linux-explorer) - Live forensics toolbox for Linux endpoints.
  * [Installation and Configuration Video](https://youtu.be/NAOtGYBG-QY)
* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) - Windows forensic artifact tools.
  * [Eric Zimmerman Tool Guide](https://cyberforensicator.com/2017/04/04/a-guide-to-eric-zimmermans-command-line-tools/)
  * [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
  * [KAPE Docs](https://ericzimmerman.github.io/KapeDocs/#!index.md)

{% file src="../.gitbook/assets/EricZimmermanCommandLineToolsCheatSheet-v1.0 (1) (1).pdf" %}

## File Systems, Imaging, and Recovery

Detailed file analysis and carving guidance lives on File/Binary Analysis.

{% content-ref url="file-analysis.md" %}
[file-analysis.md](file-analysis.md)
{% endcontent-ref %}

Useful extraction and recovery tools:

* [bulk_extractor](https://www.kali.org/tools/bulk-extractor/)
* [RegRipper](https://www.kali.org/tools/regripper/)
* [safecopy](https://www.kali.org/tools/safecopy/)
* [dumpzilla](https://www.kali.org/tools/dumpzilla/)
* [xortool](https://github.com/hellman/xortool)
* [forensics-colorize](https://www.kali.org/tools/forensics-colorize/)
* [dislocker](https://www.kali.org/tools/dislocker/)
* [mac-robber](https://www.kali.org/tools/mac-robber/)
* [testdisk](https://www.kali.org/tools/testdisk/)
* [unhide](https://www.kali.org/tools/unhide/)
* [Foremost](https://github.com/korczis/foremost)
* [scalpel](https://www.kali.org/tools/scalpel/)
* [RdpCacheStitcher](https://github.com/BSI-Bund/RdpCacheStitcher/)
* [bmc-tools](https://github.com/ANSSI-FR/bmc-tools/)

Forensic imaging:

* [FTK Imager](https://www.exterro.com/ftk-imager)
* [dd](https://man7.org/linux/man-pages/man1/dd.1.html)
* [dc3dd](https://www.kali.org/tools/dc3dd/)
* [dcfldd](https://www.kali.org/tools/dcfldd/)
* [ddrescue](https://www.kali.org/tools/ddrescue/)
* [X-Ways Imager](https://www.x-ways.net/imager/index-m.html)
* [guymager](https://www.kali.org/tools/guymager/)

```bash
dd.exe --list
dd.exe if=/dev/<drive> of=Image.img bs=1M
dd.exe if=\\.\<OSDrive>: of=<drive>:\<name>.img bs=1M --size --progress
sudo dd if=/dev/<OSDrive> of=/mnt/<name>.ddimg bs=1M conv=noerror,sync
```

## Platform-Specific Forensics

Windows, Linux, and macOS command references are linked above. macOS artifact resources:

* [Mac OS X 10.9 Forensics Wiki](https://forensicswiki.org/wiki/Mac_OS_X_10.9_-_Artifacts_Location) - Legacy macOS artifact reference.
* [Mac OS X 10.11 Forensics Wiki](https://forensicswiki.org/wiki/Mac_OS_X_10.11_\(ElCapitan\)_-_Artifacts_Location) - Legacy macOS artifact reference.
* [macOS Forensics Artifacts Spreadsheet](https://docs.google.com/spreadsheets/d/1X2Hu0NE2ptdRj023OVWIGp5dqZOw-CfxHLOW_GNGpX8/edit#gid=1317205466)
* [osxcollector](https://github.com/Yelp/osxcollector)
* [automactc](https://github.com/CrowdStrike/automactc)
* [Mac4n6](https://www.mac4n6.com/)
* [mac_apt](https://github.com/ydkhatri/mac_apt)
* [The Mitten Mac Tools](https://themittenmac.com/tools/)

## Malware Analysis and Reverse Engineering

Malware analysis resources are split by workflow:

{% content-ref url="malware.md" %}
[malware.md](malware.md)
{% endcontent-ref %}

{% content-ref url="sandboxing.md" %}
[sandboxing.md](sandboxing.md)
{% endcontent-ref %}

{% content-ref url="binary-analysis-reverse-engineering.md" %}
[binary-analysis-reverse-engineering.md](binary-analysis-reverse-engineering.md)
{% endcontent-ref %}

{% hint style="info" %}
Analyze malware in an isolated VM or lab network. Do not detonate samples on production systems.
{% endhint %}

## Legacy / Deprecated Tools

These are kept for historical reference or specific legacy cases.

* **Redline by FireEye/Mandiant** - Legacy host investigation tool. Original FireEye links may no longer be maintained.
* **CrowdResponse** - Static host data collection tool.
* **Gmer Rootkit Scanner** - Rootkit detection/removal utility.
* **chkrootkit** - Local Unix rootkit checks.
* **RKHunter** - Unix rootkit scanner.
* **Galleta** - Internet Explorer cookie file analysis.
* **Pasco** - Internet Explorer cache file analysis.
* **herdProtect** - Legacy second-opinion cloud malware scanner; verify availability before use.
