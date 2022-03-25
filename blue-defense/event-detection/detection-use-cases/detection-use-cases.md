# Detection Use Cases - Book Reference

* Remote Admin Tool Use
  * PSExec Use
    * &#x20;_PTFM: Remote Admin tools - pg. 16 (Requires WinEventLogs)_
    * _PTFM: PSExec Use pg. 55 (Requires Registry Changes)_
  * WMI use
    * _PTFM: Remote Admin tools - pg. 16 (Requires Command Line Auditing)_
* Phishing Detection
  * Zeek Detection Rule
    * _PTFM: Spearphishing - pg. 17 , 83 (Requires Zeek)_
* Persistence Detection
  * Unwanted executables and DLLs
    * Disallow specific .exe
      * _PTFM: Disallow specific executable - pg. 23 (Requires Registry Changes)_
    * Unsigned DLLs
      * _PTFM: Unsigned DLL - pg. 23 (Requires Running CLI Query)_
  * New Scheduled tasks
    * _PTFM: Scheduled Tasks - pg. 27 (Requires Powershell Query)_
    * _PTFM: Scheduled Tasks - pg. 90 (Requires cron.dAudit)_
  * Web Shell Detection
    * _PTFM: Webshell Detection - pg. 30 (Requires Procmon.exe, and Process Baseline)_
  * .bashrc and .bash\_profile changes
    * _PTFM: Bash changes- pg. 90 (Requires Bash File Audit)_
* PrivEsc Detection
  * UAC Bypas
    * _PTFM: UAC Bypass  via Event Viewer - pg. 34 (Requires Registry Changes)_
    * _PTFM: UAC Bypass  via fodhelper.exe - pg. 34 (Requires Registry Changes)_
  * Poorly configed Cron Jobs
    * _PTFM: Poorly configured Cron Jobs - pg. 96_
  * Mimikatz Use
    * Operator Handbook: Detect Mimikatz - pg.207
* Defense Evasion Detection
  * Detect Alternate Data Streams
    * _PTFM: Detect Alternate Data Streams - pg. 37 (Requires Powershell Query)_
  * Detect Rootkits
    * _PTFM: Detect Rootkits - pg. 37(Requires Memory Dump Tool)_
    * Output of Windows Security Scan
    * Output of gmer.exe
    * Output of chkrootkit
    * Output of ClamAV
    * Output of rkhunter
    * Output of Lynis
* Endpoint Enumeration/Harvesting Detection
  * Host Enumeration Detection
    * _PTFM: Windows Host Enumeration Detection Script - pg. 48_
    * _PTFM: Linux Host Enumeration Detection Script - pg. 107_
  * Detect LSASS dumping
    * _PTFM: Detect lsass dumping with sysmon - pg. 43 (Requires Sysmon)_
* Lateral movement Detection
  * Pass-the-Hash
    * _PTFM: Pass-the-hash detection with WinEventLogs - pg. 54 (Requires WinEventLogs)_
    * _PTFM: Pass-the-hash detection with Sysmon- pg. 55 (Requires Sysmon)_
  * PSExec Use
    * _PTFM: Remote Admin tools - pg. 16 (Requires WinEventLogs)_
    * _PTFM: PSExec Use pg. 55 (Requires Registry Changes)_
* C2 Detection
  * Use of Hard Coded IP addresses
    * _PTFM: Hard coded IP use pg. 65 (Requires Memory dump)_
* Cloud
  * AWS&#x20;
    * Cloudtrail Monitoring
      * _Operator Handbook: AWS\_Defend- pg. 20_

