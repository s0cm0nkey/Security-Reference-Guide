# Command Line

**Abnormal Command Line Length**

* Theory
  * Typically in legitimate administrative and defensive uses, commands sent to the command line are typically short for single purposes, or instead call premade scripts to the command line. In order to bypass AV detection of malicious scripts, attackers will send the entirety of the script into the command line. This can create command line parameters that are significantly longer than what is typically used by that user.
* Detection Requirements
  * Command Line Logging
  * Logging of Event IDs 4103 and/or 4104, 4105, and 4106
* Logic 1 - Powershell
  * Where
    * One of the following EventIDs occurs:
      * EventID 4103 OR EventID 4104 OR EventID 4105 OR EventID 4106
    * AND
    * Character count of the command line parameters >= 500
      * \*This count can be adjustable depending on the environment.\*
  * Filtering: (Legit applications with long command line tasks)
    * Chrome.exe settings actions
    * Adobe Reader
* Reference

**Commands encoded with Base64**

* Theory
  * Languages like Powershell have the ability to interpret commands encoded with Base64 at runtime. When running approved commands within a network, there is little to no reason to encode your commands. Attackers will often encode their commands to obfuscate their purpose and bypass keyword detection. Looking for anything encoded with Base64, is a great way to detect these methods.
* Detection Requirements
  * Command Line Logging
  * Optional: Native Base64 detection by SIEM or other tool.
  * Logging of Event IDs 4103 and/or 4104, 4105, and 4106
* Logic 1 - Powershell
  * Where
    * One of the following EventIDs occurs:
      * EventID 4103 OR EventID 4104 OR EventID 4105 OR EventID 4106
    * AND
    * The use of Base64 is detected within the command line.
  * Regex to detect:
    * `(?<base64_code>[A-Za-z0-9+/]{50,}[=]{0,2})`
      * Detects Base64 longer than 50 characters.

**Execution of Downloaded Code**

* Theory
  * Many languages have the ability to pull remote code directly into memory and be executed. While rarely used for legitimate defensive or administrative purposes, it is a popular way for attackers to run scripts without having them touch the local file system, and therefore be detected by AV.
* Detection Requirements
  * Command Line Logging
  * Logging of Event IDs 4103 and/or 4104, 4105, and 4106
* Logic 1 - Powershell
  * Where
    * One of the following EventIDs occurs:
      * EventID 4103 OR EventID 4104 OR EventID 4105 OR EventID 4106
    * AND
    * The presence of one of the following strings
      * "Invoke-Expression"
      * "iex"
      * "Net.WebClient"
      * "-enc"
* Reference

**Powershell Downgrade Attack**

* Theory
  * Powershell v5 has many handy security features that protect the system from various attacks. V5 systems also have the ability to downgrade powershell to earlier versions for compatibility purposes. This allows attackers to downgrade powershell to older versions, in order to evade the security features of v5.
* Detection Requirements
  * Command line logging
  * Logging of Event ID 400
* Logic
  * Where
    * EventID 400 Occcurs
    * AND
    * EngineVersion!=5.0 or newer.
* Reference

**Suspicious Command Line String Detected.**

* Theory
  * There are certain strings that can be used to detect certain types of activity that is either unwanted or should be monitored due to the context of the string.
  * "wmi" commands may be used internally, however they are a favorite for attackers exploiting a system. Filter and monitor its use.
  * "DLL" commandlets should always be monitored, as there are no built-in commandlets containing "DLL" in thier name.
* Detection Requirements
  * Command Line Logging
  * Logging of Event IDs 4103 and/or 4104, 4105, and 4106
* Logic 1 - Powershell
  * Where
    * One of the following EventIDs occurs:
      * EventID 4103 OR EventID 4104 OR EventID 4105 OR EventID 4106
    * AND
    * The presence of one of the following strings
      * "dll" or "DLL"
      * "wmi" or "WMI"
* Reference
  * [https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)

**Powershell cmdlet long tail analysis**

* Theory
  * As most legitimate powershell actions within a network are used for system administration and also involve repetitive tasks, we can use long tail analysis to look at the cmdlets that are called the least, to identify potentially suspicious activity.
  * This can also be used to help create a powershell cmdlet allow list.
* Detection Requirements
  * Command Line Logging
  * Logging of Event IDs 4103 and/or 4104, 4105, and 4106
* Logic -&#x20;
  * Descending count by cmdlet over X time
* Reference
