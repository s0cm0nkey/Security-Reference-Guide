# Payloads and Obfuscation

## **Payloads**

[**PayloadAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings) **-** The largest and greatest collection of shells and shell commands on the web.

## **Metasploit payloads**

* Metasploit Payloads - [https://github.com/rapid7/metasploit-payloads](https://github.com/rapid7/metasploit-payloads)
* Creating Metasploit Payloads - [https://netsec.ws/?p=331](https://netsec.ws/?p=331)
* Converting a Metasploit module into a standalone binary - [https://netsec.ws/?p=262](https://netsec.ws/?p=262)
* [https://github.com/g0tmi1k/msfpc](https://github.com/g0tmi1k/msfpc) - MSFvenom Payload Creator (MSFPC)
* [r00t-3xp10it/venom](https://github.com/r00t-3xp10it/venom) - metasploit Shellcode generator/compiller

## ShellCode/Payload Crafting Tools

* [shellnoob](https://www.kali.org/tools/shellnoob/) - convert shellcode between different formats and sources.
* [https://www.vividmachines.com/shellcode/shellcode.html](https://www.vividmachines.com/shellcode/shellcode.html)
* [http://shell-storm.org/shellcode/](http://shell-storm.org/shellcode/)
* [ads-payload](https://github.com/ChrisAD/ads-payload) - Powershell script which will take any payload and put it in the a bat script which delivers the payload. The payload is delivered using environment variables, alternating data streams and wmic.
* [unicorn](https://github.com/trustedsec/unicorn) - Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory.

## **Obfuscation Tools**

### **Veil Framework**

[Veil-Framework](https://github.com/Veil-Framework/Veil) - Veil is a tool designed to generate Metasploit payloads that bypass common anti-virus solutions.

* Use the Veil payload with a meterpreter session
* Can take pre-armored shellcode and use it to create a robust executable
* Securing non-armored shellcode with AES encryption to create a compiled python executable
* [GitHub - Veil-Framework/Veil: Veil 3.1.X (Check version info in Veil at runtime)](https://github.com/veil-framework/veil)&#x20;
* [GitHub - Veil-Framework/Veil-Evasion: Veil Evasion is no longer supported, use Veil 3.0!](https://github.com/Veil-Framework/Veil-Evasion)&#x20;
* [GitHub - Veil-Framework/Veil-Ordnance: Veil-Ordnance is a tool designed to quickly generate MSF stager shellcode](https://github.com/veil-framework/veil-ordnance)

{% embed url="https://youtu.be/iz1twCSJZyo" %}

### [MSFVenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

* msfvenom cheatsheet - [https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/](https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/)
* msfvenom payloads - [https://github.com/Shiva108/CTF-notes/blob/master/msfvenom.html](https://github.com/Shiva108/CTF-notes/blob/master/msfvenom.html)
* msfvenom basic guide - [https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
* Blackhills Infosec. msfvenom advanced payload guide - [https://www.blackhillsinfosec.com/advanced-msfvenom-payload-generation/](https://www.blackhillsinfosec.com/advanced-msfvenom-payload-generation/)
* msfvenom payload calculator - [https://github.com/g0tmi1k/msfpc](https://github.com/g0tmi1k/msfpc)
* [https://book.hacktricks.xyz/shells/shells/untitled](https://book.hacktricks.xyz/shells/shells/untitled)
* [https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/](https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/)
* _Operator Handbook: MSFVenom - pg.208_

{% content-ref url="msfvenom-commands.md" %}
[msfvenom-commands.md](msfvenom-commands.md)
{% endcontent-ref %}

### **Powershell Obfuscation**

* [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) - Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
* [NoPowerShell](https://github.com/Ben0xA/nps) - Windows Binary that executes powershell through .NET instead of a direct powershell.exe call
* [https://github.com/trustedsec/nps\_payload](https://github.com/trustedsec/nps\_payload)
* [HideMyPS](https://github.com/cheetz/hidemyps) - This is a custom PowerShell Obfuscator used in The Hacker Playbook 3 (THP3). Please refer to THP3 for further details.

### **Misc Tools**

* [Sharpshooter](https://github.com/mdsecactivebreach/SharpShooter) - payload stager crafting tool
  * [https://www.mdsec.co.uk/2018/03/payload-generation-using-sharpshooter](https://www.ndsec.co.uk/2018/03/payload-generation-using-sharpshooter)
* [Shellter](https://github.com/ParrotSec/shellter) - dynamic shellcode injection tool&#x20;
  * [https://www.kali.org/tools/shellter/](https://www.kali.org/tools/shellter/)
* [BashObfuscator](https://github.com/Bashfuscator/Bashfuscator) - BashObfuscator is a modular and extendable Bash obfuscation framework written in Python 3. It provides numerous different ways of making Bash one-liners or scripts much more difficult to understand.
* OneLinerize, turn any python file into a command/payload - [https://github.com/csvoss/onelinerizer](https://github.com/csvoss/onelinerizer)
* Onelinepy - [https://www.kitploit.com/2021/06/onelinepy-python-obfuscator-to-generate.html?m=1](https://www.kitploit.com/2021/06/onelinepy-python-obfuscator-to-generate.html?m=1)
* [DNSStager](https://github.com/mhaskar/DNSStager) - DNSStager will create a malicious DNS server that handles DNS requests to your domain and return your payload as a response to specific record requests such as `AAAA` or `TXT` records after splitting it into chunks and encoding the payload using different algorithms.
* [obscureV4](https://github.com/dagonis/obscureV4) - Obscure an IPv4 address into over 100 different formats that still work for connecting to network resources. Useful for bypassing web application firewalls and intrusion detection systems.

## Guides and Reference

* Collection of Microsoft vulnerabilities and exploits that they refuse to patch. [https://github.com/cfalta/MicrosoftWontFixList](https://github.com/cfalta/MicrosoftWontFixList)
* [https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation](https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation)
