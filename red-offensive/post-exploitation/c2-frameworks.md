# C2 Frameworks

C2 Frameworks (Post Exploitation Frameworks) are the command and control tools used for managing connections to compromised assets. Offensive testers can use these for research and testing of their environment's defenses against popular tools used by threat actors.

{% hint style="danger" %}
These are NOT to be used in a malicious capacity and are for testing purposes only. Seriously, dont be that person.
{% endhint %}

## Command and Control Basics

* The implant is the payload component of an exploit, which will be executed on the victim’s computer. Once an implant is running on the target system, it will attempt to call back to the C2 server periodically to check for new commands.
* The C2 servers that communicate with the implants on a victim system vary in complexity and functionality, but the basic functionality allows the attacker to queue up commands for the implant to execute. The C2 server commands typically deal with two areas: the implant configuration, and interacting with the infected host.
* The C2 servers that communicate with the implants on a victim system vary in complexity and functionality, but the basic functionality allows the attacker to queue up commands for the implant to execute. The C2 server commands typically deal with two areas: the implant configuration, and interacting with the infected host. Examples of this are changing the beacon timings and exfiltrating the Windows SAM file. Commands can be queued up with most C2 servers, allowing actions to be carried out at specific times; this could help to blend into network traffic at peak times, or to communicate when the security team have left work.
* The C2 servers are typically configured to appear as if they’re running common services, such as HTTP or DNS. This helps the communications to appear like legitimate traffic, which will assist in avoiding detection if tools such as Snort or RSA's Netwitness are deployed and monitoring the victim’s network.
* To further obfuscate network communications, most implants support domain fronting. Domain fronting is a technique that embeds the communications within a content delivery network (CDN). This results in the destination for traffic appearing to be trusted CDN networks like Cloudfront, Google, and Cloudflare. Using domain fronting, it is possible to quickly change CDNs if the Blue Team identify and block a particular CDN (although, this can be a challenge as it may block legitimate traffic).
* _Advanced Penetration Testing: C2  Basics and Essentials - pg. 19_
* _Advanced Penetration Testing: C2  Advanced  Attack Management - pg. 45_
* _Advanced Penetration Testing: Creating a covert C2 Solution - pg. 112_

## [**Cobalt Strike**](https://www.cobaltstrike.com/) ****&#x20;

Software for Adversary Simulations and Red Team Operations

<details>

<summary>Cobalt Strike Resources</summary>

* [bluscreenofjeff/AggressorScripts](https://github.com/bluscreenofjeff/AggressorScripts)- Script your cobalt strike
* [harleyQu1nn/AggressorScripts](https://github.com/harleyQu1nn/AggressorScripts) - Alternate collection of scripts
* [ElevateKit](https://github.com/rsmudge/ElevateKit) - Use 3rd party privilege escalation techniques with Cobalt Strike's beacon payload
* [StayKit](https://github.com/0xthirteen/StayKit) - StayKit is an extension for Cobalt Strike persistence by leveraging the execute\_assembly function with the SharpStay .NET assembly.
* [MoveKit](https://github.com/0xthirteen/MoveKit) - Movekit is an extension of built in Cobalt Strike lateral movement by leveraging the execute\_assembly function with the SharpMove and SharpRDP .NET assemblies.
* [spawn](https://github.com/boku7/spawn) - Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing.
* [SharpLAPS](https://github.com/swisskyrepo/SharpLAPS) - Retrieve LAPS password from LDAP
* [AzureC2Relay](https://github.com/Flangvik/AzureC2Relay) - AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
* [CobaltStrike-Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cobalt%20Strike%20-%20Cheatsheet.md)
* [https://www.ired.team/offensive-security/red-team-infrastructure/cobalt-strike-101-installation-and-interesting-commands](https://www.ired.team/offensive-security/red-team-infrastructure/cobalt-strike-101-installation-and-interesting-commands)
* _Operator Handbook: Cobalt Strike - pg. 52_

</details>

## ****[**PoshC2**](https://github.com/nettitude/PoshC2/)****

PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming, post-exploitation and lateral movement. This is my framework of choice.

<details>

<summary>PoshC2 Resources</summary>

* [https://poshc2.readthedocs.io/en/latest/](https://poshc2.readthedocs.io/en/latest/)
* [Apache Mod Python](https://labs.nettitude.com/blog/apache-mod\_python-for-red-teams/) - Advanced C2 comms through Apache web servers
* [https://www.youtube.com/watch?v=zj0ijJF9cEQ\&feature=youtu.be](https://www.youtube.com/watch?v=zj0ijJF9cEQ\&feature=youtu.be)
* [https://www.youtube.com/watch?v=XKJ4hTPGBQ4\&feature=emb\_title](https://www.youtube.com/watch?v=XKJ4hTPGBQ4\&feature=emb\_title)

</details>

<details>

<summary>PoshC2 Command Usage</summary>

* &#x20;[https://poshc2.readthedocs.io/](https://poshc2.readthedocs.io/)
* To run PoshC2, navigate to the installation directory and run the C2Server.py. This will start the server that serves the implant payloads and communicates with any running implants.
* Prior to running the C2Server.py, it is possible to modify the configuration of the C2 server with the Config.py and restart any running server.
* Once the C2 server has been started, a list of payloads will be shown to the user, which can be used in social engineering attacks or if access to cmd.exe or powershell.exe is available.
* To communicate and issue commands to any implants we have deployed, we must connect into the C2 server by using the ‘ImplantHandler.py’.
* [https://poshc2.readthedocs.io/en/latest/install\_and\_setup/firsttime2.html](https://poshc2.readthedocs.io/en/latest/install\_and\_setup/firsttime2.html)
* [https://github.com/nettitude/PoshC2/wiki/Getting-Started](https://github.com/nettitude/PoshC2/wiki/Getting-Started)
* [https://github.com/nettitude/PoshC2/wiki/Privilege-Esca](https://github.com/nettitude/PoshC2/wiki/Privilege-Escalation)

</details>

## [**DNScat2**](https://github.com/iagox86/dnscat2)&#x20;

This tool is designed to create an encrypted command-and-control (C\&C) channel over the DNS protocol, which is an effective tunnel out of almost every network.

<details>

<summary>DNScat2 Resources</summary>

* [https://www.kali.org/tools/dnscat2/](https://www.kali.org/tools/dnscat2/)
* [https://github.com/lukebaggett/dnscat2-powershell/](https://github.com/lukebaggett/dnscat2-powershell/)&#x20;
* [https://www.blackhillsinfosec.com/bypassing-cylance-part-2-using-dnscat2/](https://www.blackhillsinfosec.com/bypassing-cylance-part-2-using-dnscat2/)
* _Hacker Playbook 3: dnscat2 - pg.15_

</details>

## **Other Frameworks**

* [https://www.thec2matrix.com/matrix](https://www.thec2matrix.com/matrix) - Find All the popular C2 Frameworks

<details>

<summary>Other Frameworks</summary>

* [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) - SILENTTRINITY is modern, asynchronous, multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR.
  * [https://www.kali.org/tools/silenttrinity/](https://www.kali.org/tools/silenttrinity/)
* [Mythic](https://github.com/its-a-feature/Mythic) - A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI.
  * [https://github.com/MythicAgents/hermes](https://github.com/MythicAgents/hermes) - Swift 5 macOS agent
* [Kaodic](https://github.com/zerosum0x0/koadic) - Koadic, or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript), with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
* [trevorc2](https://github.com/trustedsec/trevorc2) - Written by Dave Kennedy of TrustedSec, TrevorC2 is a client/server model for masking command and control through a normally browsable website. Detection becomes much harder as time intervals are different and does not use POST requests for data exfil.
* [Merlin](https://github.com/Ne0nd0g/merlin) - Merlin is a cross-platform post-exploitation C2 server and agent written in Go.
  * &#x20;[https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a#df21](https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a#df21)
* [Prismatica](https://prismatica.io/) - Project Prismatica is a focused framework for Command and Control that is dedicated to extensibility. Our core objective is to provide a convenient platform with modular Transports, Backends, and Implants to enable rapid retooling opportunities and enhance Red Team operations.
  * [https://prismatica.io/guides/](https://prismatica.io/guides/)
  * [Diagon](https://github.com/Project-Prismatica/Diagon) - The Diagon Attack Framework is a Prismatica application containing the Ravenclaw, Gryffindor, and Slytherin remote access tools (RATs).
  * [Oculus](https://github.com/Project-Prismatica/Oculus) - Oculus is a malleable python-based C2 system allowing for instantiation of listeners for the purpose of communication with remote access tools (RATs).
  * [Acheron](https://github.com/Acheron-VAF/Acheron) - Acheron is a RESTful vulnerability assessment and management framework built around search and dedicated to terminal extensibility.
  * [Tiberium](https://github.com/0sm0s1z/Tiberium) - A Command and Control scanning tool
* [Gdog](https://github.com/maldevel/gdog) (gcat replacement) - A stealthy Python based Windows backdoor that uses Gmail as a command and control server. This project was inspired by the gcat([https://github.com/byt3bl33d3r/gcat](https://github.com/byt3bl33d3r/gcat)) from byt3bl33d3r.
* [DarkFinger-C2](https://github.com/hyp3rlinx/DarkFinger-C2/) - Windows TCPIP Finger Command / C2 Channel and Bypassing Security Software
  * [https://nasbench.medium.com/understanding-detecting-c2-frameworks-darkfinger-c2-539c79282a1c](https://nasbench.medium.com/understanding-detecting-c2-frameworks-darkfinger-c2-539c79282a1c)
* [Godoh](https://github.com/sensepost/godoh) - A DNS-over-HTTPS C2
  * [https://www.kali.org/tools/godoh/](https://www.kali.org/tools/godoh/)
* [sliver](https://www.kali.org/tools/sliver/) - This package contains a general purpose cross-platform implant framework that supports C2 over Mutual-TLS, HTTP(S), and DNS. Implants are dynamically compiled with unique X.509 certificates signed by a per-instance certificate authority generated when you first run the binary.
* [TripleCross](https://github.com/h3xduck/TripleCross) - A Linux eBPF rootkit with a backdoor, C2, library injection, execution hijacking, persistence and stealth capabilities.
* [iscariot-suite](https://gitlab.com/badsectorlabs/iscariot-suite) - The Iscariot Suite is a collection of tools to enhance and augment trusted open-source and commercial Blue Team/Sysadmin products, turning them into traitorware to achieve offensive security goals.
* [shad0w](https://github.com/bats3c/shad0w) - A post exploitation framework designed to operate covertly on heavily monitored environments
* [Covenant](https://github.com/cobbr/Covenant) - Covenant is a collaborative .NET C2 framework for red teamers.
* _PTFM: C2 Tools - pg. 62_

</details>

## Remote Management Shells/RATs

<details>

<summary>Shells and Rats</summary>

* [Awesome Lists Collection: RATs](https://github.com/alphaSeclab/awesome-rat/blob/master/Readme\_en.md)
* [https://github.com/AJMartel/MeGa-RAT-Pack](https://github.com/AJMartel/MeGa-RAT-Pack)
* [p0wnedshell](https://github.com/Cn33liz/p0wnedShell) - p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET).
* [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) - This shell is the ultimate WinRM shell for hacking/pentesting.
* [Pupy](https://github.com/n1nj4sec/pupy) - Pupy is a cross-platform, multi function RAT and post-exploitation tool mainly written in python. It features an all-in-memory execution guideline and leaves a very low footprint.
* [NGROK](https://ngrok.com/product) - Ngrok exposes local servers behind NATs and firewalls to the public internet over secure tunnels.
* [TheFatRat](https://github.com/Screetsec/TheFatRat) - Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and etc . This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac.d
* [EvilOSX](https://github.com/Marten4n6/EvilOSX) - Remote Administration Tool for macOS / OS X.
  * [https://www.hackingarticles.in/evilosx-rat-for-macos-osx/](https://www.hackingarticles.in/evilosx-rat-for-macos-osx/)
* [serpentine](https://github.com/jafarlihi/serpentine) - serpentine is a Windows RAT (Remote Administration Tool) that lets you interact with the clients using a multiplatform RESTful C2 server.
* [QuasarRAT](https://github.com/quasar/Quasar) - Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface, Quasar is the perfect remote administration solution for you.
* [Remcos-Professional-Cracked-By-Alcatraz3222](https://github.com/cybertoxin/Remcos-Professional-Cracked-By-Alcatraz3222) - Remcos lets you extensively control and manage one or many computers remotely.

</details>

{% embed url="https://youtu.be/kyueZUfSWO4" %}

{% embed url="https://youtu.be/rffkJDcri18" %}

## Tor C2

&#x20;A C2 server can be provisioned as a node within the Tor network and force the compromised host to connect to Tor when it comes online.&#x20;

<details>

<summary>How to Tor C2</summary>

* Torrc file - Tor stores its configuration in a file called torrc.&#x20;
  * In order to create a hidden service append the following lines to the torrc file&#x20;

```
# Configure hidden service directory 
HiddenServiceDir /home/username/tor_hidden 
# C2 Web Port 
HiddenServicePort 443 127.0.0.1:443
# C2 SSH Port 
HiddenServicePort 7022 127.0.0.1:7022
#C2 Metasploit Listener
HiddenServicePort 8080 127.0.0.1:8080
```

* The hidden service directory will be the place where our server will store the keys and should be outside the web server's root directory&#x20;
* The next time Tor is started, two files will be created in the tor\_hidden directory. Those files are a prive\_key and a hostname file that contains a has of the public key&#x20;
* When the C2 is live and being provisioned over the Tor network using this configuration, it can be accessed by C2 agents anywhere in the world.&#x20;
* Configuring a C2 agent to use the Tor network&#x20;
  * Once the C2 server is configured to accept connections over Tor, the next step is to enable the C2 agents deployed on compromised machines to do so.&#x20;
  * The easiest way is to bundle tor.exe with the agent and execute ti without parameters. ◇ This will cause it to run in a hidden window and open a SOCKS proxy port on localhost 9050.&#x20;
  * Please rename so it is not immediately visible in the Windows process list&#x20;
  * Changes that need to be made ▪ Change teh SSH tunneling IPs from the Internet IPv4 addresses within the code to point to the .onion address mentioned previously.&#x20;
  * Tell the SSH SOCKS proxy to upstream to the Tor SOCKs proxy on TCP 9050

</details>
