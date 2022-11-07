# Pivot/Proxy/Tunnel/Redirect

## Guides and Reference

<details>

<summary>Guides and Reference</summary>

* [NetworkPivotingTechniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md)
* [Abachy's Port Forwarding Guide](https://www.abatchy.com/2017/01/port-forwarding-practical-hands-on-guide)&#x20;
* [http://woshub.com/port-forwarding-in-windows/](http://woshub.com/port-forwarding-in-windows/)
* [https://www.offensive-security.com/metasploit-unleashed/portfwd/](https://www.offensive-security.com/metasploit-unleashed/portfwd/)
* [https://pentest.blog/explore-hidden-networks-with-double-pivoting/](https://pentest.blog/explore-hidden-networks-with-double-pivoting/)
* [https://fumenoid.github.io/posts/port-forwarding](https://fumenoid.github.io/posts/port-forwarding)
* [https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/](https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/)
* [https://www.offensive-security.com/metasploit-unleashed/proxytunnels/](https://www.offensive-security.com/metasploit-unleashed/proxytunnels/)
* [https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html](https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html)
* [https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/](https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/)
* [https://xapax.github.io/security/#random\_tips\_and\_tricks/port\_forwarding\_and\_tunneling/](https://xapax.github.io/security/#random\_tips\_and\_tricks/port\_forwarding\_and\_tunneling/)
* [https://xapax.github.io/security/#random\_tips\_and\_tricks/pivoting/](https://xapax.github.io/security/#random\_tips\_and\_tricks/pivoting/)
* [http://pwnwiki.io/#!pivoting/linux/index.md](http://pwnwiki.io/#!pivoting/linux/index.md)
* [https://medium.com/@kuwaitison/pivoting-and-tunneling-for-oscp-and-beyond-cheat-sheet-3435d1d6022](https://medium.com/@kuwaitison/pivoting-and-tunneling-for-oscp-and-beyond-cheat-sheet-3435d1d6022)
* _Attacking Network Protocols: Network Proxies - pg.20_

</details>

## Tools

<details>

<summary>Tools</summary>

* [PivotSuite](https://github.com/RedTeamOperations/PivotSuite) - PivotSuite is a portable, platform independent and powerful network pivoting toolkit, Which helps Red Teamers / Penetration Testers to use a compromised system to move around inside a network.
* [ProxyChains](https://github.com/haad/proxychains) - ProxyChains is a UNIX program, that hooks network-related libc functions in dynamically linked programs via a preloaded DLL and redirects the connections through SOCKS4a/5 or HTTP proxies.
* [Modaliska](https://github.com/drk1wi/Modlishka)  - Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow, which allows to transparently proxy multi-domain destination traffic, both TLS and non-TLS, over a single domain, without a requirement of installing any additional certificate on the client.
* [SSHuttle](https://github.com/sshuttle/sshuttle) - Where transparent proxy meets VPN meets ssh.
  * [https://sshuttle.readthedocs.io/en/stable/](https://sshuttle.readthedocs.io/en/stable/)&#x20;
* [Iodine](https://github.com/yarrick/iodine) - This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.
* [Mallory](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH.
* [Pivotnacci](https://github.com/blackarrowsec/pivotnacci) - Pivot into the internal network by deploying HTTP agents.
* [PacketWhisper](https://github.com/TryCatchHCF/PacketWhisper) - PacketWhisper: Stealthily exfiltrate data and defeat attribution using DNS queries and text-based steganography. Avoid the problems associated with typical DNS exfiltration methods. Transfer data between systems without the communicating devices directly connecting to each other or to a common endpoint. No need to control a DNS Name Server.
* [chisel](https://www.kali.org/tools/chisel/) - This package contains a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network.
* [cryptcat](https://www.kali.org/tools/cryptcat/) - Cryptcat is a simple Unix utility which reads and writes data across network connections, using TCP or UDP protocol while encrypting the data being transmitted.
* [dns2tcp](https://www.kali.org/tools/dns2tcp/) - dns2tcp is a set of tools to encapsulate a TCP session in DNS packets. This type of encapsulation generates smaller packets than IP-over-DNS, improving throughput.
* [dnschef](https://www.kali.org/tools/dnschef/) - DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts.
* [iodine](https://www.kali.org/tools/iodine/) - This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.
* [miredo](https://www.kali.org/tools/miredo/) - A client for the Teredo IPV6 tunneling protocol.
* [nextnet](https://www.kali.org/tools/nextnet/) - This package contains a pivot point discovery tool written in Go.
* [redsocks](https://www.kali.org/tools/redsocks/) - Redsocks is a daemon running on the local system, that will transparently tunnel any TCP connection via a remote SOCKS4, SOCKS5 or HTTP proxy server.
* [sslh](https://www.kali.org/tools/sslh/) - sslh lets one accept HTTPS, SSH, OpenVPN, tinc and XMPP connections on the same port. This makes it possible to connect to any of these servers on port 443 (e.g. from inside a corporate firewall, which almost never block port 443) while still serving HTTPS on that port.

</details>

## Techniques and Commands

{% tabs %}
{% tab title="Linux Port Fwd" %}
* rinetd&#x20;
  * \# sudo apt update && sudo apt install rinetd&#x20;
  * The rinetd configuration file, /etc/rinetd.conf, lists forwarding rules that require four parameters, including bindaddress and bindport, which define the bound (“listening”) IP address and port, and connectaddress and connectport, which define the traffic’s destination address and port:&#x20;
  * \# cat /etc/rinetd.conf&#x20;
  * \# sudo service rinetd restart


{% endtab %}

{% tab title="Plink.exe" %}
* Plink.exe&#x20;
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

{% tab title="SSH Tunnel" %}
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

{% tab title="Proxychains" %}
* \#cat /etc/proxychains.conf&#x20;
* \#sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
* [How to set up ProxyChains - Stay Anonymous](pivot-proxy-tunnel-redirect.md#linux-ssh-tunneling)
* [How to set up ProxyChains - Change IP](https://youtu.be/FtFTh-KVjsA)
{% endtab %}

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

{% tab title="Misc" %}
### **RDP Tunneling**

* _PTFM: RDP Tunneling - pg. 53_

### **NGINX for proxy**

* _PTFM: NGINX for proxy use- pg. 64_
{% endtab %}
{% endtabs %}
