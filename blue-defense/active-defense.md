# Active Defense

## Theory

### [**Mitre Shield** ](https://shield.mitre.org/matrix/)

The sister framework to Mitre Att\&ck, Mitre Shield is the framework of mapping tools and techniques to the area of Active Defense. The U.S. Department of Defense defines active defense as “The employment of limited offensive action and counterattacks to deny a contested area or position to the enemy.” Within Mitre Shield, active defense ranges from basic cyber defensive capabilities to cyber deception and adversary engagement operations. The combination of these defenses allows an organization to not only counter current attacks but also to learn more about that adversary and better prepare for new attacks in the future.

## **Tools**

### **Honeypots**

Honeypots are a core part of Active Defense. Beyond thier incredible value for learning about attackers and their methods, they are an incredible utility for detection in security programs of any maturity level. One of the core concepts of Honeypots is the assumption that compromise will happen. By preparing a target so juicy, or a resource so infrequently used that access to it can be initiated by an unsuspecting attacker, you can catch actors in your network even if they are savy enough to sneak past all your other defenses.

* [Awesome Lists Collection : Honeypots](https://github.com/paralax/awesome-honeypots)
* [https://tryhackme.com/room/introductiontohoneypots](https://tryhackme.com/room/introductiontohoneypots)
* [https://www.honeynet.org/](https://www.honeynet.org/)
* _Using Canary Honeypots for Detection - Applied Network Security Monitoring, pg.317_

{% tabs %}
{% tab title="Honeypot Tools" %}
* [HoneyD](https://www.honeyd.org) - The OG Honeypot. Honeyd is a small daemon that creates virtual hosts on a network. The hosts can be configured to run arbitrary services, and their personality can be adapted so that they appear to be running certain operating systems.
* [MDH: Modern Honeypot Network ](https://github.com/pwnlandia/mhn)- Easy to install and configure Honeypot service. Has config scripts for Snort, Cowrie, and Dionea.&#x20;
* [Open Canary](https://github.com/thinkst/opencanary) - One of the most popular and flexible honeypot applications available. OpenCanary is a daemon that runs canary services, which can trigger alerts when accessed. The alerts can be sent to syslog, emails or an opencanary-correlator.
  * [https://adhdproject.github.io/#!Tools/Attribution/OpenCanary.md](https://adhdproject.github.io/#!Tools/Attribution/OpenCanary.md)
* [Wordport - The Wordpress based Honeypot](https://github.com/adhdproject/wordpot)
  * [https://adhdproject.github.io/#!Tools/Annoyance/Wordpot.md](https://adhdproject.github.io/#!Tools/Annoyance/Wordpot.md)
* [Labrea](https://labrea.sourceforge.io/labrea-info.html) - LaBrea takes over unused IP addresses, and creates virtual servers that are attractive to worms, hackers, and other denizens of the Internet. The program answers connection attempts in such a way that the machine at the other end gets "stuck", sometimes for a very long time.
{% endtab %}

{% tab title="Honeyports" %}
Honeyports are a great way to dynamically blacklist  attacking systems. You can create a simple script that dynamically blacklist attackers when they establish full connections to certain ports, or perform simple alerting.

* [Honeyports tool](https://github.com/adhdproject/honeyports)
  * [https://adhdproject.github.io/#!Tools/Annoyance/HoneyPorts.md](https://adhdproject.github.io/#!Tools/Annoyance/HoneyPorts.md)
* [RubberGlue](https://github.com/adhdproject/rubberglue)
  * [https://adhdproject.github.io/#!Tools/Annoyance/Rubberglue.md](https://adhdproject.github.io/#!Tools/Annoyance/Rubberglue.md)
  * [https://bitbucket.org/Zaeyx/rubberglue/src/master/](https://bitbucket.org/Zaeyx/rubberglue/src/master/)
* [Invisport ](https://bitbucket.org/Zaeyx/invisiport/src/master/)&#x20;
* _Offensive Countermeasures - pg. 34_
{% endtab %}

{% tab title="Honey-Assets" %}
Files, Objects, Accounts, or other resources that would normally not be touches by any legitimate user or process, that are set to perform a specific action when accessed.

* [Canary Tokens](http://canarytokens.org/) - Canary Tokens are outstanding objects that can beacon back when activated. For example, you could create a Word document that calls back. Or, in this example, a little snippet of HTML code that calls back whenever it is activated
  * [https://adhdproject.github.io/#!Tools/Attribution/CanaryTokens.md](https://adhdproject.github.io/#!Tools/Attribution/CanaryTokens.md)
  * [https://www.youtube.com/watch?v=mDnaEmpO1C4](https://www.youtube.com/watch?v=mDnaEmpO1C4)
* [dcept](https://github.com/secureworks/dcept) - A tool for deploying and detecting use of Active Directory honeytokens
* [CryptoLocked](https://github.com/PrometheanInfoSec/cryptolocked-ng) - an anti-ransomware toolkit
* [Artillery](https://github.com/BinaryDefense/artillery) - Honeypot, honeyport, file integrity monitoring all in one. The one project to rule them all.
  * [https://adhdproject.github.io/#!Tools/Annoyance/Artillery.md](https://adhdproject.github.io/#!Tools/Annoyance/Artillery.md)
  * [https://medium.com/@Mag1cM0n/active-cyberdefense-installing-artillery-on-windows-server-2012-r2-e1ab22974947](https://medium.com/@Mag1cM0n/active-cyberdefense-installing-artillery-on-windows-server-2012-r2-e1ab22974947)
  * _Offensive Countermeasures - pg. 76_
  * _Honeydocs - Applied Network Security Monitoring, pg.335_
{% endtab %}
{% endtabs %}

{% embed url="https://youtu.be/14YuyMkfB9Q" %}

### **Attribution**

Ever wonder who is attacking you? Not what IP they are proxying through, but who is really attacking you? Unmasking attackers and getting detailed intelligence on how your data is being accessed and used, allows you to take proactive steps to protect against the next round of attacks.

* [Cowrie](https://github.com/cowrie/cowrie) - Cowrie is a medium to high interaction SSH and Telnet honeypot designed to log brute force attacks and the shell interaction performed by the attacker. In medium interaction mode (shell) it emulates a UNIX system in Python, in high interaction mode (proxy) it functions as an SSH and telnet proxy to observe attacker behavior to another system.
  * [https://adhdproject.github.io/#!Tools/Annoyance/Cowrie.md](https://adhdproject.github.io/#!Tools/Annoyance/Cowrie.md)
  * [Guide to using Cowrie](https://slashparity.com/?p=734)
* [Decloak](https://bitbucket.org/ethanr/decloak) - Used to identify the real IP address of a web user, regardless of proxy settings, using a combination of client-side technologies and custom services.
  * [https://adhdproject.github.io/#!Tools/Attribution/Decloak.md](https://adhdproject.github.io/#!Tools/Attribution/Decloak.md)
* [HoneyBadger](https://github.com/adhdproject/honeybadger) - Used to identify the physical location of a web user with a combination of geolocation techniques using a browser's share location feature, the visible WiFi networks, and the IP address.
  * [https://adhdproject.github.io/#!Tools/Attribution/HoneyBadger.md](https://adhdproject.github.io/#!Tools/Attribution/HoneyBadger.md)
* [https://github.com/Phype/telnet-iot-honeypot](https://github.com/Phype/telnet-iot-honeypot)

### **Network Poisoner Detection**

Network Poisoners like Responder can capture and respond to LLMNR, NBT-NS and MDNS traffic within your network for use in lateral movement and internal recon. It will answer to _specific_ NBT-NS (NetBIOS Name Service) queries based on their name suffix. It is possible to detect these by various means including sets of fake credentials that would only be captured by a network poisoner.

* [Respounder](https://github.com/codeexpress/respounder) - Respounder sends LLMNR name resolution requests for made-up hostnames that do not exist. In a normal non-adversarial network we do not expect such names to resolve. However, a responder, if present in the network, will resolve such queries and therefore will be forced to reveal itself.
* [HoneyCreds](https://github.com/Ben0xA/HoneyCreds) - HoneyCreds network credential injection to detect responder and other network poisoners.

## **Resources and Collections**

* [Awesome Lists Collection: Active Defense](https://github.com/adhdproject/awesome-active-defense)
* [ADHD - Active Defense Harbinger Distribution ](https://adhdproject.github.io/#!index.md)- A project that has spawned from the work of Blackhills Infosec and Active Countermeasures, ADHD is a ubuntu based OS distribution that comes loaded with a slew of the best Active defense focused tools available. It is a free distribution that also has a ton of free learning content developed by Active Countermeasures. Check out their webcasts and the training at Wild West Hackin' Fest, for more details on how to make the most of these tools
  * [https://github.com/adhdproject/adhdproject.github.io/blob/master/index.md](https://github.com/adhdproject/adhdproject.github.io/blob/master/index.md)
* [Talos Active Defense Toolkit ](https://github.com/PrometheanInfoSec/TALOS)- Provides a central hub, through which Computer Network Defenders could operate seamlessly, simply, and powerfully, to deploy Active Defense tools on their networks.
* Offensive Countermeasures: The Art of Active Defense  - John Strand
* _BTFM: Honey Techniques - pg. 48_
