# Active Defense

## Theory

### [**MITRE Engage**](https://engage.mitre.org/)

MITRE Engage (formerly MITRE Shield) is a framework designed to map tools and techniques in the realm of Active Defense and adversary engagement. The U.S. Department of Defense defines active defense as "The employment of limited offensive action and counterattacks to deny a contested area or position to the enemy." MITRE Engage helps defenders improve their cyber deception and active defense strategies by standardizing terminology and creating opportunities to engage adversaries.

*Note: The original MITRE Shield matrix has been archived and superseded by MITRE Engage.*

### **Moving Target Defense (MTD)**

Moving Target Defense is a strategy that involves dynamically shifting the attack surface to increase uncertainty and complexity for attackers. By continuously changing system configurations, network addresses, or software environments, defenders can limit the window of opportunity for an attack and force adversaries to constantly re-acquire targets.

## **Tools**

### **Honeypots**

Honeypots are a cornerstone of Active Defense. Beyond their value in gathering intelligence on attackers and their methods, they offer exceptional utility for detection across security programs of all maturity levels. A key concept behind honeypots is the assumption that compromise is inevitable. By deploying attractive targets or resources that are rarely accessed, any interaction with them becomes inherently suspicious. This approach allows defenders to detect threat actors within the network, even if those actors have successfully evaded other defensive measures.

* [Awesome Lists Collection : Honeypots](https://github.com/paralax/awesome-honeypots)
* [https://tryhackme.com/room/introductiontohoneypots](https://tryhackme.com/room/introductiontohoneypots)
* [https://www.honeynet.org/](https://www.honeynet.org/)
* _Using Canary Honeypots for Detection - Applied Network Security Monitoring, pg.317_

{% tabs %}
{% tab title="Honeypot Tools" %}
* [**OpenCanary**](https://github.com/thinkst/opencanary) - A highly popular and flexible honeypot application. OpenCanary runs "canary" services that trigger alerts upon access. These alerts can be forwarded to syslog, email, or an OpenCanary correlator.
  * [Reference: ADHD Project - OpenCanary](https://adhdproject.github.io/#!Tools/Attribution/OpenCanary.md)
* [**T-Pot**](https://github.com/telekom-security/tpotce) - An all-in-one, multi-honeypot platform. T-Pot includes many of the tools listed here (like Cowrie, HoneyTrap, etc.) in a pre-configured, Dockerized environment with an ELK stack for visualization.
* [**Dionaea**](https://github.com/Dionaea/dionaea) - A low-interaction honeypot designed to capture malware by simulating vulnerable services.
* [**Cowrie**](https://github.com/cowrie/cowrie) - A medium-to-high interaction SSH and Telnet honeypot designed to log brute-force attacks and shell interactions.
{% endtab %}

{% tab title="Tarpits" %}
Tarpits are designed to slow down or stall automated attacks and scanners. Unlike honeypots which monitor, tarpits actively consume attacker resources (time) by keeping connections open indefinitely or responding very slowly.

* [**Endlessh**](https://github.com/skeeto/endlessh) - An SSH tarpit that sends an endless, random SSH banner. It can trap SSH clients and scripted attacks, keeping them occupied for hours or days without using significant server resources.
{% endtab %}

{% tab title="Honeyports" %}
Honeyports provide an effective mechanism for dynamically blocking or "blacklisting" attacking systems. By monitoring specific ports, you can employ scripts that automatically block attackers upon establishing a full connection, or simply trigger alerting mechanisms.

* [**HoneyPorts**](https://github.com/adhdproject/honeyports)
  * [Reference: ADHD Project - HoneyPorts](https://adhdproject.github.io/#!Tools/Annoyance/HoneyPorts.md)
* [**RubberGlue**](https://github.com/adhdproject/rubberglue)
  * [Reference: ADHD Project - RubberGlue](https://adhdproject.github.io/#!Tools/Annoyance/Rubberglue.md)
  * [Source: Bitbucket](https://bitbucket.org/Zaeyx/rubberglue/src/master/)
* [**Invisiport**](https://bitbucket.org/Zaeyx/invisiport/src/master/)
* _Reference: Offensive Countermeasures - pg. 34_
{% endtab %}

{% tab title="Honey-Assets" %}
Honey-assets act as "tripwires." These are files, objects, accounts, or other resources that legitimate users or processes have no reason to access. They are configured to trigger a specific action or alert when interacted with.

* [**Canary Tokens**](http://canarytokens.org/) - Deceptive objects that beacon back to a server when activated. Examples include a Word document that alerts when opened or an HTML snippet that calls home when a page is accessed.
  * [Reference: ADHD Project - CanaryTokens](https://adhdproject.github.io/#!Tools/Attribution/CanaryTokens.md)
  * [Video: Canary Tokens Overview](https://www.youtube.com/watch?v=mDnaEmpO1C4)
* [**CryptoLocked**](https://github.com/PrometheanInfoSec/cryptolocked-ng) - An anti-ransomware toolkit designed to detect and impede ransomware activity.
  * *Note: Verify current maintenance status before deployment.*
{% endtab %}
{% endtabs %}

{% embed url="https://youtu.be/14YuyMkfB9Q" %}

### **Active Response**

Active Response involves taking automated, direct action against a detected threat to block or mitigate it in real-time. This differs from passive detection where an alert is generated for human review.

* [**Fail2Ban**](https://github.com/fail2ban/fail2ban) - A widely-used intrusion prevention software that scans log files (e.g., `/var/log/auth.log`) and bans IPs that show malicious signs like too many password failures.
* [**CrowdSec**](https://github.com/crowdsecurity/crowdsec) - A modern collaborative security automation engine. It analyzes behaviors, responds to attacks (by blocking IPs, presenting captchas, etc.), and shares threat intelligence across the community.
* [**PSAD**](https://github.com/mrash/psad) (Port Scan Attack Detection) - Analyzes iptables log messages to detect, alert, and (optionally) block port scans and other suspect traffic.

### **Attribution**

Attribution focuses on identifying the adversary behind an attack. Unmasking attackers and gathering detailed intelligence on their methods and motivations enables organizations to differentiate between opportunistic scripts and targeted campaigns, allowing for more effective response strategies.

* [**HoneyBadger**](https://github.com/adhdproject/honeybadger) - Identifies the physical location of a web user by combining browser geolocation features, visible WiFi networks, and IP address data.
  * [Reference: ADHD Project - HoneyBadger](https://adhdproject.github.io/#!Tools/Attribution/HoneyBadger.md)
* [**Telnet IoT Honeypot**](https://github.com/Phype/telnet-iot-honeypot) - A Python-based honeypot designed to catch botnets that utilize Telnet.

### **Network Poisoner Detection**

Tools like Responder act as "network poisoners" by listening for and responding to LLMNR, NBT-NS, and mDNS multicast requests within a network. Detecting these poisoners often involves broadcasting queries for non-existent resources or deploying fake credentials.

* **HoneyCreds** - A network credential injection tool designed to detect Responder and other active network poisoners by monitoring for attempts to capture the injected credentials.

## **Legacy or Deprecated Tools**

While these tools were historically significant or useful, they are often unmaintained, superseded by modern alternatives, or no longer actively developed. They are listed here for educational purposes or reference for older environments.

* **HoneyD** - The original honeypot concept, but unmaintained for many years.
* **MHN (Modern Honeypot Network)** - Once a standard for honeypot management, the original project is largely inactive.
* **Wordpot** - A WordPress honeypot, likely outdated due to the rapid changes in WordPress core.
* **LaBrea** - An early tarpit innovation, now largely of historical interest (see *Endlessh* for a modern alternative).
* **Artillery** - While effective in its time, development has slowed or ceased in favor of other EDR/active response tools.
* **Decloak** - A tool used to identify the real IP address of a web user. Relied on older technologies like Flash/Java applets which are now deprecated in modern browsers.
* **dcept** - An early tool for deploying Active Directory honey tokens (from SecureWorks).
* **Respounder** - A tool to detect Responder by generating LLMNR queries.

## **Resources and Collections**

* [**Awesome Lists: Active Defense**](https://github.com/adhdproject/awesome-active-defense)
* [**ADHD - Active Defense Harbinger Distribution**](https://adhdproject.github.io/#!index.md) - Born from the work of Black Hills Information Security and Active Countermeasures, ADHD is an Ubuntu-based distribution pre-loaded with a comprehensive suite of active defense tools. It also includes extensive learning content.
  * [Source Repo](https://github.com/adhdproject/adhdproject.github.io/blob/master/index.md)
* [**TALOS Active Defense Toolkit**](https://github.com/PrometheanInfoSec/TALOS) - A central hub for seamless deployment of active defense tools on defensive networks.
* **Book:** *Offensive Countermeasures: The Art of Active Defense* - John Strand
* _Reference: BTFM: Honey Techniques - pg. 48_
