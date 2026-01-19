# IDS/IPS

## **Intrusion Detection Systems**

Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) are critical components of network defense. They analyze network traffic and logs to deny or alert on potential threats based on defined rule sets. Open-source IDS solutions are widely respected for their detection capabilities, often rivaling premium products due to active community support and publicly shared detection rules.

## [Suricata](https://suricata-ids.org/)

Suricata is a high-performance, open-source network analysis and threat detection software. It combines intrusion detection (IDS), intrusion prevention (IPS), network security monitoring (NSM), and PCAP processing. Suricata is capable of identifying, stopping, and assessing sophisticated attacks. It is widely adopted and often integrated into other security products.

* Can collect logs with syslog, [Unified2](https://www.snort.org/faq/readme-unified2), flat files, or the preferred method of [EVE](https://suricata.readthedocs.io/en/suricata-6.0.0/output/eve/eve-json-output.html)
  * EVE is a highly configurable JSON format that can support multiple files.
* [https://suricata.readthedocs.io/en/suricata-6.0.3/](https://suricata.readthedocs.io/en/suricata-6.0.3/)
* [Evebox Suricata event viewer](https://github.com/jasonish/evebox) - EveBox is a web based Suricata "eve" event viewer for Elastic Search.
* [suricata-language-server](https://github.com/StamusNetworks/suricata-language-server) - An implementation of the Language Server Protocol for Suricata signatures. It adds syntax check, hints and auto-completion to your preferred editor once it is configured.
* [https://rules.emergingthreats.net/open/suricata/rules/](https://rules.emergingthreats.net/open/suricata/rules/)
* _PTFM: Suricata Commands - pg. 185_

## [Snort](https://github.com/snort3/snort3)

Snort is a widely deployed open-source network intrusion prevention system (NIPS) and network intrusion detection system (NIDS). It allows for packet sniffing (like tcpdump), packet logging, and full-blown network intrusion prevention.

* Can collect logs via Syslog, CSV, Database, or the preferred method of [Unified2](https://www.snort.org/faq/readme-unified2)
  * Unified2 is a binary output for Snort. It will need interpretation by tools like [Barnyard](https://github.com/firnsy/barnyard2) or [u2json](https://idstools.readthedocs.io/en/latest/tools/u2json.html)
* [https://snort.org/](https://snort.org/)
* [https://snort.org/#documents](https://snort.org/#documents)
* [https://snort.org/downloads/#rule-downloads](https://snort.org/downloads/#rule-downloads)
* [https://paper.bobylive.com/Security/Snort_rule_infographic.pdf](https://paper.bobylive.com/Security/Snort_rule_infographic.pdf)
* [https://resources.infosecinstitute.com/topic/snort-rules-workshop-part-one/](https://resources.infosecinstitute.com/topic/snort-rules-workshop-part-one/)
* [Intrusion Detection Systems with Snort](http://ptgmedia.pearsoncmg.com/images/0131407333/downloads/0131407333.pdf) (PDF)
* _BTFM: SNORT - pg. 45_
* _(BTHb: INRE): Using Snort IDS - pg. 103_
* _PTFM: Snort Commands - pg. 186_
* _Operator Handbook: SNORT - pg. 276_
* _Signature-Based Detection with Snort and Surricata - Applied Network Security Monitoring - pg. 203_

### **Writing a SNORT Rule**

* [Snort Manual: Rules](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node29.html)
* [Understanding and Configuring Snort Rules (Rapid7)](https://blog.rapid7.com/2016/12/09/understanding-and-configuring-snort-rules/)

A standard rule is broken down as follows:

`[action] [protocol] [ip address] [port number] [direction] [ip address] [port number] ([options])`

**Actions**
* `alert`: Generates an alert and logs the packet.
* `log`: Logs the packet.
* `pass`: Ignores the packet.
* `drop`: Blocks and logs the packet.
* `reject`: Blocks the packet, logs it, and then sends a TCP Reset or ICMP Port Unreachable.

**Protocol**
* `TCP`
* `UDP`
* `ICMP`
* `IP`

**IP/Port Constraints**
* `any`: Wildcard for any IP or Port.
* `10.10.10.23` or `443`: Specific IP or Port.
* `10.10.10.0/24`: CIDR notation.
* `!192.168.0.1`: Negation (NOT).
* `[192.168.1.1,192.168.1.2]`: Comma-separated list.
* `1:1024`: Port range.

**Direction**
* `<>`: Bidirectional.
* `->`: Unidirectional (Source -> Destination).

**General Options**
* `msg`: The message that displays in the log/alert.
* `sid`: Unique numerical identifier (Snort ID).
* `rev`: Revision of the rule.
* `classtype`: Categorizes the rule (e.g., attempted-admin, trojan-activity).

**Detection Options**
Key-value pairs instructing the engine to find specific data.

* **Content**: The core detection keyword. Case sensitive by default.
  * `content: "This is a string";`
  * `content: "|68 65 6c 6c 6f|";` (Hex for "hello")
  * `content: !"Not this one";` (Negation)

* **Modifiers**:
  * `depth: 3;` (Look only within the first 3 bytes)
  * `offset: 20;` (Start looking after byte 20)

## [Zeek](https://zeek.org/) (formerly Bro)

Zeek is a passive, open-source network traffic analyzer. Many operators use Zeek as a Network Security Monitor (NSM) to support detailed investigations of suspicious activity. Zeek provides compact, high-fidelity transaction logs, file content, and fully customizable output, making it distinct from traditional signature-based IDS.

* **Transaction Logs**: Zeek writes extensive logs for every connection, identifying protocols (HTTP, DNS, SMTP, etc.) and attributes (headers, status, methods).
* **Scripting**: Zeek has a powerful scripting language to analyze traffic and create custom detection logic.
* **Metadata**: Unlike Snort/Suricata which focus on alerts, Zeek focuses on rich metadata and visibility.

## [Security Onion](https://securityonionsolutions.com/)

Security Onion is a free and open-source Linux distribution for threat hunting, enterprise security monitoring, and log management. It includes Suricata, Zeek, Wazuh, the Elastic Stack, and many other security tools in a comprehensive platform.

## Legacy / Deprecated Tools

The following tools have been historically significant but are either unmaintained or have been superseded by modern alternatives.

* **[PulledPork](https://github.com/shirkdog/pulledpork)**: Historically used for rule management in Snort 2 and Suricata. Modern Snort 3 internal tools or newer managers are often preferred today.
* **[Snorby](https://github.com/Snorby/snorby)**: A Ruby on Rails web application for NSM visualization. It has not been updated in many years and is considered unmaintained.
* **[Sguil](https://github.com/bammv/sguil)**: The "Scripted GUI for Analysis of Network Packets". A veteran tool for NSM analyst workflow, largely replaced by modern web-based dashboards like Kibana (in Elastic Stack) or EveBox.
