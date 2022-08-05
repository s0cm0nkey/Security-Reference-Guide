# IDS/IPS

## **Intrusion Detection Systems**

Fantastic tools that can make detection easy. They can look at logs of various kinds and use rule sets to react and alert to any traffic that violates those rules. Open source IDS tools have huge public rule sets both included with the tool and available across the internet. It is my opinion that open source IDS products offer superior detection capability to the premium products on the market due to the power of the community behind the tools and their public sharing of detection rules.

## [Surricata](https://suricata-ids.org/)&#x20;

A solution that combines intrusion detection (IDS), intrusion prevention (IPS), network security monitoring (NSM) and PCAP processing, Surricata can quickly identify, stop, and assess the most sophisticated attacks. Truly a fantastic detection engine, it has quickly become a popular choice for IDS functions built into other products, such as the IDS function of Ubiquiti products.

* Can collect logs with syslog, [Unified2](https://www.snort.org/faq/readme-unified2), flat files, or the preferred method of [EVE](https://suricata.readthedocs.io/en/suricata-6.0.0/output/eve/eve-json-output.html)
  * EVE is a highly configurable JSON format that can support multiple files.
* [https://suricata.readthedocs.io/en/suricata-6.0.3/](https://suricata.readthedocs.io/en/suricata-6.0.3/)
* [Evebox Surricata event viewer](https://github.com/jasonish/evebox) - EveBox is a web based Suricata "eve" event viewer for Elastic Search.
* [suricata-language-server](https://github.com/StamusNetworks/suricata-language-server) - An implementation of the Language Server Protocol for Suricata signatures. It adds syntax check, hints and auto-completion to your preferred editor once it is configured.
* [https://rules.emergingthreats.net/open/suricata/rules/](https://rules.emergingthreats.net/open/suricata/rules/)
* _PTFM: Suricata Commands - pg. 185_

## [Snort ](https://github.com/snort3/snort3)&#x20;

One of the most powerful detection tools on the market  Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system.

* Can collect logs via Syslog, CSV, Database, or the prefered method of [Unified2](https://www.snort.org/faq/readme-unified2)
  * Unified2 is a binary output for Snort. It will need interpretation by tools like [Barnyard](https://github.com/firnsy/barnyard2) or [u2json](https://idstools.readthedocs.io/en/latest/tools/u2json.html)
* __[https://snort.8jorg/](https://snort.org/)
* [https://snort.org/#documents](https://snort.org/#documents)
* [https://snort.org/downloads/#rule-downloads](https://snort.org/downloads/#rule-downloads)
* [https://paper.bobylive.com/Security/Snort\_rule\_infographic.pdf](https://paper.bobylive.com/Security/Snort\_rule\_infographic.pdf)
* [https://resources.infosecinstitute.com/topic/snort-rules-workshop-part-one/](https://resources.infosecinstitute.com/topic/snort-rules-workshop-part-one/)
* [Intrusion Detection Systems with Snort](http://ptgmedia.pearsoncmg.com/images/0131407333/downloads/0131407333.pdf) (PDF)
* _BTFM: SNORT - pg. 45_
* _(BTHb: INRE): Using Snort IDS - pg. 103_
* _PTFM: Snort Commands - pg. 186_
* _Operator Handbook: SNORT - pg. 276_
* [PulledPork](https://github.com/shirkdog/pulledpork) - Rule management software for SNORT and Surricata rules.
* Snort/Surricata Alerting
  * [Snorby](https://github.com/Snorby/snorby) - Snorby is a ruby on rails web application for network security monitoring that interfaces with current popular intrusion detection systems (Snort, Suricata and Sagan).
  * [Sguil](https://github.com/bammv/sguil) - Network security monitoring tool that provides access to real time events, session data, and raw packet captures.
* _Signature-Based Detection with Snort and Surricata - Applied Network Security Monitoring - pg.203_

### **Writing a SNORT Rule**

[http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node29.html](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node29.html)\
[https://blog.rapid7.com/2016/12/09/understanding-and-configuring-snort-rules/](https://blog.rapid7.com/2016/12/09/understanding-and-configuring-snort-rules/)\
\
A standard rule is broken down as follows:\
• \[action]\
• \[protocol]\
• \[ip address] – source\
• \[port number] – source\
• \[direction options]\
• \[ip address] – destination\
• \[port number] – destination\
• \[general options]\
• \[detection options]\
\
Actions\
• `alert` generates an alert and logs the packet\
• `log` logs the packet\
• `pass` ignores the packet\
• `drop` blocks and logs the packet\
• `reject` blocks the packet, logs it and then sends a TCP Reset or ICMP Port Unreachable\
\
Protocol\
• `TCP`\
• `UDP`\
• `ICMP`\
• `IP`\
\
IP address\
• `any` – a wildcard for any IP address\
• `10.10.10.23` – any single valid IP address\
• `10.10.10.0/24` – CIDR notation for block ranges\
• `!192.168.0.1/24` – prefixing this field with an exclamation mark means ‘NOT’\
• `[192.168.1.1,192.168.1.2,192.168.1.3]` – comma-separated lists can use the previous syntax\
\
Port\
• `any` – a wildcard for any port\
• `443` – any single port number\
• `1:1024` – port range\
• \[443, 447, etc..] - listing multiple specific ports\
\
Direction\
• `<>` bidirectional\
• `->` unidirectional\
\
General Options\
• `msg` is the message that displays in the log/alert\
• `sid` is a unique numerical identifier that identifies the rule and has several reserved ranges\
• `rev` annotates the revision of a rule\
• `classtype` is used to categorise and group common rules and has many defaults\
\
Detection options - This set of key:value pairs instructs the scanning engine to detect specific data within packets.\
• Content - The content keyword forms the core of the rule detection. It can include text, binary data or a mixture of the two. It is important to keep in mind that content keywords are case sensitive.\
◇ `content: "This is a string of text";`\
◇ `content: "|68 65 6c 6c 6f|";`\
◇ `content: "Hello |77 6f | rld";`\
◇ `content: !"Not this one";`\
\
View only certin number of Bytes\
• depth:3;\
\
Starting point for search\
• offset:20;
