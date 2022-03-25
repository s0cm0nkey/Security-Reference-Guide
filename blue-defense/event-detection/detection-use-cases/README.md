# Detection Use Cases

While many security products have built in detection use cases, there will always be situations where a custom detection use case will need to be developed. In order to create a successful use cases, we need to have a few key elements.

## Theory

The first step in building a use case is the theory behind it. While the protocol, device, and situation may vary, there are a handful of detection theories that we can apply to most detection situations.

* Alert on match - Matches any specific string or data field entry
* Alert on match with exclusion - Same as above excluding anything documented as acceptable
* Repetitive matches - When occurrences of a set of events goes past acceptable volumes
* High Fluctuation - When there is a significant change in volume of a specific data field
* Low Fluctuation - When the volume of occurrences drops to abnormal levels or stops entirely.
* New or Changed Fields - When a data field has a new, previously unseen entry.
* Aggregation Thresholds - Changes in Min/Max/Average of a data field statistic.
* [https://github.com/palantir/alerting-detection-strategy-framework](https://github.com/palantir/alerting-detection-strategy-framework)

### Alert Tuning

The most effective security monitoring programs, undergo a constant state of tuning and refinement. This allows the highest degree of detection while not overwhelming your analysts with alerts to investigate. High volumes of false positives are typically either a poorly written rule, or noise in your environment that needs to be tuned out. All alerts should have a set of exclusions that should be placed within the use case logic to accommodate any known issues, and therefore not create an alert on those circumstances.

Sometimes you will have to perform a cost benefit analysis on each use case. Is there value in spending gobs of time on every port scan alert you receive? That is up to you. (You shoudnt)

## Detection Guides

* [Awesome Lists Collection: Awesome Threat Detection](https://github.com/0x4D31/awesome-threat-detection)
* [SIEM - USE CASE WRITING GUIDE - Blue Team Blog](https://blueteamblog.com/siem-use-case-writing-guide)&#x20;
* [Alerting and Detection Strategy](https://blog.palantir.com/alerting-and-detection-strategy-framework-52dc33722df2?gi=461547ef38e7) guide by Palantir
* [Mitre CAR](https://car.mitre.org) - The MITRE Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by [MITRE](https://www.mitre.org) based on the [MITRE ATT\&CK](https://attack.mitre.org) adversary model.
  * CAR is focused on providing a set of validated and well-explained analytics, in particular with regards to their operating theory and rationale.
* [https://blueteamblog.com/category/siem](https://blueteamblog.com/category/siem)
* [https://nasbench.medium.com/understanding-detecting-c2-frameworks-darkfinger-c2-539c79282a1c](https://nasbench.medium.com/understanding-detecting-c2-frameworks-darkfinger-c2-539c79282a1c)
* _Crafting the Infosec Playbook: Crafting Queries- pg. 174_
* Netflow
  * _Crafting the Infosec Playbook: Hustle and NetFlow - pg. 129_
* DNS
  * _Crafting the Infosec Playbook: DNS- pg. 135_
* Web and Web Proxies
  * _Crafting the Infosec Playbook: Web Proxies- pg. 145_
* Intelligence
  * _Crafting the Infosec Playbook: Applied Intelligence - pg. 158_

{% content-ref url="windows-event-id-logging-list.md" %}
[windows-event-id-logging-list.md](windows-event-id-logging-list.md)
{% endcontent-ref %}

## **Detection Use Case Collections**

If you ever want to take the easy way of development, and simply purchase search rules or copy some that are existing on other platforms, there are a few places available on the web. Many poopular SIEMs have sets of rules included in the software. For more, please review the Event Detection section.

* [sigma/rules at master · SigmaHQ/sigma · GitHub](https://github.com/SigmaHQ/sigma/tree/master/rules)&#x20;
* [Azure-Sentinel/Detections at master · Azure/Azure-Sentinel · GitHub](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)&#x20;
* [IBM Security App Exchange - QRadar Use Case Manager](https://exchange.xforce.ibmcloud.com/hub/extension/bf01ee398bde8e5866fe51d0e1ee684a)&#x20;
* [GitHub - elastic/detection-rules: Rules for Elastic Security's detection engine](https://github.com/elastic/detection-rules)
* [https://www.threathunting.se/detection-rules/](https://www.threathunting.se/detection-rules/)
* [C.A.R. Cyber Analytics Repository ](https://car.mitre.org)- A knowledge base of analytics developed by [MITRE](https://www.mitre.org) based on the [MITRE ATT\&CK](https://attack.mitre.org) adversary model.
* [https://infosecwriteups.com/common-tools-techniques-used-by-threat-actors-and-malware-part-i-deb05b664879?gi=37505dc3419c](https://infosecwriteups.com/common-tools-techniques-used-by-threat-actors-and-malware-part-i-deb05b664879?gi=37505dc3419c)
* [https://nasbench.medium.com/common-tools-techniques-used-by-threat-actors-and-malware-part-ii-c2e65cd6b084](https://nasbench.medium.com/common-tools-techniques-used-by-threat-actors-and-malware-part-ii-c2e65cd6b084)
* [https://github.com/bfuzzy/auditd-attack](https://github.com/bfuzzy/auditd-attack)
* [https://github.com/olafhartong/detection-sources](https://github.com/olafhartong/detection-sources)
* [https://expel.io/blog/following-cloudtrail-generating-aws-security-signals-sumo-logic/](https://expel.io/blog/following-cloudtrail-generating-aws-security-signals-sumo-logic/)

If you are looking to simply purchase use cases from a market place, the foremost of them is SOCPrime. They even have a bounty program for their searches. If you come up with a useful and unique search, you can sell it to them for a tidy profit!

* [socprime (SOC Prime) · GitHub](https://github.com/socprime)&#x20;
* [SOC Prime Threat Detection Marketplace (TDM) - SaaS Content Platform](https://my.socprime.com/tdm/)&#x20;

{% content-ref url="detection-use-cases.md" %}
[detection-use-cases.md](detection-use-cases.md)
{% endcontent-ref %}

## Detection Use Cases by Category

{% content-ref url="dns.md" %}
[dns.md](dns.md)
{% endcontent-ref %}

{% content-ref url="http.md" %}
[http.md](http.md)
{% endcontent-ref %}

{% content-ref url="smtp.md" %}
[smtp.md](smtp.md)
{% endcontent-ref %}

{% content-ref url="command-line.md" %}
[command-line.md](command-line.md)
{% endcontent-ref %}

{% content-ref url="authentication-logon.md" %}
[authentication-logon.md](authentication-logon.md)
{% endcontent-ref %}

{% content-ref url="general-network-traffic.md" %}
[general-network-traffic.md](general-network-traffic.md)
{% endcontent-ref %}

{% content-ref url="user-behavior-monitoring.md" %}
[user-behavior-monitoring.md](user-behavior-monitoring.md)
{% endcontent-ref %}

