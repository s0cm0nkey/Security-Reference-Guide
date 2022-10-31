# SIEM and Enrichment

## Open Source SIEMs

* [Elastic Stack: Kibana](https://www.elastic.co/siem/) - One of the most popular and flexible tools our there, Elastic stack is a data mining platform where you can parse logs of all kinds for all different purposes. Kibana, is the SIEM application within Elastic Stack. It comes with an event manager, alerting tools, and event a set of default alerting use cases.
  * [Download Elastic Agent Free ](https://www.elastic.co/downloads/elastic-agent) - Beyond logs sent to Elastic Stack, there is also an installable agent that be used as a sensor for endpoint collecting logs .
  * [SIEMonster | Affordable Security Monitoring Software Solution](https://siemonster.com/community-edition/) - An all in one VM that has Elastic stack as well as all of the other logging and alerting tools you might want&#x20;
  * [Cyber Wardog Lab: Building a Sysmon Dashboard with an ELK Stack](https://cyberwardog.blogspot.com/2017/03/building-sysmon-dashboard-with-elk-stack.html)
  * [Elasticsearch: The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html) ([fork it on GH](https://github.com/elastic/elasticsearch-definitive-guide))
  * [https://training.elastic.co/learn-from-home\*](https://training.elastic.co/learn-from-home\*)
* [Greylog](https://www.graylog.org/) - Greylog is a fantastically flexible logging solution that also has its own security correlation engine with Greylog Illuminate.
  * [Enhance Windows Security with Sysmon, Winlogbeat and Graylog | Graylog](https://www.graylog.org/post/back-to-basics-enhance-windows-security-with-sysmon-and-graylog)
* [MozDef: The Mozilla SIEM](https://github.com/mozilla/MozDef) - An interesting product from the makers of everyone's favorite opensource web browser, MozDef has been built to be a SIEM focused around automation and expediency of addressing of security alerts.
  * [https://mozdef.readthedocs.io/en/latest/overview.html](https://mozdef.readthedocs.io/en/latest/overview.html)
* [OSSIM: The Open Source SIEM | AlienVault](https://cybersecurity.att.com/products/ossim) - OSSIM is a super handy security platform that focuses less on the data mining and more of the security alerting. It has an incredibly easy to use security rule generation tool and also can perform cross correlation between data sources.

## &#x20;[Splunk](https://www.splunk.com/)

&#x20;Splunk is the industry leader in data mining and security monitoring,. It is an incredible tool, with unparalleled ability to parse, correlate, and present your data, as well as an unparalleled price tag!

* [SplunkTools](https://github.com/dstaulcu/SplunkTools) - A collection of scripts useful in management of Splunk deployment
* [Fuzzy Searching for Splunk](https://splunkbase.splunk.com/app/3109/)

## Data Enrichment

With most SIEMs you can add in plugins or apps that can perform a myriad of supporting functions. Some can help you normalize your data and make it CIM Compliant, some can provide more context to your data, and some can even add more options for detection and analysis.

* DNS Lookups - A simple lookup can ad much needed visibility to an investigation
  * Forward lookup - Uses DNS A records to map a domain to an IP address
  * Reverse lookup - Uses DNS PTR records to return a domain list for a given IP address.
* WHOIS/RDAP lookups - Incredibly under used utility. Can add many helpful data points to an indicator.
* [Geolite2 Geolocation Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en) - Geolite2 is a free database that gives geolocation data for the IP addresses searching within it. This is a great for looking into where your users are logging in from, or from which countries are you being attacked. This database is updated every month. If you need a more accurate query, you can pay for their premium service with runs queries against their updated database. This tool also adds ASN support which is unfortunately absence in many SIEMs.
* Popular Domain Lists - There are many public services that will pull a list of top domains searched across the internet. While you should NOT use these as a whitelist, they are super handy for identifying oddball suspicious domains.
  * [Alexa Top 1 Million Domains](https://gist.github.com/chilts/7229605)
  * [Majestic Millions](https://majestic.com/reports/majestic-million)
  * [Cisco Umbrella Top 1 Million](https://umbrella.cisco.com/blog/cisco-umbrella-1-million)
* Pre-loaded data - These are files and sets of data that can be used for reference, comparison, or enhancement. These can be white/black lists, the above domain lists, Mitre attack tables, or anything you might want to use. For easy storage and later recal, we can use a utility like [Memcached](https://memcached.org/) for storing key-value pair knowledge objects.
* Threat Intelligence - _Please see the Intelligence Section of this guide._
* [Fuzzy Searching](https://github.com/seatgeek/fuzzywuzzy) - For SIEMs that do not have integrated fuzzy searching ability, tools like [fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) uses python to calculate [Levenshtien distance](https://en.wikipedia.org/wiki/Levenshtein\_distance) for fuzzy searching of strings up to a couple characters different from the searched string.
* [APIify](https://github.com/MarkBaggett/apiify) - First and foremost on the list, APIify is a fantastic tool that you can apply to just about every security tool you have that doesn't have its own API. It essentially takes any standalone Binary and wraps it into a cached web server. Super handy for being able to integrate the functions of your favorite tools into your SIEM.
* [Domain\_stats](https://github.com/MarkBaggett/domain\_stats) - Combine this with the above APIify tool to be able to dynamically pull out useful information on your domains that might raise a security eyebrow. Honestly, every tool Mark Bagget creates is gold.
* [DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/) - DNSDB is a Passive DNS (pDNS) historical database that provides a unique, fact-based, multifaceted view of the configuration of the global Internet infrastructure. Wonderful tool to really dig into your DNS traffic and create some in depth detection use cases.
  * [DNSDB Cheatsheet](https://www.farsightsecurity.com/assets/media/download/dnsdb-cheatsheet.pdf)
* [PRADS: Passive Real-time Asset Detection System](https://github.com/gamelinux/prads/) - PRADS is a tool that can passively build an asset list with useful details like operating system and open ports. When you do not have access to an asset list or CMDB from the engineering team, this can be a huge help when adding context to security investigations.
* [hallucinate](https://github.com/SySS-Research/hallucinate/) - One-stop TLS traffic inspection and manipulation using dynamic instrumentation.
* [phishing\_catcher](https://github.com/x0rz/phishing\_catcher) - Catch possible phishing domains in near real time by looking for suspicious TLS certificate issuances reported to the [Certificate Transparency Log (CTL)](https://www.certificate-transparency.org/) via the [CertStream](https://certstream.calidog.io/) API.
* [guac](https://github.com/guacsec/guac) - Graph for Understanding Artifact Composition (GUAC) aggregates software security metadata into a high fidelity graph database—normalizing entity identities and mapping standard relationships between them. Querying this graph can drive higher-level organizational outcomes such as audit, policy, risk management, and even developer assistance.
* _Threat Hunting with Elastic Stack: Enriching Data to Make Intelligence - pg. 329_

{% embed url="https://www.youtube.com/watch?v=lb2M7-UOqVI" %}
