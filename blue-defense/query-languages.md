---
description: Common Security Events, how to analyze them, and the tools to do so
---

# Query Languages

Triaging and investigating security events are the bread and butter of any SOC analyst. Before we can investigate we must first have two things: A common terminology to define attacks and security related activity, and searches to direct us to that activity.

## **Event search languages and rules**

Weather it is an open source tool like Elastic Stack, or a proprietary tool like Splunk, every data mining or security event generating tool, has its own language it works in. Specifically for SIEMs, EDRs, and Data mining platforms, they require an extensive and flexible language to search for data with a multitude of conditions that a user might have. Writing effective searches is an artform, and it is highly encouraged that you do tons of research and testing before deployment. Blue team blog has a fantastic Use Case writing guide as well as some fantastic use cases available for free.

## [Sigma](https://github.com/Neo23x0/sigma)

The syntax and format of all of the available languages is vast and complex. Especially so, when you have to convert search parameters from one tool to another. In comes Sigma.&#x20;

"Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.Sigma is for log files what [Snort](https://www.snort.org/) is for network traffic and [YARA](https://github.com/VirusTotal/yara) is for files." - Sigma Github Notes

Sigma is a fantastic tool that decouples rule logic from vendor terminology. Sigma is stored in easy to ready YAML format and is compatible with the MISP intel tool.

Remember two things: First, Sigma queries may not be perfect, but they should get you 90-95% the way towards what you are looking for. Be prepared to tweak! \
Second, online converters might not be able to translate from one platform easily. Example: LogRhythm -> Splunk. Sometimes you need to look at various Github repositories to get the code to convert to Sigma, then on to the platform of your choice. Example: LogRhythm -> Sigma -> Splunk.

* [GitHub - Neo23x0/sigma: Generic Signature Format for SIEM Systems](https://github.com/Neo23x0/sigma)&#x20;
* [GitHub - socprime/SigmaUI: SIGMA UI is a free open-source application based on the Elastic stack and Sigma Converter (sigmac)](https://github.com/socprime/SigmaUI)&#x20;
* [How to Write Sigma Rules - Nextron Systems](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/)
* [GitHub - LogRhythm-Labs/Sigma: Convert Sigma rules to LogRhythm searches](https://github.com/LogRhythm-Labs/Sigma)&#x20;
* [https://techcommunity.microsoft.com/t5/Azure-Sentinel/Importing-Sigma-Rules-to-Azure-Sentinel/ba-p/657097](https://techcommunity.microsoft.com/t5/Azure-Sentinel/Importing-Sigma-Rules-to-Azure-Sentinel/ba-p/657097)
* [sigmaio](https://github.com/M3NIX/sigmaio) - simple webapp for converting sigma rules into siem queries using the pySigma library
  * [https://sigmaio.herokuapp.com/](https://sigmaio.herokuapp.com/)

To make Sigma even easier to use, there are tools like Uncoder.io that can easily translate the rule syntax from one platform to another, free of charge. As stated above, if you cannot do direct translations from one platform to another, try changing the source search to Sigma first, then on to the platform of your choice.

* [Online translator for SIEM saved searches, filters, queries and Sigma rules - Uncoder.IO](https://uncoder.io/)&#x20;

![](<../.gitbook/assets/image (41).png>)

## [Lucene](https://lucene.apache.org/) (ElasticSearch)

Apache's search language that is used in many technologies including Elastic Stack and Palo Alto's XSOAR

* [https://logz.io/blog/elasticsearch-queries/](https://logz.io/blog/elasticsearch-queries/)
* [https://lucene.apache.org/core/2\_9\_4/queryparsersyntax.html](https://lucene.apache.org/core/2\_9\_4/queryparsersyntax.html)
* KQL: Kibana search language based on Lucene. - [https://www.elastic.co/guide/en/kibana/master/kuery-query.html](https://www.elastic.co/guide/en/kibana/master/kuery-query.html)
* [Elasticsearch: The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html) ([fork it on GH](https://github.com/elastic/elasticsearch-definitive-guide))
* _Threat Hunting in Elastic Stack: Lucene - pg. 212_

[Solr](https://solr.apache.org/) - Solr is the popular, blazing-fast, open source enterprise search platform built on Apache Lucene

* [https://github.com/hectorcorrea/solr-for-newbies](https://github.com/hectorcorrea/solr-for-newbies)

KQL - Kibana Query Language, the default query language of the Kibana seach and alerting utility within Elastic Stack.

* _Threat Hunting in Elastic Stack: KQL - pg. 216_

EQL - Elastic Query Language, an advanced query language developed by Elastic for use in thier Security App.

* _Threat Hunting in Elastic Stack: EQL - pg. 220_

## Splunk's SPL: Search Processing Language

* [https://docs.splunk.com/Documentation/Splunk/8.2.1/SearchTutorial/Usethesearchlanguage](https://docs.splunk.com/Documentation/Splunk/8.2.1/SearchTutorial/Usethesearchlanguage)
* [https://gosplunk.com/](https://gosplunk.com/)
* [https://wiki.splunk.com/images/2/2b/Cheatsheet.pdf](https://wiki.splunk.com/images/2/2b/Cheatsheet.pdf)
* [https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf](https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf)
* [https://www.splunk.com/pdfs/solution-guides/splunk-dashboards-quick-reference-guide.pdf](https://www.splunk.com/pdfs/solution-guides/splunk-dashboards-quick-reference-guide.pdf)
* [https://docs.splunk.com/Documentation/Splunk/8.1.0/SearchReference/ListOfSearchCommands](https://docs.splunk.com/Documentation/Splunk/8.1.0/SearchReference/ListOfSearchCommands)
* _Operator Handbook: Splunk - pg. 277_

## Graylog

* Graylog's query language is very close to Lucene. Watch for syntax errors.
  * [https://docs.graylog.org/en/3.3/pages/searching/query\_language.html](https://docs.graylog.org/en/3.3/pages/searching/query\_language.html)

## Windows O365

* [https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide)

## Windows Defender ATP

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/](https://docs.microsoft.com/en-us/windows/security/threat-protection/)
* __[https://github.com/alexverboon/WindowsDefenderATP-Hunting-Queries](https://github.com/alexverboon/WindowsDefenderATP-Hunting-Queries)
* _Operator Handbook: Windows Defender ATP - pg. 417_

****
