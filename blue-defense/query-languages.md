---
description: Common Security Events, how to analyze them, and the tools to do so
---

# Query Languages

Triaging and investigating security events are the bread and butter of any SOC analyst. Before we can investigate we must first have two things: A common terminology to define attacks and security related activity, and searches to direct us to that activity.

## **Event search languages and rules**

Whether it is an open source tool like Elastic Stack, or a proprietary tool like Splunk, every data mining or security event generating tool has its own language. Specifically, SIEMs, EDRs, and Data mining platforms require an extensive and flexible language to search for data. Writing effective searches is an art form, and it is highly encouraged that you do plenty of research and testing before deployment.

## [Sigma](https://github.com/Neo23x0/sigma)

The syntax and format of all of the available languages are vast and complex. Especially so when you have to convert search parameters from one tool to another. This is where Sigma comes in.

"Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others. Sigma is for log files what [Snort](https://www.snort.org/) is for network traffic and [YARA](https://github.com/VirusTotal/yara) is for files." - Sigma Github Notes

Sigma is a fantastic tool that decouples rule logic from vendor terminology. Sigma is stored in an easy-to-read YAML format and is compatible with the MISP intel tool.

Remember two things: First, Sigma queries may not be perfect, but they should get you 90-95% the way towards what you are looking for. Be prepared to tweak! \
Second, online converters might not be able to translate from one platform easily. Example: LogRhythm -> Splunk. Sometimes you need to look at various Github repositories to get the code to convert to Sigma, then on to the platform of your choice. Example: LogRhythm -> Sigma -> Splunk.

* [GitHub - Neo23x0/sigma: Generic Signature Format for SIEM Systems](https://github.com/Neo23x0/sigma)&#x20;
* [How to Write Sigma Rules - Nextron Systems](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/)
* [GitHub - LogRhythm-Labs/Sigma: Convert Sigma rules to LogRhythm searches](https://github.com/LogRhythm-Labs/Sigma)&#x20;
* [Importing Sigma Rules to Microsoft Sentinel](https://techcommunity.microsoft.com/t5/Azure-Sentinel/Importing-Sigma-Rules-to-Azure-Sentinel/ba-p/657097)
* [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) - Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows forensic artefacts such as Event Logs and MFTs. 
* [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) - Hayabusa (隼) is a sigma-based threat hunting and fast forensics timeline generator for Windows event logs.

To make Sigma even easier to use, there are tools like Uncoder.io that can easily translate the rule syntax from one platform to another, free of charge. As stated above, if you cannot do direct translations from one platform to another, try changing the source search to Sigma first, then on to the platform of your choice.

* [Uncoder.IO](https://uncoder.io/) - Online translator for SIEM saved searches, filters, queries and Sigma rules.

![](<../.gitbook/assets/image (41).png>)

## [Lucene](https://lucene.apache.org/) (ElasticSearch)

Apache's search language is used in many technologies including Elastic Stack and Palo Alto's XSOAR.

* [Lucene Query Parser Syntax](https://lucene.apache.org/core/9_8_0/queryparser/org/apache/lucene/queryparser/classic/package-summary.html#package_description)
* [Logz.io - Elasticsearch Queries Guide](https://logz.io/blog/elasticsearch-queries/)
* [Elasticsearch: The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)
* KQL: Kibana search language based on Lucene. - [Elastic KQL Docs](https://www.elastic.co/guide/en/kibana/master/kuery-query.html)
* _Threat Hunting in Elastic Stack: Lucene - pg. 212_

[Solr](https://solr.apache.org/) - Solr is the popular, blazing-fast, open source enterprise search platform built on Apache Lucene

* [https://github.com/hectorcorrea/solr-for-newbies](https://github.com/hectorcorrea/solr-for-newbies)

KQL - Kibana Query Language, the default query language of the Kibana search and alerting utility within Elastic Stack.

* _Threat Hunting in Elastic Stack: KQL - pg. 216_

EQL - Elastic Query Language, an advanced query language developed by Elastic for use in their Security App.

* _Threat Hunting in Elastic Stack: EQL - pg. 220_

## Splunk's SPL: Search Processing Language

* [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/Usethesearchlanguage)
* [GoSplunk](https://gosplunk.com/) - A repository of Splunk queries.
* [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands)
* [Splunk Quick Reference Guide (PDF)](https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf)
* _Operator Handbook: Splunk - pg. 277_

## Graylog

* Graylog's query language is very close to Lucene.
  * [Graylog Searching Documentation](https://docs.graylog.org/docs/searching)

## Microsoft Defender XDR & Microsoft Sentinel (KQL)

Microsoft Defender XDR (formerly Microsoft 365 Defender) and Microsoft Sentinel use Kusto Query Language (KQL) for advanced hunting and analytics. KQL is a powerful, read-only request to process data and return results. The syntax is similar to SQL but uses a data-flow model where operators are connected by pipes (`|`).

*   [**Official KQL Documentation**](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/) - The primary reference for all operators and functions.
*   [**Must Learn KQL**](https://github.com/rod-trent/MustLearnKQL) - A fantastic, community-driven learning series and book by Rod Trent.
*   [**KQL Cheat Sheet**](https://github.com/marcusbakker/KQL-CheatSheet) - Quick reference for common queries.
*   [**Azure Sentinel GitHub**](https://github.com/Azure/Azure-Sentinel) - Contains a massive library of detections and hunting queries.

Example KQL structure:
```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize count() by Account, Computer
| sort by count_ desc
```

## Google Security Operations (YARA-L)

YARA-L is the detection language used by Google Security Operations (formerly Chronicle SIEM). Unlike standard YARA (used for file scanning), YARA-L is designed for log, event, and entity data. It excels at correlation logic, allowing analysts to link events over time (e.g., "User created" followed by "User logged in from unusual IP" within 10 minutes).

*   [**YARA-L syntax reference**](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax)
*   [**Google SecOps Detection Rules**](https://github.com/chronicle/detection-rules) - Official repository of YARA-L detection rules.
*   [**Chronicle YARA-L 2.0 Overview**](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)

## Osquery (SQL)

[Osquery](https://osquery.io/) allows you to query your endpoints (Windows, macOS, Linux) as if they were a relational database. It abstracts operating system concepts (processes, kernel modules, open network connections, etc.) into SQL tables. Queries are written in standard SQLite syntax.

*   [**Osquery Schema**](https://osquery.io/schema/) - Interactive documentation of all available tables and columns.
*   [**Osquery Documentation**](https://osquery.readthedocs.io/)
*   [**Generic SQL for Endpoint**](https://github.com/osquery/osquery/tree/master/packs) - See example query packs.

Example Osquery to find running processes:
```sql
SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0;
```

## Graph Query Languages (Cypher)

Graph databases like Neo4j are increasingly used in security for analyzing relationships, such as Attack Paths in Active Directory (used by [BloodHound](https://github.com/BloodHoundAD/BloodHound)). The standard language for this is **Cypher**.

*   [**Neo4j Cypher Refcard**](https://neo4j.com/docs/cypher-refcard/current/) - A cheatsheet for syntax.
*   [**BloodHound Cypher Cheatsheet**](https://github.com/CompassSecurity/BloodHound-Queries) - Security-specific queries.

Example Cypher query (Shortest path to Domain Admin):
```cypher
MATCH p=shortestPath((u:User {name:'UserA'})-[*1..]->(g:Group {name:'DOMAIN ADMINS'})) RETURN p
```

## Network Detection Rules (Snort / Suricata)

While not strictly "query languages" for log analysis, Snort and Suricata rules are the standard for Network Intrusion Detection Systems (NIDS). Understanding this syntax is crucial for network security monitoring.

*   [**Snort Rule Docs**](https://docs.snort.org/rules/)
*   [**Suricata User Guide**](https://suricata.io/documentation/)
*   [**Emerging Threats**](https://rules.emergingthreats.net/) - A great source of open rules examples.

## Cloud Log Management

### AWS CloudWatch Logs Insights
AWS uses a proprietary query syntax for CloudWatch Logs Insights. It supports filtering, stats, and sorting.
*   [**CloudWatch Logs Insights Query Syntax**](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)

### Datadog
Datadog uses a custom search syntax for log management, often boolean-based with faceted search capabilities.
*   [**Datadog Log Search Syntax**](https://docs.datadoghq.com/logs/explorer/search_syntax/)



****
