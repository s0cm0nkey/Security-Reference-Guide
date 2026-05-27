---
description: Security query languages, detection rule syntax, and search references
---

# Query Languages

Triaging and investigating security events are the bread and butter of SOC analysis. Before you can investigate effectively, you need two things: common terminology for security activity and reliable searches that point you toward that activity.

Use this page for SIEM search syntax, detection rule formats, and security query references. Tool catalogs belong on the Event Detection and Blue Toolbox pages; this page is for the languages analysts use inside those tools.

## Event Search Languages and Rules

Whether you are using an open-source stack like Elastic or a commercial tool like Splunk, every SIEM, EDR, and data platform has its own search language. Writing effective searches takes practice, testing, and tuning before deployment.

## [Sigma](https://github.com/SigmaHQ/sigma)

The syntax and format of search languages can become complex, especially when you need to translate detection logic between platforms. Sigma helps solve that problem by providing a generic, open rule format for log-based detections. Sigma is often described as being for logs what [Snort](https://www.snort.org/) is for network traffic and [YARA](https://github.com/VirusTotal/yara) is for files.

Sigma is a fantastic tool that decouples rule logic from vendor terminology. Sigma is stored in an easy-to-read YAML format and is compatible with the MISP intel tool.

Remember two things:

* Sigma conversions may get you most of the way there, but translated queries still need testing and tuning.
* Some platform-to-platform conversions require an intermediate step. For example, LogRhythm to Sigma to Splunk may work better than trying to translate LogRhythm directly to Splunk.

* [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems.
* [How to Write Sigma Rules - Nextron Systems](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/)
* [GitHub - LogRhythm-Labs/Sigma: Convert Sigma rules to LogRhythm searches](https://github.com/LogRhythm-Labs/Sigma)&#x20;
* [Importing Sigma Rules to Microsoft Sentinel](https://techcommunity.microsoft.com/t5/Azure-Sentinel/Importing-Sigma-Rules-to-Azure-Sentinel/ba-p/657097)
* [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) - Chainsaw provides a powerful first-response capability to quickly identify threats within Windows forensic artifacts such as Event Logs and MFTs.
* [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) - Hayabusa (隼) is a sigma-based threat hunting and fast forensics timeline generator for Windows event logs.

To make Sigma even easier to use, there are tools like Uncoder.io that can easily translate the rule syntax from one platform to another, free of charge. As stated above, if you cannot do direct translations from one platform to another, try changing the source search to Sigma first, then on to the platform of your choice.

* [Uncoder.IO](https://uncoder.io/) - Online translator for SIEM saved searches, filters, queries and Sigma rules.

![](<../.gitbook/assets/image (41).png>)

## [Lucene](https://lucene.apache.org/) and Elasticsearch

Apache Lucene query syntax appears in many security tools, including Elastic Stack and Graylog. Elasticsearch, Kibana Query Language (KQL), and Elastic Query Language (EQL) are common in security monitoring and threat hunting workflows.

* [Lucene Query Parser Syntax](https://lucene.apache.org/core/9_8_0/queryparser/org/apache/lucene/queryparser/classic/package-summary.html#package_description)
* [Logz.io - Elasticsearch Queries Guide](https://logz.io/blog/elasticsearch-queries/)
* [Elasticsearch: The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)
* [Elastic KQL Docs](https://www.elastic.co/guide/en/kibana/master/kuery-query.html) - Kibana Query Language, the default search language in Kibana.
* [Elastic EQL Docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) - Event Query Language for event correlation and sequence matching.
* _Threat Hunting in Elastic Stack: Lucene - pg. 212_
* _Threat Hunting in Elastic Stack: KQL - pg. 216_
* _Threat Hunting in Elastic Stack: EQL - pg. 220_

### Solr

[Solr](https://solr.apache.org/) is an open-source enterprise search platform built on Apache Lucene.

* [Solr for Newbies](https://github.com/hectorcorrea/solr-for-newbies)

## Splunk SPL: Search Processing Language

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

YARA-L is the detection language used by Google Security Operations (formerly Chronicle SIEM). Unlike standard YARA, which is used for file and malware pattern matching, YARA-L is designed for log, event, and entity data. It excels at correlation logic, allowing analysts to link events over time.

*   [**YARA-L syntax reference**](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax)
*   [**Google SecOps Detection Rules**](https://github.com/chronicle/detection-rules) - Official repository of YARA-L detection rules.
*   [**Chronicle YARA-L 2.0 Overview**](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)

For standard YARA rule writing, use the DFIR YARA page.

{% content-ref url="../dfir-digital-forensics-and-incident-response/yara.md" %}
[yara.md](../dfir-digital-forensics-and-incident-response/yara.md)
{% endcontent-ref %}

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

* [**Datadog Log Search Syntax**](https://docs.datadoghq.com/logs/explorer/search_syntax/)
