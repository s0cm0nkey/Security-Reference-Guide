---
description: Logs and the logging loggers that log them
---

# Logging and Security Architecture

## **Logging Guides**

* [https://its.uiowa.edu/support/article/3576](https://its.uiowa.edu/support/article/3576) - Limiting or Removing Unwanted Network Traffic at the Client
* [https://cheatsheetseries.owasp.org/cheatsheets/Logging\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Logging\_Cheat\_Sheet.html)
* [https://cheatsheetseries.owasp.org/cheatsheets/Logging\_Vocabulary\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Logging\_Vocabulary\_Cheat\_Sheet.html)
* Setting up Network Sensors - _Applied Network Security Monitoring_ - PG. 49
* Sensor Placement - _Applied Network Security Monitoring_ - PG. 61



## **Logging Data Types**

Before getting into the logging architecture, we need to define the various logging data types. These are the different forms of the data we use for Network Security Monitoring.

* **Packet Capture** - A complete record of every packet traveling back and forth, with all available metadata and transaction data. This is the most detailed form of data used for monitoring, but comes with an incredible storage cost.
* **Session Data** - Also called flow data, this is a summarized version of the target traffic that provides a significantly more flexible form for storage, while sacrificing content.
* **Statistical Data** - Various metrics and summary of data points found in network traffic. Variable per use case.
* **Packet String Data (PSTR)** - An intermediate form of capture between full Packet Capture and Session data. Contains specified strings from the captured traffic such as clear text protocol headers.
* **Log Data** - Raw log files generated from devices and applications.
* **Alert Data** - A specific event log generated from a detection device that can report anomalies or specific traffic patterns.

## Logging System Components

The core components of most security monitoring programs is the Security Information and Event Management system (SIEM) and the logs that support it. The architecture behind the SIEM has many components that make up the security logging ecosystem.&#x20;

### **Log Collector** - The tools that gather up the logs.&#x20;

* **Log Agents -** Applications that can be installed on devices to collect generated logs as well as perform a huge amount of other functions including: parsing, diode support, filtering, rate control, log rotation, log buffering, encryption, priority routing, file/registry monitoring, and even alerting.
  * A well configured agent will perform better than an agentless solution as remote authentication is not required.
  * Standard SIEM Agents - Agents that are paired with their premium SIEM products have easier integration, but will often have less features than their open-source alternatives, as well as usually lack filtering capabilities at the agent.
    * [Splunk Universal Forwarder](https://www.splunk.com/en\_us/download/universal-forwarder.html)
    * [ArcSight Connectors](https://www.ndm.net/siem/arcsight/arcsight-connectors)
    * [QRadar WinCollect](https://www.ibm.com/docs/en/qradar-on-cloud?topic=wincollect-overview)
    * [LogRhythm System Monitor Service](https://logrhythm.com/products/features/collection-technology/)
  * Open Source Agents - Feature rich, premium support available, and free.
    * [Elastic Beats](https://www.elastic.co/beats/) - Fantastic log collection agents that specialize in certain types of logs.&#x20;
      * Log Collection Agents focus on logs for: File integrity monitoring, Windows Events, Packet monitoring, OS metrics, Cloud infrastructure, Audit data, and device health monitoring.
      * Can get complicated managing so many different agents.
      * _Threat Hunting in Elastic Stack: Filebeat - pg. 55_
      * _Threat Hunting in Elastic Stack: Packetbeat - pg. 60_
      * _Threat Hunting in Elastic Stack: Winlogbeat - pg. 63_
      * _Threat Hunting in Elastic Stack: ElasticAgent - pg. 65_
    * [NXLog](https://nxlog.co) - Amazing agent with both a Community and Enterprise (Premium) editions.
      * Free version has more features than many premium agents.
      * Has premium support available.
      * Supports tons of log formats including W3C logs, the log format of IIS, Exchange, and Bro/Zeek
      * For endpoints, can be installed on both Windows and Linux and have its log output in the same format.
      * Configuration Sections
        * Input - defines what logs to monitor for collection
        * Output - sets where logs should go and which protocol is used
        * Route - maps inputs and outputs
        * Extension Modules - converts between formats
      * [NXLog-Autoconfig](https://github.com/SMAPPER/NXLog-AutoConfig) - With no customisation, the script will install Sysmon with the [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) config, generate a NXLog config to start pulling the Sysmon and Windows Security events.
* ****[**Syslog**](https://datatracker.ietf.org/doc/html/rfc5424) - Port 514. The most common protocol for logging. Can be TCP or UDP and can also be encrypted with TLS. Widely supported on most devices with the exception of Windows, which requires a third party agent.
  * Standard fields include: Time, Source, Facility, Severity, and Message.
  * Can also have a priority field associated with the log, calculated as Facilty(0-23) x 8 + severity (0-7)
  * Limitations: Size of logging packet is important especially when certain Windows logs can be over 30,000 bytes.
    * UDP - Limited to 1024 bytes, can lead to log duplication
    * TCP - Limited to 4096 bytes, is slower than UDP
* [**Windows Event Forwarding**](https://github.com/palantir/windows-event-forwarding) **** - TCP Port 5985. Windows built in agent for forwarding Windows event logs, in standard EVTX format.
  * Can be managed by GPO: Group Policy Objects
  * Uses AD for authentication
  * Uses WinRM to push/pull logs to/from an event collector
  * Basic filtering, encryption, and compression
  * [https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm](https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm)
* **Agentless Log Collection** - This usually involves a central server to collect logs, or a device that can natively send logs in the correct format to your SIEM.
  * Can use either a push or pull method with logs often being sent over WMI or SSH.
  * Easy to deploy and requires less maintenance
  * Can only handle a finite number of systems and logs
  * Can be a security risk with logs constantly being sent across the network and the potential requirement of the collector logging in to a device to pull the logs.
  * Data Diodes - A hardware or software tool that can improve log collection security in agentless applications, by forcing a one way connection to the logging server.
* **Script Collection**
  * Sometimes the only method of collection for cloud and third party apps.
  * Handy for collecting baseline information and inventory

### **Log Aggregator**&#x20;

The central collection point for your logs. This is where raw logs can be parsed and event have context added to them.

* Splunk Heavy Forwarder - A hybrid of a powerful logging agent and Aggregator, a Heavy forwarder can both collect logs from many sources as well as parse/filter logs.
* [Nagios - The Industry Standard In IT Infrastructure Monitoring](https://www.nagios.org) - Network logging and monitoring tool focused for network engineering.
* [Logstash ](https://github.com/elastic/logstash)- One of the most common aggregators. Built by Elastic Stack with over 200 plugins. Can be used to accept logs and convert them to other formats used by premium  SIEMs
  * Commercial support available
  * Uses a variety of plugins to perform different features
  * Can apply [tags](https://discuss.elastic.co/t/type-vs-tags/37131) to logs and data for creating categories to enhance searching
  * [HASecuritySolutions/logstash](https://github.com/HASecuritySolutions/logstash) - Repo of tons of Logstash related material and configs
  * [Plugins: Input](https://www.elastic.co/guide/en/logstash/current/input-plugins.html) - An input plugin enables a specific source of events to be read by Logstash.
    * [Plugins: Codec](https://www.elastic.co/guide/en/logstash/current/codec-plugins.html) - A Codec plugin will allow Logstash to read and parse certain special types of logging formats
    * [Plugin: stdin](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-stdin.html) - Allows for manual creation of logs
    * [Plugin: File](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-file.html) - Allows the output of files to be ingested as logs. Can be used as a way to log anything that can write a log to a file. Can use wildcards to scan for files in multiple directories.
    * [Plugin: jdbc](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-jdbc.html) - This plugin was created as a way to ingest data in any database with a JDBC interface into Logstash. This is handy for certain endpoint security suites that store their logs in a database.
    * [Plugin: UDP](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-udp.html) - The catch all plugin for logs being sent over syslog UDP 514. Can add TLS encryption to UDP streams. \*Root privileges will be required on ports under 1024.\*
  * [Plugins: Output ](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-elasticsearch.html)- Logstash can output to multiple different applications including [Elasticsearch](https://www.elastic.co/elasticsearch/)
  * [Plugins: Filter](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html) - Filtering logs by tons of different options, variables, and conditions.
    * Regex - Filter by specific Regex matching
    * Grok - Filter by set Regex built patterns
      * [Grok Debugger](https://grokdebug.herokuapp.com)
    * Pattern - Filter by customer regex that is assigned a name. Reusable regex
    * CSV - Filter by comma separated values.
    * Key Value pair
    * JSON - Handy for parsing and filtering IDS solutions like SNORT and Surricata that can output in JSON format
    * [Plugin: Date ](https://www.elastic.co/guide/en/logstash/current/plugins-filters-date.html)- Uses [Joda-Time](http://joda-time.sourceforge.net/apidocs/org/joda/time/format/DateTimeFormat.html) (java time library) to pattern match and normalize time/date stamps.
    * [Plugin: Drop](https://www.elastic.co/guide/en/logstash/current/plugins-filters-drop.html) - Used for dropping logs buy certain criteria
      * Can also be used with the remove\_field filter to remove specific data fields within a log
  * Plugins: Enrichment - Adding fields and contextual data.
    * [GeoIP](https://www.elastic.co/guide/en/logstash/current/plugins-filters-geoip.html) - Adds location to IP address entries
    * [DNS](https://www.elastic.co/guide/en/logstash/current/plugins-filters-dns.html) - Performs reverse DNS lookups
    * [Fingerprint](https://www.elastic.co/guide/en/logstash/current/plugins-filters-fingerprint.html) - Takes a data field and replaces the data with a hash of the data itself. Handy for identification but not disclosure of sensitive data like PII.
    * [Mutate](https://www.elastic.co/guide/en/logstash/current/plugins-filters-mutate.html) - Manipulating a field and its data.
    * [Ruby](https://www.elastic.co/guide/en/logstash/current/plugins-filters-ruby.html) - For making API calls. Also for analysis of data fields like suspect length.

### **Log Broker**

&#x20;An optional component, a log broker acts as a buffer for temporary storage of logs. It helps to store logs over regular flow capacity. Intended to help syslog devices as many agent based systems have their own internal broker-like services.

* [Rabbitmq](https://www.rabbitmq.com) - Easy to install, easy to use, and available for all major operating systems
* [Kafka](https://kafka.apache.org) - High powered broker with the ability to manage high volume of events at a time. Use [Apache Zookeeper](https://kafka.apache.org) to manage multiple Kafka nods

### **Storage**&#x20;

Where all of your logs are stored for later use.

* WORM - Write-Once-Read-Many. The ideal storage type for SIEM
* Typical relational database structures are not optimal as most are ACID compliant (Containing integrity checks) which is really not efficient for logging purposes.



### **Search/Report**&#x20;

The component which allows the searching of parsed data and creation of reports based on intricate search queries.

* [Elastisearch](https://www.elastic.co/elasticsearch/) - The WORM based, distributed, scalable database used for real time searching.
  * Elastisearch architecture uses the concept of a shard, which is a storage partition. These shards are usually created with replicas stored in a different location for redundancy. The cool thing is that both the original shard, and the copy are available for searching, drastically increasing search speeds. Both the primary and replica shards are used to scale out.
  * [Kibana](https://www.elastic.co/kibana/) - The Primary search interface for Elastisearch.
    * _Threat Hunting in Elastic Stack: Using Kibana - pg. 66, 198_
  * [https://www.elastic.co/elasticon/conf/2015/sf/scaling-elasticsearch-for-production-at-verizon](https://www.elastic.co/elasticon/conf/2015/sf/scaling-elasticsearch-for-production-at-verizon)__
  * _Threat Hunting in Elastic Stack: Bringing data into Elasticseach - pg. 50_
* [Splunk](https://www.splunk.com) - The premium cadillaic option of searching/data mining utilities.

### **Alert Engine**&#x20;

One of the most important components in a SIEM, the alert engine can take predefined searches and perform specific actions when those searches return results, such as create an alert.

* [Graylog](https://www.graylog.org) - An admin platform for Elastisearch that can be used to create easy and flexible alerting
* [ElastAlert](https://github.com/Yelp/elastalert) - A python based framework for setting up alerts within Elastisearch
* [Watcher/Kibana-Alerting](https://www.elastic.co/what-is/kibana-alerting) - Elastisearch's commercial offering for creating and managing alerts.
* [Splunk Security Essentials](https://www.splunk.com/en\_us/software/cyber-security-essentials.html) - A free app(plugin) for Splunk that comes with a small set of security search use cases and other utilties.
* [Splunk Enterprise Security](https://www.splunk.com/en\_us/software/enterprise-security.html) - Splunks premium SIEM alerting engine with a large selection of preset security alerts, deshboards, and an alert triaging panel for use in a SOC.
