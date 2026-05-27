# Event Detection

Event detection is foundational for security analysts and blue teams. Whether you are building automated alerting or threat hunting, you need to understand what you are looking for, which data source can show it, and how your tooling represents the activity.

Effective event detection usually requires three things:

* A data source that can observe the behavior.
* A collection path that gets the data into an analysis platform.
* Detection logic that separates suspicious activity from normal noise.

This page is the hub for detection engineering resources in the Blue section. Deep dives on threat intelligence, attack surface discovery, deception, YARA, packet analysis, and logging architecture live in their own pages and sections.

## Detection Engineering and Standards

* [Sigma](https://github.com/SigmaHQ/sigma) - Open rule format for log-based detections that can be converted into many SIEM query languages.
* [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) - Common field schema for Elasticsearch data.
* [Splunk Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) - Splunk's data normalization model for writing searches across similar data sources.
* [MITRE D3FEND](https://d3fend.mitre.org/) - Defensive countermeasure knowledge base that can help structure detection coverage.

For search syntax and rule language references, use Query Languages.

{% content-ref url="../query-languages.md" %}
[query-languages.md](../query-languages.md)
{% endcontent-ref %}

## SIEM and Enrichment

Use this page for SIEM platforms, enrichment workflows, and tools that add context to security events.

{% content-ref url="siem-and-enrichment.md" %}
[siem-and-enrichment.md](siem-and-enrichment.md)
{% endcontent-ref %}

## IDS, IPS, and Network Security Monitoring

Use this page for Snort, Suricata, Zeek, Security Onion, and network detection rule references.

{% content-ref url="ids-ips.md" %}
[ids-ips.md](ids-ips.md)
{% endcontent-ref %}

For packet capture and protocol analysis, use Packet Analysis.

{% content-ref url="../packet-analysis.md" %}
[packet-analysis.md](../packet-analysis.md)
{% endcontent-ref %}

For network log collection and architecture, use Logging and Security Architecture.

{% content-ref url="../../security-logging/logging-guide-network-services.md" %}
[logging-guide-network-services.md](../../security-logging/logging-guide-network-services.md)
{% endcontent-ref %}

## Endpoint Detection

* [OSSEC](https://www.ossec.net/about/) - A scalable, multi-platform, open-source host-based intrusion detection system.
* [Wazuh](https://github.com/wazuh/wazuh) - OSSEC fork with Elastic integration, improved rules, an API, and a UI.
* [Aurora](https://www.nextron-systems.com/aurora/) - Sigma-based endpoint detection agent from Nextron.
* [osquery](https://osquery.io/) - Endpoint visibility tool that exposes operating system state through SQL.
  * [Awesome osquery](https://github.com/sttor/awesome-osquery)
  * [Trail of Bits osquery extensions](https://github.com/trailofbits/osquery-extensions)
  * [OSQuery ATT&CK](https://github.com/teoseller/osquery-attck)
  * [Palantir osquery configuration](https://github.com/palantir/osquery-configuration)
  * [Introduction to osquery for Threat Detection and DFIR](https://www.rapid7.com/blog/post/2016/05/09/introduction-to-osquery-for-threat-detection-dfir/)
  * [Using osquery for remote forensics](https://blog.trailofbits.com/2019/05/31/using-osquery-for-remote-forensics/)
  * [Osquery: Incident Response Across the Enterprise](https://blog.palantir.com/osquery-across-the-enterprise-3c3c9d13ec55)
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Endpoint visibility and collection tool used in detection, hunting, and response workflows.
* [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Fast Windows event log timeline and threat hunting tool that uses Sigma rules.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - PowerShell tool for detecting suspicious activity in Windows event logs.

## Cloud and Container Detection

* [Falco](https://falco.org/) - Cloud-native runtime security tool for detecting unexpected behavior from Linux system calls.
* [Sysdig](https://github.com/draios/sysdig) - Linux system visibility tool useful for container and host investigation.

Cloud and container hardening tools belong with device hardening and the platform pages.

{% content-ref url="../device-hardening/" %}
[device-hardening](../device-hardening/)
{% endcontent-ref %}

{% content-ref url="../../containers.md" %}
[containers.md](../../containers.md)
{% endcontent-ref %}

## Sysmon

Use this page for Sysmon configuration, event IDs, and related tooling.

{% content-ref url="sysmon.md" %}
[sysmon.md](sysmon.md)
{% endcontent-ref %}

## Detection Use Cases

Use these pages for practical detection ideas by protocol, log type, and behavior category.

{% content-ref url="detection-use-cases/" %}
[detection-use-cases](detection-use-cases/)
{% endcontent-ref %}

## Related Sections

Some resources are useful to detection teams but belong in other buckets:

* Threat intelligence platforms, feeds, enrichment sources, and reputation lookups live in Cyber Intelligence.

{% content-ref url="../../cyber-intelligence/" %}
[cyber-intelligence](../../cyber-intelligence/)
{% endcontent-ref %}

* Attack surface discovery and active reconnaissance tools live in Red Offensive.

{% content-ref url="../../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../../red-offensive/scanning-active-recon/)
{% endcontent-ref %}

* Deception, honeypots, and canary tokens live in Active Defense.

{% content-ref url="../active-defense.md" %}
[active-defense.md](../active-defense.md)
{% endcontent-ref %}

* YARA authoring, Loki, malware scanning, and file analysis live in DFIR.

{% content-ref url="../../dfir-digital-forensics-and-incident-response/yara.md" %}
[yara.md](../../dfir-digital-forensics-and-incident-response/yara.md)
{% endcontent-ref %}

* JA3, HASSH, FATT, RITA, and other network fingerprinting or beaconing analysis resources live in Packet Analysis.

{% content-ref url="../packet-analysis.md" %}
[packet-analysis.md](../packet-analysis.md)
{% endcontent-ref %}

## Deprecated / Archived Projects

These tools were widely used or referenced in the past but are now unmaintained, archived, or superseded. They remain here for historical context.

* [BlueSpawn](https://github.com/ION28/BLUESPAWN) - EDR and active defense tool. Inactive/dormant.
* [Intrigue Core](https://github.com/intrigueio/intrigue-core) - Former attack surface discovery framework, archived after the Mandiant/Google Cloud acquisition.
* [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - PowerShell obfuscation detection research tool.
* [Flare](https://github.com/austin-taylor/flare) - Unmaintained network analysis tool for Elastic Stack.
* [OpenUBA](https://github.com/GACWR/OpenUBA) - Unmaintained user and entity behavior analytics framework.
* [OpenEDR](https://github.com/ComodoSecurity/openedr) - Open-source EDR monitoring project that appears inactive.
* [whids](https://github.com/0xrawsec/whids) - Open-source EDR for Windows. Unmaintained.
* [ODIN](https://github.com/chrismaddalena/ODIN) - Automated intelligence gathering tool. Unmaintained.
* [Asnip](https://github.com/harleo/asnip) - Attack surface mapping tool. Unmaintained.
* [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) - Reconnaissance tool. Unmaintained.
* [GQUIC Protocol Analyzer](https://github.com/salesforce/GQUIC_Protocol_Analyzer) - Obsolete; Zeek now includes native [QUIC support](https://docs.zeek.org/en/current/scripts/base/protocols/quic/index.html).
