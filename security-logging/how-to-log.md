# How to Create a Logging Strategy

Logging is not just present or absent. Logs have quality, context, coverage, cost, and operational value. A good strategy collects enough data to support detections and investigations without drowning the team in storage costs and low-value events.

## Logging Strategy

Most organizations start with a SIEM for compliance, then discover that collection quality matters more than raw volume. Common approaches include:

* **Volume logging** - Collect everything and tune later.
* **Selective logging** - Collect only known useful sources and fields.
* **Hybrid logging** - Start broad enough to avoid blind spots, then tune, filter, and prune based on evidence.

The hybrid approach usually works best. It requires maintenance, but it gives teams a way to learn what matters before they permanently discard useful evidence.

## Logging Purpose

Before collecting a source, decide who uses it and why.

* **Security alerts only** - Events and fields directly required for alerting. This is the smallest and cheapest option, but it has limited investigation value.
* **Security-relevant logs** - Alert data plus events useful for investigations, threat hunting, and incident response.
* **Operational logs** - Security and IT operations share the same logging platform, often with broader infrastructure and application coverage.

Compliance can be a starting point, but it should not be the whole strategy.

## What Logs Should You Collect?

Use a mix of compliance requirements, incident-response needs, detection coverage, and business context. ATT&CK data sources can help identify where coverage is strong or weak, but do not treat a mapped technique as proof of real detection.

The MITRE data-source statistics below were from a previous snapshot of ATT&CK and should be treated as directional, not current counts:

* Command execution and process creation were among the highest-value data objects for coverage.
* File modification, network traffic content, and network traffic flow also covered broad technique sets.
* Some techniques cannot be detected directly and require prevention, hardening, or indirect behavioral signals.

For deeper log-source coverage assessment, use the Log Source Evaluation page.

{% content-ref url="log-source-evaluation.md" %}
[log-source-evaluation.md](log-source-evaluation.md)
{% endcontent-ref %}

For the original analysis PDF:

{% file src="../.gitbook/assets/mitre_data_source_analysis.pdf" %}

## Calculating Infrastructure Needs

Plan collection and storage with a proof-of-concept whenever possible. Sample real events, measure volume, and account for peak periods.

Key sizing values:

* **EPD** - Events per day. Useful for storage capacity.
* **EPS** - Events per second. Useful for ingestion and pipeline sizing.
* **Peak EPS** - Maximum burst throughput.

If sampling is not possible, third-party estimates can help with early planning, but they should not replace measurement.

* [SANS: Benchmarking SIEM](https://apps.es.vt.edu/confluence/download/attachments/460849213/sans%20siem%20benchmarking.pdf?api=v2)
* [SolarWinds: Estimating Log Generation](https://content.solarwinds.com/creative/pdf/Whitepapers/estimating_log_generation_white_paper.pdf)

## Types of Log Storage

Retention should be driven by investigation needs, legal requirements, and budget. Mandiant's older M-Trends reporting cited long dwell times, which is a useful reminder: teams often need logs from weeks or months before detection.

* **Hot** - Recent, active logs on fast storage. Commonly 7-30 days.
* **Warm** - Older but still searchable logs on cheaper storage. Commonly 30-90+ days.
* **Cold** - Long-term storage for rare lookbacks, compliance, and historical investigations.

## Log Collection Methodology

Collection depends on the source.

* **Application and device logs** - Usually collected by native forwarding, syslog, agents, APIs, or file pickup.
* **Endpoint logs** - Windows Event Logs, PowerShell logs, Linux syslog, auditd, EDR telemetry, and supplementary agents.
* **Service logs** - DNS, HTTP, SMTP, VPN, proxy, firewall, and other service-specific records.
* **Network-derived logs** - Zeek, Corelight, flow exporters, packet sensors, and cloud flow logs.
* **Cloud logs** - Provider audit logs, identity logs, API activity, flow logs, and SaaS audit exports.

Endpoint, network, and cloud logging each have their own pages in this section.

{% content-ref url="logging-guide-windows-endpoint-logs.md" %}
[logging-guide-windows-endpoint-logs.md](logging-guide-windows-endpoint-logs.md)
{% endcontent-ref %}

{% content-ref url="logging-guide-network-services.md" %}
[logging-guide-network-services.md](logging-guide-network-services.md)
{% endcontent-ref %}

{% content-ref url="logging-cloud.md" %}
[logging-cloud.md](logging-cloud.md)
{% endcontent-ref %}

## Final Note

Logging platforms require tuning, pruning, and ownership. No SIEM can replace good source selection, clean parsing, consistent enrichment, and analysts who understand the environment.
