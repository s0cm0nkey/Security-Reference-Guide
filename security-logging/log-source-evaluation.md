---
description: Evaluating log source quality and visibility coverage
---

# Log Source Evaluation

Not all log sources are equal. Evaluation should answer whether a source is present, parsed, complete, timely, attributable, and useful for detections and investigations.

## What to Evaluate

* **Coverage** - Which systems, users, services, and environments produce the log?
* **Completeness** - Does the log contain the fields needed for the use case?
* **Fidelity** - Does the source report accurately enough to trust?
* **Timeliness** - How quickly does the event arrive?
* **Attribution** - Can the event be tied to a user, host, process, asset, or service?
* **Normalization** - Are fields mapped into the expected schema?
* **Retention** - Is the data stored long enough for investigations?
* **Cost** - Does the value justify ingestion, storage, and analyst time?

## Standards and Schemas

* Splunk Common Information Model (CIM)
* Elastic Common Schema (ECS)
* Open Cybersecurity Schema Framework (OCSF)
* OSSEM Data Model

## DeTTECT

[DeTTECT](https://github.com/rabobank-cdc/DeTTECT) helps teams score and compare data-source quality, visibility coverage, detection coverage, and threat actor behaviors against ATT&CK.

DeTTECT resources:

* [Getting Started](https://github.com/rabobank-cdc/DeTTECT/wiki/Getting-started)
* [DeTTECT presentation](https://www.youtube.com/watch?v=_kWpekkhomU)
* [DeTTECT video guide](https://www.youtube.com/watch?v=EXnutTLKS5o)
* [Mapping your Blue Team to MITRE ATT&CK](https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack)
* [dettectinator](https://github.com/siriussecurity/dettectinator) - Python library for DeTTECT YAML files.
  * [NVISO: Automate Your Detection Coverage with dettectinator](https://blog.nviso.eu/2023/01/04/dettct-automate-your-detection-coverage-with-dettectinator/)

## ATT&CK Data Mapping

* [ATTACKdatamap](https://github.com/olafhartong/ATTACKdatamap) - Olaf Hartong's event-level data-source assessment project for ATT&CK coverage.
* [Assess your data potential with ATT&CK Datamap](https://medium.com/@olafhartong/assess-your-data-potential-with-att-ck-datamap-f44884cfed11)
* [OSSEM-DM](https://github.com/OTRF/OSSEM-DM)

Windows Event ID to ATT&CK mappings and Malware Archaeology cheat sheets are maintained with terminology and mapping references.

{% content-ref url="../blue-defense/terminology-and-mapping.md" %}
[terminology-and-mapping.md](../blue-defense/terminology-and-mapping.md)
{% endcontent-ref %}

## Related Pages

For detection engineering and event analysis:

{% content-ref url="../blue-defense/event-detection/" %}
[event-detection](../blue-defense/event-detection/)
{% endcontent-ref %}

{% content-ref url="../blue-defense/event-and-log-analysis.md" %}
[event-and-log-analysis.md](../blue-defense/event-and-log-analysis.md)
{% endcontent-ref %}

For selecting collection priorities:

{% content-ref url="how-to-log.md" %}
[how-to-log.md](how-to-log.md)
{% endcontent-ref %}

## Legacy References

The older September 2018 Windows ATT&CK logging cheat sheet is a historical reference. Prefer maintained ATT&CK mappings and Malware Archaeology resources for current work.

{% embed url="https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5b8f091c0ebbe8644d3a886c/1536100639356/Windows+ATT%26CK_Logging+Cheat+Sheet_ver_Sept_2018.pdf" %}
