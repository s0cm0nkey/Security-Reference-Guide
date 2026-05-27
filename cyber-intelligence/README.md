---
description: Cyber threat intelligence and OSINT resources for indicators, threat data, enrichment, source evaluation, and intelligence workflows.
---

# Cyber Intelligence

Cyber intelligence turns public and private security data into decisions: what matters, why it matters, who needs to know, and what action should follow. This section covers CTI concepts, feed management, indicator enrichment, and OSINT workflows.

## Core Analyst Responsibilities

1. **Collect actionable intelligence** - Gather reporting, advisories, technical indicators, campaign details, vulnerabilities, and public-source evidence.
2. **Manage indicators** - Evaluate source quality, indicator fidelity, decay, false positives, and how feeds integrate with security tools.
3. **Enrich indicators** - Add context such as ASN, domain age, passive DNS, actor reporting, campaign links, observed malware, infrastructure relationships, and blacklist/reputation results.
4. **Produce and disseminate intelligence** - Turn findings into useful outputs for defenders, leaders, incident responders, vulnerability teams, or investigators.

## Section Map

{% content-ref url="intel-feeds-and-sources.md" %}
[intel-feeds-and-sources.md](intel-feeds-and-sources.md)
{% endcontent-ref %}

{% content-ref url="threat-data.md" %}
[threat-data.md](threat-data.md)
{% endcontent-ref %}

{% content-ref url="osint/" %}
[osint](osint/)
{% endcontent-ref %}

## Intelligence Disciplines

* **Cyber Threat Intelligence (CTI)** - Analysis of adversary capabilities, intent, infrastructure, targets, tooling, TTPs, indicators, and operational impact.
* **Open-Source Intelligence (OSINT)** - Publicly available information collected and analyzed to answer an intelligence requirement.
* **Geospatial Intelligence (GEOINT)** - Location-focused analysis using maps, imagery, satellite data, terrain, and geospatial context.
  * [OH SHINT GEOINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/mapping-and-geo-spatial-intelligence-geoint)
* **Imagery Intelligence (IMINT)** - Image and media analysis, including visual verification and metadata review.

{% content-ref url="osint/files-media-breach-paste-code.md" %}
[files-media-breach-paste-code.md](osint/files-media-breach-paste-code.md)
{% endcontent-ref %}

* **Signals Intelligence (SIGINT)** - Intelligence derived from communications or electronic signals. This guide treats public SIGINT-like resources cautiously and keeps practical workflows inside OSINT.
  * [OH SHINT SIGINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/signals-intelligence-sigint)
* **Human Intelligence (HUMINT)** - Intelligence from human sources. In this guide, authorized public-source interviews, debriefs, and community reporting are more relevant than espionage-style HUMINT.
* **Measurement and Signature Intelligence (MASINT)** - Technical signatures derived from physical or measurable characteristics. This is mostly outside the practical scope of the guide.

## Intelligence Cycle

The intelligence cycle is the process for turning requirements into useful products:

1. **Planning and direction** - Define the question and decision the intelligence must support.
2. **Collection** - Gather relevant data from sources that can answer the requirement.
3. **Processing** - Normalize, deduplicate, index, translate, enrich, and prepare the data for analysis.
4. **Analysis and production** - Assess the evidence, identify confidence levels, and produce the intelligence output.
5. **Dissemination** - Deliver the output to the people or systems that can act on it.
6. **Feedback and evaluation** - Learn whether the output helped and refine the next requirement.

The cycle is iterative. Analysis often exposes new collection gaps, and feedback can change the original requirement.

## Reference and Theory

* [Intelligence.gov: How Intelligence Works](https://www.intel.gov/how-the-ic-works)
* [Sergio Caltagirone: Intelligence Cycle](https://sroberts.io/posts/intelligence-concepts-the-intelligence-cycle/)
* [Sergio Caltagirone: F3EAD](https://sroberts.io/posts/intelligence-concepts-f3ead/)
* [Joint Publication 2-0: Joint Intelligence](https://www.jcs.mil/Portals/36/Documents/Doctrine/pubs/jp2_0.pdf)
* [Psychology of Intelligence Analysis](https://www.ialeia.org/docs/Psychology_of_Intelligence_Analysis.pdf)
* [Getting Started with ATT&CK: Threat Intelligence](https://medium.com/mitre-attack/getting-started-with-attack-cti-4eb205be4b2f)
* [Using ATT&CK to Advance Cyber Threat Intelligence - Part 1](https://medium.com/mitre-attack/using-att-ck-to-advance-cyber-threat-intelligence-part-1-c5ad14d59724)
* [Using ATT&CK to Advance Cyber Threat Intelligence - Part 2](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/using-attck-to-advance-cyber-threat-0)
* [SANS: ATT&CKing the Status Quo](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536260992.pdf)

CTI and OSINT training resources have been moved to Training.

{% content-ref url="../training/" %}
[training](../training/)
{% endcontent-ref %}

![](<../.gitbook/assets/image (14).png>)
