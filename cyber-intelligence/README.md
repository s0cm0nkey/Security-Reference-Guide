# Cyber Intelligence

## Intro

Intelligence programs are essential to effective security operations. Every organization should stay current with cybersecurity news to understand emerging attacks and vulnerabilities. An intelligence analyst's job is to sift through the vast amount of intelligence data generated daily and extract what is applicable to their organization.

The role of an intelligence analyst is threefold:

**1. Collect Actionable Intelligence** - Analysts gather valuable information from diverse sources including news articles, reports, white papers, blog posts, social media, and forums. Within these sources, analysts identify indicators of compromise (IOCs) that can be added to blocklists or searched for across the network. They also identify configurations or vulnerabilities that pose significant threats to operations.

**2. Manage Indicators** - Analysts curate threat intelligence feeds that integrate with security tools for alerting. Since not all indicators have equal value, analysts must evaluate which intelligence sources to use and maintain the quality of those indicators through ongoing curation.

**3. Enrich Indicators** - Context is critical; an indicator without context provides little value. Analysts manage toolsets that add enrichment data to indicators, such as the origin of the threat, associated campaigns, prevalence across threat intelligence sources, and blacklist appearances. This context enables security analysts to make informed decisions when investigating potential threats.

{% content-ref url="osint/" %}
[osint](osint/)
{% endcontent-ref %}

{% content-ref url="intel-feeds-and-sources.md" %}
[intel-feeds-and-sources.md](intel-feeds-and-sources.md)
{% endcontent-ref %}

{% content-ref url="threat-data.md" %}
[threat-data.md](threat-data.md)
{% endcontent-ref %}

## **What is Intelligence?**

Intelligence is information that has been collected, processed, and analyzed to address threats to an organization. It provides unique insights that warn of potential threats and opportunities, assesses probable risks associated with policy options, and can include profiles of threat actors or competitors.

There are several domains or disciplines that comprise intelligence:

* **Human intelligence (HUMINT)** - Human intelligence is derived from human sources. While commonly associated with espionage and covert operations, most HUMINT is collected through overt means by strategic debriefers, military attachés, and other authorized collectors. HUMINT is the oldest intelligence discipline and was the dominant source of intelligence until the technological revolution of the mid-to-late twentieth century.
* **Signal intelligence (SIGINT)** - Signal intelligence comprises communications intelligence (COMINT), electronic intelligence (ELINT), and foreign instrumentation signals intelligence (FISINT). These intelligence types are generated through signal intercepts and can be collected separately or in combination.
  * [OSHINT SIGINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/signals-intelligence-sigint)
* **Cyber threat intelligence** - Cyber threat intelligence is the collection, processing, analysis, and dissemination of information from all sources of intelligence on threat actors’ cyber programs, intentions, capabilities, research and development, tactics, targets, operational activities and indicators, and their impact or potential effects on U.S. national security interests. Cyber threat intelligence also includes information on cyber threat actor information systems, infrastructure, and data; and network characterization, or insight into the components, structures, use, and vulnerabilities of threat actors information systems.

{% content-ref url="intel-feeds-and-sources.md" %}
[intel-feeds-and-sources.md](intel-feeds-and-sources.md)
{% endcontent-ref %}

{% content-ref url="threat-data.md" %}
[threat-data.md](threat-data.md)
{% endcontent-ref %}

* **Image intelligence (IMINT)** - Imagery intelligence includes the representations of objects replicated electronically or by optical means on film, electronic display devices, or other media. Visual photography, radar sensors, and electro-optics can all be used to create imagery. The Files/Media page has many tools and resources for analyzing digital media such as photos or video.

{% content-ref url="osint/files-media-breach-paste-code.md" %}
[files-media-breach-paste-code.md](osint/files-media-breach-paste-code.md)
{% endcontent-ref %}

* **Measurement and signature intelligence (MASINT)** - Measurement and Signature Intelligence is information produced through quantitative and qualitative analysis of the physical attributes of targets and events. MASINT exploits various phenomenologies using diverse sensors and platforms to develop signatures, perform technical analysis, and detect, characterize, locate, and identify targets and events. It derives from specialized measurements of physical phenomena intrinsic to objects or events, using quantitative signatures to interpret data.
* **Geospatial intelligence (GEOINT)** - Geospatial Intelligence is the analysis and visual representation of security-related activities on Earth. It is produced through the integration of imagery, imagery intelligence, and geospatial information.
  * [OSHINT GEOINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/mapping-and-geo-spatial-intelligence-geoint)
* **Open-source intelligence (OSINT)** - Open-Source Intelligence is publicly available information that has been collected and subjected to rigorous, methodical analysis to satisfy a stakeholder's intelligence requirements.

{% content-ref url="osint/" %}
[osint](osint/)
{% endcontent-ref %}

## **How is Intelligence Conducted?**

The process of developing intelligence from multiple sources is called the "Intelligence Cycle." The intelligence cycle comprises the following steps:

* **Planning and Direction** - Defining the intelligence requirements and questions that need to be answered.
* **Collection** - Gathering the data needed to answer the intelligence requirements. Redundant data from multiple sources is valuable as it corroborates findings and increases confidence in the analysis.
* **Processing** - Transforming raw data into a usable format through:
  * **Normalization** - Converting data into a consistent format to enable parsing and manipulation, including translation, filtering, and editing.
  * **Indexing** - Organizing and tagging data to enable efficient searching of specific data points and categories.
  * **Enrichment** - Adding contextual information to enhance data value and manipulating presentation for improved usability, such as through data visualization.
* **Analysis & Production** - Analyzing processed data to answer intelligence requirements, then producing finished intelligence products that can be consumed by stakeholders.
* **Dissemination** - Delivering intelligence products to relevant stakeholders through appropriate channels.
* **Feedback and Evaluation** - Collecting feedback on intelligence products and evaluating effectiveness to identify improvements in content, presentation, or timeliness.

Each step is integral to producing intelligence, but the cycle is not strictly linear. Steps may be conducted simultaneously, or analysts may move back and forth between stages before progressing. For example, during analysis you may discover gaps requiring additional collection, or stakeholder feedback during production may require returning to earlier stages. This iterative approach ensures the final intelligence product fully addresses requirements.

## **Resources**

### **Reference and Theory**

* Intelligence Cycle - [https://www.intel.gov/how-the-ic-works](https://www.intel.gov/how-the-ic-works)
* Intelligence Cycle Concepts - [https://sroberts.io/posts/intelligence-concepts-the-intelligence-cycle/](https://sroberts.io/posts/intelligence-concepts-the-intelligence-cycle/)
* Intelligence F3EAD - [https://sroberts.io/posts/intelligence-concepts-f3ead/](https://sroberts.io/posts/intelligence-concepts-f3ead/)
* [US Intelligence Doctrine](https://www.jcs.mil/Portals/36/Documents/Doctrine/pubs/jp2_0.pdf) - Great resource for learning the process of intelligence gathering and putting it to use.
* Psychology of Intelligence Analysis- Huer - [https://www.ialeia.org/docs/Psychology\_of\_Intelligence\_Analysis.pdf](https://www.ialeia.org/docs/Psychology_of_Intelligence_Analysis.pdf)
* MITRE ATT\&CK and Threat Intelligence
  * [FIRST CTI Symposium: Turning intelligence into action with MITRE ATT\&CK™](https://www.slideshare.net/KatieNickels/first-cti-symposium-turning-intelligence-into-action-with-mitre-attck)
  * [Getting Started with ATT\&CK: Threat Intelligence](https://medium.com/mitre-attack/getting-started-with-attack-cti-4eb205be4b2f)
  * [Using ATT\&CK to Advance Cyber Threat Intelligence — Part 1](https://medium.com/mitre-attack/using-att-ck-to-advance-cyber-threat-intelligence-part-1-c5ad14d59724)
  * [Using ATT\&CK to Advance Cyber Threat Intelligence — Part 2](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/using-attck-to-advance-cyber-threat-0)
  * [ATT\&CKing the Status Quo: ThreatBased Adversary Emulation with MITRE ATT\&CK™](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536260992.pdf)
* _Intelligence Driven Incident Response - pg. 11_

### Intel Training

* [Katie Nickels's Cyber Threat Intelligence Self Study Plan](https://medium.com/katies-five-cents/a-cyber-threat-intelligence-self-study-plan-part-1-968b5a8daf9a) - Self-study plan created by the instructor of the SANS Threat Intelligence course. An excellent starting point for CTI learning.
* [MITRE ATT&CK CTI Training](https://attack.mitre.org/resources/training/cti/) - Training by Katie Nickels and Adam Pennington of the ATT&CK team on applying ATT&CK to improve threat intelligence practices.
* [Introduction to the EASY Framework](https://academy.attackiq.com/courses/introduction-to-the-easy-framework) - Threat intelligence course focusing on building your own threat intelligence workflow and program.
* [Shadowscape Cyber Intelligence Analytics Operations](https://www.shadowscape.io/cyber-intelligence-analytics-operat) - Comprehensive course covering all stages of the intelligence cycle from collection to analysis, taught by experienced intelligence professionals. Learn to employ threat intelligence for defense strategies, incident response, and creating actionable reports for decision makers.

![](<../.gitbook/assets/image (14).png>)

