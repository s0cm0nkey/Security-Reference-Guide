# Cyber Intelligence

## Intro

Intelligence programs are essential to good security. Every company should stay on top of cyber security news for the latest trending attacks and vulnerabilities. An intelligence analysts job is to sift through the metric ton of intelligence data generated every day, and pull out what is applicable to their organization.

The role of an Intelligence analyst is threefold:

First and foremost, their job is to collect actionable intelligence. This can be news articles, reports, white papers, blog posts, tweets, reddit posts, or anything that can provide value. Within these you will be looking for Indicators of compromise that can be added to block lists, or searched for in your network. You will also look for configurations or vulnerabilities that pose a great threat to your operations.

The second responsibility is indicator management. Lists of indicators come in feeds that can be fed into security tools for alerting. Some will have value, some wont. It is the intelligence analyst's role to determine which sources of intel feeds to use, as well as to curate those indicators.

Lastly, intelligence analysts manage indicator enrichment. Any indicator reported is completely useless without context. Intelligence analysts can manage toolsets that add context and enrichment to the indicators they manage. Details like where/how an indicator was first reported, or how many blacklists it may show up on, can add much needed context when a security analyst investigating interaction with an indicator.

{% content-ref url="osint/" %}
[osint](osint/)
{% endcontent-ref %}

{% content-ref url="intel-feeds-and-sources.md" %}
[intel-feeds-and-sources.md](intel-feeds-and-sources.md)
{% endcontent-ref %}

{% content-ref url="threat-data.md" %}
[threat-data.md](threat-data.md)
{% endcontent-ref %}

## **What is Intelligence?**&#x20;

Intelligence is information gathered that involves threats to an organization. Intelligence can provide insights not available elsewhere that warn of potential threats and opportunities, assess probable risk and opportunities to an organization of proposed policy options, provide leadership profiles on competitors.

There are several “domains” or disciplines that comprise intelligence: those are&#x20;

* **Human intelligence (HUMINT)** - Human intelligence comes from other humans. HUMINT is still associated with espionage and covert operations in the public mind; nevertheless, most HUMINT is collected by overt collectors such as strategic debriefers and military attachés. It is the oldest way of gathering data, and it was the dominant source of intelligence until the mid-to-late twentieth century's technological revolution.
* **Signal intelligence (SIGINT)** - Signal intelligence comprises all communications intelligence (COMINT), electronic intelligence (ELINT), and foreign instrumentation signals intelligence (FISINT) are generated through signal intercepts, which can be sent separately or in combination.
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

* **Measurement and signature intelligence (MASINT)** - Measurement and Signature Intelligence is information produced by quantitative and qualitative analysis of physical attributes of targets and events to characterize, locate, and identify them. MASINT exploits a variety of phenomenologies, from a variety of sensors and platforms, to support signature development and analysis, to perform technical analysis, and to detect, characterize, locate and identify targets and events. MASINT is derived from specialized, technically derived measurements of physical phenomenon intrinsic to an object or event and it includes the use of quantitative signatures to interpret the data.
* **Geospatial intelligence (GEOINT)** - Geospatial Intelligence is the analysis and visual representation of security-related activities on the earth. It is produced through an integration of imagery, imagery intelligence, and geospatial information.
  * [OSHINT GEOINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/mapping-and-geo-spatial-intelligence-geoint)
* **Open-source intelligence (OSINT)** - Open-Source Intelligence is open-source information that is publicly available and collected that has undergone a rigorous and methodical analysis process to satisfy a stakeholders intelligence requirement.

{% content-ref url="osint/" %}
[osint](osint/)
{% endcontent-ref %}

## **How is Intelligence Conducted?**&#x20;

The process to develop intelligence from many different sources is called “The Intelligence Cycle”. The intelligence cycle is comprised of the following steps:

* Planning and Direction - Defining the question that the intelligence is intended to answer
* Collection  - Collecting  the data needed to answer the original question. Redundant data is useful here as it corroborates other data points, adding fidelity to the reported data.&#x20;
* Processing - The process of making our data useful. This includes some of the following
  * Normalization - Converting all of the data into a similar format to allow easy parsing and manipulation. This should also include any translation, filtering, or editing.
  * Indexing - Organizing and tagging the data so that certain data points and categories so can be easily searched.
  * Enrichment - Adding additional data points to enhance the function of the data, as well as manipulating the presentation of the data for greater usability, such as with data visualization utilities.
* Analysis & Production - Taking in the post-processing data, using it to answer the original question, then subsequently turning it into new data that can be ingested and used by applicable parties.
* Dissemination - Delivering the analysis to relevant stakeholders
* Feedback and Evaluation - Gathering response data about the delivered analysis and evaluating it for potential improvements in content or presentation. This increases the overall effectiveness of the intelligence.

Each of these steps is integral to producing intelligence, but this is not conducted in a linear fashion. Instead some steps are conducted at the same time or you may need to go back and forth between two steps before progressing. An example of this is after you collected and processed all the information you believe is needed to answer stakeholder requirements and you start conducting analysis on the information, you may realize that you need more information or you do not have the information to answer the requirements. Another possibility could be that during the analysis and production phase you should collect feedback from stakeholders through reviews and make adjustments along the way.

## **Resources**

### **Reference and Theory**

* Intelligence Cycle - [https://www.intel.gov/how-the-ic-works#:\~:text=the%20SIX%20STEPS%20in%20the%20INTELLIGENCE%20CYCLE](https://www.intel.gov/how-the-ic-works#:\~:text=the%20SIX%20STEPS%20in%20the%20INTELLIGENCE%20CYCLE)
* Intelligence Cycle Concepts **-** [https://sroberts.io/posts/intelligence-concepts-the-intelligence-cycle/](https://sroberts.io/posts/intelligence-concepts-the-intelligence-cycle/)
* Intelligence F3EAD - [https://sroberts.io/posts/intelligence-concepts-f3ead/](https://sroberts.io/posts/intelligence-concepts-f3ead/)
* [US Intelligence Doctrine](https://www.jcs.mil/Portals/36/Documents/Doctrine/pubs/jp2\_0.pdf) - Great resource for learning the process of intelligence gathering and putting it to use.
* Psychology of Intelligence Analysis- Huer - [https://www.ialeia.org/docs/Psychology\_of\_Intelligence\_Analysis.pdf](https://www.ialeia.org/docs/Psychology\_of\_Intelligence\_Analysis.pdf)
* MITRE ATT\&CK and Threat Intelligence
  * [FIRST CTI Symposium: Turning intelligence into action with MITRE ATT\&CK™](https://www.slideshare.net/KatieNickels/first-cti-symposium-turning-intelligence-into-action-with-mitre-attck)
  * [Getting Started with ATT\&CK: Threat Intelligence](https://medium.com/mitre-attack/getting-started-with-attack-cti-4eb205be4b2f)
  * [Using ATT\&CK to Advance Cyber Threat Intelligence — Part 1](https://medium.com/mitre-attack/using-att-ck-to-advance-cyber-threat-intelligence-part-1-c5ad14d59724)
  * [Using ATT\&CK to Advance Cyber Threat Intelligence — Part 2](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/using-attck-to-advance-cyber-threat-0)
  * [ATT\&CKing the Status Quo: ThreatBased Adversary Emulation with MITRE ATT\&CK™](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536260992.pdf)
* _Intelligence Driven Incident Response - pg. 11_

### Intel Training

* [Katie Nickels's Cyber Threat Intelligence Self Study Plan](https://medium.com/katies-five-cents/a-cyber-threat-intelligence-self-study-plan-part-1-968b5a8daf9a) - Self study plan crafted by the instructor for the SANS Threat Intelligence course. Start here.
* [https://attack.mitre.org/resources/training/cti/](https://attack.mitre.org/resources/training/cti/) - This training by Katie Nickels and Adam Pennington of the ATT\&CK team will help you learn how to apply ATT\&CK and improve your threat intelligence practices.
* [https://academy.attackiq.com/courses/introduction-to-the-easy-framework](https://academy.attackiq.com/courses/introduction-to-the-easy-framework) - Threat intelligence couse focusing on building your own threat intelligence workflow and program.
* [https://www.shadowscape.io/cyber-intelligence-analytics-operat](https://www.shadowscape.io/cyber-intelligence-analytics-operat) - Learn the ins and outs of all stages of the intelligence cycle from collection to analysis from seasoned intel professionals. How to employ threat intelligence to conduct comprehensive defense strategies to mitigate potential compromise. How to use TI to respond to and minimize impact of cyber incidents. How to generate comprehensive and actionable reports to communicate gaps in defenses and intelligence findings to decision makers.

![](<../.gitbook/assets/image (15).png>)

****
