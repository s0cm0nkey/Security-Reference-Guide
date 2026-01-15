# Threat Hunting

## **Intro**

![](https://gblobscdn.gitbook.com/assets%2F-MQCNQTNhvnXD58Vo8Mf%2F-MS-KB8awA05FAZQytVw%2F-MS-KvDnsqWVg5ExVPRO%2Fimage.png?alt=media\&token=d9850058-0275-4b4c-ab63-92a82092b6d0)![](https://gblobscdn.gitbook.com/assets%2F-MQCNQTNhvnXD58Vo8Mf%2F-MS-KB8awA05FAZQytVw%2F-MS-Kx3vVxBJowwth4L5%2Fimage.png?alt=media\&token=2e0300fe-81d9-4e51-83cb-7fab2fb2aec7)

Threat hunting doesn’t have to be complex, but it isn't for everyone. Knowing how to begin and end a hunt is more important than knowing how to carry out a hunt. If you need a place to start, look at trends in the threat landscape and focus on threats that you do not have automated alerts/detections for. Hunting is a creative process that rewards those who take chances. Finish with something — anything actionable — so long as it provides value.

## Guides and Reference

{% tabs %}
{% tab title="General" %}
* [Threat Hunter Playbook](https://threathunterplaybook.com/introduction.html) - a community-based open source project developed to share threat hunting concepts and aid the development of techniques and hypothesis for hunting campaigns by leveraging security event logs from diverse operating systems.
* [huntpedia.pdf](https://www.threathunting.net/files/huntpedia.pdf)  - Book written by seasoned threat hunters on their techniques and theory.
* [Open Threat Research Forge](https://github.com/OTRF) - Github repository of Threat Hunting articles, playbooks and tools.
* [Sigma HQ](https://github.com/SigmaHQ/sigma) - Generic Signature Format for SIEM Systems.
* [Awesome Lists Collection: Awesome Threat Detection](https://github.com/0x4D31/awesome-threat-detection) and Hunting
  * [awesome-threat-detection/hunt-evil.pdf](https://github.com/0x4D31/awesome-threat-detection/blob/master/docs/hunt-evil.pdf)
  * [awesome-threat-detection/The-Hunters-Handbook.pdf](https://github.com/0x4D31/awesome-threat-detection/blob/master/docs/The-Hunters-Handbook.pdf)
* [ACM's Threat Hunting Labs](https://activecm.github.io/threat-hunting-labs/) - These are a series of labs that cover different types of analysis that can be done on network data when threat hunting.
* [A Simple Hunting Maturity Model | Enterprise Detection & Response](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)&#x20;
* [HowToHunt](https://github.com/KathanP19/HowToHunt) - Tutorials and Things to Do while Hunting Vulnerability.&#x20;
* [ThreatHunting Home](https://www.threathunting.net/) - Links and Blog on popular threat hunting procedures
* [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) - JP-CERT analysis on detecting the use of multiple popular tools within a network environment.
* [Microsoft's Threat Hunting Survival Guide](https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE5aC6y?culture=en-us\&country=US)
* [Introduction to Threat Hunting part 1](https://drive.google.com/file/d/14DluguBRjlUt9GWTUpGIB802qnHD2Olp/view)
{% endtab %}

{% tab title="Hunting with MITRE ATTACK" %}
* [MITRE ATT\&CKcon 2018: Hunters ATT\&CKing with the Data, Roberto Rodriguez, SpecterOps and Jose Luis Rodriguez, Student](https://www.slideshare.net/attackcon2018/mitre-attckcon-2018-hunters-attcking-with-the-data-robert-rodriguez-specterops-and-jose-luis-rodriguez-student)
* [Testing the Top MITRE ATT\&CK Techniques: PowerShell, Scripting, Regsvr32](https://redcanary.com/blog/testing-the-top-mitre-attck-techniques-powershell-scripting-regsvr32/)
* [Ten Ways Zeek Can Help You Detect the TTPs of MITRE ATT\&CK](https://m.youtube.com/watch?v=DfTbSc\_q2F8)
* [Post-Exploitation Hunting with ATT\&CK & Elastic](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1533071345.pdf)
* [How MITRE ATT\&CK helps security operations](https://www.slideshare.net/votadlos/how-mitre-attck-helps-security-operations)
* [MITRE Cyber Analytics Repository](https://car.mitre.org/)
* [MITRE ATT\&CK Windows Logging Cheat Sheets](https://github.com/MalwareArchaeology/ATTACK)
* [Defensive Gap Assessment with MITRE ATT\&CK](https://www.cybereason.com/blog/defensive-gap-assessment-with-mitre-attck)
* [Prioritizing the Remediation of Mitre ATT\&CK Framework Gaps](https://blog.netspi.com/prioritizing-the-remediation-of-mitre-attck-framework-gaps/)
* [Finding Related ATT\&CK Techniques](https://medium.com/mitre-attack/finding-related-att-ck-techniques-f1a4e8dfe2b6)
* [Getting Started with ATT\&CK: Detection and Analytics](https://medium.com/mitre-attack/getting-started-with-attack-detection-a8e49e4960d0)
* [Mapping your Blue Team to MITRE ATT\&CK™](https://www.siriussecurity.nl/blog/2019/5/8/mapping-your-blue-team-to-mitre-attack)
{% endtab %}
{% endtabs %}

<details>

<summary>Hunting in Windows Events</summary>

* [Threat Hunting with Windows Event Log Sigma Rules](https://fourcore.io/blogs/threat-hunting-with-windows-event-log-sigma-rules)

</details>

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<details>

<summary>DNS Hunting</summary>

* [SANS@MIC -Threat Hunting via DNS - SANS Institute](https://www.sans.org/webcasts/sansatmic-threat-hunting-dns-114180)&#x20;
* [Alternative DNS Techniques - Active Countermeasures](https://www.activecountermeasures.com/alternative-dns-techniques/)

</details>

<details>

<summary>Cloud Hunting - Azure/O365</summary>

* [Threat Hunting with Microsoft O365 Logs](https://medium.com/@theartofdefense/threat-hunting-with-microsoft-o365-logs-9f64b5fd49e9)
* [Threat Hunting in the Microsoft Cloud: Times They Are a-Changin' | John Stoner](https://www.youtube.com/watch?v=3fQJT1NXYrA)
* [GitHub - microsoft/Microsoft-365-Defender-Hunting-Queries: Sample queries for Advanced hunting in Microsoft 365 Defender](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
* [How Security Center (Microsoft Defender for Cloud) and Log Analytics can be used for Threat Hunting](https://azure.microsoft.com/en-us/blog/ways-to-use-azure-security-center-log-analytics-for-threat-hunting/)
* [GitHub - invictus-ir/Blue-team-app-Office-365-and-Azure](https://github.com/invictus-ir/Blue-team-app-Office-365-and-Azure)
* [Threat Hunting in Azure with AC-Hunter - Active Countermeasures](https://www.activecountermeasures.com/threat-hunting-in-azure-with-ac-hunter/)
* [ThreatHunting/Microsoft Sentinel (formerly Azure Sentinel) at master · GossiTheDog/ThreatHunting](https://github.com/GossiTheDog/ThreatHunting/tree/master/AzureSentinel)
* [GitHub - darkquasar/AzureHunter: A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365](https://github.com/darkquasar/AzureHunter)
* [Microsoft 365 Defender Hunting Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
* [Microsoft Defender for Endpoint (formerly ATP) Advanced Hunting Schema Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-schema-reference)
* [Seven ways to spot business email compromise Office 365](https://expel.io/blog/seven-ways-to-spot-business-email-compromise-office-365/)
* [Hunting Queries Detection Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)

</details>

<details>

<summary>Cloud Hunting - AWS</summary>

* [CloudTrail: Digital Breadcrumbs for AWS](https://www.splunk.com/en_us/blog/security/cloudtrail-digital-breadcrumbs-for-aws.html)
* [Go With the Flow: Network Telemetry & VPC Data in AWS](https://www.splunk.com/en_us/blog/security/go-with-the-flow-network-telemetry-vpc-data-in-aws.html)
* [Privilege Escalation in AWS](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [5 Privilege Escalation Attack Vectors in AWS](https://labs.bishopfox.com/tech-blog/5-privesc-attack-vectors-in-aws)
* [Detecting Obfuscated Attacker IP in AWS](https://www.hunters.ai/blog/hunters-research-detecting-obfuscated-attacker-ip-in-aws)
* [How to Build a Threat Hunting Capability in AWS (PDF)](https://pages.awscloud.com/rs/112-TZM-766/images/How-to-Build-a-Threat-Hunting-Capability-in-AWS_Slides.pdf)
* [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/architecture.html)

</details>

## Tools

{% tabs %}
{% tab title="OS/VM " %}
* [Commando VM](https://github.com/mandiant/commando-vm) - Complete Mandiant Offensive VM (Commando VM), a fully customizable Windows-based security distribution for penetration testing and red teaming.
* [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS) - Virtual Machine for Adversary Emulation and Threat Hunting by [RedHunt Labs](https://redhuntlabs.com/)
{% endtab %}

{% tab title="Legacy/Archived" %}
* [ThreatPursuit-VM](https://github.com/fireeye/ThreatPursuit-VM) - A fully customizable, open-sourced Windows-based distribution focused on threat intelligence analysis and hunting designed for intel and malware analysts as well as threat hunters to get up and running quickly. (Archived/No longer updated)
* [HELK: The Hunting ELK](https://github.com/Cyb3rWard0g/HELK) -  The Hunting ELK or simply the HELK is one of the first open source hunt platforms with advanced analytics capabilities such as SQL declarative language, graphing, structured streaming, and even machine learning via Jupyter notebooks and Apache Spark over an ELK stack.
* [ACM's AI-Hunter ](https://www.activecountermeasures.com/ac-hunter-how-it-works/)- Platform for hunting and detecting malware on your network.
* [ThreatHunter's Toolkit](https://github.com/ethack/tht) - Threat Hunting Toolkit is a Swiss Army knife for threat hunting, log processing, and security-focused data science
  * [Looking for Needles in Needlestacks (PDF)](https://www.blackhillsinfosec.com/wp-content/uploads/2021/11/SLIDES_LookingforNeedlesinNeedlestacks.pdf)
  * [Threat Hunting Presentation (Video)](https://www.youtube.com/watch?v=q7ai6P-cHaQ\&t=2107s)


{% endtab %}

{% tab title="DNS" %}
* [freq.py](https://github.com/sans-blue-team/freq.py) - Mark Baggett's tool for detecting randomness using NLP techniques rather than pure entropy calculations. Uses character pair frequency analysis to determine the likelihood of tested strings of characters occurring.&#x20;
* [domain\_stats](https://github.com/MarkBaggett/domain\_stats) - Domain\_stats is a log enhancement utility that is intended to help you find threats in your environment. It will identify the following possible threats in your environment.
* [dnstwist](https://github.com/elceef/dnstwist) -  Domain name permutation engine for detecting homograph phishing attacks, typo squatting, and brand impersonation


{% endtab %}

{% tab title="Misc" %}
* [Awesome Lists Collection: Cobalt Strike Defense](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)  - a PowerShell Module for Threat Hunting via Windows Event Logs
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - LogonTracer is a tool to investigate malicious logon by visualizing and analyzing Windows Active Directory event logs.
* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity
* [CyberChef](https://gchq.github.io/CyberChef/) - The "Cyber Swiss Army Knife" - a web app for encryption, encoding, compression and data analysis.
* [Mihari ](https://github.com/ninoseki/mihari)-  A framework for continuous OSINT based threat hunting
* [Oriana](https://github.com/mvelazc0/Oriana) - A threat hunting tool that leverages a subset of Windows events to build relationships, calculate totals and run analytics. The results are presented in a Web layer to help defenders identify outliers and suspicious behavior on corporate environments.
* [Zircolite](https://github.com/wagga40/Zircolite) - A standalone SIGMA-based detection tool for EVTX.
* [chainsaw](https://github.com/WithSecureLabs/chainsaw) - Rapidly Search and Hunt through Windows Event Logs
* [THOR Lite](https://www.nextron-systems.com/thor-lite/) - fast and flexible multi-platform IOC and [YARA](http://virustotal.github.io/yara/) scanner
  * [LOKI](https://github.com/Neo23x0/LOKI) - Simple IOC and Incident Response Scanner
  * [Signature Base](https://github.com/Neo23x0/signature-base)
  * [Valhalla](https://www.nextron-systems.com/valhalla/)


{% endtab %}

{% tab title="Legacy/Archived" %}
* [PSHunt](https://github.com/Infocyte/PSHunt) - Powershell Threat Hunting Module (Last update: 2016)
* [PSRecon](https://github.com/gfoss/PSRecon) -  Gathers data from a remote Windows host using PowerShell (v2 or later). (Last update: 2014)
* [rastrea2r](https://github.com/rastrea2r/rastrea2r) - A multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes. (Last update: 2016)
{% endtab %}
{% endtabs %}

### **Splunk Hunting**

<details>

<summary>Splunk Apps</summary>

* [ThreatHunting | Splunkbase](https://splunkbase.splunk.com/app/4305/)&#x20;
* [URL Toolbox | Splunkbase](https://splunkbase.splunk.com/app/2734/)&#x20;
* [URLParser | Splunkbase](https://splunkbase.splunk.com/app/3396/)&#x20;
* [Splunk Security Essentials | Splunkbase](https://splunkbase.splunk.com/app/3435/)&#x20;
* [SA-Investigator for Enterprise Security | Splunkbase](https://splunkbase.splunk.com/app/3749/)&#x20;
* [DFUR-Splunk-App](https://github.com/fireeye/DFUR-Splunk-App) -  The "DFUR" Splunk application and data that was presented at the 2020 SANS DFIR Summit.&#x20;
* [CyberMenace](https://github.com/PM0ney/CyberMenace) - A one stop shop hunting app in Splunk that can ingest Zeek, Suricata, Sysmon, and Windows event data to find malicious indicators of compromise relating to the MITRE ATT\&CK Matrix.



</details>

<details>

<summary>Splunk Hunting Resources</summary>

* [Hunting with Splunk: The Basics](https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html)&#x20;
* [ATT\&CKized Splunk - Threat Hunting with MITRE’s ATT\&CK using SplunkSecurity Affairs](https://securityaffairs.co/wordpress/81288/security/hunting-mitres-attck-splunk.html)&#x20;
* [Detecting malware beacons using Splunk | geekery](https://pleasefeedthegeek.wordpress.com/2012/12/20/detecting-malware-beacons-using-splunk/)&#x20;
* [red|blue: Automating APT Scanning with Loki Scanner and Splunk](https://www.redblue.team/2017/04/automating-apt-scanning-with-loki.html?m=1)&#x20;
* [Detecting dynamic DNS domains in Splunk | Splunk](https://www.splunk.com/en_us/blog/security/detecting-dynamic-dns-domains-in-splunk.html)&#x20;
* [Hunting The Known Unknowns with DNS (PDF)](https://www.splunk.com/pdfs/events/govsummit/hunting_the_known_unknowns_with_DNS.pdf)
* [Threat Hunting in Splunk](https://www.deepwatch.com/blog/threat-hunting-in-splunk/)
* [Cops and Robbers: Simulating the Adversary to Test Your Splunk Security Analytics (PDF)](https://static.rainfocus.com/splunk/splunkconf18/sess/1522696002986001hj1a/finalPDF/Simulating-the-Adversary-Test-1244_1538791048709001YJnK.pdf)

</details>

{% embed url="https://www.youtube.com/watch?v=ST0cuppJ2nc" %}

## **Hunting Theory**&#x20;

* **Types of Hunts** - This will cause some disagreement amongst threat hunting theorists, but this is the common thought process. There are 3 types of hunts:
  * Automated - IoC ingest, should be performed by your SIEM and SOAR.
  * Continuous - Situational awareness and Behavioral analytics. If these can be turned into alerting searches, all the better. Otherwise these should be scheduled at reasonable intervals.
  * On demand - Looking for specific activity. This typically has a temporal element such as responding to given intelligence.
* **3 Types of Hunt Hypotheses**
  * Threat Intelligence - These are hunts for specific indicators. These are easy low hanging fruit, and should be followed by adding the indicators to any alerting mechanisms present.
    * **Note on Indicators:** It is crucial to distinguish between an **Indicator of Compromise (IoC)**, which is reactive (e.g., a hash or IP), and an **Indicator of Attack (IoA)**, which focuses on the intent and behavior of the attacker (e.g., code execution method).
  * Situational Awareness - These hunts are for looking at normal system and network operations and identifying activity that is outside of normal operations. This can include changes in volume/frequency of events, the methodology of certain activities, or the specific data points associated with certain events.
    * One of the biggest threat hunting skills is not only seeing what data doesn't belong, but also see what data is missing.
  * Domain Expertise - This is one that requires specific knowledge of your local environment. These hunts look for similar items as Situational Awareness, with the added context of looking for oddities in your specific organizations operations. Many of these will be violations of corporate policy or local practice and standards.
* **Hunt Determinations**
  * Can this hunt be automated?
  * Can this hunt be repeatable?
  * Are the indicators in this hunt monitored by other services?
  * Are we already hardened against these indicators?
* **Hunting Strategy questions:**
  * What are you hunting?
  * Where will you find it?
  * How will you find it?
  * When will you find it?
  * \*Ask these questions from each point in the [Diamond Model](http://www.activecampaign.com/media/diamond_model_intrusion_analysis.pdf). 
* [A simple hunting maturity model](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)
* [The Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
  * _Threat Hunting with Elastic Stack - pg. 29_

## Techniques

### **Repeatable hunts**

These are hunt theories and searches that can and should be performed on the regular.

* [ThreatHuntingProject's Hunts List](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)
* [Windows Commands Abused by Attackers - JPCERT](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html)
* [Cisco Talos Intelligence Group - Comprehensive Threat Intelligence: Hunting for LoLBins](https://blog.talosintelligence.com/2019/11/hunting-for-lolbins.html)&#x20;
* [ThreatHunting.se Hunt Posts](https://www.threathunting.se/detection-rules/)
* [ThreatHunting Repo](https://github.com/paladin316/ThreatHunting)

### **Stacking (Frequency Analysis)**

Stacking is a technique used to identify anomalies by counting the frequency of occurrences of specific data points. By stacking values such as process names, parent-child process relationships, or domain names, hunters can identify outliers—items that appear infrequently (the "long tail") or frequently but in unexpected contexts.

### Long Tail Analysis

* [Long Tail Analysis with Eric Conrad](https://www.ericconrad.com/2015/01/long-tail-analysis-with-eric-conrad.html)

### **Crown Jewel Analysis** &#x20;

Preparing for CJA requires organizations to do the following:

* Identify the organization’s core missions.
* Map the mission to the assets and information upon which it relies.&#x20;
* Discover and document the resources on the network.&#x20;
* Construct attack graphs.
  * Determine dependencies on other systems or information.
  * Analyze potential attack paths for the assets and their interconnections.
  * Rate any potential vulnerabilities according to severity.
* This type of analysis allows hunters to prioritize their efforts to protect their most tempting targets by generating hypotheses about the threats that could impact the organization the most.
* Crown Jewel Analysis - _Crafting the Infosec Playbook: pg. 21_

### Misc

* [Finding the Elusive Active Directory Threat Hunting (PDF)](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)&#x20;
* [Quantify Your Hunt: Not Your Parent’s Red Teaming Redux](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536351477.pdf)
* [2019 Threat Detection Report](https://redcanary.com/resources/guides/threat-detection-report/)
* [A Process is No One : Hunting for Token Manipulation](https://specterops.io/assets/resources/A_Process_is_No_One.pdf)
* [Linux Threat Hunting for Persistence with Sysmon, Auditd, and Webshells](https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/)
* [AWS Threat Hunting Repo](https://github.com/schwartz1375/aws) - Repo for threat hunting in AWS.
