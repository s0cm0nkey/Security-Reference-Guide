# Threat Hunting

## **Intro**

​![](https://gblobscdn.gitbook.com/assets%2F-MQCNQTNhvnXD58Vo8Mf%2F-MS-KB8awA05FAZQytVw%2F-MS-KvDnsqWVg5ExVPRO%2Fimage.png?alt=media\&token=d9850058-0275-4b4c-ab63-92a82092b6d0)​![](https://gblobscdn.gitbook.com/assets%2F-MQCNQTNhvnXD58Vo8Mf%2F-MS-KB8awA05FAZQytVw%2F-MS-Kx3vVxBJowwth4L5%2Fimage.png?alt=media\&token=2e0300fe-81d9-4e51-83cb-7fab2fb2aec7)

Threat hunting doesn’t have to be complex, but it’s not for everyone. Knowing how to begin and end a hunt is more important than knowing how to carry out a hunt**.** If you need a place to start, look at trends in the threat landscape and focus on threats that you do not have automated alerts/detections for. Hunting is a creative process that rewards those who take chances. Finish with something, anything actionable — so long as it provides value.

## Guides and Reference

{% tabs %}
{% tab title="General" %}
* [Threat Hunter Playbook](https://threathunterplaybook.com/introduction.html) - a community-based open source project developed to share threat hunting concepts and aid the development of techniques and hypothesis for hunting campaigns by leveraging security event logs from diverse operating systems.
* [huntpedia.pdf](https://www.threathunting.net/files/huntpedia.pdf)  - Book written by seasoned threat hunters on thier techniques and theory.
* [Open Threat Research Forge](https://github.com/OTRF) - Github repository of Threat Hunting articles, playbooks and tools.
* [Awesome Lists Collection: Awesome Threat Detection](https://github.com/0x4D31/awesome-threat-detection) and Hunting
  * [awesome-threat-detection/hunt-evil.pdf](https://github.com/0x4D31/awesome-threat-detection/blob/master/docs/hunt-evil.pdf)
  * [awesome-threat-detection/The-Hunters-Handbook.pdf](https://github.com/0x4D31/awesome-threat-detection/blob/master/docs/The-Hunters-Handbook.pdf)
* [ACM's Threat Hunting Labs](https://activecm.github.io/threat-hunting-labs/) - These are a series of labs that cover different types of analysis that can be done on network data when threat hunting.
* [A Simple Hunting Maturity Model | Enterprise Detection & Response](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)&#x20;
* [HowToHunt](https://github.com/KathanP19/HowToHunt) - Tutorials and Things to Do while Hunting Vulnerability.&#x20;
* [ThreatHunting Home](https://www.threathunting.net/) - Links and Blog on popular threat hunting proceedures
* [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) - JP-CERT analysis on detecting the use of multiple popular tools within an network environment.
* [https://drive.google.com/file/d/14DluguBRjlUt9GWTUpGIB802qnHD2Olp/view](https://drive.google.com/file/d/14DluguBRjlUt9GWTUpGIB802qnHD2Olp/view) - Introduciton to Threat Hunting part 1
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

* [https://fourcore.io/blogs/threat-hunting-with-windows-event-log-sigma-rules](https://fourcore.io/blogs/threat-hunting-with-windows-event-log-sigma-rules)

</details>

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<details>

<summary>DNS Hunting</summary>

* [SANS@MIC -Threat Hunting via DNS - SANS Institute](https://www.sans.org/webcasts/sansatmic-threat-hunting-dns-114180)&#x20;
* [Alternative DNS Techniques - Active Countermeasures](https://www.activecountermeasures.com/alternative-dns-techniques/)

</details>

<details>

<summary>Cloud Hunting - Azure/O365</summary>

* [![](https://miro.medium.com/1\*m-R\_BkNf1Qjr1YbyOIJY2w.png)Threat Hunting with Microsoft O365 Logs](https://medium.com/@theartofdefense/threat-hunting-with-microsoft-o365-logs-9f64b5fd49e9)
* [![](https://www.youtube.com/s/desktop/2cbeb7d0/img/favicon\_32x32.png)Threat Hunting in the Microsoft Cloud: Times They Are a-Changin' | John Stoner](https://www.youtube.com/watch?v=3fQJT1NXYrA)
* G[itHub - microsoft/Microsoft-365-Defender-Hunting-Queries: Sample queries for Advanced hunting in Microsoft 365 Defender](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
* H[ow Security Center and Log Analytics can be used for Threat Hunting](https://azure.microsoft.com/en-us/blog/ways-to-use-azure-security-center-log-analytics-for-threat-hunting/)
* [GitHub - invictus-ir/Blue-team-app-Office-365-and-Azure](https://github.com/invictus-ir/Blue-team-app-Office-365-and-Azure)
* [Threat Hunting in Azure with AC-Hunter - Active Countermeasures](https://www.activecountermeasures.com/threat-hunting-in-azure-with-ac-hunter/)
* [ThreatHunting/AzureSentinel at master · GossiTheDog/ThreatHunting](https://github.com/GossiTheDog/ThreatHunting/tree/master/AzureSentinel)
* [GitHub - darkquasar/AzureHunter: A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365](https://github.com/darkquasar/AzureHunter)
* [https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-schema-reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-schema-reference)
* [https://expel.io/blog/seven-ways-to-spot-business-email-compromise-office-365/](https://expel.io/blog/seven-ways-to-spot-business-email-compromise-office-365/)

</details>

<details>

<summary>Cloud Hunting - AWS</summary>

* [https://www.splunk.com/en\_us/blog/security/cloudtrail-digital-breadcrumbs-for-aws.html](https://www.splunk.com/en\_us/blog/security/cloudtrail-digital-breadcrumbs-for-aws.html)
* [https://www.splunk.com/en\_us/blog/security/go-with-the-flow-network-telemetry-vpc-data-in-aws.html](https://www.splunk.com/en\_us/blog/security/go-with-the-flow-network-telemetry-vpc-data-in-aws.html)
* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [https://labs.bishopfox.com/tech-blog/5-privesc-attack-vectors-in-aws](https://labs.bishopfox.com/tech-blog/5-privesc-attack-vectors-in-aws)
* [https://www.hunters.ai/blog/hunters-research-detecting-obfuscated-attacker-ip-in-aws](https://www.hunters.ai/blog/hunters-research-detecting-obfuscated-attacker-ip-in-aws)
* [https://pages.awscloud.com/rs/112-TZM-766/images/How-to-Build-a-Threat-Hunting-Capability-in-AWS\_Slides.pdf](https://pages.awscloud.com/rs/112-TZM-766/images/How-to-Build-a-Threat-Hunting-Capability-in-AWS\_Slides.pdf)
* [https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/architecture.html](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/architecture.html)

</details>

## Tools

{% tabs %}
{% tab title="OS/VM " %}
* [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS) - Virtual Machine for Adversary Emulation and Threat Hunting by [RedHunt Labs](https://redhuntlabs.com/)
* [ThreatPursuit-VM](https://github.com/fireeye/ThreatPursuit-VM) - A fully customizable, open-sourced Windows-based distribution focused on threat intelligence analysis and hunting designed for intel and malware analysts as well as threat hunters to get up and running quickly.
{% endtab %}

{% tab title="Hunting Platforms and Toolkits" %}
* [HELK: The Hunting ELK](https://github.com/Cyb3rWard0g/HELK) -  The Hunting ELK or simply the HELK is one of the first open source hunt platforms with advanced analytics capabilities such as SQL declarative language, graphing, structured streaming, and even machine learning via Jupyter notebooks and Apache Spark over an ELK stack.
* [ACM's AI-Hunter ](https://www.activecountermeasures.com/ac-hunter-how-it-works/)- Platform for hunting and detecting malware on your network.
* [ThreatHunter's Toolkit](https://github.com/ethack/tht) - Threat Hunting Toolkit is a Swiss Army knife for threat hunting, log processing, and security-focused data science
  * [https://www.blackhillsinfosec.com/wp-content/uploads/2021/11/SLIDES\_LookingforNeedlesinNeedlestacks.pdf](https://www.blackhillsinfosec.com/wp-content/uploads/2021/11/SLIDES\_LookingforNeedlesinNeedlestacks.pdf)
  * [https://www.youtube.com/watch?v=q7ai6P-cHaQ\&t=2107s](https://www.youtube.com/watch?v=q7ai6P-cHaQ\&t=2107s)


{% endtab %}

{% tab title="DNS" %}
* [freq.py](https://github.com/sans-blue-team/freq.py) - Mark Baggett's tool for detecting randomness using NLP techniques rather than pure entropy calculations. Uses character pair frequency analysis to determine the likelihood of tested strings of characters occurring.&#x20;
* [domain\_stats](https://github.com/MarkBaggett/domain\_stats) - Domain\_stats is a log enhancment utility that is intended help you find threats in your environment. It will identify the following possible threats in your environment.
* [dnstwist](https://github.com/elceef/dnstwist) -  Domain name permutation engine for detecting homograph phishing attacks, typo squatting, and brand impersonation


{% endtab %}

{% tab title="Misc" %}
* [Awesome Lists Collection: Cobalt Strike Defense](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)&#x20;
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)  - a PowerShell Module for Threat Hunting via Windows Event Logs
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - LogonTracer is a tool to investigate malicious logon by visualizing and analyzing Windows Active Directory event logs.
* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity&#x20;
* [PSHunt](https://github.com/Infocyte/PSHunt) - Powershell Threat Hunting Module&#x20;
* [PSRecon](https://github.com/gfoss/PSRecon) -  Gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.&#x20;
* [Mihari ](https://github.com/ninoseki/mihari)-  A framework for continuous OSINT based threat hunting&#x20;
* [Oriana](https://github.com/mvelazc0/Oriana) - A threat hunting tool that leverages a subset of Windows events to build relationships, calculate totals and run analytics. The results are presented in a Web layer to help defenders identify outliers and suspicious behavior on corporate environments.
* [rastrea2r](https://github.com/rastrea2r/rastrea2r) - A multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes.
* [Zircolite](https://github.com/wagga40/Zircolite) - A standalone SIGMA-based detection tool for EVTX.
* [chainsaw](https://github.com/countercept/chainsaw) - Rapidly Search and Hunt through Windows Event Logs
* [https://www.nextron-systems.com/thor-lite/](https://www.nextron-systems.com/thor-lite/) - fast and flexible multi-platform IOC and [YARA](http://virustotal.github.io/yara/) scanner
  * [LOKI](https://github.com/Neo23x0/LOKI) - imple IOC and Incident Response Scanner
  * [https://github.com/Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
  * [https://www.nextron-systems.com/valhalla/](https://www.nextron-systems.com/valhalla/)


{% endtab %}
{% endtabs %}

### **Splunkhunting**

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
* [Detecting dynamic DNS domains in Splunk | Splunk](https://www.splunk.com/en\_us/blog/security/detecting-dynamic-dns-domains-in-splunk.html)&#x20;
* [hunting\_the\_known\_unknowns\_with\_DNS.pdf](https://www.splunk.com/pdfs/events/govsummit/hunting\_the\_known\_unknowns\_with\_DNS.pdf)
* [https://www.deepwatch.com/blog/threat-hunting-in-splunk/](https://www.deepwatch.com/blog/threat-hunting-in-splunk/)
* [SEC1244 - Cops and Robbers: Simulating the Adversary to Test Your Splunk Security Analytics](https://static.rainfocus.com/splunk/splunkconf18/sess/1522696002986001hj1a/finalPDF/Simulating-the-Adversary-Test-1244\_1538791048709001YJnK.pdf)

</details>

{% embed url="https://www.youtube.com/watch?v=ST0cuppJ2nc" %}

## **Hunting Theory**&#x20;

* Types of Hunts - \*\*This will cause some disagreement amongst threat hunting theorists, but this is the common thought process.\*\* There are 3 types of hunts:&#x20;
  * Automated - IoC ingest, should be performed by your SIEM and SOAR&#x20;
  * Continuous - Situational awareness and Behavioral analytics. If these can be turned into alerting searches, all the better. Otherwise these should be scheduled at reasonable intervals.
  * On demand - Looking for specific activity. This typically has a temporal element such as responding to given intelligence.
* &#x20;3 types of Hunt hypothesis&#x20;
  * Threat Intelligence - These are hunts for specific indicators. These are easy low handing fruit, and should be followed by adding the indicators to any alerting mechanisms present.
  * Situational Awareness - These hunts are for looking at normal system and network operations and identifying activity that is outside of normal operations. This can include changes in volume/frequency of events, the methodology of certain activities, or the specific data points associated with certain events.
    * One of the biggest threat hunting skills is not only seeing what data doesnt belong, but also see what data is missing.
  * Domain Expertise - This is one that requires specific knowledge of your local environment. These hunts look for similar items as Situational Awareness, with the added context of looking for oddities in your specific organizations operations. Many of these will be violations of corporate policy or local practice and standards.
* Hunt determinations&#x20;
  * Can this hunt be automated?&#x20;
  * Can this hunt be repeatable?&#x20;
  * Are the indicators in this hunt monitored by other services?&#x20;
  * Are we already hardened against these indicators?&#x20;
* Hunting Strategy questions:&#x20;
  * What are you hunting?
  * Where will you find it?
  * How will you find it?
  * When will you find it?&#x20;
  * _\*_Ask these questions from each point int he Diamond Model
* [a-simple-hunting-maturity-model](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)
* [the-pyramid-of-pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
  * &#x20;_Threat Hunting with Elastic Stack - pg. 29_

## Techniques

### **Repeatable hunts**

These are hunt theories and searches that can and should be performed on the regular.

* [ThreatHuntingProject's Hunts List](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)
* [Windows Commands Abused by Attackers - JPCERT](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html)
* [Cisco Talos Intelligence Group - Comprehensive Threat Intelligence: Hunting for LoLBins](https://blog.talosintelligence.com/2019/11/hunting-for-lolbins.html)&#x20;
* [ThreatHunting.se Hunt Posts](https://www.threathunting.se/detection-rules/)
* [https://github.com/paladin316/ThreatHunting](https://github.com/paladin316/ThreatHunting)

### Long Tail Analysis

&#x20;[https://www.ericconrad.com/2015/01/long-tail-analysis-with-eric-conrad.html](https://www.ericconrad.com/2015/01/long-tail-analysis-with-eric-conrad.html)

### **Crown Jewel Analysis** &#x20;

Preparing for CJA requires organizations to do the following:

* Identify the organization’s core missions.
* Map the mission to the assets and information upon which it relies.&#x20;
* Discover and document the resources on the network.&#x20;
* Construct attack graphs. → Determine dependencies on other systems or information. → Analyze potential attack paths for the assets and their interconnections. → Rate any potential vulnerabilities according to severity.
* This type of analysis allows hunters to prioritize their efforts to protect their most tempting targets by generating hypotheses about the threats that could impact the organization the most.
* Crown Jewel Analysis - _Crafting the Infosec Playbook: pg. 21_

### Misc

* [Finding the Elusive Active Directory Threat Hunting - 2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)&#x20;
* [Quantify Your Hunt: Not Your Parent’s Red Teaming Redux](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536351477.pdf)
* [2019 Threat Detection Report](https://redcanary.com/resources/guides/threat-detection-report/)
* [A Process is No One : Hunting for Token Manipulation](https://specterops.io/assets/resources/A\_Process\_is\_No\_One.pdf)
* [https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/](https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/)
* [https://github.com/schwartz1375/aws](https://github.com/schwartz1375/aws) - Repo for threat hunting in AWS.
