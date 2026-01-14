# Blue - Defensive Operations

Blue teaming forms the foundation of the cybersecurity industry. While offensive security often attracts more attention in popular culture, defensive operations are what truly protect organizations and users from real-world threats. Defending is a multi-faceted discipline that combines network hardening, environmental visibility, and attack detection—both in real-time and when threats bypass initial defenses.

The odds are inherently stacked against defenders. A defender must successfully protect against thousands of attack vectors, while an attacker needs only one successful breach. To develop effective defensive cybersecurity skills, you must begin as a generalist with broad foundational knowledge—an inch deep and a mile wide—to understand where to focus your efforts as you progress. This journey starts with foundational certifications and core terminology, then advances to more complex concepts and specialized expertise.

**Remember this key principle:** Understanding how to effectively use a security tool is just as critical as understanding the theory behind it. A SIEM is useless if you cannot perform effective queries.

This section contains comprehensive tools and references for defensive operations. Experiment with the tools, practice in lab environments, and always consult the documentation to deepen your understanding.

**Career Development:** For those looking to advance their certifications and progress in their careers, consult the [Security Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/) to plan your professional development path.

## **Blue Team Resources**

* [Awesome Lists Collection: Security Blue Team](https://github.com/fabacab/awesome-cybersecurity-blueteam) - A curated collection of resources, tools, and references for cybersecurity blue teams.
* [Awesome Lists Collection: Security](https://github.com/sbilly/awesome-security) - A collection of security software, libraries, documents, books, and resources.
* [Awesome Lists Collection: Industrial Control Systems Security](https://github.com/hslatman/awesome-industrial-control-system-security) - A curated list of resources related to Industrial Control System (ICS) security.
* [NIST Cybersecurity Framework (CSF 2.0)](https://www.nist.gov/cyberframework) - Voluntary guidance based on existing standards, guidelines, and practices for organizations to better manage and reduce cybersecurity risk. An excellent starting point for building a security program from the ground up.
  * [NIST-to-Tech](https://github.com/mikeprivette/NIST-to-Tech) - Open-source mapping of cybersecurity technologies to the NIST Cybersecurity Framework (CSF)
  * [NIST SP 800-37 Rev. 2](https://csrc.nist.gov/pubs/sp/800/37/r2/final) - Risk Management Framework for Information Systems and Organizations: A System Life Cycle Approach for Security and Privacy
  * [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls for Information Systems and Organizations: Comprehensive catalog of security and privacy controls
* [SANS Blue Team Operations](https://wiki.sans.blue/#!index.md) - Comprehensive blue team wiki created and maintained by SANS defensive course instructors.
* [ISECOM](https://www.isecom.org/) - The Institute for Security and Open Methodologies (ISECOM) is an open security research community providing original resources, tools, and certifications in the security field.
* [MITRE ATT&CK Framework](https://attack.mitre.org/) - Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Essential framework for threat-informed defense and detection engineering.
  * [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Web-based tool for annotating and exploring ATT&CK matrices, useful for mapping coverage and planning defense strategies.
  * [ATT&CK for ICS](https://attack.mitre.org/ics/) - Knowledge base tailored specifically for Industrial Control System (ICS) environments.
* [MITRE D3FEND](https://d3fend.mitre.org/) - Knowledge graph of cybersecurity countermeasures, providing a complementary defensive perspective to ATT&CK.
* [MITRE CAR](https://car.mitre.org/) - Cyber Analytics Repository: Collection of detection analytics mapped to ATT&CK, providing implementable detection pseudocode and test data. Note: Project has limited recent updates but remains a valuable reference.
* [MITRE Engage](https://engage.mitre.org/) - Framework for planning and discussing adversary engagement operations, including deception and denial activities.
* [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/news/features/history/cyber-kill-chain.html) - Framework for understanding the stages of a cyber attack developed by Lockheed Martin.
* [Diamond Model of Intrusion Analysis](https://apps.dtic.mil/sti/citations/ADA586960) - Framework for analyzing cyber intrusions by exploring the relationships between adversary, capability, infrastructure, and victim.
* [Unified Kill Chain](https://www.unifiedkillchain.com/) - Modern kill chain model that combines Cyber Kill Chain, MITRE ATT&CK, and other frameworks into a comprehensive attack lifecycle.
* [Sigma Rules](https://github.com/SigmaHQ/sigma) - Generic and open signature format for SIEM systems, enabling platform-agnostic sharing and deployment of detection rules across different security tools.
* [YARA Rules](https://virustotal.github.io/yara/) - Pattern matching tool for malware research and detection, used to identify and classify malware samples based on textual or binary patterns.
* [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Library of simple, automatable tests mapped to MITRE ATT&CK for validating security controls and detection capabilities.
* [Detection Engineering Resources](https://github.com/infosecB/awesome-detection-engineering) - Curated collection of resources for building, testing, and improving detection capabilities and engineering practices.
* [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final) - Computer Security Incident Handling Guide: Comprehensive best practices for establishing and executing incident response capabilities. (Rev. 3 in draft as of 2024)
* [SANS Incident Response Process](https://www.sans.org/posters/incident-response-cycle/) - Six-phase incident response methodology: Preparation, Identification, Containment, Eradication, Recovery, and Lessons Learned.
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) - Consensus-based configuration guidelines for securely configuring systems and software.
* [OWASP](https://owasp.org/) - Open Web Application Security Project providing free resources, tools, and standards for web application security.
  * [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Standard awareness document representing critical security risks to web applications.
* [CIS Controls (v8)](https://www.cisecurity.org/controls/cis-controls-list/) - Set of 18 prioritized safeguards designed to protect organizations from the most common cyber threats. An excellent starting point for implementing or improving your security program. Currently at version 8.1.
  * [CIS Controls Guide](https://www.cisecurity.org/controls/) - Official implementation guide and resources for the CIS Controls.
* [Detection Maturity Model](https://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html) - Framework for assessing and advancing the maturity levels of detection capabilities within a security program.
* [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) - Framework illustrating the relationship between different types of indicators of compromise (IoCs) and the difficulty they create for adversaries when detected and blocked.
* [10 Strategies of a World-Class SOC](https://www.mitre.org/news-insights/publication/10-strategies-world-class-cybersecurity-operations-center) - MITRE's strategic guide to building, maturing, and operating an effective Security Operations Center.
* [CISA Cybersecurity Resources](https://www.cisa.gov/cybersecurity) - U.S. Cybersecurity and Infrastructure Security Agency's collection of alerts, advisories, and best practices for defending critical infrastructure.
  * [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Authoritative list of vulnerabilities actively exploited in the wild, essential for prioritizing patching efforts.
* [FIRST.org](https://www.first.org/) - Forum of Incident Response and Security Teams: Global organization providing resources, best practices, and collaboration for incident response teams.
* [SANS Reading Room](https://www.sans.org/white-papers/) - Extensive collection of free, peer-reviewed cybersecurity whitepapers covering defensive techniques, tools, and methodologies.
* [Security Onion](https://securityonionsolutions.com/) - Free and open-source Linux distribution for threat hunting, enterprise security monitoring, and log management, bundling multiple defensive tools.
* [Malware Bazaar](https://bazaar.abuse.ch/) - Project from abuse.ch providing malware samples for research and testing detection capabilities.
* [AlienVault OTX](https://otx.alienvault.com/) - Open Threat Exchange: Community-driven threat intelligence platform (now part of AT&T Cybersecurity) for sharing and accessing indicators of compromise and threat data.

## **Training and Resources**

**For comprehensive resources including courses, books, capture-the-flag (CTF) competitions, and more, please refer to the Training and Resources section of this guide.**

### Hands-On Practice Platforms

* [TryHackMe: Security Operations and Monitoring](https://tryhackme.com/r/path/outline/security-operations-monitoring) - Practical module covering SOC fundamentals and monitoring techniques
* [TryHackMe: Blue Team Learning Path](https://tryhackme.com/r/path/outline/blueteam) - Comprehensive learning path covering defensive security concepts and tools
* [CyberDefenders](https://cyberdefenders.org/) - Blue team CTF platform with hands-on challenges focused on incident response, digital forensics, and threat hunting
* [Blue Team Labs Online](https://blueteamlabs.online/) - Practical, scenario-based training platform for security operations, incident response, and digital forensics
* [LetsDefend](https://letsdefend.io/) - Real-world SOC simulation platform with alerts, artifacts, and SIEM interfaces for practicing incident response
* [Boss of the SOC (BOTS)](https://github.com/splunk/security-content) - Splunk's CTF competition datasets available through their security content repository, excellent for practicing with Splunk and real-world security scenarios

{% content-ref url="../training/" %}
[training](../training/)
{% endcontent-ref %}

## Contents

{% content-ref url="terminology-and-mapping.md" %}
[terminology-and-mapping.md](terminology-and-mapping.md)
{% endcontent-ref %}

{% content-ref url="query-languages.md" %}
[query-languages.md](query-languages.md)
{% endcontent-ref %}

{% content-ref url="event-and-log-analysis.md" %}
[event-and-log-analysis.md](event-and-log-analysis.md)
{% endcontent-ref %}

{% content-ref url="event-detection/" %}
[event-detection](event-detection/)
{% endcontent-ref %}

{% content-ref url="packet-analysis.md" %}
[packet-analysis.md](packet-analysis.md)
{% endcontent-ref %}

{% content-ref url="stegonography.md" %}
[stegonography.md](stegonography.md)
{% endcontent-ref %}

{% content-ref url="threat-hunting.md" %}
[threat-hunting.md](threat-hunting.md)
{% endcontent-ref %}

{% content-ref url="active-defense.md" %}
[active-defense.md](active-defense.md)
{% endcontent-ref %}

{% content-ref url="device-hardening/" %}
[device-hardening](device-hardening/)
{% endcontent-ref %}

{% content-ref url="vulnerability-management..md" %}
[vulnerability-management..md](vulnerability-management..md)
{% endcontent-ref %}

{% content-ref url="blue-toolbox.md" %}
[blue-toolbox.md](blue-toolbox.md)
{% endcontent-ref %}
