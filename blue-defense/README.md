# Blue - Defensive Operations

Blue teaming forms the foundation of the cybersecurity industry. While offensive security may attract more attention in popular culture, defensive operations are what truly protect organizations and users. Defending is a multi-faceted process that combines hardening your network against attacks, improving visibility into your environment, and detecting attacks as they occur or when they bypass other defenses.
The odds are stacked against defenders. Defenders must successfully protect against thousands of different types of attacks, while attackers only need one successful breach. To develop your defensive cybersecurity skills, you must start as a generalist. Your knowledge must be an inch deep and a mile wide, simply to understand where you need to focus in the future. This begins with foundational certifications and terminology. From there, you will learn more complex concepts and develop specialized expertise.

Remember this key principle: Understanding how to effectively use a security tool is just as important as understanding the theory behind it. A SIEM is useless if you don't know how to perform a query.

This section contains comprehensive tools and references for defensive operations. Experiment with the tools, practice in the labs, and always read the documentation.

For those looking to advance their certifications and progress in their careers, consult the [Security Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/) to plan your next steps.

## **Blue Team Resources**

* [Awesome Lists Collection: Security Blue Team](https://github.com/fabacab/awesome-cybersecurity-blueteam) - A curated collection of resources, tools, and references for cybersecurity blue teams.
* [Awesome Lists Collection: Security](https://github.com/sbilly/awesome-security) - A collection of security software, libraries, documents, books, and resources.
* [Awesome Lists Collection: Industrial Control Systems Security](https://github.com/hslatman/awesome-industrial-control-system-security) - A curated list of resources related to Industrial Control System (ICS) security.
* [NIST Cybersecurity Framework (CSF 2.0)](https://www.nist.gov/cyberframework) - Voluntary guidance based on existing standards, guidelines, and practices for organizations to better manage and reduce cybersecurity risk. An excellent starting point when building a security program from the ground up.
  * [NIST-to-Tech](https://github.com/mikeprivette/NIST-to-Tech) - An open-source listing of cybersecurity technology mapped to the NIST Cybersecurity Framework (CSF)
  * [NIST SP 800-37 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final) - Risk Management Framework for Information Systems and Organizations
  * [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and Privacy Controls for Information Systems and Organizations
* [SANS Blue Team Operations](https://wiki.sans.blue/#!index.md) - SANS Blue Team wiki built by the instructors of the SANS defensive courses.
* [ISECOM](https://www.isecom.org/) - The Institute for Security and Open Methodologies (ISECOM) is an open, security research community providing original resources, tools, and certifications in the field of security.
* [MITRE ATT&CK Framework](https://attack.mitre.org/) - Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Essential for threat-informed defense.
  * [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Web-based tool for annotating and exploring ATT&CK matrices.
  * [ATT&CK for ICS](https://attack.mitre.org/ics/) - Knowledge base tailored to Industrial Control Systems.
* [MITRE D3FEND](https://d3fend.mitre.org/) - Knowledge graph of cybersecurity countermeasures, providing a complementary defensive perspective to ATT&CK.
* [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/news/features/history/cyber-kill-chain.html) - Framework for understanding the stages of a cyber attack developed by Lockheed Martin.
* [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf) - Framework for analyzing cyber intrusions by exploring the relationships between adversary, capability, infrastructure, and victim.
* [Sigma Rules](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems, allowing sharing of detection rules across different platforms.
* [Detection Engineering Resources](https://github.com/infosecB/awesome-detection-engineering) - Curated list of resources for building and improving detection capabilities.
* [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) - Computer Security Incident Handling Guide providing incident response best practices.
* [SANS Incident Response Process](https://www.sans.org/posters/incident-response-cycle/) - Six-phase incident response methodology (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned).
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) - Consensus-based configuration guidelines for securely configuring systems and software.
* [OWASP](https://owasp.org/) - Open Web Application Security Project providing free resources, tools, and standards for web application security.
  * [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Standard awareness document representing critical security risks to web applications.
* [CIS Controls (v8)](https://www.cisecurity.org/controls/cis-controls-list/) - Currently 18 prioritized safeguards to protect organizations from cyber threats. An excellent starting point for improving your security program.
  * [CIS Controls Guide](https://www.cisecurity.org/controls/v8) - Official guide to the current version of CIS Controls.
* [Detection Maturity Model](https://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html) - Guide for assessing the maturity levels and development stages of a security program.
* [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) - Framework showing the relationship between types of indicators and their effectiveness in detecting and preventing attacks.
* [Security Metrics](https://www.nist.gov/system/files/documents/2016/09/16/mandiant_rfi_response.pdf) by Mandiant - Comprehensive guide to measuring security program effectiveness.
* [10 Strategies of a World-Class SOC](https://www.mitre.org/news-insights/publication/10-strategies-world-class-cybersecurity-operations-center) - MITRE's guide to building and operating an effective Security Operations Center.

## **Training and Resources**

**For comprehensive resources including courses, books, CTFs, and more, please check out the Training and Resources section of this guide.**

* [TryHackMe: Security Operations and Monitoring](https://tryhackme.com/module/security-operations-and-monitoring)
* [TryHackMe: Blue Team Learning Path](https://tryhackme.com/path/outline/blueteam)

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

{% content-ref url="threat-hunting.md" %}
[threat-hunting.md](threat-hunting.md)
{% endcontent-ref %}

{% content-ref url="active-defense.md" %}
[active-defense.md](active-defense.md)
{% endcontent-ref %}

{% content-ref url="device-hardening/" %}
[device-hardening](device-hardening/)
{% endcontent-ref %}

{% content-ref url="vulnerability-management.md" %}
[vulnerability-management.md](vulnerability-management.md)
{% endcontent-ref %}

{% content-ref url="blue-toolbox.md" %}
[blue-toolbox.md](blue-toolbox.md)
{% endcontent-ref %}
