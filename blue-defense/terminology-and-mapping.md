# Standards, Frameworks, and Benchmarks

### [MITRE ATT\&CK™](https://attack.mitre.org/)&#x20;

With over a dozen tactics and hundreds of techniques, MITRE ATT\&CK has become the de facto standard for event mapping. It can be used defensively to map attacks against your network and to map your current visibility coverage, helping identify areas for growth.

* [MITRE ATT\&CK Resources](https://attack.mitre.org/resources/) - Official resources including presentations, papers, and tools.
* [Awesome Threat Detection](https://github.com/0x4D31/awesome-threat-detection) - A curated list of resources and tools for threat detection and hunting, with extensive MITRE ATT\&CK coverage.
* [Mitre Groups](https://attack.mitre.org/groups/) - A repository documenting known techniques performed by threat actor groups.
* [ATT\&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - A web-based tool for annotating and exploring ATT\&CK matrices. It can be used to visualize defensive coverage, red/blue team planning, the frequency of detected techniques, and more.
* [C.A.R. Cyber Analytics Repository](https://car.mitre.org/) - A knowledge base of analytics developed by [MITRE](https://www.mitre.org), based on the [MITRE ATT\&CK](https://attack.mitre.org/) adversary model.
* [Malware Archaeology Windows Logging Cheat Sheets](https://github.com/MalwareArchaeology/ATTACK) - The gold standard for mapping Windows Event Logs to MITRE ATT\&CK techniques.
* [Caldera](https://github.com/mitre/caldera) - A scalable Automated Adversary Emulation Platform built around MITRE techniques.
* [ATT\&CK® EVALUATIONS](https://attackevals.mitre-engenuity.org/) - Evaluations of security tools based on MITRE technique coverage.
* [ATT\&CK Flow](https://github.com/center-for-threat-informed-defense/attack-flow) - Helps executives, SOC managers, and defenders understand how attackers compose techniques into attacks by modeling suspicious flows.
  * [Center for Threat-Informed Defense Work](https://ctid.mitre-engenuity.org/our-work/attack-flow)
  * [Attack Flow Tools](https://github.com/vz-risk/flow) - Tools related to working with Attack Flow.
* [Enterprise ATT\&CK Python Module](https://github.com/xakepnz/enterpriseattack) - A lightweight Python module to interact with the MITRE ATT\&CK Enterprise dataset.
* [Mapping MITRE ATT\&CK with Windows Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/)
* [Jai Minton's MITRE ATT\&CK Resources](https://www.jaiminton.com/mitreatt\&ck)
* [TryHackMe MITRE Room](https://tryhackme.com/room/mitre)

### Deprecated / Archived Projects

* [Mitre Engage](https://engage.mitre.org) - (Sunset in 2024) A framework for planning and discussing adversary engagement operations.
* [Mitre Shield Framework](https://shield.mitre.org/matrix/) - (Deprecated) A framework mapping defensive tools and techniques to Active Defense. Succeeded by MITRE Engage.
* [Cascade](https://github.com/mitre/cascade-server) - (Archived) A research project at MITRE seeking to automate investigative work. No longer actively maintained.
* [Mitre D3fend](https://d3fend.mitre.org/) - (No longer maintained by MITRE) Initial funding provided by the NSA. A cyber countermeasure knowledge base. While valuable, check for recent updates or community forks.
* [Atomic Threat Coverage](https://github.com/atc-project/atomic-threat-coverage) - (Inactive) A tool to automatically generate actionable analytics. Not updated since ~2021.
* [OSSEM-DM](https://github.com/OTRF/OSSEM-DM) - (Inactive) A collection of MITRE mappings. Not updated since ~2022.
* [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/) - (Inactive) A knowledge base of Azure TTPs. No longer actively updated by Microsoft.

### Center for Internet Security (CIS) Benchmarks and Controls

CIS provides sets of helpful resources for hardening your environment. The most important for defensive specialists are the CIS Benchmarks and the CIS Controls. The CIS Benchmarks are a large collection of hardening and configuration standards for dozens of products from different vendors. To make life easier, build scripts are available to help you set up your infrastructure to these standards. CIS Controls are documented security best practices for your network. These are incredibly valuable for improving your security posture, and you can even map detection use cases to the controls that protect against certain attacks.

Understanding both of these is valuable for both your organization and your own professional development. Understanding critical security controls can help you develop your understanding of security theory. Digging into the CIS Benchmarks (especially the hardening scripts) is incredibly useful for gaining detailed technical knowledge of security issues.

* [CIS Controls](https://www.cisecurity.org/controls/)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [CIS Community Defense Model](https://www.cisecurity.org/insights/white-papers/cis-community-defense-model)
* [Cyber Attack Defense: CIS Benchmarks, CDM, and MITRE ATT\&CK](https://www.cisecurity.org/blog/cyber-attack-defense-cis-benchmarks-cdm-mitre-attck/)
* [Why You Should Care About CIS v8](https://www.blackhillsinfosec.com/center-for-internet-security-cis-v8-why-you-should-care/)

### Lockheed-Martin Cyber Kill-Chain&#x20;

This is a great format for visualizing the timeline of an attack. When responding to an event or alert, identify where it matches up on the kill-chain and remember to look for any evidence of activity that might fall before or after it in the chain.

{% file src="../.gitbook/assets/Gaining_the_Advantage_Cyber_Kill_Chain.pdf" %}
Cyber Kill-Chain
{% endfile %}

### [Unified Kill Chain](https://www.unifiedkillchain.com/)

An extension of the kill chain concept that incorporates MITRE ATT\&CK nuances to cover the entire attack lifecycle. It unifies the phases of the attack into Initial Foothold, Network Propagation, and Action on Objectives, providing a more comprehensive view of modern attacks.

### [Diamond Model of Intrusion Analysis](https://apps.dtic.mil/sti/citations/ADA586960)

A framework for analyzing intrusion events by mapping the relationships between the four core features of an intrusion event: Adversary, Capability, Infrastructure, and Victim. It helps analysts pivot between these points to uncover more about the attack and understand the adversary's operations.

### [The Pyramid of Pain](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)

A conceptual model that illustrates the difficulty for an adversary to change their indicators of compromise (IOCs) when those indicators are detected and blocked by defenders. The higher up the pyramid you go, the more pain you inflict on the adversary. The levels are:
* **TTPs (Tough)**: Tactics, Techniques, and Procedures.
* **Tools (Challenging)**: Software used by the adversary.
* **Network/Host Artifacts (Annoying)**: Registry keys, specific protocol strings.
* **Domain Names (Simple)**: DNS names.
* **IP Addresses (Easy)**: IP addresses.
* **Hash Values (Trivial)**: MD5/SHA1 hashes of files.

### [VERIS Framework](https://github.com/vz-risk/veris)&#x20;

A common and reasonably popular format, though it lacks some granular classification of events and attacks compared to other frameworks.

### Other Standards

* [CVSS (Common Vulnerability Scoring System)](https://www.first.org/cvss/) - The open industry standard for assessing the severity of computer system security vulnerabilities.
* [OWASP Top 10](https://owasp.org/www-project-top-ten/) - The standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.
* [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) - Structured Threat Information Expression (STIX) is a language for describing cyber threat intelligence. Trusted Automated Exchange of Intelligence Information (TAXII) defines how STIX information is shared.
* [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) - A threat modeling methodology. The acronym stands for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
* [YARA](https://github.com/VirusTotal/yara) - The de facto standard mechanism for classifying and matching malware samples based on textual or binary patterns.
* [STIGs Benchmarks - Security Technical Implementation Guides](https://public.cyber.mil/stigs/)
* [NIST - Current FIPS](https://www.nist.gov/itl/current-fips)
* [ISO Standards Catalogue](https://www.iso.org/standards.html)
* [Common Criteria for Information Technology Security Evaluation (CC)](https://www.commoncriteriaportal.org/cc/) is an international standard (ISO / IEC 15408) for computer security. It allows an objective evaluation to validate that a particular product satisfies a defined set of security requirements.
* [ISO 22301](https://www.iso.org/en/contents/data/standard/07/51/75106.html) is the international standard that provides a best-practice framework for implementing an optimized BCMS (business continuity management system).
* [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) is the international standard that describes the requirements for an ISMS (information security management system). The framework is designed to help organizations manage their security practices in one place, consistently and cost-effectively.
* [ISO 27701](https://www.iso.org/en/contents/data/standard/07/16/71670.html) specifies the requirements for a PIMS (privacy information management system) based on the requirements of ISO 27001. It is extended by a set of privacy-specific requirements, control objectives, and controls. Companies that have implemented ISO 27001 will be able to use ISO 27701 to extend their security efforts to cover privacy management.
* [EU GDPR (General Data Protection Regulation)](https://gdpr.eu/) is a privacy and data protection law that supersedes existing national data protection laws across the EU, bringing uniformity by introducing just one main data protection law for companies/organizations to comply with.
* [CCPA (California Consumer Privacy Act)](https://www.oag.ca.gov/privacy/ccpa) is a data privacy law that took effect on January 1, 2020, in the State of California. It applies to businesses that collect California residents’ personal information, and its privacy requirements are similar to those of the EU’s GDPR (General Data Protection Regulation).
* [Payment Card Industry (PCI) Data Security Standards (DSS)](https://docs.microsoft.com/en-us/microsoft-365/compliance/offering-pci-dss) is a global information security standard designed to prevent fraud through increased control of credit card data.
* [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html) is an auditing procedure that ensures your service providers securely manage your data to protect the interests of your company/organization and the privacy of their clients.
* [NIST CSF](https://www.nist.gov/national-security-standards) is a voluntary framework primarily intended for critical infrastructure organizations to manage and mitigate cybersecurity risk based on existing best practices.
* [Landlock LSM (Linux Security Module)](https://www.kernel.org/doc/html/latest/security/landlock.html) is a framework to create scoped access-control (sandboxing). Landlock is designed to be usable by unprivileged processes while following the system security policy enforced by other access control mechanisms (DAC, LSM, etc.).
* [Secure Boot](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot) is a security standard developed by members of the PC industry to help make sure that a device boots (Unified Extensible Firmware Interface (UEFI) BIOS) using only software (such as bootloaders, OS, UEFI drivers, and utilities) that is trusted by the Original Equipment Manufacturer (OEM).
