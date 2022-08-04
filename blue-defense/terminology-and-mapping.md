# Standards, Frameworks, and Benchmarks

### [MITRE ATT\&CK™](https://attack.mitre.org/)&#x20;

With over a dozen tactics and hundreds of techniques, MITRE Attack has become the defacto standard for event mapping. It can be used defensively to help you map both the attacks coming in against your network, as well as map your current coverage of visibility, to see where your organization can grow.

* [Awesome List Collection: Mitre Attack](https://github.com/Shiva108/CTF-notes/tree/master/awesome-mitre-attack)
* [Mitre Groups](https://attack.mitre.org/groups/) - Repository documenting known techniques performed by threat actor groups.
* [Attack Navigator](https://mitre-attack.github.io/attack-navigator/) - A web-based tool for annotating and exploring ATT\&CK matrices. It can be used to visualize defensive coverage, red/blue team planning, the frequency of detected techniques, and more.
* [C.A.R. Cyber Analytics Repository ](https://car.mitre.org/)- A knowledge base of analytics developed by [MITRE](https://www.mitre.org) based on the [MITRE ATT\&CK](https://attack.mitre.org/) adversary model.
* [Caldera](https://github.com/mitre/caldera) - Scalable Automated Adversary Emulation Platform built around the Mitre techniques.
* [Cascade](https://github.com/mitre/cascade-server) - A research project at MITRE which seeks to automate much of the investigative work a “blue-team” team would perform to determine the scope and maliciousness of suspicious behavior on a network using host data.
* [Mitre Shield Framework ](https://shield.mitre.org/matrix/)- Mitre Shield is a new framework that maps defensive tools and techniques to the topic of Active Defense. This includes things like decoy accounts, canary tokens, and other forms of cyber deception.
* [Mitre D3fend](https://d3fend.mitre.org/) - Thanks to some support from the NSA, Mitre has created a cyber countermeasure based framework that helps defenders map defensive techniques to coverage of offensive techniques.
* [Mitre Engage](https://engage.mitre.org) - MITRE Engage is a framework for planning and discussing adversary engagement operations that empowers you to engage your adversaries and achieve your cybersecurity goals.
* [ATT\&CK® EVALUATIONS](https://attackevals.mitre-engenuity.org/)  - Evaluations of security tools based on MITRE technique coverage
* [atomic-threat-coverage](https://github.com/atc-project/atomic-threat-coverage) - Atomic Threat Coverage is tool which allows you to automatically generate actionable analytics, designed to combat threats (based on the [MITRE ATT\&CK](https://attack.mitre.org/) adversary model) from Detection, Response, Mitigation and Simulation perspectives
* [https://github.com/OTRF/OSSEM-DM](https://github.com/OTRF/OSSEM-DM) - Collection of Mitre mappings connected to EventIDs and Mitre Data Sources.
* [https://github.com/center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow) - ATT\&CK Flow helps executives, SOC managers, and defenders easily understand how attackers compose ATT\&CK techniques into attacks by developing a representation of attack flows, modeling attack flows for a small corpus of incidents, and creating visualization tools to display attack flows.
  * [https://ctid.mitre-engenuity.org/our-work/attack-flow](https://ctid.mitre-engenuity.org/our-work/attack-flow)
  * [https://github.com/vz-risk/flow](https://github.com/vz-risk/flow) - Tools related to work with Attack Flow
* [https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/)
* [https://www.jaiminton.com/mitreatt\&ck](https://www.jaiminton.com/mitreatt\&ck)
* [https://tryhackme.com/room/mitre](https://tryhackme.com/room/mitre)

### Center for Internet Security (CIS) Benchmarks and Controls

CIS has sets of helpful resources for hardening your environment. The most important for defensive specialists is the CIS Benchmarks and the CIS Controls. The CIS Benchmarks are a large collection of hardening and configuration standards of dozens of products from different vendors. To make life even easier, there are even scripts that help you set up your infrastructure to these standards. CIS Controls are documented security best practices for your network. These are incredibly valueable for improvingyour security posture, and you can even map your detection use cases to the controls that protect against certain attacks.&#x20;

Understanding both of these are incredibly valueable to both your organization as well as you. Understanding the critical security controls can help you develop your own understanding of security theory. Digging into the CIS Benchmarks (especially the hardening scripts) is incredibly useful for more detailed technical knowledge of security issues.

* [https://www.cisecurity.org/controls/](https://www.cisecurity.org/controls/)
* [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)
* [https://www.cisecurity.org/blog/cyber-attack-defense-cis-benchmarks-cdm-mitre-attck/](https://www.cisecurity.org/blog/cyber-attack-defense-cis-benchmarks-cdm-mitre-attck/)
* [https://www.blackhillsinfosec.com/center-for-internet-security-cis-v8-why-you-should-care/](https://www.blackhillsinfosec.com/center-for-internet-security-cis-v8-why-you-should-care/)

### Lockheed-Martin Cyber Kill-Chain&#x20;

This is a great format for seeing the timeline of an attack. When responding to an event or alert you see from your security devices, see where they match up on the killchain and remember to look for any evidence of activity that might fall before it, or after it, in the kill-chain.

{% file src="../.gitbook/assets/Gaining_the_Advantage_Cyber_Kill_Chain.pdf" %}
Cyber Kill-Chain
{% endfile %}

### [VERIS Framework](https://github.com/vz-risk/veris)&#x20;

Common and reasonably popular format that has some lacking in a granular classification of events and attacks

### Other Standards

* [https://microsoft.github.io/Azure-Threat-Research-Matrix/](https://microsoft.github.io/Azure-Threat-Research-Matrix/) - A knowledge base built to document known TTPs within Azure and Azure AD.
  * [https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-the-azure-threat-research-matrix/ba-p/3584976](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-the-azure-threat-research-matrix/ba-p/3584976)
* [STIGs Benchmarks - Security Technical Implementation Guides](https://public.cyber.mil/stigs/)
* [NIST - Current FIPS](https://www.nist.gov/itl/current-fips)
* [ISO Standards Catalogue](https://www.iso.org/standards.html)
* [Common Criteria for Information Technology Security Evaluation (CC)](https://www.commoncriteriaportal.org/cc/) is an international standard (ISO / IEC 15408) for computer security. It allows an objective evaluation to validate that a particular product satisfies a defined set of security requirements.
* [ISO 22301](https://www.iso.org/en/contents/data/standard/07/51/75106.html) is the international standard that provides a best-practice framework for implementing an optimised BCMS (business continuity management system).
* [ISO27001](https://www.iso.org/isoiec-27001-information-security.html) is the international standard that describes the requirements for an ISMS (information security management system). The framework is designed to help organizations manage their security practices in one place, consistently and cost-effectively.
* [ISO 27701](https://www.iso.org/en/contents/data/standard/07/16/71670.html) specifies the requirements for a PIMS (privacy information management system) based on the requirements of ISO 27001. It is extended by a set of privacy-specific requirements, control objectives and controls. Companies that have implemented ISO 27001 will be able to use ISO 27701 to extend their security efforts to cover privacy management.
* [EU GDPR (General Data Protection Regulation)](https://gdpr.eu/) is a privacy and data protection law that supersedes existing national data protection laws across the EU, bringing uniformity by introducing just one main data protection law for companies/organizations to comply with.
* [CCPA (California Consumer Privacy Act)](https://www.oag.ca.gov/privacy/ccpa) is a data privacy law that took effect on January 1, 2020 in the State of California. It applies to businesses that collect California residents’ personal information, and its privacy requirements are similar to those of the EU’s GDPR (General Data Protection Regulation).
* [Payment Card Industry (PCI) Data Security Standards (DSS)](https://docs.microsoft.com/en-us/microsoft-365/compliance/offering-pci-dss) is a global information security standard designed to prevent fraud through increased control of credit card data.
* [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html) is an auditing procedure that ensures your service providers securely manage your data to protect the interests of your comapny/organization and the privacy of their clients.
* [NIST CSF](https://www.nist.gov/national-security-standards) is a voluntary framework primarily intended for critical infrastructure organizations to manage and mitigate cybersecurity risk based on existing best practice.
* [Landlock LSM(Linux Security Module)](https://www.kernel.org/doc/html/latest/security/landlock.html) is a framework to create scoped access-control (sandboxing). Landlock is designed to be usable by unprivileged processes while following the system security policy enforced by other access control mechanisms (DAC, LSM, etc.).
* [Secure boot](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot) is a security standard developed by members of the PC industry to help make sure that a device boots(Unified Extensible Firmware Interface (UEFI) BIOS) using only software(such as bootloaders, OS, UEFI drivers, and utilities) that is trusted by the Original Equipment Manufacturer (OEM).
