# Terminology and Mapping

First, Lets look at terminology and definition of security related activity. There are many ways of classifying these, usually by the phase at which a cyber attack is going through, or the type of activity being performed. The most popular that are referenced and used today are the Veris Framework, The Cyber Kill-Chain, and the Mitre Framework.

### [MITRE ATT\&CK™](https://attack.mitre.org)&#x20;

With over a dozen tactics and hundreds of techniques, MITRE Attack has become the defacto standard for event mapping. It can be used defensively to help you map both the attacks coming in against your network, as well as map your current coverage of visibility, to see where your organization can grow.

* [Awesome List Collection: Mitre Attack](https://github.com/Shiva108/CTF-notes/tree/master/awesome-mitre-attack)
* [Mitre Groups](https://attack.mitre.org/groups/) - Repository documenting known techniques performed by threat actor groups.
* [Attack Navigator](https://mitre-attack.github.io/attack-navigator/) - A web-based tool for annotating and exploring ATT\&CK matrices. It can be used to visualize defensive coverage, red/blue team planning, the frequency of detected techniques, and more.
* [C.A.R. Cyber Analytics Repository ](https://car.mitre.org)- A knowledge base of analytics developed by [MITRE](https://www.mitre.org) based on the [MITRE ATT\&CK](https://attack.mitre.org) adversary model.
* [Caldera](https://github.com/mitre/caldera) - Scalable Automated Adversary Emulation Platform built around the Mitre techniques.
* [Cascade](https://github.com/mitre/cascade-server) - A research project at MITRE which seeks to automate much of the investigative work a “blue-team” team would perform to determine the scope and maliciousness of suspicious behavior on a network using host data.
* [Mitre Shield Framework ](https://shield.mitre.org/matrix/)- Mitre Shield is a new framework that maps defensive tools and techniques to the topic of Active Defense. This includes things like decoy accounts, canary tokens, and other forms of cyber deception.
* [Mitre D3fend](https://d3fend.mitre.org) - Thanks to some support from the NSA, Mitre has created a cyber countermeasure based framework that helps defenders map defensive techniques to coverage of offensive techniques.
* [ATT\&CK® EVALUATIONS](https://attackevals.mitre-engenuity.org)  - Evaluations of security tools based on MITRE technique coverage
* [atomic-threat-coverage](https://github.com/atc-project/atomic-threat-coverage) - Atomic Threat Coverage is tool which allows you to automatically generate actionable analytics, designed to combat threats (based on the [MITRE ATT\&CK](https://attack.mitre.org) adversary model) from Detection, Response, Mitigation and Simulation perspectives
* [https://github.com/OTRF/OSSEM-DM](https://github.com/OTRF/OSSEM-DM) - Collection of Mitre mappings connected to EventIDs and Mitre Data Sources.
* [https://github.com/center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow) - ATT\&CK Flow helps executives, SOC managers, and defenders easily understand how attackers compose ATT\&CK techniques into attacks by developing a representation of attack flows, modeling attack flows for a small corpus of incidents, and creating visualization tools to display attack flows.
  * [https://ctid.mitre-engenuity.org/our-work/attack-flow](https://ctid.mitre-engenuity.org/our-work/attack-flow)
  * [https://github.com/vz-risk/flow](https://github.com/vz-risk/flow) - Tools related to work with Attack Flow
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
