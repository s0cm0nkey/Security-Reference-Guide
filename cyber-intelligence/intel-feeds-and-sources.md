# Intel Feeds and Sources

Use this page for cyber threat intelligence feeds, standards, sharing platforms, source collections, and research sources. Indicator reputation and enrichment lookups live in Threat Data; sandboxing and malware behavior analysis live in DFIR.

## Intelligence Lifecycle: Deprecation and Priority

Not all indicators are equal. A malware hash tied to a confirmed intrusion usually carries more evidentiary weight than an IP address observed scanning the internet. Indicator priority depends on fidelity, corroborating context, and where the indicator sits in the attack chain.

Indicators also decay. IP addresses, domains, and infrastructure relationships can change quickly; hashes and well-described behaviors usually age better. When using feed data, track first-seen time, last-seen time, source reliability, and whether the indicator still matches current adversary behavior.

## Threat Intelligence Frameworks

* [MITRE ATT&CK](https://attack.mitre.org/) - Knowledge base of adversary tactics and techniques.
* [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Lockheed Martin's seven-stage model for attack progression.
* [Diamond Model](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf) - Intrusion analysis model built around adversary, capability, infrastructure, and victim.

{% embed url="https://www.youtube.com/watch?v=J7e74QLVxCk" %}

## Indicator Standards and Formats

* [OASIS CTI Technical Committee](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti) - Standards body for STIX and TAXII.
* [STIX 2.x](https://oasis-open.github.io/cti-documentation/stix/intro) - Structured Threat Information Expression for machine-readable CTI.
* [TAXII 2.x](https://oasis-open.github.io/cti-documentation/taxii/intro) - API protocol for exchanging STIX threat intelligence.
* [OpenIOC](https://github.com/mandiant/OpenIOC_1.1) - Mandiant framework for sharing threat intelligence in a machine-digestible format.
* [CybOX](https://cyboxproject.github.io/) - Legacy cyber observable specification. CybOX concepts were folded into STIX 2.x observables.

## Daily Checkers and Roundups

* [Feedly](https://feedly.com/) - RSS reader with cybersecurity collections.
* [Hackerpom Intel Feed Tool](https://www.hackerpom.com/feed) - Aggregates security news, tweets, and Reddit sources.
* [Bad Sector Labs](https://blog.badsectorlabs.com/)
* [Security Soup](https://security-soup.net/tag/news/)
* [The Hacker News](https://thehackernews.com/)
* [BleepingComputer Security](https://www.bleepingcomputer.com/news/security/)
* [Dark Reading](https://www.darkreading.com/)
* [CyberScoop](https://www.cyberscoop.com/)
* [SecurityWeek](https://www.securityweek.com/)
* [The Register: Security](https://www.theregister.com/security/)
* [Ars Technica: Security](https://arstechnica.com/tag/security/)

DFIR-specific news and case studies are preserved in the DFIR section.

{% content-ref url="../dfir-digital-forensics-and-incident-response/" %}
[dfir-digital-forensics-and-incident-response](../dfir-digital-forensics-and-incident-response/)
{% endcontent-ref %}

## CTI Resource Collections

* [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
* [Awesome IOCs](https://github.com/sroberts/awesome-iocs)
* [Awesome Security Feeds](https://github.com/mrtouch93/awesome-security-feed)

## Threat Intelligence Platforms and Tools

* [MISP](https://www.misp-project.org/) - Open-source threat sharing platform for storing, correlating, enriching, and distributing indicators.
  * [MISP GitHub](https://github.com/MISP/MISP)
  * [MISP Modules](https://github.com/MISP/misp-modules)
  * [MISP Splunk App](https://splunkbase.splunk.com/app/4335/)
  * [MISP User Guide](https://www.circl.lu/doc/misp/book.pdf)
* [OpenCTI](https://github.com/OpenCTI-Platform/opencti) - Open-source CTI platform built around STIX 2.1 concepts.
* [Yeti](https://github.com/yeti-platform/yeti) - Platform for organizing observables, IOCs, TTPs, and threat knowledge.
* [IntelOwl](https://github.com/intelowlproject/IntelOwl) - Open-source analyzer and enrichment platform for files, IPs, domains, and other observables.
* [S-TIP](https://github.com/s-tip) - Threat intelligence platform focused on CTI sharing workflows.
* [TheHive](https://github.com/TheHive-Project/TheHive) - Incident response and case management platform that integrates with MISP and other CTI tools.
* [Cortex](https://github.com/TheHive-Project/Cortex) - Observable analysis and active response engine.
* [Harpoon](https://github.com/Te-k/harpoon) - OSINT and threat intelligence CLI.
* [IoC Ingester](https://github.com/ninoseki/iocingestor) - Extracts and aggregates IoCs from threat feeds.
* [Mihari](https://github.com/ninoseki/mihari) - Continuous OSINT-based indicator monitoring framework.
* [IoC Parser](https://github.com/armbues/ioc_parser) - Extracts indicators from security reports.
* [MITRE CTI](https://github.com/mitre/cti) - ATT&CK content expressed in STIX 2.0.
* [TALR](https://github.com/SecurityRiskAdvisors/TALR) - Detection rule sharing in STIX format.

Threat Dragon is a threat modeling tool rather than a CTI feed platform, so it belongs with secure design and architecture references rather than this page.

## Government, ISAC, and Sharing Sources

* [InfraGard](https://www.infragard.org/) - FBI-affiliated public/private partnership.
* [CISA Cybersecurity Resources](https://www.cisa.gov/cybersecurity)
* [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
* [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
* [CISA Vulnerability Bulletins](https://www.cisa.gov/news-events/bulletins)
* [CISA Analysis Reports](https://www.cisa.gov/news-events/analysis-reports)
* [CISA AIS](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais) - Automated Indicator Sharing. Treat as a historical or transition-sensitive source and verify the current program status before building new dependencies on it.
* [IC3](https://www.ic3.gov/) - FBI Internet Crime Complaint Center.
* [National Council of ISACs](https://www.nationalisacs.org/member-isacs-3) - Find sector-specific ISACs.

## Intel Platforms

* [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
* [ThreatConnect](https://app.threatconnect.com/)
* [AlienVault OTX](https://otx.alienvault.com/)
* [Anomali](https://www.anomali.com/products)
* [ThreatQ](https://www.threatquotient.com/)

Premium intelligence providers:

* [CrowdStrike Falcon Intelligence](https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/)
* [Spamhaus Data Query Service](https://www.spamhaus.com/product/data-query-service/)
* [Intel 471](https://intel471.com/products/threat-intelligence/)
* [Intelligence X](https://intelx.io/) - Search engine and archival intelligence platform.
* [Team Cymru](https://team-cymru.com/)
* [CINS Score](https://cinsscore.com/#cins-ati)
* [ThreatSTOP](https://www.threatstop.com/threatstop-pricing)
* [VirusTotal Intelligence](https://www.virustotal.com/gui/intelligence-overview)
* [Recorded Future](https://www.recordedfuture.com/platform/)
* [Mandiant Advantage](https://www.mandiant.com/advantage)

TruSTAR was acquired by Splunk; verify current Splunk Enterprise Security, SOAR, and threat intelligence workflows before depending on old TruSTAR documentation.

## IoC Feeds

MISP includes many default feeds. For the current list, use [MISP OSINT feeds](https://www.misp-project.org/feeds/).

Common free feeds:

* [CIRCL OSINT Feed](https://www.circl.lu/doc/misp/feed-osint/)
* [Botvrij.eu Feed](https://www.botvrij.eu/data/feed-osint/)
* [Emerging Threats Compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
* [Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.csv)
* [ThreatFox](https://threatfox.abuse.ch/)
* [URLhaus](https://urlhaus.abuse.ch/)
* [MalwareBazaar](https://bazaar.abuse.ch/)
* [OpenPhish](https://openphish.com/feed.txt)
* [abuse.ch SSL Blacklist](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
* [DigitalSide Threat Intel](https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/)
* [FireHOL IP Lists](https://iplists.firehol.org/)
* [AlienVault OTX API](https://github.com/AlienVault-OTX/ApiV2)
* [PhishHunt](https://phishunt.io/)
* [Disposable Email Domains](https://github.com/ivolo/disposable-email-domains)
* [FreeMail](https://github.com/dpup/freemail)
* [Stop Forum Spam](https://www.stopforumspam.com/)
* [DShield Feeds](https://www.dshield.org/xml.html)
* [dan.me.uk Tor Exit Nodes](https://www.dan.me.uk/tornodes)
* [dan.me.uk DNS Blacklists](https://www.dan.me.uk/dnsbl)
* [Spamhaus DROP](https://www.spamhaus.org/drop/)
* [Project Honey Pot IP List](https://www.projecthoneypot.org/list_of_ips.php)
* [DarkFeed](https://darkfeed.io/)
* [Anomali Limo](https://www.anomali.com/resources/limo)
* [Rescure](https://rescure.me/) - Curated CTI feeds.
* [Malware-IOCs](https://github.com/executemalware/Malware-IOCs)

Reputation and enrichment platforms such as VirusTotal, GreyNoise, AbuseIPDB, urlscan.io, and OPSWAT MetaDefender are maintained on Threat Data.

{% content-ref url="threat-data.md" %}
[threat-data.md](threat-data.md)
{% endcontent-ref %}

Malware sandboxes such as ANY.RUN, Hybrid Analysis, Joe Sandbox, Triage, Intezer, UnpacMe, and Cuckoo are maintained in DFIR sandboxing.

{% content-ref url="../dfir-digital-forensics-and-incident-response/sandboxing.md" %}
[sandboxing.md](../dfir-digital-forensics-and-incident-response/sandboxing.md)
{% endcontent-ref %}

## Research Blogs

Threat research groups:

* [Mandiant Blog](https://www.mandiant.com/resources/blog)
* [Sophos News](https://news.sophos.com/en-us/)
* [Elastic Security Labs](https://www.elastic.co/security-labs)
* [Securelist](https://securelist.com/)
* [Malwarebytes Labs](https://www.malwarebytes.com/blog)
* [Google Project Zero](https://googleprojectzero.blogspot.com/)
* [ClearSky Blog](https://www.clearskysec.com/blog/)
* [Check Point Research](https://research.checkpoint.com/)
* [Cisco Talos](https://blogs.cisco.com/security/talos)
* [FortiGuard Labs](https://www.fortiguard.com/resources/threat-brief)
* [Unit 42](https://unit42.paloaltonetworks.com/)
* [Trend Micro Research](https://www.trendmicro.com/en_us/research.html)
* [CrowdStrike Intelligence Blog](https://www.crowdstrike.com/blog/category/threat-intel-research/)
* [JPCERT/CC Eyes](https://blogs.jpcert.or.jp/en/)
* [SANS ISC Diary](https://isc.sans.edu/diary.html)
* [Cryptolaemus](https://paste.cryptolaemus.com/)
* [Uptycs Threat Research](https://www.uptycs.com/blog/tag/threat-research)

Corporate security blogs:

* [Microsoft Security Response Center](https://msrc-blog.microsoft.com/)
* [DomainTools Research](https://www.domaintools.com/resources/blog?category=domaintools-research&authors=)
* [Proofpoint Blog](https://www.proofpoint.com/us/blog)
* [Zscaler Research](https://www.zscaler.com/blogs/security-research)
* [Secureworks Blog](https://www.secureworks.com/blog)
* [Searchlight Cyber](https://www.searchlight-cyber.com/research-and-insights/)
* [Recorded Future Blog](https://www.recordedfuture.com/blog/)
* [Imperva Blog](https://www.imperva.com/blog/)
* [Tenable Blog](https://www.tenable.com/blog)
* [Google Security Blog](https://security.googleblog.com/)
* [Cofense Blog](https://cofense.com/blog/)
* [Fortinet Blog](https://www.fortinet.com/blog)
* [SpecterOps Blog](https://posts.specterops.io/)
* [Virus Bulletin](https://www.virusbulletin.com/blog/)
* [Anomali Blog](https://www.anomali.com/blog)
* [Intezer Blog](https://www.intezer.com/blog/)
* [Verisign Blog](https://blog.verisign.com/)
* [VirusTotal Blog](https://blog.virustotal.com/)
* [WeLiveSecurity](https://www.welivesecurity.com/research/)
* [TrustedSec Blog](https://www.trustedsec.com/blog/)
* [Broadcom Security Center](https://www.broadcom.com/support/security-center)
* [Trustwave SpiderLabs](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/)
* [ReversingLabs Blog](https://blog.reversinglabs.com/blog)
* [Rapid7 Research](https://blog.rapid7.com/tag/research/)
* [SecurityTrails Blog](https://securitytrails.com/blog)
* [Advanced Intelligence Blog](https://www.advanced-intel.com/blog)
* [Scythe Threat Thursday](https://www.scythe.io/threatthursday)
* [Trellix Blog](https://www.trellix.com/blogs/)
* [Huntress Blog](https://www.huntress.com/blog)
* [Red Canary Blog](https://redcanary.com/blog/)
* [Splunk Security Blog](https://www.splunk.com/en_us/blog/security.html)
* [SentinelOne Blog](https://www.sentinelone.com/blog/)

Offensive methodology blogs such as Hakluke, PentesterLab-style content, and Null Byte fit better in Red Offensive or Web App Hacking.

## Communities and Media

* [SANS ISC Forums](https://isc.sans.edu/forums/Diary+Discussions/)
* [r/blueteamsec](https://www.reddit.com/r/blueteamsec/)
* [r/cybersecurity](https://www.reddit.com/r/cybersecurity/)
* [r/Intelligence](https://www.reddit.com/r/Intelligence/)
* [r/netsec](https://www.reddit.com/r/netsec/)
* [r/threathunting](https://www.reddit.com/r/threathunting/)
* [r/AskNetsec](https://www.reddit.com/r/AskNetsec/)
* [infosec.exchange](https://infosec.exchange/) - Primary cybersecurity Mastodon instance.

Podcasts and webcasts:

* [Darknet Diaries](https://darknetdiaries.com/)
* [Privacy, Security, and OSINT Show](https://inteltechniques.com/podcast.html)
* [CyberWire Podcasts](https://www.thecyberwire.com/podcasts/)
* [Proofpoint Podcasts](https://www.proofpoint.com/us/resources/podcast)
* [Social-Engineer Podcast](https://www.social-engineer.org/category/podcast/)
* [Beers with Talos](https://blog.talosintelligence.com/)
* [Malicious Life](https://malicious.life/)
* [GIAC Podcasts](https://www.giac.org/podcasts)
* [Security Weekly](https://securityweekly.com/)
* [Black Hills Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/)

Training, YouTube channels, and labs are preserved in Training.

{% content-ref url="../training/" %}
[training](../training/)
{% endcontent-ref %}

## Deprecated or Archived Tools

* **CRITs** - Collaborative Research Into Threats. Last updated in 2018; consider OpenCTI, MISP, or TheHive.
* **NSA Unfetter** - Archived. Use ATT&CK Navigator and related MITRE tooling.
* **Malware Domain List** - Degraded/no longer maintained; use URLhaus, ThreatFox, and other abuse.ch feeds.
* **Threatpost** - Shut down in 2022 after acquisition.
* **TruSTAR standalone docs** - Splunk acquired TruSTAR; verify current Splunk CTI/SOAR workflows.
* **CybOX** - Legacy observable model folded into STIX 2.x.

## Onion Feeds

* [OSINT Party Fresh Onion RSS](https://osint.party/api/rss/fresh) - Fresh `.onion` RSS feed. Service status can vary, and links may be illegal or harmful; verify availability, treat links as untrusted, and follow the OPSEC section.

{% content-ref url="../grey-privacy-tor-opsec/" %}
[grey-privacy-tor-opsec](../grey-privacy-tor-opsec/)
{% endcontent-ref %}
