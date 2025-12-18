# Intel Feeds and Sources

## **Intelligence Lifecycle: Understanding Deprecation and Priority**

Before exploring the numerous intelligence sources available, it's essential to understand the value of intelligence and its temporal nature.

First, not all indicators are created equal—each should have an associated priority or weighting. Some indicators naturally provide stronger evidence of an attack than others. For example, consider the difference between detecting the hash of a known piece of malware versus observing an IP address associated with a known malicious scanner. The former demonstrates the presence of a known malicious object and represents a later stage in the attack chain. The latter simply indicates interaction with an indicator that *could* be malicious—additional data is needed to confirm an actual attack. These two indicators would have different priorities based on three factors: the fidelity of the indicator, the amount of additional data or correlation needed to confirm an attack, and the phase of the attack chain the indicator represents.

Second, we must understand the temporal element of indicators. An indicator's fidelity and priority deprecate over time. The further removed we are from both the initial reporting date and the last confirmed detection, the lower the probability that the indicator remains valid. This is especially true for indicators that change frequently, such as IP addresses. Conversely, indicators like hash values remain largely valid over extended periods due to their cryptographic uniqueness.

### **Threat Intelligence Frameworks**

Several frameworks help structure and contextualize threat intelligence:

* **[MITRE ATT&CK](https://attack.mitre.org/)** - A globally accessible knowledge base of adversary tactics and techniques based on real-world observations. Essential for mapping threat actor behaviors and detection strategies.
* **[Cyber Kill Chain](https://www.lockheedmartin.com/en-us/news/features/history/cyber-kill-chain.html)** - Lockheed Martin's framework identifying seven stages of cyber attacks, useful for understanding attack progression.
* **[Diamond Model](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)** - A framework for analyzing cyber intrusion events by examining four core features: adversary, capability, infrastructure, and victim.

{% embed url="https://www.youtube.com/watch?v=J7e74QLVxCk" %}

## **Indicator Standards and Formats**

* **[Oasis](https://www.oasis-open.org/) Suite** - OASIS is a non-profit standardization organization that manages the [standards](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti) for multiple intelligence feed formats.
  * **[STIX](https://stixproject.github.io/)** - Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI). STIX enables organizations to share CTI in a consistent and machine-readable manner, allowing security communities to better understand likely attacks and respond faster and more effectively.
    * [https://oasis-open.github.io/cti-documentation/stix/intro](https://oasis-open.github.io/cti-documentation/stix/intro)
    * **[CyBOX](https://cyboxproject.github.io/)** - An older standard that has been subsequently absorbed into STIX.
  * **[TAXII](https://taxiiproject.github.io/)** - Trusted Automated Exchange of Intelligence Information (TAXII™) is an application layer protocol for communicating cyber threat information in a simple and scalable manner. TAXII enables organizations to share CTI over HTTPS by defining an API that aligns with common sharing models. TAXII is specifically designed to support the exchange of CTI represented in STIX.
    * [https://oasis-open.github.io/cti-documentation/taxii/intro](https://oasis-open.github.io/cti-documentation/taxii/intro)
* **[OpenIOC](https://github.com/mandiant/OpenIOC_1.1)** - An open framework for sharing threat intelligence in a machine-digestible format, originally developed by Mandiant (now part of Google Cloud).

## **Daily Checkers and Round-ups**

Intelligence analysts parse through intel sources daily. Rather than maintaining 100+ browser tabs, RSS feeds can centralize articles in one location. [Feedly](https://feedly.com) is a popular RSS feed platform—its free tier supports 100+ sources in a single feed and includes preset cybersecurity collections. However, RSS feeds cannot capture content like tweets and Reddit posts. For this, Hackerpom's [intel feed tool](https://www.hackerpom.com/feed) aggregates top intel sources with relevant tweets and Reddit posts.

Beyond daily checkers, regular review of "round-up" style blogs helps condense popular topics and surface insights other tools might miss:

* [https://blog.badsectorlabs.com/](https://blog.badsectorlabs.com/)
* [https://sec.today/pulses/](https://sec.today/pulses/)
* [https://thisweekin4n6.com/](https://thisweekin4n6.com/)
* [https://latesthackingnews.com/](https://latesthackingnews.com/)
* [https://security-soup.net/tag/news/](https://security-soup.net/tag/news/)

## Intelligence Tools and Resources

<details>

<summary>Intel Resource Collections</summary>

* [Awesome Lists Collection: Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
* [Awesome Lists Collection: IOCs](https://github.com/sroberts/awesome-iocs)
* [Awesome Lists Collection: Security Feeds](https://github.com/mrtouch93/awesome-security-feed)

</details>

### Indicator Gathering and Enrichment Tools

These are tools for collecting, enriching, and sharing threat indicators. Most are open source and focus on indicator sharing within the cyber community and flexibility to work with a wide array of tools that might use the data.

<details>

<summary>Indicator Gathering and Enrichment Tools</summary>

* [CSIRTGadget's CIF: Collective Intelligence Framework](https://csirtgadgets.com/collective-intelligence-framework) - Pulls feeds from multiple locations and makes them available for other systems to use for lookup or enrichment.
* [Yeti](https://github.com/yeti-platform/yeti) - Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository.
* [IntelOWL](https://github.com/intelowlproject/IntelOwl) - Intel Owl is an Open Source Intelligence, or OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale.
* [S-TIP](https://github.com/s-tip) - S-TIP is a threat intelligence platform to bring down barriers among separate practices of CTI sharing.
* [OpenCTI](https://github.com/OpenCTI-Platform/opencti) - OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables
* [TheHive](https://github.com/TheHive-Project/TheHive) - A scalable, open-source security incident response platform designed to integrate with MISP and other threat intelligence tools.
* [Cortex](https://github.com/TheHive-Project/Cortex) - Powerful observable analysis and active response engine that works with TheHive.
* [Harpoon](https://github.com/Te-k/harpoon) - OSINT / Threat Intel CLI tool.
* [Threat Dragon](https://github.com/OWASP/threat-dragon) - Threat Dragon is a free, open-source, cross-platform threat modeling application including system diagramming and a rule engine to auto-generate threats/mitigations.
* [IoC Ingester ](https://github.com/ninoseki/iocingestor)- An extendable tool to extract and aggregate IoCs from threat feeds.
* [IoC Parser](https://github.com/armbues/ioc\_parser) - IOC Parser is a tool to extract indicators of compromise from security reports in PDF format
* [cti](https://github.com/mitre/cti) - Cyber Threat Intelligence Repository expressed in STIX 2.0
* [TALR](https://github.com/SecurityRiskAdvisors/TALR) - A public repository for the collection and sharing of detection rules in STIX format.

</details>

### MISP

[**MISP**](https://www.misp-project.org/)**:** The Malware Information Sharing Platform - MISP is a free and open-source threat sharing platform that facilitates information sharing of threat intelligence, including cybersecurity indicators. MISP can ingest numerous indicator feeds, enrich indicators, and distribute them to other platforms. It includes an extensive array of high-fidelity default feeds and modules that enable integration with numerous platforms and technologies.

<details>

<summary>MISP Resources</summary>

* MISP Github - [https://github.com/MISP/MISP](https://github.com/MISP/MISP)
* MISP Modules - [https://github.com/MISP/misp-modules](https://github.com/MISP/misp-modules)
* MISP Splunk App - [https://splunkbase.splunk.com/app/4335/](https://splunkbase.splunk.com/app/4335/)
* CIRCL User Guide - [https://www.circl.lu/doc/misp/book.pdf](https://www.circl.lu/doc/misp/book.pdf)
* [https://www.recordedfuture.com/misp-integration-overview/](https://www.recordedfuture.com/misp-integration-overview/)
* [https://www.circl.lu/assets/files/infosharing.pdf](https://www.circl.lu/assets/files/infosharing.pdf)
* [https://www.sans.org/webcasts/sharing-alerts-threat-intelligence-misp-110000](https://www.sans.org/webcasts/sharing-alerts-threat-intelligence-misp-110000)
* [https://www.sans.org/webcasts/friend-creating-threat-intelligence-capability-103532](https://www.sans.org/webcasts/friend-creating-threat-intelligence-capability-103532)

</details>

{% embed url="https://www.youtube.com/watch?app=desktop&v=00jq7Gbqdz8" %}

## Intelligence Sources

<details>

<summary>Government Feeds</summary>

* FBI Infragaurd - [https://www.infragard.org/](https://www.infragard.org/)
* CISA
  * Cybersecurity Advisories - [https://www.cisa.gov/news-events/cybersecurity-advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
  * Known Exploited Vulnerabilities - [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  * Vulnerability Bulletins - [https://www.cisa.gov/news-events/bulletins](https://www.cisa.gov/news-events/bulletins)
  * Analysis Reports - [https://www.cisa.gov/news-events/analysis-reports](https://www.cisa.gov/news-events/analysis-reports)
  * Automated Indicator Sharing (AIS) TAXII API (free/registration required) - [https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais)
* IC3 News Releases -[https://www.ic3.gov/](https://www.ic3.gov/)
* Various ISAC - Find an ISAC in your sector - [https://www.nationalisacs.org/member-isacs-3](https://www.nationalisacs.org/member-isacs-3)

</details>

<details>

<summary>Intel Platforms</summary>

* IBM X-Force Exchange - [https://exchange.xforce.ibmcloud.com/](https://exchange.xforce.ibmcloud.com/)
* ThreatConnect - [https://app.threatconnect.com/](https://app.threatconnect.com/)
* AlienVault OTX (AT&T Cybersecurity) - [https://otx.alienvault.com/](https://otx.alienvault.com/)

</details>

<details>

<summary>Cyber News</summary>

* PacketStorm -[https://packetstormsecurity.com/](https://packetstormsecurity.com/)
* The Hacker News - [https://thehackernews.com/](https://thehackernews.com/)
* Bleeping Computer -[https://www.bleepingcomputer.com/news/security/](https://www.bleepingcomputer.com/news/security/)
* Dark Reading - [https://www.darkreading.com/](https://www.darkreading.com/)
* Cyber Scoop -[https://www.cyberscoop.com/](https://www.cyberscoop.com/)
* Security Week -[https://www.securityweek.com/](https://www.securityweek.com/)
* Gizmodo: Security - [https://gizmodo.com/tag/security](https://gizmodo.com/tag/security)
* The Register: Security -[https://www.theregister.com/security/](https://www.theregister.com/security/)
* ITSec Guru - [https://www.itsecurityguru.org/](https://www.itsecurityguru.org/)
* Hackaday - [https://hackaday.com/category/security-hacks/](https://hackaday.com/category/security-hacks/)
* Cyber Talk - [https://www.cybertalk.org/](https://www.cybertalk.org/)
* Hackbusters -[https://hackbusters.com/](https://hackbusters.com/)
* Data Breaches -[https://www.databreaches.net/category/breach-reports/us/](https://www.databreaches.net/category/breach-reports/us/)
* CSO Online -[https://www.csoonline.com/](https://www.csoonline.com/)
* Null-Byte -[https://null-byte.wonderhowto.com/](https://null-byte.wonderhowto.com/)
* Security News Wire - [https://securitynewswire.com/index.php/Home](https://securitynewswire.com/index.php/Home)
* Ars Technica: Security - [https://arstechnica.com/tag/security/](https://arstechnica.com/tag/security/)

</details>

<details>

<summary>Vulnerability Disclosure</summary>

* NIST -[https://nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
* Full Disclosure -[https://seclists.org/fulldisclosure/](https://seclists.org/fulldisclosure/)
* PacketStorm Vuls and Exploits - [https://packetstormsecurity.com/files/tags/exploit/](https://packetstormsecurity.com/files/tags/exploit/)
* Exploit DB -[https://www.exploit-db.com/](https://www.exploit-db.com/)
* CX Security - [https://cxsecurity.com/](https://cxsecurity.com/)
* Japan Vul Notes -[https://jvn.jp/en/](https://jvn.jp/en/)
* VulDB - [https://vuldb.com/](https://vuldb.com/)
* vFeed -[https://vfeed.io/](https://vfeed.io/)

</details>

<details>

<summary>Threat Research Group Blogs</summary>

* Mandiant - [https://www.mandiant.com/resources/blog](https://www.mandiant.com/resources/blog) (formerly FireEye)
* Sophos -[https://news.sophos.com/en-us/](https://news.sophos.com/en-us/)
* Elastic Security Labs - [https://www.elastic.co/security-labs](https://www.elastic.co/security-labs)
* SecureList - [https://securelist.com/](https://securelist.com/)
* MalwareBytes Blog -[https://blog.malwarebytes.com/](https://blog.malwarebytes.com/)
* Google Project Zero - [https://googleprojectzero.blogspot.com/](https://googleprojectzero.blogspot.com/)
* ClearSky Blog - [https://www.clearskysec.com/blog/](https://www.clearskysec.com/blog/)
* CheckPoint Research - [https://research.checkpoint.com/](https://research.checkpoint.com/)
* Cisco Talos Research - [https://blogs.cisco.com/security/talos](https://blogs.cisco.com/security/talos)
* Cisco Talos Blog -[https://blog.talosintelligence.com/](https://blog.talosintelligence.com/)
* FortiGuard Labs - [https://www.fortiguard.com/resources/threat-brief](https://www.fortiguard.com/resources/threat-brief)
* Unit42 - [https://unit42.paloaltonetworks.com/](https://unit42.paloaltonetworks.com/)
* TrendMicro Research - [https://www.trendmicro.com/en\_us/research.html](https://www.trendmicro.com/en\_us/research.html)
* Malware-Traffic-Analysis - [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
* CrowdStrike Intel -[https://www.crowdstrike.com/blog/category/threat-intel-research/](https://www.crowdstrike.com/blog/category/threat-intel-research/)
* JPCERT/CC - [https://blogs.jpcert.or.jp/en/](https://blogs.jpcert.or.jp/en/)
* SANS ISC Diary - [https://isc.sans.edu/diary.html](https://isc.sans.edu/diary.html)
* Cryptolaemus - [https://paste.cryptolaemus.com/](https://paste.cryptolaemus.com/)
* Uptycs - [https://www.uptycs.com/blog/tag/threat-research](https://www.uptycs.com/blog/tag/threat-research)

</details>

<details>

<summary>Solo Researcher Blogs</summary>

* Krebs on Security - [https://krebsonsecurity.com/](https://krebsonsecurity.com/)
* Schneier on Security - [https://www.schneier.com/](https://www.schneier.com/)
* Eric Conrad -[https://www.ericconrad.com/](https://www.ericconrad.com/)
* Daniel Miessler - [https://danielmiessler.com/blog/](https://danielmiessler.com/blog/)
* RedTimmy - [https://www.redtimmy.com/blog/](https://www.redtimmy.com/blog/)
* BC Sec - [http://bc-security.org/blog](http://bc-security.org/blog)
* Rastamouse - [http://rastamouse.me/](http://rastamouse.me/)
* Hakluke -[https://medium.com/@hakluke](https://medium.com/@hakluke)
* Hausec - [https://hausec.com/](https://hausec.com/)
* Pentesting Labs -[https://pentestlab.blog/](https://pentestlab.blog/)
* Intel Techniques Blog - [https://inteltechniques.com/blog/](https://inteltechniques.com/blog/)
* Jack Whitton - [https://whitton.io/](https://whitton.io/)
* hacks4pancakes -[https://tisiphone.net/](https://tisiphone.net/)
* Tao Security -[https://taosecurity.blogspot.com/](https://taosecurity.blogspot.com/)
* Troy Hunt - [https://www.troyhunt.com/](https://www.troyhunt.com/)\
  ZeroSec - [https://blog.zsec.uk/](https://blog.zsec.uk/)
* Graham Cluely - [https://grahamcluley.com/](https://grahamcluley.com/)

</details>

<details>

<summary>Corporate Security Blogs</summary>

* TrendMicro - [https://blog.trendmicro.com/](https://blog.trendmicro.com/)
* Microsoft - [https://msrc-blog.microsoft.com/](https://msrc-blog.microsoft.com/)
* DomainTools -[https://www.domaintools.com/resources/blog?category=domaintools-research\&authors=](https://www.domaintools.com/resources/blog?category=domaintools-research\&authors=)
* ProofPoint - [https://www.proofpoint.com/us/blog](https://www.proofpoint.com/us/blog)
* Zscaler - [https://www.zscaler.com/blogs/security-research](https://www.zscaler.com/blogs/security-research)
* SecureWorks - [https://www.secureworks.com/blog](https://www.secureworks.com/blog)
* Searchlight Cyber (formerly Digital Shadows) - [https://www.searchlight-cyber.com/research-and-insights/](https://www.searchlight-cyber.com/research-and-insights/)
* Recorded Future - [https://www.recordedfuture.com/blog/](https://www.recordedfuture.com/blog/)
* Heimdal Security - [https://heimdalsecurity.com/blog/posts/](https://heimdalsecurity.com/blog/posts/)
* Morphisec - [https://blog.morphisec.com/](https://blog.morphisec.com/)
* Imperva - [https://www.imperva.com/blog/](https://www.imperva.com/blog/)
* Tenable - [https://www.tenable.com/blog](https://www.tenable.com/blog)
* PhishLabs - [https://info.phishlabs.com/blog](https://info.phishlabs.com/blog)
* Google Blog - [https://security.googleblog.com/](https://security.googleblog.com/)
* Cofense - [https://cofense.com/blog/](https://cofense.com/blog/)
* Fortinet -[https://www.fortinet.com/blog](https://www.fortinet.com/blog)
* SpectreOps - [https://posts.specterops.io/?gi=c476d247e3c8](https://posts.specterops.io/?gi=c476d247e3c8)
* Virus Bulletin - [https://www.virusbulletin.com/blog/](https://www.virusbulletin.com/blog/)
* Anomali - [https://www.anomali.com/blog](https://www.anomali.com/blog)
* Intezer - [https://www.intezer.com/blog/](https://www.intezer.com/blog/)
* Verisign - [https://blog.verisign.com/](https://blog.verisign.com/)
* Virustotal - [https://blog.virustotal.com/](https://blog.virustotal.com/)
* WeLiveSecurity - [https://www.welivesecurity.com/research/](https://www.welivesecurity.com/research/)
* TrustedSec - [https://www.trustedsec.com/blog/](https://www.trustedsec.com/blog/)
* Broadcom Symantec - [https://www.broadcom.com/support/security-center](https://www.broadcom.com/support/security-center)
* Avast - [https://blog.avast.com/topic/security-news](https://blog.avast.com/topic/security-news)
* TrustWave -[https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/)
* ReversingLabs -[https://blog.reversinglabs.com/blog](https://blog.reversinglabs.com/blog)
* Rapid7 - [https://blog.rapid7.com/tag/research/](https://blog.rapid7.com/tag/research/)
* Security Trails - [https://securitytrails.com/blog](https://securitytrails.com/blog)
* Advanced Intel - [https://www.advanced-intel.com/blog](https://www.advanced-intel.com/blog)
* Scythe - [https://www.scythe.io/threatthursday](https://www.scythe.io/threatthursday)
* Trellix (formerly McAfee Enterprise) - [https://www.trellix.com/blogs/](https://www.trellix.com/blogs/)
* Huntress Labs - [https://www.huntress.com/blog](https://www.huntress.com/blog)
* Red Canary - [https://redcanary.com/blog/](https://redcanary.com/blog/)
* Splunk Security - [https://www.splunk.com/en_us/blog/security.html](https://www.splunk.com/en_us/blog/security.html)
* SentinelOne - [https://www.sentinelone.com/blog/](https://www.sentinelone.com/blog/)

</details>

<details>

<summary>New Cyber Tool Blogs</summary>

* [https://www.darknet.org.uk/](https://www.darknet.org.uk/)
* [https://www.toolswatch.org/](https://www.toolswatch.org/)
* [https://www.kitploit.com/](https://www.kitploit.com/)
* [https://packetstormsecurity.com/files/tags/tool/](https://packetstormsecurity.com/files/tags/tool/)
* [https://hakin9.org/blog-2/](https://hakin9.org/blog-2/)

</details>

****

## IoC Feeds

MISP includes over 30 default feeds, with more being added regularly. Below are some of the most popular feeds. For a complete list of feeds available in MISP, visit: [https://www.misp-project.org/feeds/](https://www.misp-project.org/feeds/)

<details>

<summary>Free (In MISP)</summary>

* CIRCL - [https://www.circl.lu/doc/misp/feed-osint/](https://www.circl.lu/doc/misp/feed-osint/)
* Botvrj - [https://www.botvrij.eu/data/feed-osint/](https://www.botvrij.eu/data/feed-osint/)
* Emerging Threats - [https://rules.emergingthreats.net/blockrules/compromised-ips.txt](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
* Feodo Tracker - [https://feodotracker.abuse.ch/downloads/ipblocklist.csv](https://feodotracker.abuse.ch/downloads/ipblocklist.csv)
* ThreatFox - [https://threatfox.abuse.ch/](https://threatfox.abuse.ch/) - Sharing IOCs associated with malware
* URLhaus - [https://urlhaus.abuse.ch/](https://urlhaus.abuse.ch/) - Malicious URL sharing
* MalwareBazaar - [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/) - Malware sample sharing
* OpenPhish - [https://openphish.com/feed.txt](https://openphish.com/feed.txt)
* SSL Blacklist - [https://sslbl.abuse.ch/blacklist/sslipblacklist.csv](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
* Digital Side - [https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/](https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/)
* FireHOL - [https://iplists.firehol.org/](https://iplists.firehol.org/)

</details>

<details>

<summary>Free (Not in MISP)</summary>

* AlienVault OTX - [https://otx.alienvault.com/](https://otx.alienvault.com/)
  * [https://github.com/AlienVault-OTX/ApiV2](https://github.com/AlienVault-OTX/ApiV2)
* PhishHunt - [https://phishunt.io/](https://phishunt.io/)
* Disposable Email Domains - [https://github.com/ivolo/disposable-email-domains](https://github.com/ivolo/disposable-email-domains)
* FreeMail - [https://github.com/dpup/freemail](https://github.com/dpup/freemail)
* AbuseIPDB - [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
* Stop Forum Spam - [https://www.stopforumspam.com/](https://www.stopforumspam.com/)
* D-Shield - [https://www.dshield.org/xml.html](https://www.dshield.org/xml.html)
* Dan.me.uk - Contains multiple different types of constantly updated block lists
  * Tor Exit Nodes - [https://www.dan.me.uk/tornodes](https://www.dan.me.uk/tornodes)
  * DNS Blacklists - [https://www.dan.me.uk/dnsbl](https://www.dan.me.uk/dnsbl)
* Spamhaus Block Lists - [https://www.spamhaus.org/drop/](https://www.spamhaus.org/drop/)
* ProjectHoneyPot - [https://www.projecthoneypot.org/list\_of\_ips.php](https://www.projecthoneypot.org/list\_of\_ips.php)
* Darkfeed - [https://darkfeed.io/](https://darkfeed.io/)
* Anomali  Limo - [https://www.anomali.com/resources/limo](https://www.anomali.com/resources/limo)
* Uncoder CTI - [https://socprime.com/blog/uncoder-cti-step-by-step-guidelines/](https://socprime.com/blog/uncoder-cti-step-by-step-guidelines/)
* [Rescure](https://rescure.me/) - Curated cyber threat intelligence for everyone
* [https://github.com/executemalware/Malware-IOCs](https://github.com/executemalware/Malware-IOCs)
* Shodan - [https://www.shodan.io/](https://www.shodan.io/) - Search engine for Internet-connected devices (free tier available)
* Censys - [https://censys.io/](https://censys.io/) - Internet-wide scanning and intelligence platform
* GreyNoise - [https://www.greynoise.io/](https://www.greynoise.io/) - Identifies internet scanners and benign activity
* VirusTotal - [https://www.virustotal.com/](https://www.virustotal.com/) - File, URL, and IP reputation service
* Hybrid Analysis - [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/) - Free automated malware analysis
* ANY.RUN - [https://any.run/](https://any.run/) - Interactive malware analysis sandbox
* Joe Sandbox - [https://www.joesandbox.com/](https://www.joesandbox.com/) - Automated malware analysis (free tier)
* URLScan.io - [https://urlscan.io/](https://urlscan.io/) - Service to scan and analyze websites

</details>

<details>

<summary>Premium Feeds</summary>

* CrowdStrike - [https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/](https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/)
* SpamHaus - [https://www.spamhaus.com/product/data-query-service/](https://www.spamhaus.com/product/data-query-service/)
* HashDD - [https://www.hashdd.com/#pricing](https://www.hashdd.com/#pricing)
* Intel471 - [https://intel471.com/products/threat-intelligence/](https://intel471.com/products/threat-intelligence/)
* IntelX - [https://www.sophos.com/en-us/labs/intelix.aspx](https://www.sophos.com/en-us/labs/intelix.aspx)
* TruSTAR (acquired by Splunk) - [https://www.splunk.com/en_us/products/trustar.html](https://www.splunk.com/en_us/products/trustar.html)
* Cymru - [https://team-cymru.com/](https://team-cymru.com/)
* CINS - [https://cinsscore.com/#cins-ati](https://cinsscore.com/#cins-ati)
* FarsightDB - [https://www.farsightsecurity.com/solutions/threat-intelligence-team/newly-observed-domains/](https://www.farsightsecurity.com/solutions/threat-intelligence-team/newly-observed-domains/)
* ThreatStop - [https://www.threatstop.com/threatstop-pricing](https://www.threatstop.com/threatstop-pricing)
* Well-Fed Intelligence -[https://wellfedintelligence.com/](https://wellfedintelligence.com/)
* VirusTotal Intelligence - [https://www.virustotal.com/gui/intelligence-overview](https://www.virustotal.com/gui/intelligence-overview)
* Recorded Future - [https://www.recordedfuture.com/platform/](https://www.recordedfuture.com/platform/)
* Mandiant Advantage - [https://www.mandiant.com/advantage](https://www.mandiant.com/advantage)

</details>

## Deprecated or Archived Tools

The following tools and resources are no longer actively maintained but may still be referenced in historical documentation:

<details>

<summary>Deprecated Tools</summary>

* **CRITs** - [https://github.com/crits/crits](https://github.com/crits/crits) - Collaborative Research Into Threats. Last updated 2018, project is no longer maintained. Consider using OpenCTI, MISP, or TheHive as alternatives.
* **NSA Unfetter Project** - [https://nsacyber.github.io/unfetter/](https://nsacyber.github.io/unfetter/) - Project archived, no longer maintained. Use MITRE ATT&CK Navigator or other gap analysis tools instead.
* **Malware Domain List** - [https://www.malwaredomainlist.com/](https://www.malwaredomainlist.com/) - Site functionality has degraded significantly. Consider using URLhaus, ThreatFox, or other abuse.ch feeds instead.
* **ThreatPost** - [https://threatpost.com/](https://threatpost.com/) - News site was shut down in 2022 after being acquired. Content may be available in archives but is no longer updated.

</details>

## Other Sources and Media

<details>

<summary>Forums and Communities</summary>

* SANS Forums - [https://isc.sans.edu/forums/Diary+Discussions/](https://isc.sans.edu/forums/Diary+Discussions/)
* HackBusters -[https://discuss.hackbusters.com/](https://discuss.hackbusters.com/)
* Reddit
  * r/blueteamsec
  * r/cybersecurity
  * r/hacking
  * r/HowToHack
  * r/Intelligence
  * r/Linux
  * r/kalilinux
  * r/netsec
  * r/pentesting
  * r/redteamsec
  * r/security
  * r/SecurityBlueTeam
  * r/SecurityRedTeam
  * r/threathunting
  * r/AskNetsec
* Discord Communities
  * SANS Discord
  * DFIR Discord
  * BloodHound Gang
  * InfoSec Prep
* Slack Communities
  * BloodHound Slack
  * Threat Hunting Community
  * OSINT Curious
* Mastodon
  * infosec.exchange - Primary cybersecurity Mastodon instance

</details>

<details>

<summary>Podcast/Webcast</summary>

* Darknet Diaries - [https://darknetdiaries.com/](https://darknetdiaries.com/)
* Privacy, Security, and OSINT show - [https://inteltechniques.com/podcast.html](https://inteltechniques.com/podcast.html)
* CyberWire - [https://www.thecyberwire.com/podcasts/](https://www.thecyberwire.com/podcasts/)
* ProofPoint Podcasts - [https://www.proofpoint.com/us/resources/podcast](https://www.proofpoint.com/us/resources/podcast)
* Social-engineer - [https://www.social-engineer.org/category/podcast/](https://www.social-engineer.org/category/podcast/)
* Beers with Talos - [https://blog.talosintelligence.com/](https://blog.talosintelligence.com/2020/08/beers-with-talos-ep-90-hacktivism.html)
* Malicious Life - [https://malicious.life/](https://malicious.life/)
* GIAC - [https://www.giac.org/podcasts](https://www.giac.org/podcasts)
* Security Weekly - [https://securityweekly.com/](https://securityweekly.com/)
* BlackHills Webcasts - [https://www.blackhillsinfosec.com/blog/webcasts/](https://www.blackhillsinfosec.com/blog/webcasts/)

</details>

<details>

<summary>YouTube Channels</summary>

* SANS Cyber Security - [https://www.youtube.com/@SANSCyberSecurity](https://www.youtube.com/@SANSCyberSecurity)
* The Cyber Mentor - [https://www.youtube.com/@TCMSecurityAcademy](https://www.youtube.com/@TCMSecurityAcademy)
* John Hammond - [https://www.youtube.com/@_JohnHammond](https://www.youtube.com/@_JohnHammond)
* 13Cubed - [https://www.youtube.com/@13Cubed](https://www.youtube.com/@13Cubed)
* Black Hills Information Security - [https://www.youtube.com/@BlackHillsInformationSecurity](https://www.youtube.com/@BlackHillsInformationSecurity)
* NetworkChuck - [https://www.youtube.com/@NetworkChuck](https://www.youtube.com/@NetworkChuck)
* IppSec - [https://www.youtube.com/@ippsec](https://www.youtube.com/@ippsec)
* STÖK - [https://www.youtube.com/@STOKfredrik](https://www.youtube.com/@STOKfredrik)

</details>

* **Onion Sites** -  [https://osint.party/api/rss/fresh](https://osint.party/api/rss/fresh) - An amazing RSS feed of fresh and newly discovered .onion sites. Be careful, this feed remains uncensored, so you may encounter illegal content.
* **Twitter Users to Follow** - For high-fidelity, user-created intelligence, follow the curated list of security researchers and analysts at: [https://phishunt.io/community/](https://phishunt.io/community/)
