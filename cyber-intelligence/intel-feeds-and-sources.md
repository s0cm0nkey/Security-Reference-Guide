# Intel Feeds and Sources

## **Intelligence Lifecycle: Understanding depreciation and priority.**

Before we go into the plethora of intelligence sources available, we need to understand a few things about the value of intelligence and its temporal nature.&#x20;

The first thing we should understand is that not all indicators are created equal, and that they should have a priority or a weighting associated with them. Some indicators will naturally have a stronger indication of the presence of an attack than others. Consider comparing the hash of a known piece of malware, versus an IP address of an known malicious scanner. The detection of the former demonstrates the presence of a known malicious object, and an action that is farther in any attack chain. The detecting the latter does not mean that malicious intent was detected, simple interaction with an indicator that COULD do something malicious. More data would be needed here to confirm if there is an attack or not. So, those two indicators would have different priorities based on the fidelity of the indicator, the amount of other data/correlation needed to confirm an attack, and the phase of an attack chain indicated by the indicator.

The second thing we must understand is the time element associated with an indicator. Indicators fidelity and priority depreciate overtime. The farther we get from both the initial date of reporting as well as as the last time the indicator was seen by any form of detection, the lower the chance that the indicator is still valid. As above, this is especially so with indicators that can change frequently like IP addresses. Indicators like hash values are so unique, they still mostly valid after a long period of time.

{% embed url="https://www.youtube.com/watch?v=J7e74QLVxCk" %}

## **Indicator Standards and Formats**

* ****[**Oasis**](https://www.oasis-open.org/) **Suite -** Oasis is a non-profit standardization organization that manages the [standards](https://www.oasis-open.org/committees/tc\_home.php?wg\_abbrev=cti) for multiple intelligence feed formats.
  * ****[**STIX**](https://stixproject.github.io/) **** - Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI). STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.
    * [https://oasis-open.github.io/cti-documentation/stix/intro](https://oasis-open.github.io/cti-documentation/stix/intro)
    * ****[**CyBOX**](https://cyboxproject.github.io/) **-** An older standard that has been subsequently absorbed into the STIX standard.
  * ****[**TAXII**](https://taxiiproject.github.io/) **-** Trusted Automated Exchange of Intelligence Information (TAXII™) is an application layer protocol for the communication of cyber threat information in a simple and scalable manner. TAXII is a protocol used to exchange cyber threat intelligence (CTI) over HTTPS. TAXII enables organizations to share CTI by defining an API that aligns with common sharing models.TAXII is specifically designed to support the exchange of CTI represented in STIX.
    * [https://oasis-open.github.io/cti-documentation/taxii/intro](https://oasis-open.github.io/cti-documentation/taxii/intro)

## **Daily Checkers/Round-ups**

Parsing through intel sources is a daily task for an intelligence analyst. To make things easier than having 100+ tabs open for every source, we can use RSS feeds to centralize all of the articles into one place. [Feedly](https://feedly.com) is my RSS feed platform of choice. The free option allows you to ingest 100+ sources all in one feed. It even has a preset collection of feeds focusing on cyber security. One thing that these feeds cannot do is bring in items like tweets and Reddit posts. For those, we can turn to a handy tool written by Hackerpom. His [intel feed tool ](https://www.hackerpom.com/feed)adds some of the top intel sources to a list of relevant tweets and reddit posts.

Beyond the daily checkers, regular parsing of "Round-up" style blogs are super handy for condensing some of the popular topics and can grab a few interesting notes that other tools do not.

* [https://blog.badsectorlabs.com/](https://blog.badsectorlabs.com/)
* [https://sec.today/pulses/](https://sec.today/pulses/)
* [https://thisweekin4n6.com/](https://thisweekin4n6.com/)
* [https://latesthackingnews.com/](https://latesthackingnews.com/)
* [https://security-soup.net/tag/news/](https://security-soup.net/tag/news/)a

## Intelligence Tools and Resources

<details>

<summary>Intel Resource Collections</summary>

* [Awesome Lists Collection: Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
* [Awesome Lists Collection: IOCs](https://github.com/sroberts/awesome-iocs)
* [Awesome Lists Collection: Security Feeds](https://github.com/mrtouch93/awesome-security-feed)

</details>

### Indicator Gathering and Enrichment Tools

These are tools for collecting, enriching, and shareing threat indicators. Most are open source and focus on indicator sharing within the cyber community and flexibility to work with a wide array of tools that might use the data.

<details>

<summary>Indicator Gathering and Enrichment Tools</summary>

* [CSIRTGadget's CIF: Collective Intelligence Framework](https://csirtgadgets.com/collective-intelligence-framework) - Pulls feeds from multiple locations and makes them available for other systems to use for lookup or enrichment.
* [Yeti](https://github.com/yeti-platform/yeti) - Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository.
* [IntelOWL](https://github.com/intelowlproject/IntelOwl) - Intel Owl is an Open Source Intelligence, or OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale.
* [S-TIP](https://github.com/s-tip) - S-TIP is a threat intelligence platform to bring down barriers among separate practices of CTI sharing.
* [OpenCTI](https://github.com/OpenCTI-Platform/opencti) - OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables
* [Harpoon](https://github.com/Te-k/harpoon) - OSINT / Threat Intel CLI tool.
* [Threat Dragon](https://github.com/mike-goodwin/owasp-threat-dragon-desktop) - Threat Dragon is a free, open-source, cross-platform [threat modeling](https://owasp.org/www-community/Threat\_Modeling) application including system diagramming and a rule engine to auto-generate threats/mitigations.
* [IoC Ingester ](https://github.com/ninoseki/iocingestor)- An extendable tool to extract and aggregate IoCs from threat feeds.
* [IoC Parser](https://github.com/armbues/ioc\_parser) - IOC Parser is a tool to extract indicators of compromise from security reports in PDF format
* [cti](https://github.com/mitre/cti) - Cyber Threat Intelligence Repository expressed in STIX 2.0
* [TALR](https://github.com/SecurityRiskAdvisors/TALR) - A public repository for the collection and sharing of detection rules in STIX format.
* [github.com/crits/crits](https://github.com/crits/crits) - CRITs - Collaborative Research Into Threats

</details>

### MISP

[**MISP**](https://www.misp-project.org/)**:** The Malware Information Sharing Platform - The MISP threat sharing platform is a free and open source software helping information sharing of threat intelligence including cyber security indicators. This tool has the ability to ingest a large number of indicator feeds, enrich indicators, and funnel them into other platforms. It comes with a large array of feeds that come default in the platform, all of which have a high degree of fidelity. Best of all, it comes with modules that allow it to integrate with a slew of other platforms and technologies.

<details>

<summary>MISP Resources</summary>

* MISP Github - [https://github.com/MISP/MISP](https://github.com/MISP/MISP)
* MISP Modules - [https://github.com/MISP/misp-modules](https://github.com/MISP/misp-modules)
* MISP Splunk App - [https://splunkbase.splunk.com/app/4335/](https://splunkbase.splunk.com/app/4335/)
* CIRC/LU User Guide - [https://www.circl.lu/doc/misp/book.pdf](https://www.circl.lu/doc/misp/book.pdf)
* [https://www.recordedfuture.com/misp-integration-overview/](https://www.recordedfuture.com/misp-integration-overview/)
* [https://www.circl.lu/assets/files/infosharing.pdf](https://www.circl.lu/assets/files/infosharing.pdf)
* [https://www.sans.org/webcasts/sharing-alerts-threat-intelligence-misp-110000](https://www.sans.org/webcasts/sharing-alerts-threat-intelligence-misp-110000)
* [https://www.sans.org/webcasts/friend-creating-threat-intelligence-capability-103532](https://www.sans.org/webcasts/friend-creating-threat-intelligence-capability-103532)

</details>

{% embed url="https://www.youtube.com/watch?app=desktop&v=00jq7Gbqdz8" %}

## Intelligence News Feeds

<details>

<summary>Government Feeds</summary>

* FBI Infragaurd - [https://www.infragard.org/](https://www.infragard.org/)
* CISA
  * Current Activity - [https://us-cert.cisa.gov/ncas/current-activity](https://us-cert.cisa.gov/ncas/current-activity)
  * Bullitins - [https://us-cert.cisa.gov/ncas/bulletins/2020](https://us-cert.cisa.gov/ncas/bulletins/2020)
  * Ammouncements - [https://us-cert.cisa.gov/announcements](https://us-cert.cisa.gov/announcements)
* IC3 News Releases -[https://www.ic3.gov/](https://www.ic3.gov/)
* Various ISAC - Find an ISAC in your sector

</details>

<details>

<summary>Intel Platforms</summary>

* IBM X-Force - [https://exchange.xforce.ibmcloud.com/](https://exchange.xforce.ibmcloud.com/)
* ThreatConnect - [https://app.threatconnect.com/auth/index.xhtml#/](https://app.threatconnect.com/auth/index.xhtml#/)
* AlienVault - [https://otx.alienvault.com/browse/global?q=\&include\_inactive=0\&sort=-modified\&page=1\&indicatorsSearch=modified:%22%22](https://otx.alienvault.com/browse/global?q=\&include\_inactive=0\&sort=-modified\&page=1\&indicatorsSearch=modified:%22%22)

</details>

<details>

<summary>Cyber News</summary>

* Threat Post - [https://threatpost.com/](https://threatpost.com/)
* PacketStorm -[https://packetstormsecurity.com/](https://packetstormsecurity.com/)
* Hacker News - [https://thehackernews.com/](https://thehackernews.com/)
* Zero Day  - [https://www.zdnet.com/blog/security/](https://www.zdnet.com/blog/security/)
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

* FireEye - [https://www.fireeye.com/blog/threat-research.html](https://www.fireeye.com/blog/threat-research.html)
* Sophos -[https://news.sophos.com/en-us/](https://news.sophos.com/en-us/)
* SecureList - [https://securelist.com/](https://securelist.com/)
* MalwareBytes Blog -[https://blog.malwarebytes.com/](https://blog.malwarebytes.com/)
* Google Project Zero - [https://googleprojectzero.blogspot.com/](https://googleprojectzero.blogspot.com/)
* ClearSky Blog - [https://www.clearskysec.com/blog/](https://www.clearskysec.com/blog/)
* CheckPoint Research - [https://research.checkpoint.com/](https://research.checkpoint.com/)
* Cisco Talos Research - [https://blogs.cisco.com/security/talos](https://blogs.cisco.com/security/talos)
* Cisco Talos Blog -[https://blog.talosintelligence.com/](https://blog.talosintelligence.com/)
* Fortigaurd ThreatBrief - [https://www.fortiguard.com/resources/threat-brief](https://www.fortiguard.com/resources/threat-brief)
* Unit42 - [https://unit42.paloaltonetworks.com/](https://unit42.paloaltonetworks.com/)\\
* TrendMicro Research - [https://www.trendmicro.com/en\_us/research.html](https://www.trendmicro.com/en\_us/research.html)
* Malware-Traffic-Analysis - [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
* CrowdStike Intel -[https://www.crowdstrike.com/blog/category/threat-intel-research/](https://www.crowdstrike.com/blog/category/threat-intel-research/)
* JP Cert - [https://blogs.jpcert.or.jp/en/](https://blogs.jpcert.or.jp/en/)
* Sans ISC Diary - [https://isc.sans.edu/diaryarchive.html?year=2021\&month=1](https://isc.sans.edu/diaryarchive.html?year=2021\&month=1)
* Cryptolaemus - [https://paste.cryptolaemus.com/](https://paste.cryptolaemus.com/)
* Uptycs - [https://www.uptycs.com/blog/tag/threat-research](https://www.uptycs.com/blog/tag/threat-research)

</details>

<details>

<summary>Solo Researcher Blogs</summary>

* Krebs on Security - [https://krebsonsecurity.com/](https://krebsonsecurity.com/)
* Schnier on Security - [https://www.schneier.com/](https://www.schneier.com/)
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



### Corporate Security Blogs

* TrendMicro - [https://blog.trendmicro.com/](https://blog.trendmicro.com/)
* Microsoft - [https://msrc-blog.microsoft.com/](https://msrc-blog.microsoft.com/)
* DomainTools -[https://www.domaintools.com/resources/blog?category=domaintools-research\&authors=](https://www.domaintools.com/resources/blog?category=domaintools-research\&authors=)
* ProofPoint - [https://www.proofpoint.com/us/blog](https://www.proofpoint.com/us/blog)
* Zscalar - [https://www.zscaler.com/blogs/security-research](https://www.zscaler.com/blogs/security-research)
* SecureWorks - [https://www.secureworks.com/blog](https://www.secureworks.com/blog)
* Digital Shadows - [https://www.digitalshadows.com/blog-and-research/](https://www.digitalshadows.com/blog-and-research/)
* Recorded Future - [https://www.recordedfuture.com/blog/](https://www.recordedfuture.com/blog/)
* Hiemdall Sec - [https://heimdalsecurity.com/blog/posts/](https://heimdalsecurity.com/blog/posts/)
* Morphisec - [https://blog.morphisec.com/](https://blog.morphisec.com/)
* Imperva - [https://www.imperva.com/blog/](https://www.imperva.com/blog/)
* Tenable - [https://www.tenable.com/blog](https://www.tenable.com/blog)\
  PhishLabs - [https://info.phishlabs.com/blog](https://info.phishlabs.com/blog)
* Google Blog - [https://security.googleblog.com/](https://security.googleblog.com/)
* Cofense - [https://cofense.com/blog/](https://cofense.com/blog/)
* Fortinet -[https://www.fortinet.com/blog](https://www.fortinet.com/blog)
* SpectreOps - [https://posts.specterops.io/?gi=c476d247e3c8](https://posts.specterops.io/?gi=c476d247e3c8)
* VirusBulliten - [https://www.virusbulletin.com/blog/](https://www.virusbulletin.com/blog/)
* Anomali - [https://www.anomali.com/blog](https://www.anomali.com/blog)
* Intezer - [https://www.intezer.com/blog/](https://www.intezer.com/blog/)
* Verisign - [https://blog.verisign.com/](https://blog.verisign.com/)
* Virustotal - [https://blog.virustotal.com/](https://blog.virustotal.com/)
* WeLiveSecurity - [https://www.welivesecurity.com/research/](https://www.welivesecurity.com/research/)
* TrustedSec - [https://www.trustedsec.com/blog/](https://www.trustedsec.com/blog/)
* Symantec - [https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence)
* Avast - [https://blog.avast.com/topic/security-news](https://blog.avast.com/topic/security-news)
* TrustWave -[https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/)
* ReversingLabs -[https://blog.reversinglabs.com/blog](https://blog.reversinglabs.com/blog)
* Rapid7 - [https://blog.rapid7.com/tag/research/](https://blog.rapid7.com/tag/research/)
* Security Trails - [https://securitytrails.com/blog](https://securitytrails.com/blog)
* Advanced Intel - [https://www.advanced-intel.com/blog](https://www.advanced-intel.com/blog)
* Scythe - [https://www.scythe.io/threatthursday](https://www.scythe.io/threatthursday)
* McAfee - [https://www.mcafee.com/blogs/](https://www.mcafee.com/blogs/)

### **New Cyber Tool Blogs**

* [https://www.darknet.org.uk/](https://www.darknet.org.uk/)
* [https://www.toolswatch.org/](https://www.toolswatch.org/)
* [https://www.kitploit.com/](https://www.kitploit.com/)
* [https://packetstormsecurity.com/files/tags/tool/](https://packetstormsecurity.com/files/tags/tool/)
* [https://hakin9.org/blog-2/](https://hakin9.org/blog-2/)

## IoC Feeds

### Free (In MISP)

MISP has over 30 default feeds and growing. Below are some of the most popular. For more information on which feeds are in MISP, see here: [https://www.misp-project.org/feeds/](https://www.misp-project.org/feeds/)

* CIRC.LU - [https://www.circl.lu/doc/misp/feed-osint/](https://www.circl.lu/doc/misp/feed-osint/)
* Botvrj - [https://www.botvrij.eu/data/feed-osint/](https://www.botvrij.eu/data/feed-osint/)
* Emerging Threats - [https://rules.emergingthreats.net/blockrules/compromised-ips.txt](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
* Feodo - [https://feodotracker.abuse.ch/downloads/ipblocklist.csv](https://feodotracker.abuse.ch/downloads/ipblocklist.csv)
* OpenPhish - [https://openphish.com/feed.txt](https://openphish.com/feed.txt)
* Abuse CH - [https://sslbl.abuse.ch/blacklist/sslipblacklist.csv](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
* Digital Side - [https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/](https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/)
* FireHOL - [https://iplists.firehol.org/](https://iplists.firehol.org/)

### Free (Not in MISP)

* AlienVault OTX - [https://otx.alienvault.com/](https://otx.alienvault.com/)
  * [https://github.com/AlienVault-OTX/ApiV2](https://github.com/AlienVault-OTX/ApiV2)
* PhishHunt - [https://phishunt.io/](https://phishunt.io/)
* Disposable Email Domains - [https://github.com/ivolo/disposable-email-domains](https://github.com/ivolo/disposable-email-domains)
* FreeMail - [https://github.com/dpup/freemail](https://github.com/dpup/freemail)
* AbuseIPDB - [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
* Stop Forum Spam - [https://www.stopforumspam.com/](https://www.stopforumspam.com/)
* D-Shield - [https://www.dshield.org/xml.html](https://www.dshield.org/xml.html)
* Malware Domain List - [https://www.malwaredomainlist.com/](https://www.malwaredomainlist.com/)
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

### Premium

* CrowdStrike - [https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/](https://www.crowdstrike.com/endpoint-security-products/falcon-x-threat-intelligence/)
* SpamHaus - [https://www.spamhaus.com/product/data-query-service/](https://www.spamhaus.com/product/data-query-service/)
* HashDD - [https://www.hashdd.com/#pricing](https://www.hashdd.com/#pricing)
* Intel471 - [https://intel471.com/products/threat-intelligence/](https://intel471.com/products/threat-intelligence/)
* IntelX - [https://www.sophos.com/en-us/labs/intelix.aspx](https://www.sophos.com/en-us/labs/intelix.aspx)
* Trustar - [https://www.trustar.co/integrations?type=premium-intelligence](https://www.trustar.co/integrations?type=premium-intelligence)
* Cymru - [https://team-cymru.com/](https://team-cymru.com/)
* CINS - [https://cinsscore.com/#cins-ati](https://cinsscore.com/#cins-ati)
* FarsightDB - [https://www.farsightsecurity.com/solutions/threat-intelligence-team/newly-observed-domains/](https://www.farsightsecurity.com/solutions/threat-intelligence-team/newly-observed-domains/)
* ThreatStop - [https://www.threatstop.com/threatstop-pricing](https://www.threatstop.com/threatstop-pricing)
* Well-Fed Intelligence -[https://wellfedintelligence.com/](https://wellfedintelligence.com/)

## Other Sources and Media

* &#x20;[https://osint.party/api/rss/fresh](https://osint.party/api/rss/fresh) - An amazing RSS feed of fresh and newly discovered .onion sites. Be careful, this feed remains uncensored, so you may encounter illegal content.

### Twitter Feeds

* Lets make it easy. Sub to everyone on this list for raw, user created intel with a high level of fidelity. [https://phishunt.io/community/](https://phishunt.io/community/)

### Forum

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

### Podcast/Webcast

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
