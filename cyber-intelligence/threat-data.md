---
description: Is this bad?
---

# Threat Data

## Intro

When investigating the reputation and threat data behind an indicator, there are two main components: checking for the presence of the indicator on available blacklists and enriching your investigation with intelligence and metadata around the target indicator.

When checking your indicators against the sources below, be sure to examine all available data beyond the blacklist check. Tools like Hurricane Electric and Cisco Talos can provide information about the ASN or subnet an indicator is a part of. Use them to determine if not just one IP is flagged, but whether an entire subnet or ASN is compromised. For domains, review registration information and registration dates. When was that domain registered? Have you encountered malicious domains registered by this user before? Always examine any related data, even if it's as simple as the comments section of VirusTotal. Other analysts can save you considerable time by sharing insights through simple notes.

**⚠️ WARNING**: An indicator can still be malicious even if it does not appear on any searched blacklists. Never assume an indicator is benign simply because your searches returned no results. Absence of evidence is not evidence of absence.

## Threat Maps

Threat maps provide real-time visualizations showing volume trends in traffic and detected cyber attacks mapped to geographic locations worldwide. These dashboards offer valuable situational awareness and can be useful for monitoring global threat patterns and identifying emerging attack trends.

<details>

<summary>Threat Maps</summary>

* [https://threatmap.bitdefender.com](https://threatmap.bitdefender.com)
* [https://cybermap.kaspersky.com](https://cybermap.kaspersky.com)
* [https://www.digitalattackmap.com](https://www.digitalattackmap.com) - **Note: This service has been discontinued.**
* [Mandiant Cyber Threat Map](https://www.mandiant.com/resources/cyber-threat-map) - (Previously FireEye)
* [https://map.lookingglasscyber.com](https://map.lookingglasscyber.com)
* [https://threatmap.checkpoint.com](https://threatmap.checkpoint.com)
* [https://talosintelligence.com/reputation\_center/](https://talosintelligence.com/reputation\_center/)
* [https://talosintelligence.com/fullpage\_maps/](https://talosintelligence.com/fullpage\_maps/)
* [https://www.spamhaus.com/threat-map/](https://www.spamhaus.com/threat-map/)
* [https://www.imperva.com/cyber-threat-attack-map/](https://www.imperva.com/cyber-threat-attack-map/)
* [https://threatbutt.com/map/](https://threatbutt.com/map/)
* [https://threatmap.fortiguard.com](https://threatmap.fortiguard.com)
* [Sophos Threat Dashboard](https://www.sophos.com/en-us/threat-center)
* [https://horizon.netscout.com](https://horizon.netscout.com)
* [https://securitycenter.sonicwall.com/m/page/worldwide-attacks](https://securitycenter.sonicwall.com/m/page/worldwide-attacks)

</details>

## Threat Actor Information

Major threat actors are continuously researched to build comprehensive intelligence profiles. This ongoing analysis aids in identifying future attacks, understanding threat actor tactics, techniques, and procedures (TTPs), and providing accurate attribution.

<details>

<summary>Threat Actor Information</summary>

* [https://darkfeed.io/ransomwiki/](https://darkfeed.io/ransomwiki/) - A researcher-focused site that tracks and provides links to various ransomware group dark web sites.
* [Ransomware Group Site](http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion/) - An onion site providing links and details about active ransomware groups.
  * [Clearnet Proxy](http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion.pet/)
* [Crowdstrike E-Crime Index](https://adversary.crowdstrike.com/en-US/ecrime-index-ecx/?L=236)
* [https://malpedia.caad.fkie.fraunhofer.de/](https://malpedia.caad.fkie.fraunhofer.de/) - A resource for rapid identification and actionable context when investigating malware.

</details>

## Infrastructure Search Engines

Internet-connected device search engines provide valuable reconnaissance data by scanning and indexing exposed services, devices, and vulnerabilities across the internet. These platforms are essential for identifying infrastructure associated with threats.

<details>

<summary>Infrastructure Search Engines</summary>

* [Shodan](https://www.shodan.io/) - The world's first search engine for Internet-connected devices, providing information on exposed services, ICS/SCADA systems, and misconfigured devices.
* [Censys](https://search.censys.io/) - Internet-wide scanning platform providing data on hosts, certificates, and websites with extensive filtering capabilities.
* [BinaryEdge](https://www.binaryedge.io/) - Internet scanning platform with threat intelligence data, open port detection, and vulnerability information.
* [FOFA](https://fofa.info/) - Cyberspace search engine with advanced filtering for identifying internet assets and exposed services.
* [ZoomEye](https://www.zoomeye.org/) - Cyberspace search engine by Knownsec, indexing devices and web services worldwide.
* [Onyphe](https://www.onyphe.io/) - Cyber defense search engine collecting open-source and cyber threat intelligence data.
* [FullHunt](https://fullhunt.io/) - Attack surface database providing exposure discovery and reconnaissance data.

</details>

## **Blacklist Checks and Reputation Data**

<details>

<summary>Multi - Blacklist Checkers</summary>

* [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
  * Searches: IP address, Domain, ASN, Subnet
  * Returns: IP information, WHOIS, DNS (A records), Reputation Check ( IP Only - 93 sources), Website info, Website Preview
* [Virustotal](https://www.virustotal.com/)
  * Searches: File, hash, ip, domain search
  * Returns: Reputation check (84 sources), DNS records, HTTPS Cert, WHOIS, Related domains, Community comments
  * Has a premium API
  * [https://virustotal.com/wargame/ ](https://virustotal.com/wargame/)- Virustotal training!
  * [https://github.com/Neo23x0/vti-dorks](https://github.com/Neo23x0/vti-dorks) - VirusTotal Dorking
* [Cisco Talos](https://talosintelligence.com/reputation\_center)
  * Searches: IP and Domain data
  * Returns: Reputation check, content details, mail servers, owner details, Subnet reputation details, WHOIS, email volume history, Top Network owners
* [MXtoolbox Blacklist checker](https://mxtoolbox.com/blacklists.aspx)
  * Search: Domain, IP address
  * Returns: Reputation data (94 blacklists)
* [MultiRBL](http://multirbl.valli.org/lookup/)
  * Searches: IP, domain
  * Returns: FCrDNS Test data, Reputation data (242 blacklist checks)
* [https://www.infobyip.com/ipbulklookup.php](https://www.infobyip.com/ipbulklookup.php) - (Honorable Mention) - A great tool that allows you to take a bulk list of IP addresses or Domains and check them for the presence on blacklists.

</details>

<details>

<summary>IP Reputation data</summary>

* [IPVoid](https://www.ipvoid.com/ip-blacklist-check/) - Returns: Reputation data (115 sources checked), Reverse DNS, ASN, Country
* [DNSBL Email server spam checker](https://www.dnsbl.info/) - Checks IP of mail server for spam data across 100+ blacklists
* [IPSpam List](http://www.ipspamlist.com/ip-lookup/) - Checks IP against their internal blacklist for reporting spam
* [Cymru IP Reputation Lookup](https://reputation.team-cymru.com/) - Checks IP against Cymru's internal reputation feed (High quality)
* [http://www.blocklist.de/en/search.html](http://www.blocklist.de/en/search.html) - Check if a netblock or IP is malicious according to blocklist.de.
* [https://www.projecthoneypot.org/search\_ip.php](https://www.projecthoneypot.org/search\_ip.php) - Checks IP Attack data from distributed honeypot network.
* [https://focsec.com/](https://focsec.com/) (API ONLY) - Determine if a user’s IP address is associated with a VPN, Proxy, TOR or malicious bots.
* [https://www.ipqualityscore.com/ip-reputation-check](https://www.ipqualityscore.com/ip-reputation-check) - Use this free tool to accurately **check IP Reputation** using leading IP address intelligence. **Lookup IP reputation history** which could indicate SPAM issues, threats, or elevated IP fraud scores that could be causing your IP address to be blocked and blacklisted.
  * [https://www.ipqualityscore.com/vpn-ip-address-check](https://www.ipqualityscore.com/vpn-ip-address-check) - Use this tool to perform a **VPN detection test** on any IP address. Lookup any IP addresses that recently allowed VPN activity or functioned as a Virtual Private Network.

</details>

<details>

<summary>URL/Domain Reputation data</summary>

* [URLScan ](https://urlscan.io/) - Returns: Summary data, Reputation data, IP data, domain tree, HTTP transaction data, Screenshot of page, Detected Technologies, links
* [URLVoid](https://www.urlvoid.com/)  - Returns Reputation data (34 sources), Registration info, WHOIS, Reverse DNS, ASN
* [Zscaler Zulu](https://zulu.zscaler.com/) - Returns: URL info, Risk analysis, Content, URL checks, Host checks
* [PhishTank](https://www.phishtank.com/) - Community-driven phishing site database. Returns: Phishing verification status, submission details, and related information
* [Quttera Malware Scanner ](https://quttera.com/website-malware-scanner)- Returns: Website malware scan report
* [MergiTools RBL check](https://megritools.com/blacklist-lookup) - Returns: Reputation data&#x20;
* [Malware Domain Lists](http://www.malwaredomainlist.com/mdl.php?search=\&colsearch=All\&quantity=50) - **Note: This service appears to be no longer actively maintained.** Returns: Reputation data&#x20;
* [Sucuri SiteCheck](https://sitecheck.sucuri.net/) - Returns: Security check and malware scan
* [https://lots-project.com/](https://lots-project.com/) - Living Off Trusted Sites (LOTS) Project, Attackers are using popular legitimate domains when conducting phishing, C\&C, exfiltration and downloading tools to evade detection. The list of websites below allow attackers to use their domain or subdomain.
* [https://reports.adguard.com/en/welcome.html](https://reports.adguard.com/en/welcome.html) - Checks if site is on AdGuard's block list

</details>

<details>

<summary>File Hash Reputation Data</summary>

* [Cisco Talos File Reputation ](https://talosintelligence.com/talos\_file\_reputation)- SHA256 Only
* [Abuse\[.\]ch Malware Bazaar ](https://bazaar.abuse.ch/browse/)- Searches MD5, SHA256, and Keyword
  * Returns: Hash, tag, file type, clamAV signature, Yara rule, misc.
* [Cymru MHR lookup](https://hash.cymru.com/) - Searches MD5, SHA-1, and SHA-256
* [CIRCL Hashlookup](https://hashlookup.circl.lu/) - A super handy API hash lookup from the creators of MISP. Takes MD5, SHA-1, and SHA-256.
* [Xcitium Valkyrie](https://valkyrie.comodo.com/) - (Previously Comodo Valkyrie) SHA-1 and SHA-256 support. Returns: File name, submit date, threat verdict by dynamic and human analysis.

</details>

<details>

<summary>File Analysis & Sandboxing Platforms</summary>

* [Hybrid Analysis](https://www.hybrid-analysis.com/) - Free malware analysis service powered by Falcon Sandbox, providing detailed behavioral analysis and threat scoring.
* [ANY.RUN](https://app.any.run/) - Interactive malware analysis sandbox allowing real-time interaction with samples in isolated environments.
* [Joe Sandbox](https://www.joesandbox.com/) - Deep malware analysis platform with comprehensive behavioral analysis and reporting.
* [Triage](https://tria.ge/) - Automated malware analysis sandbox by Hatching with fast analysis and detailed reports.
* [Intezer Analyze](https://analyze.intezer.com/) - Genetic malware analysis platform that identifies code reuse and similarities to known threats.
* [Cuckoo Sandbox](https://cuckoosandbox.org/) - Open-source automated malware analysis system.
* [VirusTotal](https://www.virustotal.com/) - Already listed above but also provides sandboxed file execution analysis.
* [UnpacMe](https://www.unpac.me/) - Automated malware unpacking service for analyzing packed samples.

</details>

<details>

<summary>Email/Spam Data</summary>

* [Simple Email Rep checker](https://emailrep.io/) - Returns: Domain reputation, presence on social media, Blacklisted/Malicious activity, Email policy settings
* [MXtoolbox MX lookup](https://mxtoolbox.com/MXLookup.aspx) and [Super tool ](https://mxtoolbox.com/SuperTool.aspx)-  Returns: Host information, DMARC and DNS record data, Pivot to Blacklist check
* [HaveIBeenEmotet](https://www.haveibeenemotet.com/) - **Note: Emotet was disrupted in 2021 but has reemerged.** Returns: If your email address or domain is involved in the Emotet malspam.

</details>

## **Indicator Enrichment**

While these resources may not specifically return reputation data, they leverage internet scanning services, global traffic metadata, and indicator enrichment platforms to provide valuable context for threat intelligence investigations. This additional context is crucial for comprehensive indicator analysis.&#x20;

{% content-ref url="osint/cyber-search.md" %}
[cyber-search.md](osint/cyber-search.md)
{% endcontent-ref %}

<details>

<summary>Indicator Enrichment Tools</summary>

* [Greynoise](https://viz.greynoise.io/)
  * Searches: IP address, domain
  * Returns: Reputation data, tags of related activity, location data, “last-seen”, reverse DNS, Threat Actor Information, Related Organizations, Related ASNs, Top Operating Systems, service type
  * Premium API available, command line version available
  * [Community API (Free)](https://developer.greynoise.io/reference/community-api)
  * [https://www.greynoise.io/viz/cheat-sheet](https://www.greynoise.io/viz/cheat-sheet)
  * [https://github.com/GreyNoise-Intelligence/pygreynoise](https://github.com/GreyNoise-Intelligence/pygreynoise)
  * _Operator Handbook: Greynoise - pg. 84_
* [BrightCloud URL/IP Lookup](https://brightcloud.com/tools/url-ip-lookup.php)
  * Searches: IP address, domain, URL
  * Returns: Web Reputation score, Web category classification, threat information
* [ThreatCrowd](https://www.threatcrowd.org/) - **Note: This service is deprecated. Data has been migrated to AlienVault OTX.**
  * Searches: Domain, IP, Email, Organization
  * Returns: Reputation data, WHOIS, Reverse DNS, Open Ports, Subdomains, Related Entity Graph, pivot search to AlienVault OTX indicator information
* [AbuseIPDB](https://www.abuseipdb.com/)
  * Searches: IP, Subnet (CIDR notation)
  * Returns: Reputation data, abuse confidence score, usage type, location info, recent reports
* [SANS D-Shield](https://secure.dshield.org/)
  * Searches: Keyword, IP, domain, Port, Header
  * Returns: General information, Reputation data, SSH logs, Honeypot logs, WHOIS
* [Abuse\[.\]ch ThreatFox IOC library](https://threatfox.abuse.ch/browse/)
  * Search: IoCs (ip, domain, hash, etc.)
  * Returns: date, IoC, malware family, Tags, Reporter
* [Spamhaus Project](https://check.spamhaus.org/)
  * Searches: IP, Domain
  * Returns: Reputation data, blacklist status (SBL, XBL, DBL, etc.)
* [ThreatInteligencePlatform.com](https://threatintelligenceplatform.com)
  * Searches: IP, Domain, Hash
  * Returns: Reputation Data, Web site data, Open Ports, SSL Certificate data, Malware Detection, WHOIS, MX records and config, NS records and config
* [OPSWAT Metadefender](https://metadefender.opswat.com/?lang=en)
  * Searches: File, URL, IP, Domain, Hash, CVE
  * Returns: Any detection from multiple other engines with link to that engines data.
* [Microsoft Defender Threat Intelligence Articles](https://community.riskiq.com/home) - (Previously RiskIQ)
  * Searches: Domain, Hosts, IP, Email, Hash, Tags
  * Returns: Associated intelligence article containing the searched for indicator
* [PulseDive](https://pulsedive.com/)
  * Searches: Indicators, Threats, Feeds, Misc. data
  * Returns: Risk Info, Highlights, Ports, Threat info, Reputation data, Linked Indicators
* [Malc0de database](https://malc0de.com/database/)
  * Searches: IP, domain, hash, ASN
  * Returns: Malware information, IP/domain reputation data, and related indicators
* [ThreatShare](https://threatshare.io/malware/)
  * Searches: IP, URL
  * Returns: malware family, online status, URLscan data
* [Phishstats](https://phishstats.info/) (Public Dashboard 2)
  * Searches: IP, host, domain, full URL
  * Returns: Related metadata and reputation data.
* [TweetTIOC](http://tweettioc.com/) - A powerful tool that scrapes X (formerly Twitter) for IoCs that are publicly reported through the platform and aggregates them into a searchable repository. Socially-sourced IoCs are one of the fastest ways to obtain information on newly discovered indicators, as they often include context around their discovery.
* [https://lookup.abusix.com/](https://lookup.abusix.com/)
  * Search: IP, domain, or email address
  * Returns: Presence on internal blocklist and misc available detail.
* [https://cleantalk.org/#](https://cleantalk.org)
  * Search: IP Addresses, Email, Subnet, Domain
  * Returns: Presence on internal blocklist for spam activity

</details>

<details>

<summary>Passive DNS & Historical Data</summary>

* [SecurityTrails](https://securitytrails.com/) - Historical DNS data, WHOIS records, subdomain discovery, and IP history with extensive API.
* [Microsoft Defender Threat Intelligence](https://ti.defender.microsoft.com/) - (Previously RiskIQ/PassiveTotal) - Microsoft's threat intelligence platform providing passive DNS, WHOIS, SSL certificates, and threat intelligence. Community edition available at [community.riskiq.com](https://community.riskiq.com/)
* [Farsight DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/) - World's largest passive DNS database for historical DNS query analysis.
* [DNSHistory.org](https://dnshistory.org/) - Free historical DNS lookup service showing domain resolution history.
* [WhoisXMLAPI](https://www.whoisxmlapi.com/) - Historical WHOIS data and DNS records with comprehensive API access.
* [ViewDNS.info](https://viewdns.info/) - Free DNS and network tools including historical data and reverse lookups.
* [DNSTrails](https://dnstrails.com/) - Historical DNS data and passive DNS database.

</details>

<details>

<summary>Certificate Transparency & SSL/TLS Analysis</summary>

* [crt.sh](https://crt.sh/) - Certificate transparency log search engine for discovering certificates and subdomains.
* [Censys Certificates](https://search.censys.io/certificates) - Certificate search with extensive filtering on certificate fields and metadata.
* [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) - Comprehensive SSL/TLS configuration analysis and grading.
* [SSLShopper Tools](https://www.sslshopper.com/ssl-checker.html) - SSL certificate verification and chain analysis tools.
* [Certificate Search](https://certificatesearch.com/) - Multi-source certificate transparency log search.
* [Google Transparency Report](https://transparencyreport.google.com/https/certificates) - Google's certificate transparency search interface.

</details>

<details>

<summary>Threat Intelligence Platforms & Exchanges</summary>

* [MISP Project](https://www.misp-project.org/) - Open-source threat intelligence platform for sharing, storing, and correlating IoCs.
* [AlienVault OTX](https://otx.alienvault.com/) - Open Threat Exchange for collaborative threat intelligence sharing.
* [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) - Cloud-based threat intelligence sharing platform with extensive threat data.
* [ThreatConnect](https://threatconnect.com/) - Threat intelligence platform with aggregation, analysis, and orchestration capabilities.
* [Anomali Platform](https://www.anomali.com/products) - Threat intelligence platform with automated enrichment and integration (includes ThreatStream functionality).
* [OpenCTI](https://www.opencti.io/) - Open-source cyber threat intelligence platform built on STIX 2.1 standards.
* [ThreatQuotient ThreatQ](https://www.threatquotient.com/) - Threat intelligence platform focused on operationalizing threat data and orchestration.
* [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Web-based tool for visualizing and analyzing ATT&CK matrices.

</details>

<details>

<summary>Cryptocurrency & Blockchain Analysis</summary>

* [Blockchain.com Explorer](https://www.blockchain.com/explorer) - Bitcoin blockchain explorer for tracking transactions and addresses.
* [Etherscan](https://etherscan.io/) - Ethereum blockchain explorer with contract analysis and token tracking.
* [BlockCypher](https://live.blockcypher.com/) - Multi-blockchain explorer supporting Bitcoin, Ethereum, Litecoin, and more.
* [BTC.com](https://btc.com/) - Bitcoin blockchain explorer with mining pool statistics.
* [Chainalysis](https://www.chainalysis.com/) - Professional blockchain analysis platform (commercial) for cryptocurrency investigations.
* [Elliptic](https://www.elliptic.co/) - Cryptocurrency compliance and investigation tools (commercial).
* [Crystal Blockchain](https://crystalblockchain.com/) - Cryptocurrency intelligence and compliance platform (Now part of Bitfury).
* [Ransomwhere](https://ransomwhe.re/) - **Note: Service appears inactive/discontinued.** Was an open database tracking ransomware Bitcoin payments.
* [Bitcoin Abuse Database](https://www.bitcoinabusedatabase.com/) - Community-driven database of Bitcoin addresses used in scams and ransomware.

</details>

<details>

<summary>Specialized Threat Hunting & Vulnerability Data</summary>

* [Shodan Exploits](https://exploits.shodan.io/) - Searchable exploit database integrated with Shodan device data.
* [Vulners](https://vulners.com/) - Comprehensive vulnerability database with exploit correlation and search capabilities.
* [Exploit-DB](https://www.exploit-db.com/) - The Exploit Database - a CVE-compliant archive of public exploits and vulnerable software.
* [VulnCheck](https://vulncheck.com/) - Vulnerability intelligence platform with exploit prediction and threat scoring.
* [CVE Details](https://www.cvedetails.com/) - Searchable CVE database with statistics and vendor information.
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/) - U.S. government repository of standards-based vulnerability data.
* [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities catalog maintained by CISA.
* [Packet Storm Security](https://packetstormsecurity.com/) - Information security resource providing exploits, advisories, and tools.

</details>

## Browser Extensions & Quick Lookup Tools

Browser extensions provide rapid indicator lookups and threat intelligence directly within your browser, streamlining the investigation workflow.

<details>

<summary>Browser Extensions</summary>

* [CrowdSec CTI Extension](https://chrome.google.com/webstore/detail/crowdsec-cti/nfhlhlkjnlkdgbkjkhjkngakjfaljbec) - Quick threat intelligence lookups for IPs and URLs from the browser.
* [Sputnik](https://github.com/mitchmoser/sputnik) - Chrome extension for OSINT and threat intelligence with configurable data sources.
* [Gotanda](https://github.com/HASH1da1/Gotanda) - OSINT browser extension for extracting and searching indicators from web pages.
* [ThreatConnect Extension](https://chrome.google.com/webstore/detail/threatconnect/hbghlhcflekehioljloookhpdfjpbcka) - Quick lookups in ThreatConnect platform from selected text.
* [URL Unshortener](https://chrome.google.com/webstore/detail/url-unshortener/gbobhobdgeopnhpommcvdckfhqjknjom) - Reveals true destinations of shortened URLs before clicking.
* [VirusTotal Checker](https://chrome.google.com/webstore/detail/virustotal/efbjojhplkelaegfbieplglfidafgoka) - Quick VirusTotal lookups from browser context menu.

</details>

## API Aggregators & Multi-Tool Platforms

These platforms aggregate multiple threat intelligence sources and analysis tools, providing centralized analysis and automated enrichment capabilities.

<details>

<summary>API Aggregators & Platforms</summary>

* [IntelOwl](https://github.com/intelowlproject/IntelOwl) - Open-source intelligence aggregator that runs multiple analyzers simultaneously on observables.
* [Cortex](https://github.com/TheHive-Project/Cortex) - Observable analysis and active response engine with 100+ analyzers and responders.
* [TheHive](https://thehive-project.org/) - Scalable security incident response platform integrating with Cortex for automated analysis.
* [MISP Modules](https://github.com/MISP/misp-modules) - Expansion modules for MISP providing enrichment, import, and export capabilities.
* [ThreatIngestor](https://github.com/InQuest/ThreatIngestor) - Automated tool for extracting and aggregating threat intelligence from sources.
* [Yeti](https://yeti-platform.github.io/) - Platform for organizing observables, indicators, TTPs, and knowledge on threats.
* [OpenCTI Connectors](https://www.opencti.io/ecosystem) - Extensive connector ecosystem for enriching threat intelligence data.
* [PhishingKitTracker](https://github.com/neonprimetime/PhishingKitTracker) - Automated tracking and analysis of phishing kits.

</details>

## Investigation Tools

Without a SOAR (Security Orchestration, Automation and Response) platform to automate OSINT lookups, security analysts must manually query IoCs across multiple tools to gather comprehensive data. To streamline this process, the following tool enables analysts to open multiple investigation resources simultaneously and pivot directly to their results.

{% hint style="info" %}
**Note**: Some tools require more complex URL structures than simple parameter appending. Additional functionality to support these tools is under development.
{% endhint %}

{% file src="../.gitbook/assets/EasyOSINT.html" %}

{% embed url="https://github.com/s0cm0nkey/EasyOSINT" %}

The following mind map illustrates commonly used tools for indicator analysis and their relationships:

![](<../.gitbook/assets/Threat Object.png>)

The interactive version can be found here:

{% file src="../.gitbook/assets/Threat Object (1).xmind" %}

## Emerging Techniques & Detection Engineering

Modern threat hunting and detection engineering require familiarity with standardized detection rules, behavioral signatures, and adversary techniques. These resources provide the foundation for building robust detection capabilities.

<details>

<summary>YARA Rules & Signature Hunting</summary>

* [YARAify](https://yaraify.abuse.ch/) - YARA rule search engine and malware hunting platform by abuse.ch.
* [YARA Rules GitHub](https://github.com/Yara-Rules/rules) - Community-maintained repository of YARA rules. **Note: Repository is archived; refer to individual rule authors for updates.**
* [Florian Roth's YARA Rules](https://github.com/Neo23x0/signature-base) - High-quality YARA rules for malware detection.
* [ReversingLabs YARA Rules](https://github.com/reversinglabs/reversinglabs-yara-rules) - Enterprise-grade YARA rules.
* [InQuest YARA Rules](https://github.com/InQuest/yara-rules) - YARA rules focused on files and network artifacts.
* [Awesome YARA](https://github.com/InQuest/awesome-yara) - Curated list of YARA rules, tools, and resources.

</details>

<details>

<summary>Sigma Rules & Detection Engineering</summary>

* [Sigma HQ](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems with extensive rule repository.
* [Sigma Rule Repository](https://github.com/SigmaHQ/sigma/tree/master/rules) - Community-contributed detection rules.
* [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) - Curated Sigma rules and detection content.
* [Uncoder.io](https://uncoder.io/) - Online Sigma rule converter for multiple SIEM platforms.
* [pySigma](https://github.com/SigmaHQ/pySigma) - Python library for parsing and converting Sigma rules (Replaces deprecated sigmac).
* [sigma-cli](https://github.com/SigmaHQ/sigma-cli) - Command-line interface for Sigma rule processing.

</details>

<details>

<summary>MITRE ATT&CK Framework</summary>

* [MITRE ATT&CK](https://attack.mitre.org/) - Globally-accessible knowledge base of adversary tactics and techniques.
* [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Web-based tool for visualizing ATT&CK matrices.
* [ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) - ATT&CK knowledge base for Industrial Control Systems.
* [MITRE D3FEND](https://d3fend.mitre.org/) - Knowledge graph of cybersecurity countermeasures.
* [MITRE Cyber Analytics Repository (CAR)](https://car.mitre.org/) - Analytics developed by MITRE based on ATT&CK.
* [ATT&CK Powered Suit](https://github.com/SadProcessor/SomeStuff/tree/master/ATT%26CK%20Powered%20Suit) - PowerShell ATT&CK automation.

</details>

<details>

<summary>Living Off The Land (LOL) Techniques</summary>

* [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries and Scripts for Windows.
* [GTFOBins](https://gtfobins.github.io/) - Curated list of Unix binaries that can be exploited for privilege escalation.
* [LOLDrivers](https://www.loldrivers.io/) - Living Off The Land drivers for Windows privilege escalation.
* [LOLAPPS](https://lolapps-project.github.io/) - Living Off The Land macOS applications.
* [WADComs](https://wadcoms.github.io/) - Interactive cheat sheet for Windows/Active Directory security.

</details>

<details>

<summary>Threat Intelligence Standards & Frameworks</summary>

* [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) - Structured Threat Information Expression (STIX) and Trusted Automated Exchange (TAXII).
* [MISP Standard](https://www.misp-standard.org/) - Standard format for sharing, storing, and correlating IoCs.
* [OpenIOC](https://github.com/fireeye/OpenIOC_1.1) - Open framework for sharing threat intelligence. Original blog reference: [FireEye/Mandiant](https://www.mandiant.com/resources/blog)
* [CybOX](https://cyboxproject.github.io/) - Cyber Observable eXpression specification. **Note: Project is archived; functionality incorporated into STIX 2.x**
* [VERIS Framework](https://verisframework.org/) - Vocabulary for Event Recording and Incident Sharing. [GitHub Repository](https://github.com/vz-risk/veris)
* [Diamond Model](https://www.activeresponse.org/the-diamond-model/) - Framework for analyzing cyber intrusions.
* [Kill Chain Analysis](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Lockheed Martin's Cyber Kill Chain framework.

</details>

## Best Practices for Indicator Analysis

When conducting threat intelligence analysis, follow these best practices:

1. **Validate Across Multiple Sources**: Never rely on a single reputation source. Cross-reference findings across at least 3-5 different platforms.

2. **Consider Context**: Age of domain registration, geographic anomalies, associated infrastructure, and historical behavior all provide critical context.

3. **Document Your Investigation**: Maintain detailed notes of your analysis process, sources consulted, and findings. This creates an audit trail and aids future investigations.

4. **Leverage Automation**: Use API aggregators and automation tools to streamline repetitive lookups while applying human analysis to the results.

5. **Stay Current**: Threat landscapes evolve rapidly. Regularly review new threat intelligence sources and update your investigation toolkit.

6. **Understand False Positives**: Legitimate services, CDNs, and shared hosting can trigger false positives. Always investigate the full context.

7. **Use Passive Analysis First**: When possible, use passive reconnaissance techniques (passive DNS, certificate transparency) before active scanning to avoid alerting adversaries.

8. **Enrich with ATT&CK Mapping**: Map observed behaviors to MITRE ATT&CK techniques to understand adversary TTPs and predict next moves.

9. **Collaborate and Share**: Participate in threat intelligence sharing communities. Your findings can help others, and vice versa.

10. **Verify Indicators**: Before blocking or alerting on indicators, verify they are truly malicious to avoid disrupting legitimate business operations.

## Deprecated & Legacy Tools

The following tools are no longer actively maintained, have been discontinued, or have been superseded by newer platforms. They are listed here for historical reference and in case legacy data sources are needed.

<details>

<summary>Deprecated Tools</summary>

* **ThreatCrowd** - Deprecated. Data migrated to AlienVault OTX. The original service at threatcrowd.org is no longer actively maintained.
* **Digital Attack Map** - Discontinued by Arbor Networks/NetScout. No longer accessible.
* **Malware Domain List (MDL)** - No longer actively maintained. Last updates were several years ago.
* **Sigmac** - Deprecated Sigma rule converter. Replaced by pySigma and sigma-cli.
* **CybOX (Cyber Observable eXpression)** - Legacy specification largely superseded by STIX 2.x observables. Project is archived.
* **Ransomwhere** - Bitcoin ransomware tracker that appears to be inactive/discontinued.
* **YARA Rules GitHub (Yara-Rules/rules)** - Repository is archived. Use individual maintainer repositories instead.

</details>

## Tool Accuracy Notes

- **Blacklist counts**: The number of sources checked by multi-source reputation tools may vary over time as providers are added or removed.
- **API availability**: Some free tools have rate limits or require registration for API access.
- **Browser extensions**: Chrome Web Store links may change; search by extension name if links are outdated.
- **Historical data retention**: Passive DNS and historical lookup tools vary in their data retention periods.
- **Sandbox detection**: Advanced malware may detect sandbox environments and alter behavior.
