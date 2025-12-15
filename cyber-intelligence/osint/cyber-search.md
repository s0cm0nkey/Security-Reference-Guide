# Cyber Search Engines

Cyber search engines are specialized tools that continuously scan and index internet-connected devices, services, and assets. Unlike traditional search engines that index web content, these platforms focus on technical infrastructure, vulnerabilities, and security-related metadata. They are essential tools for security professionals conducting reconnaissance, threat hunting, asset discovery, and vulnerability management.

## [Shodan](https://www.shodan.io/)

Shodan is often called the "Search Engine for the Internet of Everything" or "Hacker's Search Engine". Unlike traditional search engines, Shodan continuously scans the entire internet for connected devices and services, cataloging their open ports, running services, and associated metadata. It supports advanced search operators (similar to Google dorks) that enable precise queries for specific technologies, vulnerabilities, or configurations. Shodan's flexible API allows integration with security tools and automated workflows.

**Key Resources:**
* [Shodan CLI Documentation](https://cli.shodan.io/) - Command-line interface for Shodan queries and automation
* [Shodan Search Filters](https://beta.shodan.io/search/filters) - Complete list of available search filters and operators
* [TryHackMe Shodan Room](https://tryhackme.com/room/shodan) - Interactive training module for learning Shodan
* _Operator Handbook: Shodan CLI - pg. 274_ - Command reference guide

<details>

<summary>Shodan Dorking (Search Query Collections)</summary>

Shodan "dorks" are specialized search queries designed to find specific types of devices, vulnerabilities, or configurations. These collections provide ready-to-use queries for security research and reconnaissance.

* [Awesome Shodan Queries](https://github.com/jakejarvis/awesome-shodan-queries) - Curated collection of useful Shodan search queries
* [Bug Bounty Shodan Dorks](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Recon/Shodan%20Dorks.md) - Queries focused on bug bounty reconnaissance
* [Pentesting Bible - Shodan Queries](https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE/blob/master/1-part-100-article/google/Shodan%20Queries.txt) - Comprehensive pentesting query collection
* [Shodan-Dorks by humblelad](https://github.com/humblelad/Shodan-Dorks) - General purpose Shodan dork repository
* [ICS/IoT Shodan Dorks](https://github.com/AustrianEnergyCERT/ICS\_IoT\_Shodan\_Dorks) - Specialized queries for Industrial Control Systems and IoT devices
* [Shodan Dorks by lothos612](https://github.com/lothos612/shodan) - Additional query collection
* [IFLinfosec Shodan Dorks](https://github.com/IFLinfosec/shodan-dorks) - InfoSec-focused search queries
* [Ultimate OSINT with Shodan](https://www.osintme.com/index.php/2021/01/16/ultimate-osint-with-shodan-100-great-shodan-queries/) - 100 practical Shodan queries for OSINT

</details>

{% embed url="https://youtu.be/v2EdwgX72PQ" %}

## Additional Cyber Search Tools

Asset search engines are powerful platforms that continuously scan the internet, cataloging every detectable entity and their characteristics. Using distributed networks of sensors and scanners, these tools collect comprehensive data including domain registration information, open ports, running services, SSL certificates, vulnerabilities, and network traffic patterns. This data is invaluable for attack surface management, threat intelligence, and security research.

<details>

<summary>Internet Asset Search Engines</summary>

* [FullHunt](https://fullhunt.io/) - Attack surface database covering the entire internet with focus on exposures, misconfigurations, and vulnerabilities.
* [Maltiverse](https://maltiverse.com/search) - Specialized search engine for threat-based indicators (IPs, domains, hashes, URLs). Provides multiple threat intelligence feeds that can be integrated into security platforms for real-time alerting.
* [Onyphe](https://www.onyphe.io/) - Cyber defense search engine aggregating open-source and threat intelligence data from multiple sources including internet background noise, active scanning of connected devices, and web crawling. Excels at correlating diverse data sources for comprehensive analysis.
  * [Onyphe Dorkpedia](https://www.onyphe.io/documentation/dorkpedia) - Search query documentation and examples

* [IntelligenceX](https://intelx.io/) - Advanced search engine supporting specialized selectors including email addresses, domains, URLs, IPs, CIDRs, Bitcoin addresses, and IPFS hashes. Searches across darknet sources, document sharing platforms, WHOIS data, and public data breaches. Maintains historical archives similar to the Wayback Machine for tracking changes over time.
* [Synapsint](https://synapsint.com/) - Unified OSINT research platform that aggregates data from multiple sources, allowing comprehensive searches across various indicators and data types.
* [Natlas](https://natlas.io/) - Self-hostable network scanning platform designed for scaling and managing large-scale reconnaissance operations.
* [Netlas.io](https://netlas.io/) - Internet asset discovery and monitoring platform for tracking online infrastructure and detecting changes in attack surface.
* [Pulsedive](https://pulsedive.com/) - Threat intelligence platform that balances raw technical data with enriched context and community-driven insights. Excellent for both manual analysis and automated lookups.
* [ThreatMiner](https://www.threatminer.org/) - Threat intelligence portal aggregating data from multiple sources into a single analyst interface. Featured in the [SANS FOR578 Cyber Threat Intelligence course](https://digital-forensics.sans.org/media/DFPS\_FOR578\_v1.5\_4-19.pdf) as a training tool.
* [OPSWAT MetaDefender](https://metadefender.opswat.com/?lang=en) - Multi-engine malware scanning and threat intelligence platform providing contextual analysis of indicators, vulnerabilities, and files.
* [ShadowServer](https://www.shadowserver.org/what-we-do/) - Free threat intelligence service aggregating data from honeypots, malware collection systems, and internet-wide scanning infrastructure. Valuable for tracking botnet activity and vulnerable systems.
* [Trend Micro Threat Encyclopedia](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/) - Comprehensive intelligence repository covering malware families, vulnerabilities (CVEs), and threat actor profiles.
* [ThreatView.io](https://threatview.io/) - Curated directory of threat intelligence feeds and resources organized by use case and data type.
* [BinaryEdge](https://app.binaryedge.io/services/query) - Internet scanning platform specializing in discovering exposed services, databases, webcams, and Industrial Control Systems (ICS). Strong capabilities for identifying indicators of compromise.
* [Censys](https://search.censys.io/) - Internet-wide asset discovery platform focused on certificate transparency, scanning data, and continuous monitoring. Excellent for attack surface management and alerting on infrastructure changes.
* [LeakIX](https://leakix.net/) - Search engine focused on finding publicly exposed databases, API keys, configuration files, and misconfigurations. Provides real-time scanning data and leak detection across the internet.

</details>

<details>

<summary>Favicon Analysis Tools</summary>

Favicon hashes can be used as unique fingerprints to identify web applications and infrastructure across the internet. These tools leverage favicon analysis for reconnaissance and asset discovery.

* [FavFreak](https://github.com/devanshbatham/FavFreak) - Tool for weaponizing favicon.ico files in bug bounty reconnaissance and OSINT investigations. Generates favicon hashes for searching across platforms like Shodan.
  * [Weaponizing favicon.ico Article](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) - Detailed guide on favicon-based reconnaissance techniques
* [fav-up](https://github.com/pielco11/fav-up) - Performs IP address lookups using favicon hashes via Shodan. Particularly useful for discovering real IP addresses of servers hidden behind CDNs like Cloudflare.
  * [Cloud Hunting Article](https://pielco11.ovh/posts/cloud-hunting/) - Methodology for finding servers behind cloud protection

</details>
## Additional Specialized Search Engines

<details>

<summary>Alternative Internet Scanning Platforms</summary>

These platforms offer similar capabilities to Shodan but with unique features, data sources, or regional coverage:

* [ZoomEye](https://www.zoomeye.org/) - Chinese cyberspace mapping platform that scans and indexes internet-connected devices. Offers both web-based search and API access with strong coverage of Asian networks.
* [Fofa](https://en.fofa.info/) - Chinese cyber asset search engine with extensive device fingerprinting capabilities and advanced search syntax. Popular for discovering exposed services and devices globally.
* [Criminal IP](https://www.criminalip.io/) - Comprehensive cyber threat intelligence search engine providing real-time vulnerability detection, malicious IP tracking, and exposed asset discovery. Features user-friendly interface and detailed risk scoring.
* [Wigle](https://wigle.net/) - Wireless network mapping database. The world's largest database of wireless networks and cell towers, collected through wardriving and crowdsourcing.

</details>

## Search Techniques and Dorking

**Google Dorking** - The original advanced search technique using specialized operators to find specific information indexed by Google. While not specific to cybersecurity, it remains a fundamental OSINT skill for discovering exposed files, directories, vulnerable systems, and sensitive information. See the [search engines section](search-engines/) for detailed Google dork resources.

**Shodan Dorking** - Similar concept applied to Shodan's search syntax (see Shodan section above).

## Deprecated and Discontinued Services

These tools are no longer actively maintained or have shut down their services. They are listed here for historical reference:

* **Spyse (spyse.com)** - Internet asset search engine acquired by SOCRadar in 2023. The original Spyse.com service was shut down and integrated into SOCRadar's commercial platform. Free public search capabilities are no longer available. Consider alternatives like FullHunt, Censys, or Netlas.io.
* **Riddler.io** - Historical internet scanning data and DNS records search engine. Service shut down in 2022. Consider alternatives like Censys or SecurityTrails for historical DNS data.
* **BestIcon (besticon.herokuapp.com)** - Web service for extracting favicon files. The Heroku-hosted public instance became unreliable after Heroku ended free tier hosting in 2022. The [open-source project](https://github.com/mat/besticon) can still be self-hosted.
* **Guardicore Threat Intelligence** - Free public threat intelligence portal. Discontinued after Akamai's acquisition of Guardicore in 2021. The platform was integrated into Akamai's commercial offerings.
