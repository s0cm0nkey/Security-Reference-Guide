# Domain

## Domains

A **domain name** is a [string](https://en.wikipedia.org/wiki/String\_\(computer\_science\)) that identifies a realm of administrative autonomy, authority or control within the [Internet](https://en.wikipedia.org/wiki/Internet). Domain names are used in various networking contexts and for application-specific naming and addressing purposes. In general, a domain name identifies a [network domain](https://en.wikipedia.org/wiki/Network\_domain) or an [Internet Protocol](https://en.wikipedia.org/wiki/Internet\_Protocol) (IP) resource, such as a personal computer used to access the Internet, or a server computer. Domain names are often used to identify services provided through the Internet, such as [websites](https://en.wikipedia.org/wiki/Website) and [email](https://en.wikipedia.org/wiki/Email) services

Domains, more than almost any other target, have one of the largest assortments of associated data points. The most important that we will look for out of this section is the Registration data, the hosting data, site information, archived data, and analytics.

## **WHOIS vs. RDAP**

WHOIS has been the traditional protocol for gathering registration data for IP addresses and domains. However, WHOIS lacks a clearly defined structure to organize registration data points and maintain them consistently across different registrars.

**RDAP (Registration Data Access Protocol)** is the modern successor to WHOIS. Standardized in 2019, RDAP provides several key advantages:

* Structured, machine-readable JSON responses (vs. unstructured text)
* Internationalization support for non-ASCII characters
* Differentiated access based on authentication
* RESTful API design for easier integration
* Better privacy controls and data accuracy

RDAP lookups are rapidly replacing WHOIS as the preferred method for registration data queries.

**Resources:**
* RDAP lookup tool - [https://client.rdap.org](https://client.rdap.org)
* General information on RDAP - [https://www.icann.org/rdap](https://www.icann.org/rdap)

## Domain Analysis Tools

<details>

<summary><strong>Domain.html</strong></summary>

Domain.html is a comprehensive tool that allows you to research multiple data points associated with a domain during an investigation.

* **Registration Data** - Checks the domain for WHOIS-based registration data against multiple sources to obtain the most current information.
* **Hosting Data** - Reveals which provider is physically hosting the domain. Look for indicators showing whether the target domain is hosted by a third-party hosting provider or self-hosted by your target organization.
* **Exposed Data** - Identifies information that may be publicly exposed (note: other specialized sources may provide better results).
* **Archive Data** - Searches for older cached or saved versions of the website that may yield valuable information through Google Cache, Archive.is, and the Wayback Machine.
* **Analytics Data** - Provides various searches ranging from general site details and analytics to similar sites on the web and backlink analysis from other sites.
* **Threat Data** - See the Blue - Threat Data section for details.
* **Shortened URL Metadata** - Extracts metadata from shortened URLs.

</details>

{% file src="../../.gitbook/assets/Domain.html" %}

<details>

<summary>Domain Toolboxes</summary>

These tools are comprehensive collections of utilities focused on domain investigation. While some can be used for research on other network artifacts like IP addresses and email records, they excel at DNS records and domain-related metadata analysis.

* [ViewDNS](https://viewdns.info/) - Extensive toolbox with various utilities for enumerating information about a domain, including DNS lookups, IP location, and reverse lookup tools.
* [DNSDumpster](https://dnsdumpster.com/) - Free domain research tool that discovers hosts related to a domain through DNS reconnaissance and visualization.
* [MXToolbox](https://mxtoolbox.com/) - Comprehensive tool for checking MX (mail exchange) records and diagnosing email delivery issues for a given domain.
* [DNSLytics](https://dnslytics.com/) - Comprehensive domain intelligence platform for discovering information about domain names, IP addresses, and providers. Shows relationships between entities and historical data, useful for digital investigations, fraud prevention, and brand protection.
* [HostSpider](https://github.com/h3x0crypt/HostSpider) - Command-line tool that gathers extensive information about a domain including DNS records, subdomains, WHOIS data, Cloudflare IP detection, and more.

</details>

<details>

<summary>Passive DNS and Historical Records</summary>

Passive DNS (pDNS) systems collect DNS resolution data from recursive DNS servers worldwide, providing historical DNS records that can reveal infrastructure changes, associated domains, and past hosting information.

* [SecurityTrails](https://securitytrails.com/) - Comprehensive passive DNS database with historical DNS records, WHOIS history, and subdomain discovery.
* [Farsight DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/) - World's largest passive DNS database for threat intelligence and investigation.
* [PassiveTotal / Microsoft Defender TI](https://community.riskiq.com/) - Threat intelligence platform (now part of Microsoft Defender Threat Intelligence) with passive DNS, WHOIS, SSL certificates, and trackers.
* [VirusTotal](https://www.virustotal.com/) - Besides malware scanning, provides passive DNS data, subdomains, and related indicators.
* [Passive DNS Mnemonic](https://passivedns.mnemonic.no/) - Norwegian passive DNS service providing historical DNS data.
* [Cisco Umbrella Investigate](https://umbrella.cisco.com/) - DNS security and threat intelligence platform with passive DNS capabilities.
* [AlienVault OTX](https://otx.alienvault.com/) - Open Threat Exchange providing passive DNS and threat intelligence data.

</details>

<details>

<summary>Reverse WHOIS and IP Lookups</summary>

Reverse WHOIS searches allow you to find all domains registered by the same organization, email address, or registrant name. Reverse IP lookups reveal all domains hosted on the same IP address or server.

* [ViewDNS Reverse IP](https://viewdns.info/reverseip/) - Find other domains hosted on the same IP address.
* [WhoisXMLAPI Reverse WHOIS](https://www.whoisxmlapi.com/reverse-whois-search) - Search domains by registrant name, email, or organization.
* [Reverse WHOIS by DomainTools](https://reversewhois.domaintools.com/) - Premium reverse WHOIS search service.
* [Hosting Checker](https://hostingchecker.com/) - Identify web hosting provider and find other sites on the same server.
* [YouGetSignal Reverse IP](https://www.yougetsignal.com/tools/web-sites-on-web-server/) - Simple tool to find domains sharing an IP address.
* [Bing IP Search](https://www.bing.com/) - Use `ip:x.x.x.x` search operator to find domains on an IP.

</details>

<details>

<summary>Subdomain <strong>Discovery</strong></summary>

Numerous highly effective tools exist for subdomain enumeration and brute-forcing, but active scanning methods can be quite noisy and may alert defenders. During the passive reconnaissance phase of a penetration test, leveraging subdomains already recorded by other sources allows you to plan your attack strategy without tipping off the target.

* [Chaos](https://chaos.projectdiscovery.io/) - ProjectDiscovery's actively maintained DNS reconnaissance dataset with subdomain data.
* [Pentest-Tools Subdomain Finder](https://pentest-tools.com/information-gathering/find-subdomains-of-domain) - Online subdomain discovery tool for information gathering.
* [censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) - Tool to enumerate subdomains using Certificate Transparency logs stored by [Censys](https://censys.io).
* [ctfr](https://github.com/UnaPibaGeek/ctfr) - Leverages Certificate Transparency logs to discover subdomains for HTTPS-enabled websites.
* [Sublist3r](https://github.com/aboul3la/Sublist3r) - Python tool designed to enumerate subdomains using OSINT techniques. Queries multiple search engines and services (Note: some data sources like ThreatCrowd are no longer active).
  * [TryHackMe Sublist3r Room](https://tryhackme.com/room/rpsublist3r) - Hands-on practice with Sublist3r
* [puredns](https://github.com/d3mondev/puredns) - Fast domain resolver and subdomain brute-forcing tool that accurately filters out wildcard subdomains and DNS-poisoned entries.
* [Amass](https://github.com/owasp-amass/amass) - OWASP Amass is a comprehensive OSINT reconnaissance and attack surface mapping tool that performs subdomain enumeration through scraping, recursive brute-forcing, crawling, and more.
* [Subfinder](https://github.com/projectdiscovery/subfinder) - Fast passive subdomain discovery tool by ProjectDiscovery.
* [Assetfinder](https://github.com/tomnomnom/assetfinder) - Find domains and subdomains related to a given domain.

</details>

<details>

<summary>Domain Reputation and Threat Intelligence</summary>

Domain reputation services help identify malicious, suspicious, or compromised domains, which is critical for threat hunting and security investigations.

* [VirusTotal](https://www.virustotal.com/) - Analyze domains for malware, phishing, and malicious activity across 70+ security vendors.
* [URLhaus](https://urlhaus.abuse.ch/) - Database of malicious URLs used for malware distribution.
* [PhishTank](https://www.phishtank.com/) - Community-driven anti-phishing site with verified phishing URLs.
* [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) - Check if a domain is flagged for phishing or malware.
* [Talos Intelligence](https://talosintelligence.com/) - Cisco's threat intelligence service with domain reputation data.
* [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) - Threat intelligence platform with domain and IP reputation data.
* [AlienVault OTX](https://otx.alienvault.com/) - Open threat intelligence community with domain indicators.
* [AbuseIPDB](https://www.abuseipdb.com/) - Database for reporting and checking abusive IPs and domains.
* [Pulsedive](https://pulsedive.com/) - Threat intelligence platform with domain risk scoring.

</details>

<details>

<summary>Email Security Records (SPF, DMARC, DKIM)</summary>

Email authentication records help verify legitimate email sources and can reveal authorized sending infrastructure for a domain.

* [MXToolbox DMARC Lookup](https://mxtoolbox.com/dmarc.aspx) - Check DMARC records for email authentication policy.
* [MXToolbox SPF Lookup](https://mxtoolbox.com/spf.aspx) - Verify SPF (Sender Policy Framework) records.
* [DKIM Validator](https://dkimvalidator.com/) - Test DKIM (DomainKeys Identified Mail) configuration.
* [DMARCian](https://dmarcian.com/dmarc-inspector/) - DMARC record inspector and validator.
* [EasyDMARC](https://easydmarc.com/tools/dmarc-lookup) - DMARC, SPF, and DKIM lookup and analysis tool.
* [Mail-Tester](https://www.mail-tester.com/) - Comprehensive email testing including SPF, DKIM, and DMARC validation.

</details>

<details>

<summary>Typosquatting and Domain Permutations</summary>

Typosquatting detection tools generate domain variations and check for registered lookalike domains used for phishing or brand abuse.

* [dnstwist](https://github.com/elceef/dnstwist) - Domain name permutation engine for detecting typosquatting, phishing, and corporate espionage.
* [URLCrazy](https://github.com/urbanadventurer/urlcrazy) - Generate and test domain typos and variations.

</details>

<details>

<summary>Favicon Hash and Technology Fingerprinting</summary>

Favicon hashes and technology fingerprinting can identify related infrastructure by matching unique identifiers across multiple domains.

* [Shodan Favicon Hash Search](https://www.shodan.io/) - Use `http.favicon.hash:` to find servers with matching favicons.
* [FavFreak](https://github.com/devanshbatham/FavFreak) - Tool to fetch favicon hashes for Shodan searches.
* [Wappalyzer](https://www.wappalyzer.com/) - Identify technologies used on websites including CMS, frameworks, and analytics.
* [BuiltWith](https://builtwith.com/) - Website technology profiler showing tech stack and hosting details.
* [WhatRuns](https://www.whatruns.com/) - Browser extension to identify technologies running on a website.
* [Netcraft Site Report](https://sitereport.netcraft.com/) - Detailed site technology and hosting information.

</details>

<details>

<summary>Domain Certificates</summary>

Domain Certificates are an interesting and useful item to research when mapping out a target domain. Beyond the various attacks that can be performed by exploiting these certificates, looking up the domain certificates can lead to discovery of hosts, sub-domains, and related targets that were previously undiscovered.

* [Crt.sh](https://crt.sh) - Enter an Identity (Domain Name, Organization Name, etc), a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID to return detailed domain and certificate information.
* [CTSearch](https://ui.ctsearch.entrust.com/ui/ctsearchui) - Certificate Transparency Search Tool
* [CertSpotter](https://sslmate.com/certspotter/) - Monitors your domains for expiring, unauthorized, and invalid SSL certificates
* [SynapsInt](https://synapsint.com/) - The unified OSINT research tool
* [Censys - Certificates](https://search.censys.io/certificates) - Certificates Search
* [PassiveTotal / Microsoft Defender TI](https://community.riskiq.com/) - Security intelligence platform (now part of Microsoft Defender Threat Intelligence) with certificate and domain analysis
* [Google Transparency Report](https://transparencyreport.google.com/https/certificates) - A tool used to look up all of a domain’s certificates that are present in [active public Certificate Transparency logs](https://www.certificate-transparency.org/known-logs)
* [https://sslmate.com/labs/ct\_policy\_analyzer/](https://sslmate.com/labs/ct\_policy\_analyzer/) - Certificate Transparency Policy Analyzer

</details>

<details>

<summary>Archive and Historical Data</summary>

Historical snapshots of websites can reveal sensitive information that has since been removed, track changes over time, or discover old vulnerabilities.

* [Wayback Machine](https://web.archive.org/) - Internet Archive's massive collection of historical website snapshots dating back to 1996.
* [Archive.today (Archive.is)](https://archive.ph/) - Time capsule for web pages with on-demand archiving capabilities.
* [CachedView](https://cachedview.com/) - Check Google Cache, Wayback Machine, and Archive.is from one interface.
* [Waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch all URLs from the Wayback Machine for a domain.
* [waymore](https://github.com/xnl-h4ck3r/waymore) - Find even more URLs from the Wayback Machine with advanced filtering.
* [Google Cache](http://webcache.googleusercontent.com/search?q=cache:example.com) - Access Google's cached version of web pages (Note: Google is phasing out cache links).

</details>

<details>

<summary>Website Change Tracking</summary>

Monitoring websites for changes can be valuable during ongoing investigations or penetration tests. Changes to content, structure, or functionality may reveal new attack surfaces, security misconfigurations, or intelligence about the target organization's activities.

* [Follow That Page](https://followthatpage.com/) - Change detection and notification service that sends email alerts when monitored web pages are modified.
* [VisualPing](https://visualping.io/) - Advanced monitoring tool that tracks multiple types of changes on web pages and provides alerts based on specific conditions you define.

</details>

<details>

<summary>URL Shortening and Redirections</summary>

Shortened URLs and redirections can obscure malicious destinations and are commonly used in phishing campaigns and malware distribution. These tools help you safely investigate shortened URLs and redirect chains without clicking through to potentially malicious sites.

* [GrayHatWarfare URL Shorteners](https://shorteners.grayhatwarfare.com) - Search engine for URLs exposed via URL shortening services.
* [urlhunter](https://github.com/utkusen/urlhunter) - Reconnaissance tool for discovering URLs exposed through shortener services.
* [Unshorten.It](https://unshorten.it/) - Retrieve information about a shortened link without visiting the destination.
* [Redirect Detective](http://redirectdetective.com/) - Follow and analyze URL redirection chains to reveal the final destination.
* [Where Goes?](https://wheregoes.com) - Tool for tracing and enumerating URL redirections.
* [Lookyloo](https://lookyloo.circl.lu) - Web forensics tool for capturing and analyzing redirect chains and web page behavior.

**Preview shortened URLs without redirecting:**
* **bit.ly** - Add `+` at the end of the URL
* **cutt.ly** - Add `@` at the end of the URL
* **tiny.cc** - Add `=` at the end of the URL
* **tinyurl.com** - Add `preview.` to the beginning of the URL

</details>

<details>

<summary>Similar Website Search</summary>

Identifying similar or related websites can help expand the scope of an investigation, discover additional assets owned by a target organization, or identify infrastructure patterns across multiple domains.

* [SimilarSites](https://www.similarsites.com/) - Discover websites similar to a given URL based on content and purpose.
* [SitesLike](https://siteslike.com/) - Find websites similar to a specific URL or matching a keyword query.
* [SimilarWeb](https://www.similarweb.com/) - Comprehensive tool for finding similar and competitor websites, with detailed analytics and comparison features. Search by website URL.

</details>

<details>

<summary>Browser Proxy/Simulator</summary>

These tools allow you to view websites without directly interacting with them, which is useful for safely investigating potentially malicious sites or avoiding detection by the target.

* [WannaBrowser](https://www.wannabrowser.net/) - View the HTML source code of any website from the perspective of any User-Agent string. Useful for detecting simple cloaking techniques based on User-Agent identification.
* [Browserling](https://www.browserling.com/) - Browser testing platform that can be used to safely view and interact with websites through a sandboxed environment.
* [URL2PNG](https://www.url2png.com/) - Capture visual snapshots of websites without visiting them directly in your browser.

</details>

<details>

<summary>Miscellaneous Utilities</summary>

* [DNPedia](https://dnpedia.com/) - Domain name solutions, statistics, scripts, news, and tools.
* [Google Dig](https://toolbox.googleapps.com/apps/dig/) - Online version of the DNS dig command for performing DNS lookups.
* [SimilarWeb Traffic Analytics](https://www.similarweb.com) - Compare metadata about domains and traffic patterns across the web.
* [Backlink Checker](https://smallseotools.com/backlink-checker/) - Monitor and analyze backlinks pointing to a particular domain.
* [DomLink](https://github.com/vysecurity/DomLink) - Discover organization names and associated email addresses from a domain, then pivot to find additional related domains.
* [Unfurl](https://dfir.blog/unfurl/) - Break down and visualize the components of a URL for analysis.
* [r3con1z3r](https://github.com/abdulgaphy/r3con1z3r) - Lightweight web information gathering tool written in Python that provides a comprehensive OSINT environment for web-based footprinting.
* [theHarvester](https://github.com/laramies/theHarvester) - Tool to extract domain email addresses, subdomains, hosts, and other information from public sources.
* [gau (getallurls)](https://github.com/lc/gau) - Fetches known URLs from AlienVault's [Open Threat Exchange](https://otx.alienvault.com), the Wayback Machine, and Common Crawl for any given domain.
* [lbd (Load Balancing Detector)](https://www.kali.org/tools/lbd/) - Detects if a given domain uses DNS and/or HTTP load-balancing.
* [Metagoofil](https://github.com/laramies/metagoofil) - Extracts metadata from public documents (PDF, DOC, XLS, PPT, etc.) for a given domain.
* [Cache Checker](https://www.giftofspeed.com/cache-checker/) - Lists which web files on a website are cached, the caching method used, and the cache expiry time.
* [CloudFlair](https://github.com/christophetd/CloudFlair) - Discover origin servers of websites behind Cloudflare by using Internet-wide scan data from Censys.
* [cf-check](https://github.com/dwisiswant0/cf-check) - Check if a host is protected by Cloudflare.
* [AnalyticsRelationships](https://github.com/Josue87/AnalyticsRelationships) - Discover related domains and subdomains by analyzing shared Google Analytics IDs.
* [LOTS Project](https://lots-project.com/) - Living Off Trusted Sites - Database of legitimate domains commonly abused by attackers for phishing, C2 (command and control), exfiltration, and malware delivery to evade detection.

</details>

<details>

<summary>Google Dorking for Domains</summary>

Google's advanced search operators can reveal indexed content related to a domain, including sensitive files, subdomains, and configuration data.

**Useful Google Dork Operators for Domain Research:**
* `site:example.com` - All indexed pages for a domain
* `site:*.example.com` - Find subdomains
* `site:example.com filetype:pdf` - Find specific file types
* `site:example.com inurl:admin` - Find admin panels
* `site:example.com intitle:"index of"` - Find directory listings
* `intext:"example.com" site:pastebin.com` - Find domain mentions in pastes
* `related:example.com` - Find similar websites

**Resources:**
* [Google Advanced Search](https://www.google.com/advanced_search)
* [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
* [DorkSearch](https://dorksearch.com/) - Fast Google dorking tool

</details>

<details>

<summary>Domain Takedown and Monitoring</summary>

Tools for monitoring domain availability, expiration dates, and potential domain takeover vulnerabilities.

* [DomainTools](https://www.domaintools.com/) - Comprehensive domain research and monitoring platform with WHOIS history, DNS records, and brand monitoring.
* [ExpiredDomains.net](https://www.expireddomains.net/) - Search and monitor expiring and deleted domains.
* [nuclei](https://github.com/projectdiscovery/nuclei) - Fast vulnerability scanner with templates for subdomain takeover detection (SubOver is no longer maintained).
* [Subjack](https://github.com/haccer/subjack) - Subdomain takeover tool with fingerprints for popular services.
* [Can I Take Over XYZ](https://github.com/EdOverflow/can-i-take-over-xyz) - List of services vulnerable to subdomain takeover.
* [Domain Monitor](https://whoisxmlapi.com/domain-availability-api) - API for monitoring domain availability and changes.

</details>

<details>

<summary>DNS Infrastructure Reconnaissance</summary>

Tools for deep DNS analysis including zone transfers, resolver testing, and nameserver enumeration.

* [dnsenum](https://github.com/fwaeytens/dnsenum) - Multithreaded script to enumerate DNS information and discover non-contiguous IP blocks.
* [fierce](https://github.com/mschwager/fierce) - DNS reconnaissance tool for locating non-contiguous IP space.
* [dnsrecon](https://github.com/darkoperator/dnsrecon) - DNS enumeration and reconnaissance tool with multiple query types.
* [MassDNS](https://github.com/blechschmidt/massdns) - High-performance DNS resolver for bulk lookups.
* [dnsx](https://github.com/projectdiscovery/dnsx) - Fast and multi-purpose DNS toolkit by ProjectDiscovery.

</details>

<details>

<summary>Deprecated or Offline Tools</summary>

**Note:** The following tools were previously popular but are no longer operational or have been deprecated. They are listed here for historical reference and in case they return to service.

* **[omnisint.io](https://omnisint.io/) / [Project Crobat](https://github.com/Cgboal/SonarSearch)** - Rapid7's DNS database with fast API access (service discontinued)
* **[ThreatCrowd](https://www.threatcrowd.org/)** - Search engine for threats with domain relationships (service offline)
* **[tls.bufferover.run](https://tls.bufferover.run/)** - Certificate search in IPv4 space (BufferOver services discontinued)
* **[Riddler.io](https://riddler.io/)** - F-Secure network intelligence API (service discontinued)
* **[CheckShortURL](https://checkshorturl.com/)** - URL shortener analysis tool (frequently offline/unreliable)
* **[W3DT](https://w3dt.net/)** - Network troubleshooting site (appears offline)
* **[DomainIQ](https://www.domainiq.com/)** - Reverse WHOIS searches (service unavailable)
* **[SubOver](https://github.com/Ice3man543/SubOver)** - Subdomain takeover vulnerability scanner (no longer maintained, use nuclei instead)
* **[Spyse](https://spyse.com/)** - OSINT search engine (free tier heavily limited, most features require paid subscription)
* **[DomainFuzz](https://github.com/monkeym4ster/DomainFuzz)** - Domain fuzzing tool (repository appears unavailable)
* **[Bolster CheckPhish at bolster.ai/checkphish](https://bolster.ai/checkphish)** - Phishing URL checker (not specifically for typosquatting)

</details>

## **Investigation Mind Maps**

![](<../../.gitbook/assets/image (40).png>)
