# Domain

Use this page for passive domain investigation: registration data, RDAP/WHOIS, DNS records, passive DNS, certificate transparency, archives, email security records, typosquatting, redirects, and related infrastructure pivots. Active subdomain brute forcing, takeover testing, nuclei scanning, and exploit-driven recon belong in Red Offensive.

## WHOIS vs. RDAP

WHOIS is the older registration lookup protocol. It is useful, but responses are inconsistent across registrars and hard to parse reliably.

RDAP (Registration Data Access Protocol) is the modern successor. The core RFC 7480 series was published in 2015, and ICANN's gTLD RDAP requirements have continued to expand since then. RDAP provides structured JSON responses, better internationalization support, authentication-aware access, RESTful APIs, and more consistent privacy handling.

* [RDAP Lookup](https://client.rdap.org)
* [ICANN RDAP](https://www.icann.org/rdap)

## Domain.html

Domain.html is a multi-lookup helper for pivoting through domain investigation sources.

* **Registration Data** - WHOIS/RDAP-style ownership and registrar details.
* **Hosting Data** - Hosting provider and related infrastructure.
* **Archive Data** - Wayback Machine, Archive.today, and other historical snapshots.
* **Analytics Data** - Similar sites, backlinks, and relationship pivots.
* **Threat Data** - Use the Threat Data page for reputation and enrichment.
* **Shortened URL Metadata** - Shortener preview and redirect investigation.

Local helper copy: [Domain.html](../../.gitbook/assets/Domain.html)

## Domain Toolboxes

* [ViewDNS](https://viewdns.info/) - DNS, reverse IP, IP history, and related lookup utilities.
* [DNSDumpster](https://dnsdumpster.com/) - Passive DNS reconnaissance and visualization.
* [MXToolbox](https://mxtoolbox.com/) - MX, DNS, DMARC, and blacklist diagnostics.
* [DNSLytics](https://dnslytics.com/) - Domain/IP/provider relationships and historical data.
* [HostSpider](https://github.com/h3x0crypt/HostSpider) - Domain information gathering CLI.

## Passive DNS and Historical Records

Passive DNS systems collect observed DNS resolution history. Use them to find past hosting, related subdomains, and infrastructure relationships without directly touching a target.

* [SecurityTrails](https://securitytrails.com/) - Passive DNS, WHOIS history, and subdomains.
* [Farsight DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/) - Passive DNS database.
* [Microsoft Defender Threat Intelligence](https://ti.defender.microsoft.com/) - Formerly RiskIQ/PassiveTotal; passive DNS, WHOIS, certificates, trackers, and threat intelligence.
* [Passive DNS Mnemonic](https://passivedns.mnemonic.no/) - Historical DNS data.
* [Cisco Umbrella Investigate](https://umbrella.cisco.com/) - DNS security and passive DNS context.
* [AlienVault OTX](https://otx.alienvault.com/) - Indicator relationships and passive DNS pivots.

More indicator-focused passive DNS sources are maintained on Threat Data.

{% content-ref url="../threat-data.md" %}
[threat-data.md](../threat-data.md)
{% endcontent-ref %}

## Reverse WHOIS and Reverse IP

* [ViewDNS Reverse IP](https://viewdns.info/reverseip/) - Domains hosted on the same IP.
* [WhoisXMLAPI Reverse WHOIS](https://www.whoisxmlapi.com/reverse-whois-search) - Search domains by registrant name, email, or organization.
* [DomainTools Reverse WHOIS](https://reversewhois.domaintools.com/) - Commercial reverse WHOIS.
* [Hosting Checker](https://hostingchecker.com/) - Hosting provider and shared-hosting lookup.
* [YouGetSignal Reverse IP](https://www.yougetsignal.com/tools/web-sites-on-web-server/) - Domains sharing an IP.
* [Bing IP Search](https://www.bing.com/) - Use `ip:x.x.x.x` to find indexed domains on an IP.

## Passive Subdomain Discovery

These tools primarily use public datasets, certificate transparency, search engines, or other passive sources. They are useful for OSINT and scoping, but review each tool's options because some can also perform active queries.

* [Chaos](https://chaos.projectdiscovery.io/) - ProjectDiscovery subdomain dataset.
* [Pentest-Tools Subdomain Finder](https://pentest-tools.com/information-gathering/find-subdomains-of-domain) - Online subdomain discovery.
* [censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) - Enumerates subdomains from Censys certificate data.
* [ctfr](https://github.com/UnaPibaGeek/ctfr) - Certificate Transparency subdomain discovery.
* [Sublist3r](https://github.com/aboul3la/Sublist3r) - OSINT subdomain enumeration. Some older sources it references, such as ThreatCrowd, are no longer active.
* [Subfinder](https://github.com/projectdiscovery/subfinder) - Fast passive subdomain discovery by ProjectDiscovery.
* [Assetfinder](https://github.com/tomnomnom/assetfinder) - Finds domains and subdomains related to a target.

Active DNS reconnaissance and brute forcing tools such as Amass active modes, puredns, dnsenum, fierce, dnsrecon, MassDNS, and dnsx are preserved in Red Offensive.

{% content-ref url="../../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../../red-offensive/scanning-active-recon/)
{% endcontent-ref %}

## Domain Reputation and Threat Intelligence

Domain reputation lookups are maintained on Threat Data to avoid repeating the same VirusTotal, URLhaus, PhishTank, Talos, OTX, Pulsedive, and Google Safe Browsing resources across multiple pages.

{% content-ref url="../threat-data.md" %}
[threat-data.md](../threat-data.md)
{% endcontent-ref %}

## Email Security Records

Email authentication records help verify legitimate sending infrastructure and can expose authorized third-party services.

* [MXToolbox DMARC Lookup](https://mxtoolbox.com/dmarc.aspx)
* [MXToolbox SPF Lookup](https://mxtoolbox.com/spf.aspx)
* [DKIM Validator](https://dkimvalidator.com/)
* [DMARCian Inspector](https://dmarcian.com/dmarc-inspector/)
* [EasyDMARC Tools](https://easydmarc.com/tools/dmarc-lookup)
* [Mail-Tester](https://www.mail-tester.com/)

## Typosquatting and Domain Permutations

* [dnstwist](https://github.com/elceef/dnstwist) - Domain permutation engine for typosquatting and phishing detection.
* [URLCrazy](https://github.com/urbanadventurer/urlcrazy) - Domain typo and variation generator.

## Favicon Hash and Technology Fingerprinting

* [Shodan Favicon Hash Search](https://www.shodan.io/) - Use `http.favicon.hash:` to find related servers.
* [FavFreak](https://github.com/devanshbatham/FavFreak) - Fetch favicon hashes for Shodan searches.
* [Wappalyzer](https://www.wappalyzer.com/) - Website technology profiler.
* [BuiltWith](https://builtwith.com/) - Website technology and hosting profile.
* [WhatRuns](https://www.whatruns.com/) - Browser extension for web technology detection.
* [Netcraft Site Report](https://sitereport.netcraft.com/) - Site technology and hosting report.

## Certificate Transparency

* [crt.sh](https://crt.sh) - Certificate Transparency search.
* [Entrust CTSearch](https://ui.ctsearch.entrust.com/ui/ctsearchui)
* [CertSpotter](https://sslmate.com/certspotter/) - Certificate monitoring.
* [SynapsInt](https://synapsint.com/) - Unified OSINT research tool.
* [Censys Certificates](https://search.censys.io/certificates)
* [Google Certificate Transparency Report](https://transparencyreport.google.com/https/certificates)
* [SSLMate CT Policy Analyzer](https://sslmate.com/labs/ct_policy_analyzer/)

## Archive and Historical Data

* [Wayback Machine](https://web.archive.org/) - Historical website snapshots.
* [Archive.today](https://archive.ph/) - On-demand and historical page archives.
* [CachedView](https://cachedview.com/) - Google cache, Wayback Machine, and Archive.today helper.
* [waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch URLs from the Wayback Machine.
* [waymore](https://github.com/xnl-h4ck3r/waymore) - URL discovery from web archives and public datasets.

Google removed the old cache link feature from search results, so avoid relying on Google cache workflows for future investigations.

## Website Change Tracking

* [Follow That Page](https://followthatpage.com/) - Email alerts for web page changes.
* [Visualping](https://visualping.io/) - Visual and content change monitoring.

## URL Shortening and Redirections

* [GrayHatWarfare URL Shorteners](https://shorteners.grayhatwarfare.com) - Searches URLs exposed by shortener services.
* [urlhunter](https://github.com/utkusen/urlhunter) - Finds URLs exposed through shorteners.
* [Unshorten.It](https://unshorten.it/) - Reveals shortened-link destinations.
* [Redirect Detective](http://redirectdetective.com/) - Redirect-chain analysis.
* [Where Goes?](https://wheregoes.com) - URL redirect tracing.
* [Lookyloo](https://lookyloo.circl.lu) - Web forensics and redirect-chain capture.

Shortener preview tricks:

* **bit.ly** - Add `+` to the end of the URL.
* **cutt.ly** - Add `@` to the end of the URL.
* **tiny.cc** - Add `=` to the end of the URL.
* **tinyurl.com** - Add `preview.` before the host.

## Similar Website Search

* [SimilarSites](https://www.similarsites.com/)
* [SitesLike](https://siteslike.com/)
* [Similarweb](https://www.similarweb.com/)

## Safe Browser Views

* [WannaBrowser](https://www.wannabrowser.net/) - View source using different user-agent strings.
* [Browserling](https://www.browserling.com/) - Browser testing through hosted browsers.
* [URL2PNG](https://www.url2png.com/) - Website screenshots without visiting directly.

## Miscellaneous Domain Utilities

* [DNPedia](https://dnpedia.com/) - Domain statistics, scripts, news, and tools.
* [Google Admin Toolbox Dig](https://toolbox.googleapps.com/apps/dig/) - Web-based DNS lookup.
* [Backlink Checker](https://smallseotools.com/backlink-checker/) - Backlink monitoring.
* [DomLink](https://github.com/vysecurity/DomLink) - Finds organization names and email addresses from a domain.
* [Unfurl](https://dfir.blog/unfurl/) - Breaks down URLs into components.
* [r3con1z3r](https://github.com/abdulgaphy/r3con1z3r) - Web-based footprinting and OSINT CLI.
* [theHarvester](https://github.com/laramies/theHarvester) - Public-source email, host, and subdomain gathering.
* [gau](https://github.com/lc/gau) - Fetches known URLs from OTX, Wayback Machine, and Common Crawl.
* [lbd](https://www.kali.org/tools/lbd/) - Load-balancing detector.
* [Metagoofil](https://github.com/laramies/metagoofil) - Extracts metadata from public documents for a domain.
* [Cache Checker](https://www.giftofspeed.com/cache-checker/) - Lists cached web files and cache behavior.
* [CloudFlair](https://github.com/christophetd/CloudFlair) - Finds possible Cloudflare origin IPs from scan data.
* [cf-check](https://github.com/dwisiswant0/cf-check) - Checks Cloudflare protection.
* [AnalyticsRelationships](https://github.com/Josue87/AnalyticsRelationships) - Finds related domains through shared Google Analytics IDs.
* [LOTS Project](https://lots-project.com/) - Legitimate domains commonly abused for phishing, C2, exfiltration, and malware delivery.

## Google Dorking for Domains

* `site:example.com` - Indexed pages for a domain.
* `site:*.example.com` - Indexed subdomains.
* `site:example.com filetype:pdf` - Specific file types.
* `site:example.com inurl:admin` - Admin-related paths.
* `site:example.com intitle:"index of"` - Directory listings.
* `intext:"example.com" site:pastebin.com` - Domain mentions in pastes.
* `related:example.com` - Similar websites.

{% content-ref url="search-engines/google-dorking-cheatsheet.md" %}
[google-dorking-cheatsheet.md](search-engines/google-dorking-cheatsheet.md)
{% endcontent-ref %}

## Domain Monitoring

* [DomainTools](https://www.domaintools.com/) - Domain research, WHOIS history, DNS records, and brand monitoring.
* [ExpiredDomains.net](https://www.expireddomains.net/) - Expiring and deleted domains.
* [WhoisXMLAPI Domain Availability API](https://whoisxmlapi.com/domain-availability-api) - Domain availability monitoring.

Subdomain takeover testing with nuclei, Subjack, and related tools is offensive validation and belongs with active recon and web application testing.

{% content-ref url="../../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../../red-offensive/scanning-active-recon/)
{% endcontent-ref %}

{% content-ref url="../../web-app-hacking/" %}
[web-app-hacking](../../web-app-hacking/)
{% endcontent-ref %}

## Deprecated or Offline Tools

* **omnisint.io / Project Crobat** - Rapid7 DNS dataset service discontinued.
* **ThreatCrowd** - Offline/deprecated; data migrated to AlienVault OTX.
* **tls.bufferover.run** - BufferOver services discontinued.
* **Riddler.io** - Discontinued F-Secure network intelligence API.
* **CheckShortURL** - Frequently offline/unreliable.
* **W3DT** - Appears offline.
* **DomainIQ** - Service unavailable.
* **SubOver** - No longer maintained; use current takeover detection workflows in active recon.
* **Spyse** - Rebranded/acquired and no longer the same free OSINT search engine.
* **DomainFuzz** - Repository appears unavailable.
* **Bolster CheckPhish at bolster.ai/checkphish** - Not specifically a typosquatting resource.

## Investigation Mind Maps

![](<../../.gitbook/assets/image (40).png>)
