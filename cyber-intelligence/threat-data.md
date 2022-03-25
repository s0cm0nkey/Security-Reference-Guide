---
description: Is this bad?
---

# Threat Data

## Intro

When checking out the reputation and threat data behind and indicator, there are two main parts: Checking for the presence of the indicator on available blacklists and enriching your investigation with intelligence and metadata around the target indicator.

When checking your indicators against the below sources, be sure you are looking at the other data that is provided outside of the blacklist check. Tools like Hurricane Electric and Cisco's Talos can give you information about the ASN or subnet an indicator is apart of. Use them to see if its not just one IP that is flagged, but if it is an entire subnet or ASN. For domains, look for registration information and registration dates. How long ago was that domain registered? Have you seen malicious domains registered by this user before? Lastly make sure you look at any other related data, even if it is as simple as the comments section of VirusTotal. Other analysts can save you a tremendous amount of work, by making a simple note to help you.

\*WARNING\* - An indicator can still be malicious even if it is not on any searched blacklists. Do not make the mistake of assuming something is benign, simply because your searches returned nothing.

## Threat Maps

* [https://threatmap.bitdefender.com](https://threatmap.bitdefender.com)
* [https://cybermap.kaspersky.com](https://cybermap.kaspersky.com)
* [https://www.digitalattackmap.com](https://www.digitalattackmap.com)
* [https://www.fireeye.com/cyber-map/threat-map.html](https://www.fireeye.com/cyber-map/threat-map.html)
* [https://map.lookingglasscyber.com](https://map.lookingglasscyber.com)
* [https://threatmap.checkpoint.com](https://threatmap.checkpoint.com)
* [https://talosintelligence.com/reputation\_center/](https://talosintelligence.com/reputation\_center/)
* [https://talosintelligence.com/fullpage\_maps/](https://talosintelligence.com/fullpage\_maps/)
* [https://www.spamhaus.com/threat-map/](https://www.spamhaus.com/threat-map/)
* [https://www.imperva.com/cyber-threat-attack-map/](https://www.imperva.com/cyber-threat-attack-map/)
* [https://threatbutt.com/map/](https://threatbutt.com/map/)
* [https://threatmap.fortiguard.com](https://threatmap.fortiguard.com)
* [https://www.sophos.com/en-us/threat-center/threat-monitoring/threatdashboard.aspx](https://www.sophos.com/en-us/threat-center/threat-monitoring/threatdashboard.aspx)
* [https://horizon.netscout.com](https://horizon.netscout.com)
* [https://securitycenter.sonicwall.com/m/page/worldwide-attacks](https://securitycenter.sonicwall.com/m/page/worldwide-attacks)

## Threat Actor Information

* [https://darkfeed.io/ransomwiki/](https://darkfeed.io/ransomwiki/) - A site for researchers that keeps track and provides links to various ransomware group darknet sites.
* [Ransomware Group Site](http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion) - An onion site that provides links and details about ransomware groups currently operating.
  * [Clearnet Proxy](http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion.pet)

## **Blacklist Checks and Reputation Data**

### Multi - Blacklist Checkers

* [Hurricane Electric BGP Toolkit](https://bgp.he.net)
  * Searches: IP address, Domain, ASN, Subnet
  * Returns: IP information, WHOIS, DNS (A records), Reputation Check ( IP Only - 93 sources), Website info, Website Preview
* [Virustotal](https://www.virustotal.com)
  * Searches: File, hash, ip, domain search
  * Returns: Reputation check (84 sources), DNS records, HTTPS Cert, WHOIS, Related domains, Community comments
  * Has a premium API
  * [https://virustotal.com/wargame/ ](https://virustotal.com/wargame/)- Virustotal training!
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

### IP Reputation data

* [IPVoid](https://www.ipvoid.com/ip-blacklist-check/) - Returns: Reputation data (115 sources checked), Reverse DNS, ASN, Country
* [DNSBL Email server spam checker](https://www.dnsbl.info) - Checks IP of mail server for spam data accross 100+ blacklists
* [IPSpam List](http://www.ipspamlist.com/ip-lookup/) - Checks IP against their internal blacklist for reporting spam
* [Cymru IP Reputation Lookup](https://reputation.team-cymru.com) - Checks IP against Cymru's internal reputation feed (High quality)
* [http://www.blocklist.de/en/search.html](http://www.blocklist.de/en/search.html) - Check if a netblock or IP is malicious according to blocklist.de.
* [https://www.projecthoneypot.org/search\_ip.php](https://www.projecthoneypot.org/search\_ip.php) - Checks IP Attack data from distributed honeypot network.
* [https://focsec.com/](https://focsec.com) (API ONLY) - Determine if a user’s IP address is associated with a VPN, Proxy, TOR or malicious bots.

### URL/Domain Reputation data

* [URLScan ](https://urlscan.io) - Returns: Summary data, Reputation data, IP data, domain tree, HTTP transaction data, Screenshot of page, Detected Technologies, links
* [URLVoid](https://www.urlvoid.com)  - Returns Reputation data (34 sources), Registration info, WHOIS, Reverse DNS, ASN
* [Zscalar Zulu](https://zulu.zscaler.com) - Returns: URL info, Risk analysis, Content, URL checks, Host checks
* [PhishTank](https://www.phishtank.com) - Returns: Listed on PhishTank
* [Quttera Malware Scanner ](https://quttera.com/website-malware-scanner)- Returns: Website malware scan report
* [MergiTools RBL check](https://megritools.com/blacklist-lookup) - Returns: Reputation data&#x20;
* [Malware Domain Lists](http://www.malwaredomainlist.com/mdl.php?search=\&colsearch=All\&quantity=50) - Returns: Reputation data&#x20;
* [Securi SiteCheck](https://sitecheck.sucuri.net) - Returns: Security check and malware scan
* [https://lots-project.com/](https://lots-project.com) - Living Off Trusted Sites (LOTS) Project, Attackers are using popular legitimate domains when conducting phishing, C\&C, exfiltration and downloading tools to evade detection. The list of websites below allow attackers to use their domain or subdomain.
* [https://reports.adguard.com/en/welcome.html](https://reports.adguard.com/en/welcome.html) - Checks if site is on AdGuard's block list

### File Hash Reputation Data

* [Cisco Talos File Reputation ](https://talosintelligence.com/talos\_file\_reputation)- SHA256 Only
* [Abuse\[.\]ch Malware Baazar ](https://bazaar.abuse.ch/browse/)- Searches MD5, SHA256, and Keyword
  * Returns: Hash, tag, file type, clamAV signature, Yara rule, misc.
* [Cymru MHR lookup](https://hash.cymru.com) - Searches SHA1 and MD5
* [CIRCL Hashlookup](https://hashlookup.circl.lu) - A super handy API hash lookup from the creators of MISP. Takes MD5 and SHA1.
* [Comodo Valkyrie](https://valkyrie.comodo.com) - SHA1 Only. Returns: File name, submit date, threat verdict by dynamic and human analysis.

### Email/Spam Data

* [Simple Email Rep checker](https://emailrep.io) - Returns: Domain reputation, presence on social media, Blacklisted/Malicious activity, Email policy settings
* [MXtoolbox MX lookup](https://mxtoolbox.com/MXLookup.aspx) and [Super tool ](https://mxtoolbox.com/SuperTool.aspx)-  Returns: Host information, DMARC and DNS record data, Pivot to Blacklist check
* [HaveIBeenEmotet](https://www.haveibeenemotet.com) - Returns: If your email address or domain is involved in the Emotet malspam.

## **Indicator Enrichment**

These resources may not specifically return reputation data, but with the help of internet scanning services, internet-wide traffic metadata, and indicator enrichment and sharing platforms, we can now add much needed context to our indicators.&#x20;

{% content-ref url="osint/cyber-search.md" %}
[cyber-search.md](osint/cyber-search.md)
{% endcontent-ref %}

* [Greynoise](https://viz.greynoise.io)
  * Searches: IP address, domain
  * Returns: Reputation data, tags of related activity, location data, “last-seen”, reverse DNS, Threat Actor Information, Related Organizations, Related ASNs, Top Operating Systems, service type
  * Premium API available, command line version available
  * [Community API (Free)](https://developer.greynoise.io/reference/community-api)
  * [https://www.greynoise.io/viz/cheat-sheet](https://www.greynoise.io/viz/cheat-sheet)
  * [https://github.com/GreyNoise-Intelligence/pygreynoise](https://github.com/GreyNoise-Intelligence/pygreynoise)
  * _Operator Handbook: Greynoise - pg. 84_
* [BrightCloud](https://www.brightcloud.com/tools/url-ip-lookup.php)
  * Searches: IP address, domain
  * Returns: Web Reputation, Web category, WHOIS
* [ThreatCrowd (Alienvault)](https://www.threatcrowd.org)
  * Searches: Domain, IP, Email, Organization
  * Returns: Reputation data, WHOIS, Reverse DNS, Open Ports, Subdomains, Related Entity Graph, pivot search to AlienVault OTX indicator information
* [AbuseIPDB](https://www.abuseipdb.com)
  * Searches: IP, Domain, Subnet
  * Returns: Reputation data, usage type, Location info
* [SANS D-Shield](https://secure.dshield.org)
  * Searches: Keyword, IP, domain, Port, Header
  * Returns: General information, Reputation data, SSH logs, Honeypot logs, WHOIS
* [Abuse\[.\]ch ThreatFox IOC library](https://threatfox.abuse.ch/browse/)
  * Search: IoCs (ip, domain, hash, etc.)
  * Returns: date, IoC, malware family, Tags, Reporter
* [Spamhaus Project](https://check.spamhaus.org)
  * Searches: IP, Domain, Hash
  * Returns: Reputation data
* [ThreatInteligencePlatform.com](https://threatintelligenceplatform.com)
  * Searches: IP, Domain, Hash
  * Returns: Reputation Data, Web site data, Open Ports, SSL Certificate data, Malware Detection, WHOIS, MX records and config, NS records and config
* [OPSWAT Metadefender](https://metadefender.opswat.com/?lang=en)
  * Searches: File, URL, IP, Domain, Hash, CVE
  * Returns: Any detection from multiple other engines with link to that engines data.
* [RiskIQ Intel Articles](https://community.riskiq.com/home)
  * Searches: Domain, Hosts, IP, Email, Hash, Tags
  * Returns: Associated intelligence article containing the searched for indicator
* [PulseDive](https://pulsedive.com)
  * Searches: Indicators, Threats, Feeds, Misc. data
  * Returns: Risk Info, Highlights, Ports, Threat info, Reputation data, Linked Indicators
* [Malc0de database](https://malc0de.com/database/)
  * Searches: IP, domain, hash, ASN
  * Returns: ?????
* [ThreatShare](https://threatshare.io/malware/)
  * Searches: IP, URL
  * Returns: malware family, online status, URLscan data
* [Phishstats](https://phishstats.info) (Public Dashboard 2)
  * Searches: IP, host, domain, full URL
  * Returns: Related metadata and reputation data.
* [Twitter IOC Hunter](http://tweettioc.com) - An incredible tool that scrapes twitter for IoCs that are publicly reported through thier platform and puts them into a searchable repository. Tweet IoCs are one of the fastest ways to get information on newly discovered IoCs as they will often have context around thier discovery.
* [https://lookup.abusix.com/](https://lookup.abusix.com)
  * Search: IP, domain, or email address
  * Returns: Presence on internal blocklist and misc available detail.
* [https://cleantalk.org/#](https://cleantalk.org/#)
  * Search: IP Addresses, Email, Subnet, Domain
  * Returns: Presence on internal blocklist for spam activity

## Investigation Tools

If you do not have a SOAR platform to perform some of the OSINT lookups for you, Security analysts must take the tedious effort of plugging their IoC into one of the above tools to gather data manually. To make that process easier, I created a tool that will allow you to open all the tools you want and pivot directly to their results.

{% hint style="info" %}
Note: Some tools require more than a simple append on to the end of the URI. I am currently working on expanding that functionality.
{% endhint %}

{% file src="../.gitbook/assets/EasyOSINT.html" %}

{% embed url="https://github.com/s0cm0nkey/EasyOSINT" %}

Here is a MindMap I have made of the popular tools I use for analyzing indicators.

![](<../.gitbook/assets/Threat Object.png>)

The interactive version can be found here:

{% file src="../.gitbook/assets/Threat Object (1).xmind" %}

