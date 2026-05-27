---
description: Is this bad?
---

# Threat Data

Use this page for indicator reputation, enrichment, passive DNS, certificate history, blockchain analysis, and quick lookup tools. Detection engineering, YARA, sandboxes, reverse engineering, active recon, and exploit research live in their own sections.

## How to Use This Page

Reputation checks are starting points, not verdicts. An indicator can still be malicious even if it does not appear on any blacklist, and a shared service, CDN, or compromised host can create false positives. Use multiple sources, document what each source said, and keep the surrounding context: ASN, registrar, creation date, passive DNS history, related certificates, associated malware families, and analyst comments.

## Threat Maps

Threat maps can help with situational awareness, but they should not be treated as precise telemetry for a specific incident.

* [Bitdefender Threat Map](https://threatmap.bitdefender.com)
* [Kaspersky Cyberthreat Real-Time Map](https://cybermap.kaspersky.com)
* [Mandiant Cyber Threat Map](https://www.mandiant.com/resources/cyber-threat-map)
* [Checkpoint Threat Map](https://threatmap.checkpoint.com)
* [FortiGuard Threat Map](https://threatmap.fortiguard.com)
* [Sophos Threat Center](https://www.sophos.com/en-us/threat-center)
* [NETSCOUT Horizon](https://horizon.netscout.com)
* [SonicWall Worldwide Attacks](https://securitycenter.sonicwall.com/m/page/worldwide-attacks)
* [Spamhaus Threat Map](https://www.spamhaus.com/threat-map/)

## Threat Actor Information

* [DarkFeed RansomWiki](https://darkfeed.io/ransomwiki/) - Ransomware group tracking and links.
* [CrowdStrike Adversary Universe](https://adversary.crowdstrike.com/) - Threat actor profiles and e-crime tracking.
* [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) - Malware family and actor context. Malware analysis details are maintained in DFIR.

{% content-ref url="../dfir-digital-forensics-and-incident-response/malware.md" %}
[malware.md](../dfir-digital-forensics-and-incident-response/malware.md)
{% endcontent-ref %}

## Blacklist Checks and Reputation Data

### Multi-Source Lookups

* [Hurricane Electric BGP Toolkit](https://bgp.he.net/) - IP, domain, ASN, subnet, WHOIS, BGP, DNS, and related metadata.
* [VirusTotal](https://www.virustotal.com/) - File, hash, IP, URL, and domain reputation with community comments and relationship pivots.
  * [VirusTotal Dorks](https://github.com/Neo23x0/vti-dorks)
* [Cisco Talos Intelligence](https://talosintelligence.com/reputation_center) - IP, domain, network owner, email volume, and reputation data.
* [MXToolbox Blacklist Check](https://mxtoolbox.com/blacklists.aspx) - Domain and IP blacklist checks.
* [MultiRBL](http://multirbl.valli.org/lookup/) - DNSBL and FCrDNS lookup.
* [InfoByIP Bulk IP Lookup](https://www.infobyip.com/ipbulklookup.php) - Bulk IP/domain lookup.

### IP Reputation

* [IPVoid](https://www.ipvoid.com/ip-blacklist-check/) - IP blacklist, reverse DNS, ASN, and geolocation summary.
* [DNSBL.info](https://www.dnsbl.info/) - Mail server DNSBL checks.
* [Team Cymru IP Reputation](https://reputation.team-cymru.com/) - IP reputation lookup.
* [blocklist.de](http://www.blocklist.de/en/search.html) - Abuse-oriented IP and netblock lookup.
* [Project Honey Pot](https://www.projecthoneypot.org/search_ip.php) - Distributed honeypot IP activity.
* [Focsec](https://focsec.com/) - API-only VPN, proxy, Tor, and bot risk checks.
* [IPQualityScore IP Reputation](https://www.ipqualityscore.com/ip-reputation-check) - IP fraud, spam, proxy, and VPN risk checks.
  * [IPQualityScore VPN IP Check](https://www.ipqualityscore.com/vpn-ip-address-check)

### URL and Domain Reputation

* [urlscan.io](https://urlscan.io/) - URL scanning, screenshot, HTTP transaction, IP, domain tree, and technology data.
* [URLVoid](https://www.urlvoid.com/) - URL/domain reputation, WHOIS, reverse DNS, and ASN data.
* [Zscaler Zulu](https://zulu.zscaler.com/) - URL risk analysis.
* [PhishTank](https://www.phishtank.com/) - Community phishing URL database.
* [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) - Google phishing and malware status.
* [Quttera](https://quttera.com/website-malware-scanner) - Website malware scanning.
* [Sucuri SiteCheck](https://sitecheck.sucuri.net/) - Website malware and security checks.
* [AdGuard Reports](https://reports.adguard.com/en/welcome.html) - AdGuard block list lookup.
* [LOTS Project](https://lots-project.com/) - Legitimate domains commonly abused for phishing, C2, exfiltration, and malware delivery.

### File Hash Reputation

* [Cisco Talos File Reputation](https://talosintelligence.com/talos_file_reputation) - SHA-256 file reputation.
* [MalwareBazaar](https://bazaar.abuse.ch/browse/) - Malware samples and hash lookup from abuse.ch.
* [Team Cymru Malware Hash Registry](https://hash.cymru.com/) - MD5, SHA-1, and SHA-256 hash lookup.
* [CIRCL Hashlookup](https://hashlookup.circl.lu/) - Hash lookup API from CIRCL.
* [Xcitium Valkyrie](https://valkyrie.comodo.com/) - File verdicts and dynamic analysis metadata.

For full sandboxing and malware behavior analysis, use DFIR sandboxing.

{% content-ref url="../dfir-digital-forensics-and-incident-response/sandboxing.md" %}
[sandboxing.md](../dfir-digital-forensics-and-incident-response/sandboxing.md)
{% endcontent-ref %}

### Email and Spam Data

* [EmailRep](https://emailrep.io/) - Email reputation, domain reputation, social presence, and policy context.
* [MXToolbox MX Lookup](https://mxtoolbox.com/MXLookup.aspx) and [SuperTool](https://mxtoolbox.com/SuperTool.aspx) - MX, DMARC, DNS, and blacklist pivots.
* [HaveIBeenEmotet](https://www.haveibeenemotet.com/) - Historical Emotet malspam involvement lookup.

## Indicator Enrichment

These platforms add context to indicators through scanner telemetry, historical data, abuse reports, and related infrastructure.

* [GreyNoise](https://viz.greynoise.io/) - Separates internet background noise from targeted activity and provides scanner tags.
* [BrightCloud URL/IP Lookup](https://brightcloud.com/tools/url-ip-lookup.php) - URL/IP category and reputation.
* [AbuseIPDB](https://www.abuseipdb.com/) - IP abuse reporting and confidence scores.
* [SANS DShield](https://secure.dshield.org/) - Honeypot, SSH, port, header, and reputation context.
* [ThreatFox](https://threatfox.abuse.ch/browse/) - IoC library from abuse.ch.
* [Spamhaus](https://check.spamhaus.org/) - IP and domain blacklist status.
* [ThreatIntelligencePlatform.com](https://threatintelligenceplatform.com) - Domain/IP/hash enrichment.
* [OPSWAT MetaDefender](https://metadefender.opswat.com/?lang=en) - File, URL, IP, domain, hash, and CVE lookup.
* [Microsoft Defender Threat Intelligence](https://ti.defender.microsoft.com/) - Microsoft threat intelligence platform, formerly RiskIQ/PassiveTotal.
* [Pulsedive](https://pulsedive.com/) - Indicator, threat, and feed enrichment.
* [ThreatShare](https://threatshare.io/malware/) - Malware URL and family context.
* [PhishStats](https://phishstats.info/) - Phishing URL metadata.
* [Abusix Lookup](https://lookup.abusix.com/) - IP, domain, and email blocklist lookup.
* [CleanTalk](https://cleantalk.org) - Spam and blocklist checks.

Threat intelligence platforms and feed management tools live in Intel Feeds and Sources.

{% content-ref url="intel-feeds-and-sources.md" %}
[intel-feeds-and-sources.md](intel-feeds-and-sources.md)
{% endcontent-ref %}

## Passive DNS and Historical Data

* [SecurityTrails](https://securitytrails.com/) - Historical DNS, WHOIS, subdomains, and IP history.
* [Microsoft Defender Threat Intelligence](https://ti.defender.microsoft.com/) - Passive DNS, WHOIS, SSL certificates, trackers, and related infrastructure.
* [Farsight DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/) - Passive DNS database.
* [DNSHistory.org](https://dnshistory.org/) - Historical DNS lookup.
* [WhoisXMLAPI](https://www.whoisxmlapi.com/) - Historical WHOIS and DNS records.
* [ViewDNS.info](https://viewdns.info/) - DNS and network lookup tools.
* [DNSTrails](https://dnstrails.com/) - Historical DNS and passive DNS database.

Domain-focused passive investigation workflows live in Domain OSINT.

{% content-ref url="osint/domain.md" %}
[domain.md](osint/domain.md)
{% endcontent-ref %}

## Certificate Transparency and SSL/TLS Analysis

* [crt.sh](https://crt.sh/) - Certificate transparency log search.
* [Censys Certificates](https://search.censys.io/certificates) - Certificate search with filtering.
* [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) - SSL/TLS configuration analysis.
* [SSLShopper SSL Checker](https://www.sslshopper.com/ssl-checker.html) - Certificate verification and chain analysis.
* [Certificate Search](https://certificatesearch.com/) - Multi-source certificate transparency search.
* [Google Certificate Transparency Report](https://transparencyreport.google.com/https/certificates) - Google CT search interface.

## Browser Extensions and Quick Lookup Tools

* [CrowdSec CTI Extension](https://chrome.google.com/webstore/detail/crowdsec-cti/nfhlhlkjnlkdgbkjkhjkngakjfaljbec) - Quick IP and URL lookups.
* [Sputnik](https://github.com/mitchmoser/sputnik) - Configurable OSINT and threat intelligence lookup extension.
* [Gotanda](https://github.com/HASH1da1/Gotanda) - OSINT browser extension for extracting and searching indicators.
* [ThreatConnect Extension](https://chrome.google.com/webstore/detail/threatconnect/hbghlhcflekehioljloookhpdfjpbcka) - ThreatConnect lookups from selected text.
* [URL Unshortener](https://chrome.google.com/webstore/detail/url-unshortener/gbobhobdgeopnhpommcvdckfhqjknjom) - Shows destinations of shortened URLs.
* [VirusTotal Checker](https://chrome.google.com/webstore/detail/virustotal/efbjojhplkelaegfbieplglfidafgoka) - Browser context-menu VirusTotal lookups.

## Cryptocurrency and Blockchain Analysis

* [Blockchain.com Explorer](https://www.blockchain.com/explorer) - Bitcoin explorer.
* [Etherscan](https://etherscan.io/) - Ethereum explorer.
* [BlockCypher](https://live.blockcypher.com/) - Multi-blockchain explorer.
* [BTC.com](https://btc.com/) - Bitcoin explorer and mining pool statistics.
* [Chainalysis](https://www.chainalysis.com/) - Commercial blockchain analysis platform.
* [Elliptic](https://www.elliptic.co/) - Commercial cryptocurrency compliance and investigation tooling.
* [Crystal Blockchain](https://crystalblockchain.com/) - Cryptocurrency intelligence platform.
* [Bitcoin Abuse Database](https://www.bitcoinabusedatabase.com/) - Community reports of scam and ransomware Bitcoin addresses.

## Investigation Tools

{% hint style="info" %}
Some tools require more complex URL structures than simple parameter appending. Additional functionality may be needed for full automation.
{% endhint %}

{% file src="../.gitbook/assets/EasyOSINT.html" %}

{% embed url="https://github.com/s0cm0nkey/EasyOSINT" %}

The following mind map illustrates commonly used tools for indicator analysis and their relationships:

![](<../.gitbook/assets/Threat Object.png>)

The interactive version can be found here:

{% file src="../.gitbook/assets/Threat Object (1).xmind" %}

## Related Sections

* Internet-wide search engines such as Shodan, Censys, FOFA, ZoomEye, BinaryEdge, Onyphe, and FullHunt live in Cyber Search.

{% content-ref url="osint/cyber-search.md" %}
[cyber-search.md](osint/cyber-search.md)
{% endcontent-ref %}

* YARA rules and malware signature hunting live in DFIR.

{% content-ref url="../dfir-digital-forensics-and-incident-response/yara.md" %}
[yara.md](../dfir-digital-forensics-and-incident-response/yara.md)
{% endcontent-ref %}

* Sigma rules, MITRE CAR, detection content, and detection engineering live in Event Detection.

{% content-ref url="../blue-defense/event-detection/" %}
[event-detection](../blue-defense/event-detection/)
{% endcontent-ref %}

* LOLBAS, GTFOBins, LOLDrivers, LOLAPPS, and WADComs are useful for detection and adversary tradecraft context. Keep them with detection engineering or technique-specific pages rather than reputation lookup.

{% content-ref url="../blue-defense/event-detection/detection-use-cases/" %}
[detection-use-cases](../blue-defense/event-detection/detection-use-cases/)
{% endcontent-ref %}

* Vulnerability databases, CISA KEV, EPSS, SSVC, and CVSS live in Asset and Vulnerability Management.

{% content-ref url="../blue-defense/vulnerability-management.md" %}
[vulnerability-management.md](../blue-defense/vulnerability-management.md)
{% endcontent-ref %}

* Exploit archives and offensive exploit research live in Red Offensive.

{% content-ref url="../red-offensive/testing-methodology/exploit-research.md" %}
[exploit-research.md](../red-offensive/testing-methodology/exploit-research.md)
{% endcontent-ref %}

## Best Practices for Indicator Analysis

1. Validate across multiple sources.
2. Preserve context such as ASN, registrar, domain age, passive DNS, certificates, and comments.
3. Document sources consulted and the time of lookup.
4. Use passive analysis first when you do not want to alert adversaries.
5. Treat blocklist absence as unknown, not benign.
6. Verify indicators before blocking or alerting on them.

## Deprecated and Legacy Tools

* **ThreatCrowd** - Deprecated. Data migrated to AlienVault OTX; original service is no longer maintained.
* **Digital Attack Map** - Discontinued by Arbor Networks/NETSCOUT.
* **Malware Domain List (MDL)** - No longer actively maintained.
* **Ransomwhere** - Bitcoin ransomware tracker that appears inactive.
* **CybOX** - Legacy observable specification largely superseded by STIX 2.x observables.
* **Sigmac** - Deprecated Sigma converter; pySigma and sigma-cli replaced it.
* **YARA-Rules/rules** - Archived community YARA rules repository.

## Tool Accuracy Notes

* Blacklist source counts change frequently, so this page avoids hard-coding source counts.
* Free APIs often have rate limits or require registration.
* Browser extension links can change; search by extension name if a store link breaks.
* Passive DNS retention varies by provider.
* Advanced malware may detect sandbox environments and alter behavior.
