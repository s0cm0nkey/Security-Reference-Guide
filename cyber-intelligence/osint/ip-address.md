# IP Address

## Overview

When researching IP addresses, understanding the context of your investigation is critical. The tools and methods you use will vary depending on whether you're conducting offensive or defensive operations.

**Offensive Security & Reconnaissance:**
For offensive security, threat hunting, and attack surface mapping, focus on current registration data and associated artifacts such as:
- Hosted domains
- Autonomous System Numbers (ASN)
- Network infrastructure
- Related services and ports

**Defensive Security Operations:**
For defensive operations (blue team), prioritize historical activity data and behavioral patterns. These defensive tools are covered in the threat research section. This page focuses primarily on offensive intelligence gathering and reconnaissance.

## IP.html Tool

IP.html is a convenient automation tool created by Michael Bazzel that streamlines initial IP address reconnaissance. The tool automatically populates multiple search queries across various intelligence platforms, allowing you to quickly gather comprehensive information about your target.

> **Important Note:** Some platforms included in this tool are no longer available or have been deprecated (see Deprecated Tools section below). Always verify tool functionality before relying on results.

**Included search platforms (currently active):**
- **Search Engines:** Bing
- **Network Analysis:** Reverse IP, Port Scan, TraceRoute
- **Registration Data:** IP Whois, Who.IS IP
- **Threat Intelligence:** Shodan, ZoomEye
- **Public Records:** "That's Them", Dehashed (requires authentication)
- **Miscellaneous:** Locate IP, Torrents, UltraTools IP

{% file src="../../.gitbook/assets/IP (1).html" %}



## WHOIS vs. RDAP

WHOIS has been the traditional protocol for gathering registration data on IP addresses and domains. However, it lacks a standardized structure for organizing and maintaining registration data, which can lead to inconsistent results.

**RDAP (Registration Data Access Protocol)** addresses these limitations. Standardized in 2015 (RFCs 7480-7485), RDAP provides a structured, modern alternative to WHOIS with consistent data formatting and better security features. RDAP is gradually replacing WHOIS as the preferred protocol for registration data queries.

**Resources:**
* RDAP lookup tool: [https://client.rdap.org](https://client.rdap.org)
* RDAP documentation: [https://www.icann.org/rdap](https://www.icann.org/rdap)

## ASN (Autonomous System Number) Lookup

Understanding the Autonomous System Number (ASN) associated with an IP address is crucial for mapping network ownership, identifying infrastructure relationships, and conducting thorough reconnaissance. ASNs are assigned to networks and internet service providers, providing insight into who controls the routing of specific IP ranges.

**ASN Lookup Tools:**
* [https://bgp.he.net/](https://bgp.he.net/) - Hurricane Electric BGP Toolkit - Comprehensive ASN information, prefixes, and peering data
* [https://asnlookup.com/](https://asnlookup.com/) - Quick ASN lookup with network prefix information
* [https://stat.ripe.net/](https://stat.ripe.net/) - RIPE Stat - Detailed statistics and data about IP addresses, ASNs, and prefixes
* [https://mxtoolbox.com/asn.aspx](https://mxtoolbox.com/asn.aspx) - MXToolbox ASN Lookup - ASN information with network details
* [https://ipinfo.io/](https://ipinfo.io/) - IP address data including ASN, geolocation, and company information
* [https://www.ultratools.com/tools/asnInfo](https://www.ultratools.com/tools/asnInfo) - UltraTools ASN Information lookup

## BGP & Routing Information

Border Gateway Protocol (BGP) is the routing protocol of the internet. Analyzing BGP data provides visibility into how networks are interconnected, routing paths, and network relationships. This information is valuable for understanding internet infrastructure, identifying upstream providers, and detecting routing anomalies.

**BGP Analysis Tools:**
* [https://bgpview.io/](https://bgpview.io/) - BGP routing information, ASN details, peer relationships, and prefix announcements
* [https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris) - RIPE RIS - Real-time BGP routing data collection
* [https://www.routeviews.org/](https://www.routeviews.org/) - University of Oregon Route Views Project - BGP routing table archives and analysis
* [https://bgp.tools/](https://bgp.tools/) - Modern BGP analysis and monitoring platform
* [https://www.peeringdb.com/](https://www.peeringdb.com/) - Database of networks and interconnection data for peering coordination

## IP Anonymization Detection

Determining whether an IP address is associated with anonymization services is crucial for threat intelligence and investigation work.

### Tor Node Detection

**ExoneraTor** - Check if an IP address was a Tor relay on a specific date:
* [https://metrics.torproject.org/exonerator.html](https://metrics.torproject.org/exonerator.html)

**SEON Intelligence Tool** - Comprehensive IP analysis including Tor detection, VPN, proxy, and blacklist checks:
* [https://seon.io/intelligence-tool/#ip-analysis-module](https://seon.io/intelligence-tool/#ip-analysis-module)

### VPN Detection

**IPQualityScore** - Identify VPN exit nodes and proxy services:
* [https://www.ipqualityscore.com/vpn-ip-address-check](https://www.ipqualityscore.com/vpn-ip-address-check)

### Torrent Activity

**I Know What You Download** - Search for torrent activity associated with an IP address:
* [https://iknowwhatyoudownload.com](https://iknowwhatyoudownload.com)

## IP Geolocation

IP [geolocation](https://www.iplocation.net/geolocation) can be determined through various methods including HTML5 API, cellular signal triangulation, and IP address databases. The following services use different geolocation databases and methodologies to approximate the physical location of an IP address.

> **Important Note:** Always cross-reference multiple geolocation tools for accuracy. Results may show the registrant's location rather than the actual IP location. Geographic precision varies based on the IP type (data center, residential, mobile) and the quality of the geolocation database.

**Geolocation Tools:**
* [https://www.iplocation.net/](https://www.iplocation.net/) - Comprehensive IP location and network information
* [https://www.ip2location.com/](https://www.ip2location.com/) - IP geolocation with ISP and domain data
* [https://ipapi.com/](https://ipapi.com/) - Real-time IP geolocation with comprehensive location and ISP data
* [https://ipstack.com/](https://ipstack.com/) - IP geolocation API with detailed location information
* [https://www.maxmind.com/en/geoip-demo](https://www.maxmind.com/en/geoip-demo) - MaxMind GeoIP2 lookup (industry-standard geolocation database)

## Additional IP Intelligence Tools

* [https://focsec.com/](https://focsec.com/) - Comprehensive IP reputation check for VPN, proxy, Tor, and malicious bot detection


