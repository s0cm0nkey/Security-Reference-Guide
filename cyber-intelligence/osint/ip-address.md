# IP Address

Use this page for passive IP investigation: registration data, ASN ownership, BGP/routing context, geolocation, anonymization checks, and related infrastructure pivots. Active port scanning belongs in Red Offensive; reputation and blacklist checks belong in Threat Data.

{% content-ref url="../threat-data.md" %}
[threat-data.md](../threat-data.md)
{% endcontent-ref %}

{% content-ref url="../../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../../red-offensive/scanning-active-recon/)
{% endcontent-ref %}

## IP.html Tool

IP.html is a Michael Bazzell helper that opens multiple IP research sources from one input.

{% hint style="info" %}
Some entries in older IP.html workflows may be stale or active recon oriented. Treat port scanning as active testing, and verify each external service before relying on it.
{% endhint %}

Current useful lookup categories include:

* **Search engines** - Bing and other indexed references.
* **Registration data** - IP WHOIS and RDAP.
* **Network ownership** - ASN, routing, reverse IP, and infrastructure pivots.
* **Cyber search** - Shodan, ZoomEye, and similar indexed scan data.
* **Public records** - Identity or breach pivots where legally appropriate.

{% file src="../../.gitbook/assets/IP (1).html" %}

## WHOIS vs. RDAP

WHOIS is the older protocol for IP and domain registration lookups. It is useful, but response formatting varies between registries.

RDAP (Registration Data Access Protocol) is the modern structured replacement. The RFC 7480 series was published in 2015, and RDAP adoption has continued across registries since then.

* [RDAP Lookup](https://client.rdap.org)
* [ICANN RDAP](https://www.icann.org/rdap)

## ASN Lookup

Autonomous System Numbers (ASNs) help identify who controls routed IP space and how infrastructure relates to providers, peers, and prefixes.

* [Hurricane Electric BGP Toolkit](https://bgp.he.net/) - ASN, prefix, peering, WHOIS, and DNS context.
* [ASNLookup](https://asnlookup.com/) - Quick ASN and prefix lookup.
* [RIPE Stat](https://stat.ripe.net/) - IP, ASN, and routing statistics.
* [MXToolbox ASN Lookup](https://mxtoolbox.com/asn.aspx) - ASN lookup with network details.
* [ipinfo.io](https://ipinfo.io/) - ASN, geolocation, organization, and IP metadata.
* [UltraTools ASN Info](https://www.ultratools.com/tools/asnInfo)

## BGP and Routing Information

* [BGPView](https://bgpview.io/) - ASN details, prefixes, peers, and routing data.
* [RIPE RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris) - Real-time BGP routing data.
* [Route Views](https://www.routeviews.org/) - BGP route archives.
* [bgp.tools](https://bgp.tools/) - Modern BGP and ASN analysis.
* [PeeringDB](https://www.peeringdb.com/) - Peering and interconnection data.

## IP Anonymization Detection

These tools help identify Tor exits, VPN/proxy services, and other anonymization infrastructure. Cross-reference results before making enforcement decisions.

* [ExoneraTor](https://metrics.torproject.org/exonerator.html) - Check whether an IP was a Tor relay on a specific date.
* [SEON IP Analysis](https://seon.io/intelligence-tool/#ip-analysis-module) - IP risk, Tor, VPN, proxy, and blacklist context.
* [IPQualityScore VPN IP Check](https://www.ipqualityscore.com/vpn-ip-address-check) - VPN and proxy detection.
* [I Know What You Download](https://iknowwhatyoudownload.com) - Torrent activity associated with an IP address.

Tor and VPN OPSEC guidance lives in the privacy section.

{% content-ref url="../../grey-privacy-tor-opsec/" %}
[grey-privacy-tor-opsec](../../grey-privacy-tor-opsec/)
{% endcontent-ref %}

## IP Geolocation

IP geolocation is approximate. Results can reflect ISP registration, VPN/proxy exit location, cloud region, or mobile carrier infrastructure rather than a user's physical location.

* [IPLocation.net](https://www.iplocation.net/)
* [IP2Location](https://www.ip2location.com/)
* [ipapi](https://ipapi.com/)
* [ipstack](https://ipstack.com/)
* [MaxMind GeoIP Demo](https://www.maxmind.com/en/geoip-demo)

## Additional IP Intelligence Tools

* [Focsec](https://focsec.com/) - IP reputation API for VPN, proxy, Tor, and bot detection.

## Deprecated or Unreliable Tools

These are preserved for historical reference or because they may appear in older IP.html workflows.

* **Google cached pages** - Google removed the classic cached-page feature from search results.
* **Legacy public port-scan widgets** - Treat as active testing and use current authorized scanning workflows instead.
* **Unmaintained IP reputation mirrors** - Prefer current providers listed on Threat Data.
