# Logging - Network Services

Network service logs provide visibility into communication patterns, service use, policy enforcement, and investigation context. This page focuses on collection and useful fields. Packet analysis tools, PCAP workflows, and deep NFAT analysis live in Blue Defense.

{% content-ref url="../blue-defense/packet-analysis.md" %}
[packet-analysis.md](../blue-defense/packet-analysis.md)
{% endcontent-ref %}

## Logging Sources

* **Network devices** - Routers, layer 3 switches, firewalls, VPN concentrators, and load balancers can export flow or session metadata.
* **Next-generation firewalls** - Often provide flow logs, application labels, user identity, URL categories, actions, and threat signatures.
* **Network sensors** - TAP/SPAN-connected sensors can generate Zeek/Corelight logs, flow records, PSTR, and PCAP.
* **Cloud infrastructure** - Cloud providers can produce flow logs such as AWS VPC Flow Logs, Azure NSG Flow Logs, and Google VPC Flow Logs.

Cloud flow logs are covered with other cloud audit sources on the Cloud Logging page.

{% content-ref url="logging-cloud.md" %}
[logging-cloud.md](logging-cloud.md)
{% endcontent-ref %}

## Session and Flow Basics

The **5-tuple** is the minimum connection identity for flow records:

* Source IP
* Source port
* Destination IP
* Destination port
* Protocol

Flow records end when traffic naturally closes, remains idle beyond a timeout, or exceeds an active timeout.

Common flow formats:

* [NetFlow](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html) - Cisco-originated flow export format.
* NetFlow v5 - Widely deployed fixed-field format.
* NetFlow v9 - Template-based NetFlow format with more fields.
* [IPFIX](https://datatracker.ietf.org/doc/html/rfc7011) - Flexible, template-based flow standard.
* JFlow - Juniper flow export.
* [sFlow](https://sflow.org/) - Packet-sampling-based telemetry.

## Flow Export and Collection Tools

* [Fprobe](https://github.com/digitalocean/fprobe) - libpcap-based NetFlow exporter.
* [YAF](https://tools.netsa.cert.org/yaf/) - Processes PCAP or live traffic into bidirectional IPFIX flows.
* [OpenArgus](https://openargus.org/) - Real-time flow monitor for traffic auditing.
* [NTOP / ntopng](https://www.ntop.org/) - Network visibility stack that can create packet captures, NetFlow logs, and traffic probes.

Flow and packet analysis tooling such as SiLK, super_mediator, URLSnarf, httpry, and justniffer is preserved on the Packet Analysis page.

{% content-ref url="../blue-defense/packet-analysis.md" %}
[packet-analysis.md](../blue-defense/packet-analysis.md)
{% endcontent-ref %}

## Required Flow Fields

* Timestamp
* Source IP
* Source port
* Destination IP
* Destination port
* Protocol
* TCP flags
* Duration
* Start and stop times
* Byte count
* Packet count
* Sensor or device name

## DNS Logs

DNS logs can come from DNS servers, resolvers, firewalls, endpoint agents, Zeek/Corelight, and cloud DNS services.

### Collection Notes

* **Windows DNS** - Event logging and debug logging can expose DNS requests. Analytical logs use ETL and may require tooling that can process ETL at scale.
* **BIND DNS** - Common open source DNS service with configurable query logging.
* **Zeek/Corelight DNS logs** - High-quality network-derived DNS logs with consistent fields.
* **Cloud DNS logs** - Route 53 Resolver Query Logs, Azure DNS logs, and Google Cloud DNS logging can help cover cloud workloads.

### Encrypted DNS

DoT and DoH reduce network-level visibility into DNS queries. Organizations that need internal DNS visibility should define browser, endpoint, and resolver policy rather than relying on ad hoc blocking alone.

Useful references:

* [RFC 7858: DNS over TLS](https://datatracker.ietf.org/doc/html/rfc7858)
* [RFC 8484: DNS over HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)
* [Mozilla Canary Domain](https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet)
* [Black Hills: The DNS over HTTPS Mess](https://www.blackhillsinfosec.com/the-dns-over-https-doh-mess/) - Useful 2019-era discussion of defender visibility concerns.

### DNS Fields

* Timestamp
* Source IP
* Source hostname
* DNS server IP
* DNS server hostname
* Client source port
* Domain query
* Response
* Query type
* Response code

DNS enrichment techniques such as domain age, entropy, popularity, GeoIP, RDAP, and passive DNS are maintained in SIEM Enrichment and Cyber Intelligence.

{% content-ref url="../blue-defense/event-detection/siem-and-enrichment.md" %}
[siem-and-enrichment.md](../blue-defense/event-detection/siem-and-enrichment.md)
{% endcontent-ref %}

{% content-ref url="../cyber-intelligence/threat-data.md" %}
[threat-data.md](../cyber-intelligence/threat-data.md)
{% endcontent-ref %}

## HTTP and HTTPS Logs

HTTP/S logs can come from web servers, reverse proxies, WAFs, forward proxies, firewalls, Zeek/Corelight, packet sensors, cloud load balancers, and application platforms.

### Collection Notes

* **Web servers** - IIS, Apache, NGINX, and application servers provide request logs. Normalize field names and include X-Forwarded-For where applicable.
* **Web proxies** - Strong source for outbound HTTP/S visibility, user mapping, URL categories, cache status, and actions.
* **WAFs** - Useful for inbound application traffic, rule IDs, actions, and attack categories.
* **Next-generation firewalls** - Can provide application IDs, URL categories, TLS metadata, and actions.
* **Zeek/Corelight** - Useful source for HTTP logs and TLS metadata when sensor placement provides visibility.
* **SSL/TLS inspection devices** - Can add decrypted or certificate-level details where lawful and authorized.

### HTTP/S Fields

* Timestamp
* Source IP
* Source hostname or user, when available
* Destination IP
* Destination hostname
* Host header or SNI
* URI and query string
* HTTP method
* HTTP status code
* User-Agent
* Referrer
* Request and response byte counts
* Proxy, firewall, or WAF action
* Rule ID, category, or signature name when available

### TLS Metadata

TLS 1.3 and encrypted client hello reduce some passive visibility. When available, TLS metadata can still help investigations:

* SNI
* JA3/JA4-style fingerprints
* Certificate issuer and subject
* Certificate validity window
* TLS version and cipher suite

JA3 and packet-level TLS fingerprinting are maintained in Packet Analysis.

{% content-ref url="../blue-defense/packet-analysis.md" %}
[packet-analysis.md](../blue-defense/packet-analysis.md)
{% endcontent-ref %}

## SMTP and Email Logs

Email logs should usually come from focused email infrastructure and security tooling first: mail servers, secure email gateways, cloud email audit logs, spam filters, and mail proxies. Network-derived SMTP logs can supplement this visibility.

### SMTP Fields

* Timestamp
* Source IP
* Source hostname
* Destination IP
* Destination hostname
* Sender address
* Recipient address
* Return path
* Message ID
* Subject
* Message size
* Attachment names and hashes, when available
* Delivery action
* Security appliance action and rule ID

For phishing investigation and threat data enrichment, use Cyber Intelligence and DFIR pages rather than duplicating those sources here.

{% content-ref url="../cyber-intelligence/threat-data.md" %}
[threat-data.md](../cyber-intelligence/threat-data.md)
{% endcontent-ref %}

{% content-ref url="../dfir-digital-forensics-and-incident-response/" %}
[dfir-digital-forensics-and-incident-response](../dfir-digital-forensics-and-incident-response/)
{% endcontent-ref %}
