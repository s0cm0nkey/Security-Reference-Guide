---
description: Detection, Enrichment, and Use cases
---

# DNS

**Detection Use Cases**

* Newly accessed domains&#x20;
  * By taking a list of all of the domains accessed for a day, removing those found within a top million domains list, and then running a historical check, we can create a list of domains that have been accessed for the first time that would warrant investigation. Most malware today uses DNS. This use case will be best if run as a daily report for an analyst to review for any suspicious domains on the resulting list. Can be further enriched with reputation data for more efficacy.
* Baby domains
  * There are very few instances that traffic to a newly created domain is warranted in an environment. Most phishing domains are used within the first three months they are created. By choosing a short time frame (My recommendation is about a week), and enriching the domain age with WHOIS, we can create alerting around contact to any of these baby domains. We can also use this with phishing use cases by checking the age of the domain found in MX records.
* High Volumes of outbound NXDOMAIN resolutions.
  * NXDOMAIN is the response given when a request is made for a non-existent domain. While this typically appears in low volumes, spikes in this traffic can indicate a misconfiguration or malware using a DGA: Domain Generation Algorithm.
  * Google chrome will send random DNS requests on startup as an attempt to detect ISP DNS Hijacking. These requests, while noisy, are tied to the local search domain and easy to filter out.
* High Volume of inbound or internal NXDOMAIN resolutions.
  * When an attacker is performing DNS bruteforcing or subdomain enumeration with tools like DNSRecon, large amounts of NXDOMAIN requests will be made in a short amount of time. By detecting these spikes, we can identify external or possibly internal attackers attempting to enumerate the network.
* Fast Flux Detection
  * The Fast Flux technique is one employed by different malware authors to bypass DNS filters by using a single domain, and rotating the IP addresses found in DNS A records. We can detect this with seeing a disproportionate number of associated A records with a single domain.
  * Detecting this can be difficult with DNS load-balancing, but can be achieved by looking for repetitive DNS calls with TTLs <300 and answer counts more than 12. Monitor DNS queries by count and source IP address where the source addresses are more than 12
  * Double fast flux takes this idea further by using some compromised machines as DNS proxies to hide the true malware domain. This can be protected against, by making your internal DNS server, the authoritative name server.
* DGA detection
  * Beyond the above use case for large volumes of NXDOMAIN entries, we can look at a parent domain for levels of high entropy, as calculated by Mark Bagget's freq.py.
  * [https://isc.sans.edu/forums/diary/Detecting+Random+Finding+Algorithmically+chosen+DNS+names+DGA/19893/](https://isc.sans.edu/forums/diary/Detecting+Random+Finding+Algorithmically+chosen+DNS+names+DGA/19893/)
* DNS Tunneling/Unauthorized DNS
  * Assuming that enforce all DNS traffic through our DNS servers by policy, we can set up easy detection of potential DNS tunneling or unauthorized DNS requests by monitoring direct port 53 requests out of the environment.
  * We can take this one step further by looking for traffic to major DNS providers such as Google's DNS service at 8.8.8.8
  * More Advanced DNS tunneling techniques and tools such as DNSCat2, will still be able to leverage internal DNS servers for tunneling if they allow external DNS recursion. If the internal DNS server does not know how to resolve a domain and it passes the task off to an external DNS server, the originating host will use the external server for DNS resolutions and interact with it instead. By disabling external DNS recursion or limiting which external DNS servers we can use, we can block this type of activity.
* DNS Tunneling through TXT records
  * Information can be exfiltrated or C2 communications can happen within TXT records of DNS requests. With the exception of certain security devices, TXT records are typically few and far between. We can monitor for larger spikes in TXT record requests to identify suspicious activity related to this technique.
* Direct out connection detection
  * There are very few instances that outbound traffic will not have a DNS entry. This will occur when an application or malware is reaching out to a hard-coded IP address and does not make a DNS request. By matching outbound traffic with DNS requests, and looking for all of those that do not show in the DNS entry, we can detect this activity.
  * Exceptions can include Microsoft IP addresses, CDN addresses like Akamai, Root DNS server addresses, and functions of specific vendor tools. Will require white listing.
