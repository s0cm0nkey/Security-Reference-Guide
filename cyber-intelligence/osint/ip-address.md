# IP Address

## **IP Address**

When researching IP addresses, it is important to know the context of the search you are performing. There are a multitude of sources to research IP addresses and they can vary depending on what information you want to learn about them. For offensive security, threat hunting, and attack surface mapping, we want current registration data, and any associated data points that our searches may return. These can include hosted domains, ASN, associated network artifacts, etc.

For defensive operations, such as those of the security blue team, you would be looking for historical data and activity data of the IP address. These tools will be detailed in another section about threat research. The below links and tools are specifically for offensive intelligence gathering and reconnaissance.&#x20;

**IP.html**

IP.html is another handy little tool created by Michael Bazzel that makes initial research of an IP address quite easy. This tool will populate multiple searches automatically for you to see what information you can gather about your target.&#x20;

Sites Include: Bing, Reverse IP, Locate IP, Port Scan, IP Whois, TraceRoute, Who.IS IP, Cynsys, ThreatCrowd, Shodan, ZoomEye, Torrents, "That's Them", WeLeakInfo, Dehashed, and UltraTools IP.

{% file src="../../.gitbook/assets/IP (1).html" %}



### **Whois Vs. RDAP**

Whois is a great tool for gathering registration data for IP addresses and domains. The only problem with it is that there is not a clearly defined structure to organize registration data points and keep them maintained. Enter RDAP. A new Standard as of 2019, RDAP lookups will quickly replace WHOIS lookups.&#x20;

* RDAP lookup tool - [https://client.rdap.org](https://client.rdap.org)
* General information on RDAP - [https://www.icann.org/rdap](https://www.icann.org/rdap)

### **Is this a Tor Node?**  &#x20;

Maybe? Check it with this! [https://metrics.torproject.org/exonerator.html](https://metrics.torproject.org/exonerator.html)

Torrent IP addresses **-**  [https://iknowwhatyoudownload.com](https://iknowwhatyoudownload.com)

[https://seon.io/intelligence-tool/#ip-analysis-module](https://seon.io/intelligence-tool/#ip-analysis-module) - Check if an IP is a tor node, VPN, proxy and even run a blacklist check.

### **IP Location Info**

&#x20;There are a several ways to find [geolocation](https://www.iplocation.net/geolocation) of a user: HTML5 API, Cell Signal and IP Address to name a few. If you have an IP Address and want to find the geolocation data for the target, the below sites use various methods to determine that data.

\*Note: It is recommended that you use as many tools as possible for a consensus determination on the location. Some times results will show the location of the registrant, but not the location of the IP in use.

* [https://www.iplocation.net/](https://www.iplocation.net/)
* [https://www.ip2location.com/](https://www.ip2location.com/)
* [https://www.ipfingerprints.com/](https://www.ipfingerprints.com/)
* [https://ipstack.com/](https://ipstack.com/)

### Misc Tools

* [https://focsec.com/](https://focsec.com/) - Determine if a user’s IP address is associated with a VPN, Proxy, TOR or malicious bots
