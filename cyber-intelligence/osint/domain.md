# Domain

![](<../../.gitbook/assets/image (40).png>)

## Domains

Domains, more than almost any other target, have one of the largest assortments of associated data points. The most important that we will look for out of this section is the Registration data, the hosting data, site information, archived data, and analytics.

**Domain.html**

Domain.html is a tool that allows us to research multiple data points associated with a domain that might be handy during an investigation.

* Registration Data - This tool will check the domain for whois based registration data against multiple sources to get the most up to date data.
* Hosting Data - This is the information that shows which provider is physically hosting the domain. Be sure to look for indicators if the target domain is hosted by a hosting provider, or self hosted by your target.
* Exposed Data - Any information that may be exposed to the public. (Other sources are better)
* Archive Data  - When researching a domain, sometimes you can find older cached or saved versions of the website that may yield valuable information. These include Google Cache, Archive.is, and the WayBack Machine.
* Analytics data - This is a grab bag of handy searches, ranging from general site details and analytics, to similar sites on the web, or checks for backlinks to from other sites.
* Threat Data - Discussed under the Blue - Threat Data section
* Shortened URL metadata.

{% file src="../../.gitbook/assets/Domain.html" %}

### **Domain Toolboxes**

These next few tools are collections of utilities focused around domains. Some can be used for research on other network artifacts like IP addresses and email records, but DNS records and domain related metadata is really where they shine.

* [ViewDNS](https://viewdns.info) - Huge toolbox with various utilities for enumerating information about a domain.
* [DNSDumpster](https://dnsdumpster.com) - Free domain research tool that can discover hosts related to a domain.&#x20;
* [MXToolbox ](https://mxtoolbox.com)-  Checks MX information for the given domain
* [W3DT](https://w3dt.net) - W3dt.Net is an online network troubleshooting site dedicated to providing relevant real-time data regarding networks, websites and other technical resources.
* [DNSLytics](https://dnslytics.com) - Find out everything about a domain name, IP address or provider. Discover relations between them and see historical data. Use it for your digital investigation, fraud prevention or brand protection.
* [HostSpider](https://github.com/h3x0crypt/HostSpider) - Command line tool that gathers tons of information about a domain including DNS records, subdomains, WHOIS, Cloudflare IP, and more!

### **Whois Vs. RDAP**

Whois is a great tool for gathering registration data for IP addresses and domains. The only problem with it is that there is not a clearly defined structure to organize registration data points and keep them maintained. Enter RDAP. A new Standard as of 2019, RDAP lookups will quickly replace WHOIS lookups.&#x20;

* RDAP lookup tool - [https://client.rdap.org](https://client.rdap.org)
* General information on RDAP - [https://www.icann.org/rdap](https://www.icann.org/rdap)

### **Sub-domains**

There are tons of highly effective tools for subdomain enumeration and brute forcing, but they can be quite noisy. During the Passive Recon phase of a penetration test, we can start with any subdomains recorded by other sources to plan out our attack/test.

* [https://omnisint.io/](https://omnisint.io) - Project Crobat: Rapid7's DNS Database easily searchable via a lightening fast API, with domains available in milliseconds.
* [Spyse Sub-domain finder](https://spyse.com/tools/subdomain-finder)
* [Pentest Tool's Sub-domain Finder](https://pentest-tools.com/information-gathering/find-subdomains-of-domain)
* [censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) - This is a tool to enumerate subdomains using the Certificate Transparency logs stored by [Censys](https://censys.io).
* [ctfr](https://github.com/UnaPibaGeek/ctfr) - Abusing Certificate Transparency logs for getting HTTPS websites subdomains.
* [Sublist3r](https://github.com/aboul3la/Sublist3r) - Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS.
  * [https://tryhackme.com/room/rpsublist3r](https://tryhackme.com/room/rpsublist3r)
* [puredns](https://github.com/d3mondev/puredns) - Puredns is a fast domain resolver and subdomain bruteforcing tool that can accurately filter out wildcard subdomains and DNS poisoned entries.

### **Domain Certificates**

Domain Certificates are an interesting and useful item to research when mapping out a target domain. Beyond the various attacks that can be performed by exploiting these certificates, looking up the domain certificates can lead to discovery of hosts, sub-domains, and related targets that were previously undiscovered.

* [Crt.sh](https://crt.sh) - Enter an Identity (Domain Name, Organization Name, etc), a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID to return detailed domain and certificate information.
* [Google Transparency Report](https://transparencyreport.google.com/https/certificates) - A tool used to look up all of a domain’s certificates that are present in [active public Certificate Transparency logs](https://www.certificate-transparency.org/known-logs)
* [https://sslmate.com/labs/ct\_policy\_analyzer/](https://sslmate.com/labs/ct\_policy\_analyzer/) - Certificate Transparency Policy Analyzer

### **Web Site Change Tracking**

Some times a target will change a website and you will want to be notified right away, usually to see what has changed and how you can exploit it.

* [Follow that page](https://followthatpage.com) - Follow That Page is a change detection and notification service that sends you an email when your favorite web pages have changed.
* [Visual Ping](https://visualping.io) - Tool that can track multiple different kinds of changes in a particular webpage and alert on specific conditions.

### URL Shortening and Redirections

* [https://shorteners.grayhatwarfare.com](https://shorteners.grayhatwarfare.com) - search URL Shorteners
* [urlhunter](https://github.com/utkusen/urlhunter) - a recon tool that allows searching on URLs that are exposed via shortener services
* [https://checkshorturl.com](https://checkshorturl.com) - Get information about a shortened link
* [http://redirectdetective.com/](http://redirectdetective.com) - Where does this redirection go?
* [https://wheregoes.com](https://wheregoes.com) - Redirection link enumeration tool
* [https://lookyloo.circl.lu](https://lookyloo.circl.lu) - Redirection link enumeration tool
* [https://www.scribd.com/doc/308659143/Cornell-Tech-Url-Shortening-Research](https://www.scribd.com/doc/308659143/Cornell-Tech-Url-Shortening-Research)
* How to check a short link instead of being redirected:
  * bit.ly - add + at the end
  * cutt.ly - add @
  * tiny.cc - add =
  * tunyurl.com - add "preview." to the beginning of the url.

### Similar Web Site Search

* [https://www.similarsites.com/](https://www.similarsites.com) - Enter a website URL and view websites that are similar.
* [https://siteslike.com/](https://siteslike.com) - Enter a URL or keyword and view websites that are similar or match your keyword
* [https://www.similarweb.com/](https://www.similarweb.com) - A great tool for finding similar and/or competitor websites. Search via website URL.

### Browser Proxy/Simulator

For when you want to look at a site, without interacting with it.

* [https://www.wannabrowser.net/](https://www.wannabrowser.net) - With Wannabroser you can have a look at the HTML-source code of any website from the view of any User-Agent you like. It's even possible to detect simple cloaking using Wannabrowser if the cloaking is just based on the visiting User-Agent.
* [https://www.browserling.com/](https://www.browserling.com) - Used for browser testing, but can be used for safely looking at various sites.
* [https://www.url2png.com/](https://www.url2png.com) - Capture snapshots of any website

### **Misc. Utilities**

* [DNPedia](https://dnpedia.com) - Domain Name Solutions, Statistics, Scripts, News and Tools
* [https://riddler.io/](https://riddler.io) - Obtain network information from F-Secure Riddler.io API.
* [Google's Online Dig command](https://toolbox.googleapps.com/apps/dig/) - Online version of the Dig command
* [SimilarWeb Traffic Analytics](https://www.similarweb.com) - Compare meta data about domains and traffic to other elements on the web
* [Backlink Checker](https://smallseotools.com/backlink-checker/) - Tool to easily monitor backlinks for a particular domain.
* [DomLink](https://github.com/vysecurity/DomLink) - DomLink is a tool that uses a domain name to discover organization name and associated e-mail address to then find further associated domains.
* [https://dfir.blog/unfurl/](https://dfir.blog/unfurl/) - Easily breakdown and visualize the elements of a URL link.
* [r3con1z3r](https://github.com/abdulgaphy/r3con1z3r) - R3con1z3r is a lightweight Web information gathering tool with an intuitive features written in python. it provides a powerful environment in which open source intelligence (OSINT) web-based footprinting can be conducted quickly and thoroughly.
* [emailharvester](https://www.kali.org/tools/emailharvester/) - A tool to retrieve Domain email addresses from Search Engines.
* [https://github.com/lc/gau](https://github.com/lc/gau) - getallurls (gau) fetches known URLs from AlienVault's [Open Threat Exchange](https://otx.alienvault.com), the Wayback Machine, and Common Crawl for any given domain. Inspired by Tomnomnom's [waybackurls](https://github.com/tomnomnom/waybackurls).
* [lbd](https://www.kali.org/tools/lbd/) - Checks if a given domain uses load-balancing.
* [Metagoofil ](https://github.com/laramies/metagoofil)- Tool for extracting metadata out of public documents.
* [https://www.giftofspeed.com/cache-checker/](https://www.giftofspeed.com/cache-checker/) - This tool lists which web files on a website are cached and which are not. Furthermore it checks by which method these files are cached and what the expiry time of the cached files is.
* [CloudFlair](https://github.com/christophetd/CloudFlair) - Find origin servers of websites behind CloudFlare by using Internet-wide scan data from Censys.
* [cf-check](https://github.com/dwisiswant0/cf-check) - Check an Host is Owned by CloudFlare.
* [AnalyticsRelationships](https://github.com/Josue87/AnalyticsRelationships) - Get related domains / subdomains by looking at Google Analytics IDs
