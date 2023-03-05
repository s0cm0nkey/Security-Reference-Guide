---
description: >-
  Scanning for the technology used within your target. Understand how it works,
  to understand how to break it.
---

# Scanning Utilities

## **Visual scanning with Screenshots**

The content on your target pages can provide a wealth of information as well as screenshots of those pages are part of good documentation. There are some tools that can  help with that.

<details>

<summary>Screenshot tools</summary>

* [gowitness](https://github.com/sensepost/gowitness) - A website screenshot utility written in Golang, that uses Chrome Headless to generate screenshots of web interfaces using the command line, with a handy report viewer to process results.
* [eyeballer](https://github.com/bishopfox/eyeballer) - Eyeballer is meant for large-scope network penetration tests where you need to find "interesting" targets from a huge set of web-based hosts. Go ahead and use your favorite screenshotting tool like normal (EyeWitness or GoWitness) and then run them through Eyeballer to tell you what's likely to contain vulnerabilities, and what isn't.
* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) - EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
  * [https://www.christophertruncer.com/eyewitness-usage-guide/](https://www.christophertruncer.com/eyewitness-usage-guide/)

</details>

## **Web Application Fingerprinting**

<details>

<summary>Web-Based Utilities</summary>

* These are not only very detailed and helpful tools, but they allow you to gather tons of intel on your target in a passive recon phase, as to not interaction with the target or its infrastructure at all.
* [Netcraft](https://www.netcraft.com/) - Offers a slew of tools including a handy browser extension for on demand scanning of websites for reputation and technical data.
* [Wappalyzer](https://www.wappalyzer.com/) - Scanning tool that can determine the web technologies that are used on the target web page.
* [Builtwith](https://builtwith.com/) - Similar as above.&#x20;
* [Visual Site Mapper ](http://visualsitemapper.com/)- Handy tool for conceptualizing a target website in a different way.
* [Mozilla Observatory](https://observatory.mozilla.org/) - Fantastic resource that will scan for HTTP, SSL, and TLS settings and return with an overall grade based on a scored checklist. Can be run to include a few other popular third party scanning utilities for even easier recon.
  * [Qualys SSLlabs test ](https://www.ssllabs.com/ssltest/)- Scan and score SLL/TLS settings
  * [Security Headers](https://securityheaders.com/) - Analyze the data found in HTTP responses to a domain
  * Immuniweb tools [SSL](https://www.immuniweb.com/ssl/) and [WebSec](https://www.immuniweb.com/websec/) test

</details>

<details>

<summary>CLI Based Utilities</summary>

* [What Web](https://github.com/urbanadventurer/whatweb) - WhatWeb recognizes web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1800 plugins, each to recognize something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
* [wafw00f](https://github.com/EnableSecurity/wafw00f) - WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.
* [Blind Elephant](http://blindelephant.sourceforge.net/) - The BlindElephant Web Application Fingerprinter attempts to discover the version of a (known) web application by comparing static files at known locations against precomputed hashes for versions of those files in all all available releases. The technique is fast, low-bandwidth, non-invasive, generic, and highly automatable.
* [Virtual Host Scanner](https://github.com/codingo/VHostScan) - A virtual host scanner that can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
* [https://whatcms.org/](https://whatcms.org/) - Web based tool to determine what CMS a site is using.
* [httprint](https://www.kali.org/tools/httprint/) - httprint is a web server fingerprinting tool. It relies on web server characteristics to accurately identify web servers, despite the fact that they may have been obfuscated by changing the server banner strings, or by plug-ins such as mod\_security or servermaskd

</details>

## **Web Vulnerability Scanning**

<details>

<summary>Web App Vuln Scanning Tools</summary>

...burp.....

* [Nikto](https://github.com/sullo/nikto) - Nikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers.
  * [https://cirt.net/Nikto2](https://cirt.net/Nikto2)
  *   Nikto web server scan

      ```
      nikto -h 10.10.10.10
      ```
* [Arachni](https://www.arachni-scanner.com/) - Arachni is a feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of modern web applications.
  * [Arachni Web UI](https://github.com/Arachni/arachni-ui-web/wiki)
* [W3AF](https://github.com/andresriancho/w3af) - w3af: web application attack and audit framework, the open source web vulnerability scanner.
*   [Wapiti](https://wapiti.sourceforge.io/) - Wapiti allows you to audit the security of your websites or web applications.

    It performs "black-box" scans (it does not study the source code) of the web application by crawling the webpages of the deployed webapp, looking for scripts and forms where it can inject data.
* [Vega Scanner](https://subgraph.com/vega/) - Vega is a free and open source web security scanner and web security testing platform to test the security of web applications. Vega can help you find and validate SQL Injection, Cross-Site Scripting (XSS), inadvertently disclosed sensitive information, and other vulnerabilities.
* [WAVE](https://github.com/adithyan-ak/WAVE) - Web Application Vulnerability Exploiter (WAVE) is basically a vulnerability scanner which scans for Secuirity Vulnerabilities in web applications.
* [https://snyk.io/website-scanner/](https://snyk.io/website-scanner/) - Get a full website security check for known vulnerabilities and HTTP security headers

</details>

## SSL Scanning

<details>

<summary>SLL Scanning Tools</summary>

* [sslscan](https://www.kali.org/tools/sslscan/) - SSLScan queries SSL services, such as HTTPS, in order to determine the ciphers that are supported. SSLScan is designed to be easy, lean and fast. The output includes preferred ciphers of the SSL service, the certificate and is in text and XML formats.
  * [tlssled](https://www.kali.org/tools/tlssled/) - TLSSLed is a Linux shell script whose purpose is to evaluate the security of a target SSL/TLS (HTTPS) web server implementation. Basec on sslscan.
* [sslyze](https://www.kali.org/tools/sslyze/) - SSLyze is a Python tool that can analyze the SSL configuration of a server by connecting to it. It is designed to be fast and comprehensive, and should help organizations and testers identify misconfigurations affecting their SSL servers.
* [testssl.sh](https://www.kali.org/tools/testssl.sh/) - testssl.sh is a free command line tool which checks a server’s service on any port for the support of TLS/SSL ciphers, protocols as well as recent cryptographic flaws and more.
* [o-saft](https://www.kali.org/tools/o-saft/) - O-Saft is an easy to use tool to show information about SSL certificates and tests the SSL connection according to a given list of ciphers and various SSL configurations.
* [qsslcaudit](https://www.kali.org/tools/qsslcaudit/) - This tool can be used to determine if an application that uses TLS/SSL for its data transfers does this in a secure way.

</details>

## **CMS Scanners**

{% tabs %}
{% tab title="Multi-CMS Scanners" %}
* [CMSMap](https://github.com/Dionach/CMSmap) - CMSmap is a python open source CMS scanner that automates the process of detecting security flaws of the most popular CMSs. The main purpose of CMSmap is to integrate common vulnerabilities for different types of CMSs in a single tool.
* [CMSScan](https://github.com/ajinabraham/CMSScan) - CMS Scanner: Scan Wordpress, Drupal, Joomla, vBulletin websites for Security issues
* [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) - CMS Detection and Exploitation suite - Scan WordPress, Joomla, Drupal and over 180 other CMSs
  * [https://www.kali.org/tools/cmseek/](https://www.kali.org/tools/cmseek/)
* [Droopscan](https://github.com/droope/droopescan) - plugin-based scanner that aids security researchers in identifying issues with several CMS.
* [Vulnx](https://github.com/anouarbensaad/vulnx) - Vulnx is An Intelligent Bot Auto [Shell Injector](https://github.com/anouarbensaad/vulnx/wiki/Usage#run-exploits) that detects vulnerabilities in multiple types of Cms, fast cms detection,informations gathering and vulnerabilitie Scanning of the target like subdomains, ipaddresses, country, org, timezone, region, ans and more ...
{% endtab %}

{% tab title="WordPress" %}
* [WPScan](https://github.com/wpscanteam/wpscan) - The Wordpress Vulnerability Scanner
  * [https://wpsec.com/](https://wpsec.com/) - Online Wordpress scanner
* [Wordpress Exploit Framework ](https://github.com/rastating/wordpress-exploit-framework) - A Ruby framework designed to aid in the penetration testing of WordPress systems.
* [WPSploit](https://github.com/espreto/wpsploit) - This repository is designed for creating and/or porting of specific exploits for WordPress using metasploit as exploitation tool.
{% endtab %}

{% tab title="Joomla" %}
* [JCS](https://github.com/TheM4hd1/JCS) - JCS (Joomla Component Scanner) made for penetration testing purpose on Joomla CMS
* [Joomscan](https://wiki.owasp.org/index.php/Category:OWASP\_Joomla\_Vulnerability\_Scanner\_Project) - OWASP Joomla! Vulnerability Scanner (JoomScan) is an open source project, developed with the aim of automating the task of vulnerability detection and reliability assurance in Joomla CMS deployments.
{% endtab %}
{% endtabs %}

## **Parameter Extraction**

<details>

<summary>Parameter Extraction Tools</summary>

* [ParamSpider](https://github.com/devanshbatham/ParamSpider) - Utility that scans the domain and sub-domains for exploitable parameters
* [Parameth](https://github.com/maK-/parameth) - This tool can be used to brute discover GET and POST parameters
* [Arjun](https://github.com/s0md3v/Arjun) - Arjun can find query parameters for URL endpoints.
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8) - Hidden parameters discovery suite
* [Burp Suite Extension: Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) - This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.
* [ffuf](https://www.kali.org/tools/ffuf/) - ffuf is a fest web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing.

</details>

## Misc Tools

<details>

<summary>Misc Tools</summary>

* [BFAC](https://github.com/mazen160/bfac) - BFAC (Backup File Artifacts Checker): An automated tool that checks for backup artifacts that may disclose the web-application's source code.
* [csprecon](https://github.com/edoardottt/csprecon) - Discover new target domains using Content Security Policy
* [RetireJS](https://retirejs.github.io/retire.js/) - Scanner to detect javascript libraries and known vulnerabilities within them.
* [SnallyGaster](https://github.com/hannob/snallygaster) - Snallygaster is a tool that looks for files accessible on web servers that shouldn't be public and can pose a security risk.
* [Broken Link Checker](https://github.com/stevenvachon/broken-link-checker) - Find broken links, missing images, etc within your HTML.
* [AAP](https://github.com/PushpenderIndia/aapfinder) - AAP Finder (Advanced Admin Page Finder) is a tool written in Python3 with advanced functionalities, with more than 700+ Potential Admin Panels. This Tool Can Easily Find Login Pages of Any Site & is also capable to detect _robots.txt_ File.
* [Admin-Scanner](https://github.com/alienwhatever/Admin-Scanner) - This tool is design to find admin panel of any website by using custom wordlist or default wordlist easily and allow you to find admin panel trough a proxy server.
* [Breacher](https://github.com/s0md3v/Breacher) - An advanced multithreaded admin panel finder written in python.
* [JS-Scan](https://github.com/zseano/JS-Scan) - aA.js scanner, built in php. designed to scrape urls and other info
* [SecretFinder](https://github.com/m4ll0k/SecretFinder) - A python script for find sensitive data (apikeys, accesstoken,jwt,..) and search anything on javascript files.
* [certgraph](https://www.kali.org/tools/certgraph/) - This package contains a tool to crawl the graph of certificate Alternate Names. CertGraph crawls SSL certificates creating a directed graph where each domain is a node and the certificate alternative names for that domain’s certificate are the edges to other domain nodes.
* [changeme](https://www.kali.org/tools/changeme/) - This package contains a default credential scanner. changeme supports the http/https, MSSQL, MySQL, Postgres, ssh and ssh w/key protocols.O-Saft is an easy to use tool to show information about SSL certificates and tests the SSL connection according to a given list of ciphers and various SSL configurations.
* [https://csp-evaluator.withgoogle.com/](https://csp-evaluator.withgoogle.com/) - CSP Evaluator allows developers and security experts to check if a Content Security Policy (CSP) serves as a strong mitigation against [cross-site scripting attacks](https://www.google.com/about/appsecurity/learning/xss/)[https://github.com/rly0nheart/oxdork](https://github.com/rly0nheart/oxdork)
* [oxdork](https://github.com/rly0nheart/oxdork) - oxDork uses Google dorking techniques and Google dorks to find security holes and misconfigurations in web servers.
* [subjs](https://github.com/lc/subjs) - Fetches javascript file from a list of URLS or subdomains.
* [Interlace](https://github.com/codingo/Interlace) - Easily turn single threaded command line applications into a fast, multi-threaded application with CIDR and glob support.
  * [https://hakluke.medium.com/interlace-a-productivity-tool-for-pentesters-and-bug-hunters-automate-and-multithread-your-d18c81371d3d](https://hakluke.medium.com/interlace-a-productivity-tool-for-pentesters-and-bug-hunters-automate-and-multithread-your-d18c81371d3d)

</details>
