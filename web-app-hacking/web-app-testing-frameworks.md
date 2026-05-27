# Web App Testing Frameworks

These are proxies, scanners, DAST tools, and web-focused assessment frameworks. General attack-surface discovery tools such as subdomain enumerators and port scanners are maintained in Red Recon; credential-stuffing automation belongs in password attacks or should be omitted unless there is a clear authorized-testing use case.

{% embed url="https://pentestbook.six2dez.com/others/recon-suites-review" %}

* [ProjectDiscovery](https://projectdiscovery.io/#/) - Collection of open source tools for attack surface management and bug bounty workflows.
  * [nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner based on simple YAML based DSL.
    * [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
    * [https://github.com/geeknik/the-nuclei-templates](https://github.com/geeknik/the-nuclei-templates)
    * [https://github.com/projectdiscovery/nuclei-docs](https://github.com/projectdiscovery/nuclei-docs)
    * [https://cheatsheet.haax.fr/web-pentest/tools/nuclei/](https://cheatsheet.haax.fr/web-pentest/tools/nuclei/)
  * [subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain discovery tool; canonical active/passive recon references live in Red Recon.
  * [naabu](https://github.com/projectdiscovery/naabu) - Fast port scanner; canonical port scanning references live in Red Recon.
  * [httpx](https://github.com/projectdiscovery/httpx) - httpx is a fast and multi-purpose HTTP toolkit allows to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads.
  * [proxify](https://github.com/projectdiscovery/proxify) - Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
  * [dnsx](https://github.com/projectdiscovery/dnsx) - DNS toolkit for running DNS queries against user-supplied resolvers.
* [Fiddler](https://www.telerik.com/fiddler) - Powerful and flexible web debugging proxy.
* [OWASP Zap](https://owasp.org/www-project-zap/) - Open Source Web Application testing tool made by the OWASP Foundation. Serves a similar function to Burp and even shares many extensions.
  * [https://tryhackme.com/room/learnowaspzap](https://tryhackme.com/room/learnowaspzap)
* [Jaeles](https://github.com/jaeles-project/jaeles) - Jaeles is a powerful, flexible and easily extensible framework written in Go for building your own Web Application Scanner.
* [REngine ](https://github.com/yogeshojha/rengine)- reNgine is an automated reconnaissance framework meant for information gathering during penetration testing of web applications. reNgine has customizable scan engines, which can be used to scan the domains, endpoints, or gather information. The beauty of reNgine is that it gathers everything in one place. It has a pipeline of reconnaissance, which is highly customizable.
* [OpenBullet2](https://github.com/openbullet/OpenBullet2) - High-abuse automation suite often associated with credential stuffing. Do not treat it as a general web testing framework; only use in explicitly authorized lab contexts.
  * [https://discourse.openbullet.dev/](https://discourse.openbullet.dev/)
* [FinalRecon](https://github.com/thewhiteh4t/finalrecon) - FinalRecon is an automatic web reconnaissance tool written in python. Goal of FinalRecon is to provide an overview of the target in a short amount of time while maintaining the accuracy of results.
* [ChopChop](https://github.com/michelin/ChopChop) - ChopChop is a command-line tool for dynamic application security testing on web applications, initially written by the Michelin CERT. Its goal is to scan several endpoints and identify exposition of services/files/folders through the webroot.
* [TIDoS-Framework](https://github.com/0xInfection/TIDoS-Framework) - Exceedingly detailed offensive manual web application testing framework.
* [SecApps Suite](https://secapps.com/tools/suite/) - SecApps Suite is a browser-based web security testing toolkit made of a growing number of applications and features suitable for a diverse set of offensive and defensive activities: from automated web application security assessments to fuzzing, manual web auditing and much more.
* [RapidScan](https://github.com/skavngr/rapidscan) - Multi-tool vulnerability scanner that runs separate tools in tandem for saving time in the scanning phase.
* [Sitadel](https://github.com/shenril/Sitadel) - Sitadel is basically an update for WAScan making it compatible for python >= 3.4 It allows more flexibility for you to write new modules and implement new features
* [Garud](https://github.com/R0X4R/Garud) - An automation tool that scans sub-domains, sub-domain takeover, then filters out XSS, SSTI, SSRF, and more injection point parameters and scans for some low hanging vulnerabilities automatically.
* [OpenWebTestingFramework ](https://github.com/owtf/owtf)- **OWTF** is a project focused on penetration testing efficiency and alignment of security tests to security standards like the OWASP Testing Guide (v3 and v4), the OWASP Top 10, PTES and NIST
* [SecApps](https://secapps.com/tools/suite/) - Flexible web-based testing platform with free and paid features.
* [paros](https://www.kali.org/tools/paros/) - Lightweight web application testing proxy
* [sumrecon](https://github.com/Gr1mmie/sumrecon) - Web recon script. No need to fear, sumrecon is here!
* [0d1n](https://github.com/CoolerVoid/0d1n) - Tool for automating customized attacks against web applications. Fully made in C language with pthreads, it has fast performance.
* [BlackWidow](https://github.com/1N3/BlackWidow) - A Python based web application scanner to gather OSINT and fuzz for OWASP vulnerabilities on a target website.
* [https://caido.io/](https://caido.io/) - A lightweight web security auditing toolkit. Built from the ground up in Rust, Caido aims to help security professionals and enthusiasts audit web applications with efficiency and ease
