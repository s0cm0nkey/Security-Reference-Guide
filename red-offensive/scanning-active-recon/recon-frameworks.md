# Recon Frameworks

Recon frameworks combine multiple data sources, command-line tools, APIs, scans, screenshots, and reports into repeatable workflows. Many support both passive and active techniques, so match modules to the engagement scope before running them.

For purely passive OSINT investigation, use Cyber Intelligence.

{% content-ref url="../../cyber-intelligence/osint/" %}
[osint](../../cyber-intelligence/osint/)
{% endcontent-ref %}

## Primary Frameworks

### SpiderFoot

[SpiderFoot](https://www.spiderfoot.net/) is an OSINT automation platform with a web UI, templates, and many modules for collecting target data from public sources and APIs.

* [Documentation](https://www.spiderfoot.net/documentation/)
* [SpiderFoot tutorials](https://asciinema.org/~spiderfoot)
* [iRed Team: SpiderFoot 101 with Kali and Docker](https://www.ired.team/offensive-security/red-team-infrastructure/spiderfoot-101-with-kali-using-docker)

### Recon-ng

[Recon-ng](https://github.com/lanmaster53/recon-ng) is a modular Python reconnaissance framework. It is useful when you want repeatable modules, API-backed lookups, and structured output.

* [Recon-ng Wiki](https://github.com/lanmaster53/recon-ng/wiki)
* [lanmaster53](https://www.lanmaster53.com/)
* [Pluralsight: Technical Information Gathering with Recon-ng](https://www.pluralsight.com/courses/technical-information-gathering-recon-ng)
* [Black Hills: What's Changed in Recon-ng 5.x](https://www.blackhillsinfosec.com/whats-changed-in-recon-ng-5x/)
* [Black Hills Recon-ng Cheat Sheet](https://www.blackhillsinfosec.com/wp-content/uploads/2019/11/recon-ng-5.x-cheat-sheet-Sheet1-1.pdf)

{% embed url="https://youtu.be/0J6Auz88iTY" %}

### Maltego

[Maltego](https://www.maltego.com/) is a graphical link-analysis and OSINT platform for connecting people, domains, infrastructure, social accounts, and other entities.

* [Maltego Support and Docs](https://docs.maltego.com/support/home)
* [Maltego Handbook for Social Media Investigations](https://static.maltego.com/cdn/Handbooks/Maltego-Handbook-for-Social-Media-Investigations-Short.pdf)

{% embed url="https://youtu.be/zemNLx0-LRw" %}

## Offensive Recon and ASM Frameworks

* [BBOT](https://github.com/blacklanternsecurity/bbot) - Recursive modular OSINT and recon framework with subdomain enumeration, port scanning, screenshots, and nuclei support.
* [ReconFTW](https://github.com/six2dez/reconftw) - Automated recon workflow for domains, bug bounty, and pentest targets.
* [Sn1per](https://github.com/1N3/Sn1per) - Automated recon and penetration testing framework with OSINT, scanning, and reporting.
* [reNgine](https://github.com/yogeshojha/rengine) - Web application reconnaissance suite with engines, screenshots, correlation, reports, and continuous monitoring.
* [OWASP Amass](https://github.com/OWASP/Amass) - External attack surface mapping and asset discovery.
* [runZero](https://www.runzero.com/) - Network discovery and asset inventory platform.
* [ReconNess](https://www.reconness.com/) - Recon management platform for organizing targets and findings.
* [Axiom](https://github.com/pry0cc/axiom) - Dynamic infrastructure framework for distributed recon and offensive workflows.
* [JupyterPen](https://github.com/obheda12/JupyterPen) - Jupyter-based OSINT and penetration testing toolkit.

## Other Frameworks and Toolkits

* [sn0int](https://github.com/kpcyrd/sn0int) - Semi-automatic OSINT framework and package manager.
* [Raccoon](https://github.com/evyatarmeged/Raccoon) - Offensive recon framework with OSINT and active scanning.
* [ReconSpider](https://github.com/bhavsec/reconspider) - Information-gathering tool with visual output.
* [OWASP Maryam](https://github.com/saeeddhqan/Maryam) - Modular OSINT and data-gathering framework.
* [Discover Scripts](https://github.com/leebaird/discover) - Early-stage penetration test discovery scripts.
* [DMitry](https://www.kali.org/tools/dmitry/) - Finds subdomains, email addresses, uptime, WHOIS data, and TCP ports.
* [finalrecon](https://www.kali.org/tools/finalrecon/) - Modular web reconnaissance script.
* [gasmask](https://github.com/twelvesec/gasmask) - Information-gathering toolkit.
* [machinae](https://github.com/HurricaneLabs/machinae) - Collects public intelligence about IPs, domains, URLs, emails, file hashes, and SSL fingerprints.

## Low Signal or Validate Before Use

These are preserved for resource completeness, but validate maintenance and quality before adding them to a workflow.

* [DarkSide](https://github.com/ultrasecurity/DarkSide) - Older information-gathering and social engineering toolkit.
* [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) - Large all-in-one hacking tool menu; review modules carefully before use.
* [eReKon](https://github.com/slithery0/eReKon) - Web recon tool that appears incomplete or under active development.
