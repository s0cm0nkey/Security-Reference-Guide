# Search Engines

Cybersecurity-focused search engines are powerful tools that enable targeted research on specific assets, vulnerabilities, and threat intelligence. By searching for IP addresses, domains, CVEs, and other indicators, security professionals can perform tasks ranging from passive reconnaissance during penetration testing to comprehensive threat intelligence analysis.

## Search.html - Your OSINT Starting Point

When beginning any OSINT investigation, consider starting with Search.html, a comprehensive HTML interface created by OSINT expert Michael Bazzell. This tool provides a unified interface for searching multiple sources simultaneously, allowing researchers to efficiently query various search engines and services with a single action. The tool's design facilitates manual analysis and enables investigators to follow multiple leads as they emerge during research.

**Included Search Engines:** Google, Google Date, Bing, Yahoo, Searx, Yandex, Baidu, Exalead, DuckDuckGo, Startpage, Newsgroups, Blogs, FTP Servers, Indexes, Scholars, Patents, Qwant, News, Wayback Machine, and Ahmia.

The resources listed below provide a solid foundation for search engine-based investigation techniques, though they represent only a starting point for comprehensive OSINT research.

{% file src="../../../.gitbook/assets/Search (1).html" %}

## [**Google**](https://google.com)

Google remains one of the most comprehensive information gathering tools available to security professionals. While basic keyword searches are useful, leveraging advanced search operators (commonly known as "Google Dorks") can significantly refine results and uncover valuable intelligence about targets, including exposed files, vulnerable systems, and sensitive information inadvertently published online.

<details>

<summary>Google Search Utilities</summary>

* [Google Advanced Search](https://www.google.com/advanced_search) - Google's native advanced search interface with multiple filtering options for refining search parameters
* [Keyword Tool](https://keywordtool.io) - Analyzes keyword effectiveness and generates related search terms to improve search strategy
* [Google Alerts](https://www.google.com/alerts) - Automated monitoring service that sends notifications when new content matching specified keywords appears in Google's index
* [ISearchFrom](https://isearchfrom.com/) - Simulates Google searches from different geographic locations to analyze regional variations in search results

</details>

{% tabs %}
{% tab title="Google search commands (Dorks)" %}
* [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) - Comprehensive repository of Google search operators and techniques for discovering exposed information, vulnerable systems, and misconfigured websites
* [SANS Google Cheatsheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf) - Quick reference guide for Google search operators
* [https://ahrefs.com/blog/google-advanced-search-operators/](https://ahrefs.com/blog/google-advanced-search-operators/) - Detailed guide to Google's advanced search operators
* [http://www.googleguide.com/advanced\_operators\_reference.html](http://www.googleguide.com/advanced_operators_reference.html) - Complete reference for advanced Google operators



{% content-ref url="google-dorking-cheatsheet.md" %}
[google-dorking-cheatsheet.md](google-dorking-cheatsheet.md)
{% endcontent-ref %}
{% endtab %}

{% tab title="Google Dorking Tools" %}
* [EasyRecon.html](https://s0cm0nkey.github.io/EasyRecon.html) - Web-based reconnaissance tool that consolidates multiple Google Dork resources into a single, user-friendly interface. Incorporates dorks from:
  * [Goohak](https://github.com/1N3/Goohak/) - Automated tool for launching Google Hacking Database queries against target domains to identify vulnerabilities and enumerate exposed information
    * [https://www.isec.ne.jp/wp-content/uploads/2017/10/65Goohack.pdf](https://www.isec.ne.jp/wp-content/uploads/2017/10/65Goohack.pdf)
  * [https://dorks.faisalahmed.me/](https://dorks.faisalahmed.me/) - Bug bounty-focused Google dorking assistant
  * [Fast Google Dorks Scan](https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan) - Rapid scanning tool for executing multiple Google dorks efficiently
* [0xDork](https://github.com/rlyonheart/0xdork) - Command-line Google dorking tool for automating dorking operations
* [SDorker](https://github.com/TheSpeedX/SDorker) - Automated Google dork scanner with multiple search engine support
* [Google Dork Builder Firefox Add-on](https://addons.mozilla.org/ru/firefox/addon/google-dork-builder/) - Browser extension for constructing and testing Google dork queries interactively
{% endtab %}

{% tab title="Pagodo" %}
[pagodo](https://github.com/opsdisk/pagodo) - Passive Google Dork tool that automates Google Hacking Database scraping and searching against target domains

```bash
## Install
git clone https://github.com/opsdisk/pagodo.git
cd pagodo
virtualenv -p python3.7 .venv           # If using a virtual environment
source .venv/bin/activate               # If using a virtual environment
pip install -r requirements.txt

## Get Latest GHDB
python ghdb_scraper.py -s -j -i

## Run All Dorks
python pagodo.py -d example.com -g dorks/all_google_dorks.txt
```
{% endtab %}
{% endtabs %}

{% embed url="https://youtu.be/cFOBUYaxdWI" %}

## Utility Search Engines

<details>

<summary>Archived Page Search Engines</summary>

Web pages frequently become unavailable due to deletion, site restructuring, or domain expiration. However, archived versions often persist in web archives and cached data repositories. These resources are essential when investigating historical website content or tracking changes over time.

* [Quick Cache and Archive Search](https://cipher387.github.io/quickcacheandarchivesearch/) - Unified interface for searching multiple web archives and cached versions of websites simultaneously
  * [Wayback Machine](https://web.archive.org/) - The most comprehensive web archive, containing billions of archived pages dating back to 1996. Essential for retrieving historical versions of web pages at specific dates and times
    * [waybackurls](https://github.com/tomnomnom/waybackurls) - Command-line tool for retrieving all URLs archived for a domain from the Wayback Machine
  * [archive.ph](https://archive.ph) - On-demand archiving service that creates permanent snapshots of web pages
  * [Common Crawl](https://commoncrawl.org/) - Open repository of web crawl data collected since 2008, containing petabytes of archived web content

* [gau (Get All URLs)](https://github.com/lc/gau) - Command-line tool that fetches all known URLs for a domain from AlienVault's Open Threat Exchange, Wayback Machine, and Common Crawl

</details>

<details>

<summary>Privacy-Focused Search Engines</summary>

* [Swisscows](https://swisscows.com/) - Privacy-centric search engine that does not track, store, or profile users. All searches are encrypted and no data is logged
* [Gigablast](https://www.gigablast.com/) - Open-source private search engine. Note: Service availability can be intermittent
* [Startpage](https://www.startpage.com) - Privacy-focused search engine that delivers Google search results without tracking or storing user information. Based in the Netherlands with strong privacy protections
* [DuckDuckGo](https://duckduckgo.com/) - Privacy-focused search engine that doesn't track users or personalize search results

</details>

<details>

<summary>Metasearch Engines</summary>

* [FaganFinder](https://www.faganfinder.com/) - Comprehensive metasearch tool providing unified access to numerous search engines, social media platforms, encyclopedias, libraries, news sources, government databases, and document repositories
* [All-io.net](https://all-io.net/) - Customizable metasearch engine aggregating results from major search engines. Allows users to create and configure personalized search engine interfaces

</details>

<details>

<summary>Miscellaneous Search Engines and Utilities</summary>

Additional specialized search engines and utilities for comprehensive OSINT research.

* [Search Engine Colossus](https://www.searchenginecolossus.com/) - Comprehensive directory of search engines worldwide, organized by country and region
* [Million Short](https://millionshort.com/) - Unique search engine that filters out the top 100, 1,000, 10,000, 100,000, or 1 million most popular websites, revealing lesser-known sources and obscure content
* [LeakIX](https://leakix.net/) - Specialized search engine indexing publicly exposed systems and data leaks, combined with an open reporting platform for security findings

**International Search Engines**
  * Russia - [Yandex](https://yandex.com/) - Leading Russian search engine, essential for research targeting Russian-language content
  * China - [Baidu](https://www.baidu.com) - Dominant Chinese search engine, necessary for accessing content within China's internet ecosystem
  * Japan - [Goo](https://www.goo.ne.jp/) - Popular Japanese search engine and web portal
  * Korea - [Daum](https://www.daum.net/) - Major South Korean search engine and web portal
  * Iran - [Parseek](https://www.parseek.com/) - Persian-language news aggregator and content portal (primarily aggregates news rather than providing web search)
  * Additional resources - [OH SHINT! Search Engine List](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/search-engines) - Extensive compilation of international and specialized search engines

**Specialized Content Search**
* [Blog Search Engine](https://www.blogsearchengine.org/) - Dedicated blog search platform with options to search, submit, and subscribe to RSS feeds by topic
* [Boardreader](https://boardreader.com/) - Multi-forum search engine indexing discussions across thousands of forums and message boards
* [Firebounty](https://firebounty.com) - Search engine specifically for bug bounty programs and vulnerability disclosure information

</details>

## Deprecated and Inactive Tools

The following tools and services are no longer maintained or have been discontinued. They are listed here for historical reference and to prevent wasted time attempting to use them.

### Google Dorking Tools
* [ASHOK](https://github.com/ankitdobhal/Ashok) - OSINT Swiss Army knife. Repository archived and no longer maintained
* [Googd0rker](https://github.com/ZephrFish/GoogD0rker/) - Automated Google dork launcher for domain-specific OSINT. Repository last updated in 2018

### Archive Services
* [WebCite](https://www.webcitation.org) - On-demand archive service formerly used for preserving cited web content in academic and scientific publications. **No longer accepting new archiving requests as of 2020.** Existing archives remain accessible

### Search Engines
* [Exalead](https://www.exalead.com/search/web/) - Enterprise search platform acquired by Dassault Systèmes and transitioned to Netvibes. The public web search interface is no longer available

## **Training and Educational Resources**

* [TryHackMe - Google Dorking Room](https://tryhackme.com/room/googledorking) - Interactive hands-on training module covering Google Dorking techniques and practical applications
* [Google Hacking for Penetration Testers](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf) - Classic Black Hat Europe presentation on Google Hacking techniques and methodology

