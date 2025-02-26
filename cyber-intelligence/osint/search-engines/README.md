# Search Engines

Cyber search engines are a beautiful set of tools that allow us to do research on specific targets as they relate to cybersecurity. Searching by IP, domain, vulnerability, etc. allows us to perform tasks ranging from passive recon as part of a penetration test, to threat intelligence research. Search.html - Your OSINT starting place.

When initiating a search on anything, the first stop is a bit of HTML whipped up by OSINT master Michael Bazzell. This handy tool allows an easy search of multiple sources with one click. I prefer this to other others as it allows me to manually parse the search page and go down rabbit holes from there.

Included Search Engines: Google, Google Date, Bing, Yahoo, Searx, Yandex, Baidu, Exalead, Duckduckgo, Startpage, Newsgroups, Blogs, FTP Servers, Indexes, Scholars, Patents, Qwant, News, Wayback, and Ahmia. Google is the most powerful and scary information gathering tool today. Beyond searching for basic keywords, adding in advanced commands can refine your results and reveal incredible amounts of information about your target.

These are by no means exhaustive, but they are a handy place to start.

{% file src="../../../.gitbook/assets/Search (1).html" %}

## [**Google**](https://google.com)

Google is the most powerful and scary information gathering tool today. Beyond searching for basic keywords, adding in advanced commands can refine your results and reveal incredible amounts of information about your target.

<details>

<summary>Google search utility</summary>

* [Google Advanced Search](https://www.google.com/advanced_search) - Google search with multiple special options for your search parameters
* [Keyword Tool](https://keywordtool.io) - Tool for assisting in analyzing the efficacy of searching for certain keywords
* [Google keyword monitor](https://www.google.com/alerts) - An awesome tool that can alert you on new search hits on certain keywords.
* [ISearchFrom](https://isearchfrom.com/) - Tool that allows you to search google as if you are in different locations to analyze the differences in results.

</details>

{% tabs %}
{% tab title="Google search commands (Dorks)" %}
* [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) - Repository of google search tricks for searching for exactly what you need.
* [SANS Google Cheatsheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf)
* [https://ahrefs.com/blog/google-advanced-search-operators/](https://ahrefs.com/blog/google-advanced-search-operators/)
* [http://www.googleguide.com/advanced\_operators\_reference.html](http://www.googleguide.com/advanced_operators_reference.html)



{% content-ref url="google-dorking-cheatsheet.md" %}
[google-dorking-cheatsheet.md](google-dorking-cheatsheet.md)
{% endcontent-ref %}
{% endtab %}

{% tab title="Google Dorking Tools" %}
* [EasyRecon.html](https://s0cm0nkey.github.io/EasyRecon.html) - My Recon tool that takes multiple resources and puts them in an easy to use webpage. Incorporates dorks from:
  * [Goohak](https://github.com/1N3/Goohak/) - Automatically launch google hacking queries against a target domain to find vulnerabilities and enumerate a target.
    * [https://www.isec.ne.jp/wp-content/uploads/2017/10/65Goohack.pdf](https://www.isec.ne.jp/wp-content/uploads/2017/10/65Goohack.pdf)
  * [https://dorks.faisalahmed.me/](https://dorks.faisalahmed.me/) - Bug Bounty focused dorking helper
  * Fast Google Dorks Scan [https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan](https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan)
* 0xDork [https://github.com/rlyonheart/0xdork](https://github.com/rlyonheart/0xdork)
* SDorker [https://github.com/TheSpeedX/SDorker](https://github.com/TheSpeedX/SDorker)
* Google Dork Builder Firefox Add-on [https://addons.mozilla.org/ru/firefox/addon/google-dork-builder/](https://addons.mozilla.org/ru/firefox/addon/google-dork-builder/)
* Depreciated
  * ASHOK (osint swiss knife) [https://github.com/ankitdobhal/Ashok](https://github.com/ankitdobhal/Ashok)
  * [Googd0rker ](https://github.com/ZephrFish/GoogD0rker/)- GoogD0rker is a tool for firing off google dorks against a target domain, it is purely for OSINT against a specific target domain.
{% endtab %}

{% tab title="Pagodo" %}
[pagodo](https://github.com/opsdisk/pagodo) - pagodo (Passive Google Dork) - Automate Google Hacking Database scraping and searching

```
##Install
git clone https://github.com/opsdisk/pagodo.git
cd pagodo
virtualenv -p python3.7 .venv           #If using a virtual environment.
source .venv/bin/activate               #If using a virtual environment.
pip install -r requirements.txt

##Get Latest GHDB
python ghdb_scraper.py -s -j -i

##Run All Dorks
python pagodo.py -d example.com -g dorks/all_google_dorks.txt
```
{% endtab %}
{% endtabs %}

{% embed url="https://youtu.be/cFOBUYaxdWI" %}

## Utility Search Engines

<details>

<summary>Archived Page Search Engines</summary>

Sometimes the page you are trying to find is no longer available. But it still may exist in web archives or cached data. Be sure to check these when you are getting stuck.

* [https://cipher387.github.io/quickcacheandarchivesearch/](https://cipher387.github.io/quickcacheandarchivesearch/) - An awesome tool that lets you search for older versions of websites via search engines and various web archive services.
  * [Wayback Machine](https://web.archive.org/) - The gold standard web archive. if you are looking for a version of a web page at a specific place and time, check this!
    * [waybackurls](https://github.com/tomnomnom/waybackurls) - CLI version of the Wayback Machine
  * [https://archive.ph](https://archive.ph) - A time capsule for web pages!
  * [https://www.webcitation.org](https://www.webcitation.org) (Depreciated) - WebCite is an on-demand archive site, designed to digitally preserve scientific and educationally important material on the web by making snapshots of Internet contents as they existed at the time when a blogger, or a scholar cited or quoted from it.

- [gau](https://github.com/lc/gau) - Get All URLs - Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.
  * [https://commoncrawl.org/](https://commoncrawl.org/) - Cached data from public web crawlers since 2008

</details>

<details>

<summary>Privacy Focused Search Engines</summary>

* [https://swisscows.com/](https://swisscows.com/) - The data-secure Google alternative. A search engine where your privacy is protected. Swisscows does not monitor or save any data.
* [https://www.gigablast.com/](https://www.gigablast.com/) and [https://private.sh/](https://private.sh/) - A "cryptographically-protected" private search engine.
* [https://www.startpage.com](https://www.startpage.com) - Startpage is a Dutch search engine company that highlights privacy as its distinguishing feature.

</details>

<details>

<summary>Metasearch Engines</summary>

* [https://www.faganfinder.com/](https://www.faganfinder.com/) - One of the best metasearch tools there is. Allows you to search through search engines, social media, encyclopedias, libraries, news, government, documents and much more.
* [https://www.exalead.com/search/web/](https://www.exalead.com/search/web/) - A high-end data discovery and search platform that powers search, data collection, and indexing among all technology solutions.
* [https://all-io.net/](https://all-io.net/) - A metasearch engine that combines all major search engines into one. They also allow you to create, configure and customize your own engine.

</details>

<details>

<summary>Misc Search Engines and Utilities</summary>

This section contains miscellaneous search engines and utilities.

* [Search Engine Colossus](https://www.searchenginecolossus.com/) - Giant list of the various search engines from across the globe.
* [Million Short ](https://millionshort.com/)- Want to search for something not on the top 1 million web pages? This does it.
* [https://leakix.net/](https://leakix.net/) - LeakIX is the first platform combining a **search engine indexing public information** AND an **open reporting platform** linked to the results.
* International Search Engines
  * Russia - [https://yandex.com/](https://yandex.com/)
  * China - [https://www.baidu.com](https://www.baidu.com)
  * Japan - [https://www.goo.ne.jp/](https://www.goo.ne.jp/)
  * Korea - [https://www.daum.net/](https://www.daum.net/)
  * Iran - [https://www.parseek.com](https://www.parseek.com/)
  * Large list of other search engines - [https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/search-engines](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/search-engines)
* [https://www.blogsearchengine.org/](https://www.blogsearchengine.org/) - A great tool for searching blogs online. Search for a blog, submit your own blogs, or subscribe to an RSS feed on the blog topic.
* [https://boardreader.com/ ](https://boardreader.com/) - Multi-forum search engine
* [Firebounty](https://firebounty.com) — Bug bounty search engine

</details>

## **Training**

* [https://tryhackme.com/room/googledorking](https://tryhackme.com/room/googledorking)
* [https://www.blackhat.com/presentations/bh-europe-05/BH\_EU\_05-Long.pdf](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf) - Blackhat presentation on Google Hacking

