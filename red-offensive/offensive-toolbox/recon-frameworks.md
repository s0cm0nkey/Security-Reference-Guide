# Recon Frameworks

## Recon Frameworks&#x20;

Recon Frameworks are the backbone of any recon phase of a penetration test. With the wealth of information they can retrieve, they can also be leveraged for assisting in actions such as threat hunting, threat intelligence, attack surface mapping, and many others.&#x20;

### [**Spiderfoot** ](https://github.com/smicallef/spiderfoot) ****&#x20;

This is my go to for OSINT searches. Not only is it easy to use, it has a great web UI with loadable templates you can tailor to the scan that you want. It has over 200 different modules to collect different information about your target. These modules can call on other command line utilities as well as web services to pull in data.&#x20;

Some of these modules will require an API key, but most services offer a free version. Getting as many of these free API keys as possible is preferable. Once you have your API keys, you can save them as part of a scan template that allows them to be imported and used at ease.

As with any great tool, make sure you read the [documentation](https://www.spiderfoot.net/documentation/), and check out some of the [video tutorials](https://asciinema.org/\~spiderfoot) on the tool.

* [https://www.ired.team/offensive-security/red-team-infrastructure/spiderfoot-101-with-kali-using-docker](https://www.ired.team/offensive-security/red-team-infrastructure/spiderfoot-101-with-kali-using-docker)

### ****[**Recon-ng**](https://github.com/lanmaster53/recon-ng) ****&#x20;

This command line tool is the gold standard for recon. Tim Tomes (lanmaster53) has done an incredible job with it, making a plethora of modules for various needs. It is a flexible python framework that makes it ideal for automating tasks. After loading your API keys into a lookup file for the Recon-ng modules, you can select some or all of the modules to run and output the results into the file of your choice. Because the modules in Recon-ng can be run independently and can be scripted pretty easily, it is easy to incorporate its modules into other workflows outside of passive recon. Take a look at all of them, and see what you can use.

Recon-ng has a ton of great resources, but by far the BlackHills Infosec walkthroughs are the best guides for how to use this tool. Also check out Tim's website with his training and other tools.

* [Recon-ng Wiki](https://github.com/lanmaster53/recon-ng/wiki) - Read the documentation. Always.
* [Website for the creator of Recon-ng, lanmaster53](https://www.lanmaster53.com) - Check out his training courses. Highly reccomended.
* [PluralSight course on using Recon-ng](https://www.pluralsight.com/courses/technical-information-gathering-recon-ng) - Great structured training on this tool's use.
* [Black Hills Infosec Intro to Recon-ng](https://www.blackhillsinfosec.com/whats-changed-in-recon-ng-5x/)
* [Black Hills Infosec Recon-ng cheatsheet](https://www.blackhillsinfosec.com/wp-content/uploads/2019/11/recon-ng-5.x-cheat-sheet-Sheet1-1.pdf)

{% embed url="https://youtu.be/0J6Auz88iTY" %}

### **Other Frameworks**

These other frameworks do many of the same tasks that the previous two perform. Some are still actively being developed and promise expanded functionality in the future.

* [Maltego](https://www.maltego.com/) - Maltego is an open source intelligence and graphical link analysis tool for gathering and connecting information for investigative tasks.
  * [https://docs.maltego.com/support/home](https://docs.maltego.com/support/home)
  * [https://static.maltego.com/cdn/Handbooks/Maltego-Handbook-for-Social-Media-Investigations-Short.pdf](https://static.maltego.com/cdn/Handbooks/Maltego-Handbook-for-Social-Media-Investigations-Short.pdf)
* [sn0int ](https://github.com/kpcyrd/sn0int)- A semi-automatic OSINT framework and package manager. It was built for IT security professionals and bug hunters to gather intelligence about a given target or about yourself.
* [Raccoon](https://github.com/evyatarmeged/Raccoon) - An offensive security focused framework that performs a good bit of OSINT as well as active scanning on your target to get everything you need before attempts at exploitation.
* [ReconSpider ](https://github.com/bhavsec/reconspider)- Another great offensive recon tool that has a great option to present the data in different visuals to help you conceptualize the data around your target
* [OWASP Maryam](https://github.com/saeeddhqan/Maryam) - A modular open-source framework based on OSINT and data gathering. It is designed to provide a robust environment to harvest data from open sources and search engines quickly and thoroughly.
* [Discover Scripts ](https://github.com/leebaird/discover)- One of the first offensive reconnaissance tools, the discover scripts by Lee Baird are a set of custom scripts for automating the inital phases of a penetration test.
* [DarkSide](https://github.com/ultrasecurity/DarkSide) - Tool Information Gathering & social engineering Write By \[Python,JS,PHP]
* [ReconFTW](https://github.com/six2dez/reconftw) - ReconFTW is a tool designed to perform automated recon on a target domain by running the best set of tools to perform scanning and finding out vulnerabilities
* [dmitry](https://www.kali.org/tools/dmitry/) - DMitry can find possible subdomains, email addresses, uptime information, perform tcp port scan, whois lookups, and more.
* [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) - Thorough all-in-one tool for hacking.
* [finalrecon](https://www.kali.org/tools/finalrecon/) - A fast and simple python script for web reconnaissance that follows a modular structure and provides detailed information on various areas.
* [gasmask](https://github.com/twelvesec/gasmask) - All in one Information gathering tool
* [machinae](https://github.com/HurricaneLabs/machinae) - Machinae is a tool for collecting intelligence from public sites/feeds about various security-related pieces of data: IP addresses, domain names, URLs, email addresses, file hashes and SSL fingerprints.

{% embed url="https://youtu.be/zemNLx0-LRw" %}
