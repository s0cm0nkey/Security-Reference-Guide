# Social Engineering

## Basics

{% tabs %}
{% tab title="Guides and Reference" %}
* [Awesome Lists Collection: Social Engineering](https://github.com/v2-dev/awesome-social-engineering)
* [https://www.social-engineer.org/](https://www.social-engineer.org/)
* [https://www.social-engineer.com/](https://www.social-engineer.com/)
* [https://www.social-engineer.org/framework/general-discussion/categories-social-engineers/hackers/](https://www.social-engineer.org/framework/general-discussion/categories-social-engineers/hackers/)
* _The Hacker's Playbook 3: Social Engineering - pg. 174_
* _Social Engineering: The Science of Human Hacking - Christopher Hadnagy_
* _Advanced Penetration Testing: Advanced Concepts in Social Engineering- pg. 194_
* _Hacking: The next generation - Infiltrating the phishing underground: learning from online criminals, pg 177_
{% endtab %}

{% tab title="General Tools" %}
* [Social Engineers Toolkit](https://github.com/trustedsec/social-engineer-toolkit) - The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly
  * [https://www.kali.org/tools/set/](https://www.kali.org/tools/set/)
* [BeeLogger](https://github.com/4w4k3/BeeLogger) - Generate Gmail Emailing Keyloggers to Windows.
* [evilgrade](https://github.com/infobyte/evilgrade) - Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates.
{% endtab %}

{% tab title="Attack Vectors" %}
* ****[**Phishing**](https://www.social-engineer.org/framework/attack-vectors/phishing-attacks-2/) - _“practice of sending emails appearing to be from reputable sources with the goal of influencing or gaining personal information.”_ (Hadnagy, Fincher. _Phishing Dark Waters: The Offensive and Defensive Sides of Malicious Emails._ Wiley, 2015).
* ****[**SMiShing**](https://www.social-engineer.org/framework/attack-vectors/smishing/) **** - _“the act of using mobile phone text messages, SMS (Short Message Service), to lure victims into immediate action. This action may include downloading mobile malware, visiting a malicious website, or calling a fraudulent phone number.”_
* ****[**Vishing**](https://www.social-engineer.org/framework/attack-vectors/vishing/) **** - "_practice of eliciting information or attempting to influence action via the telephone."_
* ****[**Impersonation**](https://www.social-engineer.org/framework/attack-vectors/impersonation/) **** - _“practice of pretexting as another person with the goal of obtaining information or access to a person, company, or computer system.”_
* [https://www.social-engineer.org/framework/attack-vectors/](https://www.social-engineer.org/framework/attack-vectors/)
{% endtab %}

{% tab title="Attack Phases" %}
* **OSINT** - The research performed on the target using Open-Source Intelligence tools. This phase does not interact with the target in anyway.
  * _Social Engineering: Christopher Hadnagy - pg.17_
* **Pretext Development** - This is where an attacker develops their reason for initial interaction.&#x20;
* **Attack Plan** - Planning out the Who, What, When, Where, Why, and How of the attack.
* **Attack Launch**&#x20;
* **Reporting** - The full details of the attack. This is crucial for a client to understand all that was done and what they need to improve their defenses.
{% endtab %}
{% endtabs %}

## Phishing

{% tabs %}
{% tab title="Tools" %}
* [squarephish](https://github.com/secureworks/squarephish) - SquarePhish is an advanced phishing tool that uses a technique combining the OAuth Device code authentication flow and QR codes.
* [PhishInSuits](https://github.com/secureworks/PhishInSuits) - OAuth Device Code Phishing with Verified Apps
* [Muraena](https://github.com/muraenateam/muraena) - Muraena is an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities.
  * [NecroBrowser](https://github.com/muraenateam/necrobrowser) - Necrobrowser is a browser instrumentation microservice written in NodeJS: it uses the Puppeteer library to control instances of Chrome or Firefox in headless and GUI mode.
* [catphish](https://github.com/ring0lab/catphish) - Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers. Perfect for Red Team engagements.
* [king-phisher](https://github.com/rsmusllp/king-phisher) - Advanced Phishing Campaign toolkit
* [evilginx2](https://github.com/kgretzky/evilginx2) - Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication
* [ReelPhish](https://github.com/fireeye/ReelPhish) - FireEye phishing and 2fa bypass tool
  * [https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html)
* [FiercePhish](https://github.com/Raikia/FiercePhish) - FiercePhish is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more.
* [CredSniper](https://github.com/ustayready/CredSniper) - CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.
* [TigerShark](https://github.com/s1l3nt78/TigerShark) - Bilingual PhishingKit. TigerShark integrates a vast array of various phishing tools and frameworks, from C2 servers, backdoors and delivery methods in multiple scripting languages in order to suit whatever your deployment needs may be.
* [Zphisher](https://github.com/htr-tech/zphisher) - An automated phishing tool with 30+ templates.
* [SharpPhish](https://github.com/Yaxser/SharpPhish) - Using outlook COM objects to create convincing phishing emails without the user noticing. This project is meant for internal phishing.
* [SocialFish](https://github.com/UndeadSec/SocialFish) - Educational Phishing Tool & Information Collector
* [shellphish](https://github.com/suljot/shellphish) - Phishing Tool for Instagram, Facebook, Twitter, Snapchat, Github
  * [https://www.hackingarticles.in/shellphish-a-phishing-tool/](https://www.hackingarticles.in/shellphish-a-phishing-tool/)
* [saycheese](https://github.com/hangetzzu/saycheese) - Take webcam shots from target just sending a malicious link
{% endtab %}

{% tab title="Guides and Methodology" %}
* [https://book.hacktricks.xyz/phishing-methodology](https://book.hacktricks.xyz/phishing-methodology)
* [https://www.blackhillsinfosec.com/how-to-phish-for-geniuses/](https://www.blackhillsinfosec.com/how-to-phish-for-geniuses/)
* [https://sidb.in/2021/08/03/Phishing-0-to-100.html](https://sidb.in/2021/08/03/Phishing-0-to-100.html)
* [https://xapax.github.io/security/#initial\_access/social\_engineering\_-\_phishing/](https://xapax.github.io/security/#initial\_access/social\_engineering\_-\_phishing/)
* Phishing Defense
  * [https://www.blackhillsinfosec.com/offensive-spf-how-to-automate-anti-phishing-reconnaissance-using-sender-policy-framework/](https://www.blackhillsinfosec.com/offensive-spf-how-to-automate-anti-phishing-reconnaissance-using-sender-policy-framework/)
  * [https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-attack-of-the-chameleon-phishing-page/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-attack-of-the-chameleon-phishing-page/)
* Auth attacks
  * [https://curtbraz.medium.com/you-aint-got-no-problem-jules-i-m-on-the-multifactor-e05d5e2a6ade](https://curtbraz.medium.com/you-aint-got-no-problem-jules-i-m-on-the-multifactor-e05d5e2a6ade)
  * [https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication)
* Phishing Tool use
  * [https://www.ired.team/offensive-security/red-team-infrastructure/how-to-setup-modliska-reverse-http-proxy-for-phishing](https://www.ired.team/offensive-security/red-team-infrastructure/how-to-setup-modliska-reverse-http-proxy-for-phishing)
* Misc
  * [https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office)
  * [https://www.ired.team/offensive-security/initial-access/phishing-with-gophish-and-digitalocean](https://www.ired.team/offensive-security/initial-access/phishing-with-gophish-and-digitalocean)
  * [https://www.ired.team/offensive-security/initial-access/netntlmv2-hash-stealing-using-outlook](https://www.ired.team/offensive-security/initial-access/netntlmv2-hash-stealing-using-outlook)
  * [https://mrd0x.com/browser-in-the-browser-phishing-attack/](https://mrd0x.com/browser-in-the-browser-phishing-attack/)
{% endtab %}

{% tab title="Persona Creation" %}
* [This Person Does Not Exist](https://thispersondoesnotexist.com/)
* &#x20;[Why a Fake Resume Generator? – trick the HR but not the job](https://thisresumedoesnotexist.com/)&#x20;
* [This Rental Does Not Exist](https://thisrentaldoesnotexist.com/about/)&#x20;
* [Generate a Random Name - Fake Name Generator](https://www.fakenamegenerator.com/)&#x20;
* [Random Name Generator | Fake ID Generator](https://www.elfqrin.com/fakeid.php)
* [**AI Generated Photos**](https://generated.photos) - 100.000 AI generated faces.
* [Facial composite (identikit) maker](http://facemaker.uvrg.org/)
{% endtab %}

{% tab title="User Tracking" %}
* [I-See-You](https://github.com/Viralmaniar/I-See-You) - A Bash and Javascript tool to find the exact location of the users during social engineering or phishing engagements. Using exact location coordinates an attacker can perform preliminary reconnaissance which will help them in performing further targeted attacks.
* [https://iplogger.org/](https://iplogger.org/)
* [http://canarytokens.org/generate](http://canarytokens.org/generate)
* [http://www.urlbiggy.com/](http://www.urlbiggy.com/)
* [https://getnotify.com/](https://getnotify.com/)
* User tracking with Wireshark and Google Maps -[https://youtu.be/xuNuy8n8u-Y](https://youtu.be/xuNuy8n8u-Y)
{% endtab %}
{% endtabs %}

## Mal-docs

{% tabs %}
{% tab title="Guides and Resources" %}
* [https://www.optiv.com/insights/source-zero/blog/defeating-edrs-office-products](https://www.optiv.com/insights/source-zero/blog/defeating-edrs-office-products)
* _Advanced Penetration Testing: Learning how to use the VBA macro - pg. 5_
* _Advanced Penetration Testing: VBA Redux, Alternative Command Line Attack Vectors- pg. 116_
* _Advanced Penetration Testing: Deploying with HTA - pg. 138_
{% endtab %}

{% tab title="Tools" %}
* [Lucky Strike](https://github.com/curi0usJack/luckystrike) - create excel docs with payloads within the worksheets
  * [https://www.shellintel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator](https://www.shellintel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
* [Vbad](https://github.com/Pepitoh/VBad) - Heavily obscures vba payloads within word documents\
  \- destroys references to module containing effective payload in order to mave invisible from VBA dev tools
* &#x20;[demiguise](https://github.com/nccgroup/demiguise) - HTA encryption tool for RedTeams
* [EmbedInHTML](https://github.com/Arno0x/EmbedInHTML) - Embed and hide any file in an HTML file
* [OffensiveVBA](https://github.com/S3cur3Th1sSh1t/OffensiveVBA) - This repo covers some code execution and AV Evasion methods for Macros in Office documents
* [malicious-pdf](https://github.com/pussycat0x/malicious-pdf) - Generate a bunch of malicious pdf files with phone-home functionality. Can be used with Burp Collaborator
* [Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage) - Invoke-PSImage takes a PowerShell script and embeds the bytes of the script into the pixels of a PNG image.
* DDE Dynamic Data Exchange - Sends messages and data between applications
  * [https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774\(v=vs.85\).aspx)
  * [https://sensepost.com/blog/2017/macro-less-code-exec-in-msword](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword)
* Sub-doc attacks
  * [https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc)
  * Sub-doc injection [http://bit.ly/2qxOuiA](http://bit.ly/2qxOuiA)
* _The Hacker Playbook 3: Maldocs - pg. 178_
* [https://blog.f-secure.com/dechaining-macros-and-evading-edr/](https://blog.f-secure.com/dechaining-macros-and-evading-edr/)
{% endtab %}

{% tab title="Tips" %}
* General
  * Remember to change .docm extensions to .doc
  * Give the end user a compelling reason to enable macros.
  * Tailor the attack to the client. Gather information with a mass email and get an OOTO response to get a template for the interna email style
* Embeded macros in Microsoft office documents
  * Run test file against VirusTotal to check for ease of detection
  * Review “Tags” section for offending tags that set off signature matches
  * Often AV will only scan the main body of the code and NOT the declaration section.
    * Use an alias for a function import to get around this.
  * Avoid Obvious use of shellcode
  * Functions that will most assuredly get flagged: VirtualAlloc, RtlMoveMemory, Shell, URLDownloadToFile, and CreateThread
  * Automatic execution in macros
    * Three deifferent methods depending on which format you are using: word, excel spreadsheet, or excel workbook
    * Often all three are enabled when auto code execution is enabled.
    * Reduce to 1 or 0 depending on what you need to reduce chance of detection.
  * Using a VBA/VBS Dual Stager
    * While VBA is used exclusively in Office products, VBS is used to perform other tasks outside of office, therefore it is given more freedom of execution.
    * Deploy a VBA macro containing VBS code
    * Two separate scripts, one VBA and one VBS
* Code obfuscation
  * Encoding script with possibilities such as Base64 and XOR and have it decrypted at run-time
{% endtab %}
{% endtabs %}
