# Burp Suite

## [**Burp**](https://portswigger.net/burp) ****&#x20;

The Leading Web application testing tool on the market. Has a community edition that is free and handy for basic web app testing and CTF level functionality. Also has a pro version that has advanced features like a powerful brute forcing too, vulnerability scanner and access to more extensions.

* [Burp Commander](https://github.com/pentestgeek/burpcommander) - Ruby command-line interface to Burp Suite's REST API
* [https://burpsuite.guide/](https://burpsuite.guide/) - Get information on the usage of extensions along with other tips and tricksc
* [https://www.blackhillsinfosec.com/using-simple-burp-macros-to-automate-testing/](https://www.blackhillsinfosec.com/using-simple-burp-macros-to-automate-testing/)
* [https://portswigger.net/support/using-burp-suites-engagement-tools](https://portswigger.net/support/using-burp-suites-engagement-tools)
* SANS Burp Cheat Sheet - [https://sansorg.egnyte.com/dl/x19ByeTOpS](https://sansorg.egnyte.com/dl/x19ByeTOpS)
* [IntruderPayloads](https://github.com/1N3/IntruderPayloads) - A collection of Burpsuite Intruder payloads, BurpBounty payloads, fuzz lists, malicious file uploads and web pentesting methodologies and checklists.

## Burp Platform Components

* Dashboard - Burp's dashboard lets you control and monitor Burp's automated activity:
  * [https://portswigger.net/burp/documentation/desktop/dashboard](https://portswigger.net/burp/documentation/desktop/dashboard)
  * [https://portswigger.net/blog/the-new-dashboard](https://portswigger.net/blog/the-new-dashboard)
* Target - The Target tool contains the site map, with detailed information about your target applications. It lets you define which targets are in scope for your current work, and also lets you drive the process of testing for vulnerabilities.
  * [https://portswigger.net/burp/documentation/desktop/tools/target](https://portswigger.net/burp/documentation/desktop/tools/target)
  * [How to Spider Web Applications using Burpsuite](https://www.hackingarticles.in/spider-web-applications-using-burpsuite/)
* Proxy - Burp Proxy lies at the heart of Burp's [user-driven workflow](https://portswigger.net/burp/documentation/desktop/penetration-testing), and lets you intercept, view, and modify all requests and responses passing between your browser and destination web servers.
  * [https://portswigger.net/burp/documentation/desktop/tools/proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy)
  * [https://www.hackingarticles.in/burp-suite-for-pentester-configuring-proxy/](https://www.hackingarticles.in/burp-suite-for-pentester-configuring-proxy/)
* Intruder - Burp Intruder is a powerful tool for automating customized attacks against web applications. It can be used to automate all kinds of tasks that may arise during your testing.
  * [https://portswigger.net/burp/documentation/desktop/tools/intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)
  * [https://portswigger.net/burp/documentation/desktop/tools/intruder/using](https://portswigger.net/burp/documentation/desktop/tools/intruder/using)
  * [https://www.hackingarticles.in/burp-suite-for-pentester-fuzzing-with-intruder-part-1/](https://www.hackingarticles.in/burp-suite-for-pentester-fuzzing-with-intruder-part-1/)
  * [https://www.hackingarticles.in/burpsuite-for-pentester-fuzzing-with-intruder-part-2/](https://www.hackingarticles.in/burpsuite-for-pentester-fuzzing-with-intruder-part-2/)
* Repeater - Burp Repeater is a simple tool for manually manipulating and reissuing individual HTTP requests, and analyzing the application's responses. You can send a request to Repeater from anywhere within Burp, modify the request and issue it over and over.
  * [https://portswigger.net/burp/documentation/desktop/tools/repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater)
  * [https://portswigger.net/burp/documentation/desktop/tools/repeater/using](https://portswigger.net/burp/documentation/desktop/tools/repeater/using)
  * [https://www.hackingarticles.in/burp-suite-for-pentester-repeater/](https://www.hackingarticles.in/burp-suite-for-pentester-repeater/)
* Sequencer - Burp Sequencer is a tool for analyzing the quality of randomness in a sample of data items. You can use it to test an application's session tokens or other important data items that are intended to be unpredictable, such as anti-CSRF tokens, password reset tokens, etc.
  * [https://portswigger.net/burp/documentation/desktop/tools/sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer)
* Decoder - Burp Decoder is a simple tool for transforming encoded data into its canonical form, or for transforming raw data into various encoded and hashed forms. It is capable of intelligently recognizing several encoding formats using heuristic techniques.
  * [https://portswigger.net/burp/documentation/desktop/tools/decoder](https://portswigger.net/burp/documentation/desktop/tools/decoder)
  * [Burpsuite Encoder & Decoder Tutorial](https://www.hackingarticles.in/burpsuite-encoder-decoder-tutorial/)
* Comparer - Burp Comparer is a simple tool for performing a comparison (a visual "diff") between any two items of data.
  * [https://portswigger.net/burp/documentation/desktop/tools/comparer](https://portswigger.net/burp/documentation/desktop/tools/comparer)
  * [https://www.youtube.com/watch?v=lT56Z54K-Jo](https://www.youtube.com/watch?v=lT56Z54K-Jo)
* Logger - Logger is a tool for recording network activity. Logger records all HTTP traffic that Burp Suite generates, for investigation and analysis
  * [https://portswigger.net/burp/documentation/desktop/tools/logger](https://portswigger.net/burp/documentation/desktop/tools/logger)
  * [https://github.com/PortSwigger/logger-plus-plus](https://github.com/PortSwigger/logger-plus-plus)
* Extender - Burp Extender lets you use Burp extensions, to extend Burp's functionality using your own or third-party code.
  * [https://portswigger.net/burp/documentation/desktop/tools/extender](https://portswigger.net/burp/documentation/desktop/tools/extender)
* Project Options - Burp contains a large number of suite-wide options that affect the behavior of all tools.
  * [https://portswigger.net/burp/documentation/desktop/options](https://portswigger.net/burp/documentation/desktop/options)
  * [https://www.hackingarticles.in/burp-suite-for-pentester-burps-project-management/](https://www.hackingarticles.in/burp-suite-for-pentester-burps-project-management/)
  * [https://www.youtube.com/watch?v=CdcJcdp-ObQ](https://www.youtube.com/watch?v=CdcJcdp-ObQ)
* Collaborater - Burp Collaborator is a network service that Burp Suite uses to help discover many kinds of vulnerabilities.
  * [https://portswigger.net/burp/documentation/collaborator](https://portswigger.net/burp/documentation/collaborator)
  * [https://www.hackingarticles.in/burp-suite-for-pentester-burp-collaborator/](https://www.hackingarticles.in/burp-suite-for-pentester-burp-collaborator/)

## Burp Extensions

### Extension Collections

* [Awesome Lists Collection: Burp Extensions](https://github.com/snoopysecurity/awesome-burp-extensions)
* [Bug Bounty Forum's Burp Extensions List](https://bugbountyforum.com/tools/proxy-plugins/)

### Multi-Vulnerability Scanning Extensions

* [HUNT](https://github.com/bugcrowd/HUNT) - HUNT Suite is a collection of Burp Suite Pro/Free and OWASP ZAP extensions, collected by Bug Crowd.
* [BurpBounty](https://github.com/wagiro/BurpBounty) - This Burp Suite extension allows you, in a quick and simple way, to improve the active and passive Burp Suite scanner by means of personalized rules through a very intuitive graphical interface.
  * [Burp Bounty Pro](https://burpbounty.net/) - Premium bundle of vulnerabilites to scan for.
* [VulnersScan](https://github.com/vulnersCom/burp-vulners-scanner) - Burp Suite scanner plugin based on [Vulners.com](https://vulners.com) vulnerability database API
  * Same thing as [https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb](https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb)
* [Active Scan++](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976) - Burp Scanner automates the task of scanning web sites for content and vulnerabilities. Depending on configuration, the Scanner can [crawl the application](https://portswigger.net/burp/documentation/scanner/crawling) to discover its content and functionality, and [audit the application](https://portswigger.net/burp/documentation/scanner/auditing) to discover vulnerabilities. Active Scan++ is an extension that expands the scanning capabilities of Burp Suite.
  * [https://portswigger.net/burp/documentation/desktop/scanning](https://portswigger.net/burp/documentation/desktop/scanning)
  * [https://www.hackingarticles.in/burp-suite-for-pentester-active-scan/](https://www.hackingarticles.in/burp-suite-for-pentester-active-scan/)
* [ParamMiner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) - This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.

### Single Vulnerability Extensions

* [Retire.JS](https://github.com/h3xstream/burp-retire-js) - Burp/ZAP/Maven extension that integrate Retire.js repository to find vulnerable Javascript libraries.
* [sqlipy](https://github.com/codewatchorg/sqlipy) - SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
* [Backslash powered scanner](https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8) - Active scan for SSTI detection
* [CSFR Scanner](https://portswigger.net/bappstore/60f172f27a9b49a1b538ed414f9f27c3) - Passive CSRF detection
* [Freddy ](https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3)- Find Deserialization Bugs
* [JSON Web Tokens](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6) - decode and manipulate JSON web tokens
* [Web cache deception scanner ](https://portswigger.net/bappstore/7c1ca94a61474d9e897d307c858d52f0)- Tests applications for the Web Cache Deception vulnerability.
* [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - Active scanner and launcher for HTTP Request Smuggling attacks
* [Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa) - Tests various upload vulnerabilities
* [SSRF-KIng](https://github.com/ethicalhackingplayground/ssrf-king?s=09) - SSRF plugin for burp Automates SSRF Detection in all of the Request
* [shelling](https://github.com/ewilded/shelling) - a comprehensive OS command injection payload generator
* [Autorise](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f) - Tool for detecting autorization vulerabilities such as Indirect Object Reference.
* [Java Deserialization Scanner](https://portswigger.net/bappstore/228336544ebe4e68824b5146dbbd93ae) - Active and passive scanner to find Java deserialization vulnerabilities

### Utility Extensions

* [Hackbar](https://github.com/d3vilbug/HackBar) - Hackbar is a plugin designed for the penetration tester such in order to help them to speed their manual testing procedures**.**
  * [https://www.hackingarticles.in/burp-suite-for-pentester-hackbar/](https://www.hackingarticles.in/burp-suite-for-pentester-hackbar/)
* [Burp-Send-To](https://github.com/bytebutcher/burp-send-to) - Adds a customizable "Send to..."-context-menu to your Burp Suite. Handy for easily sending data into another tool like SQLmap
* [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988) - Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results. It's intended to complement Burp Intruder by handling attacks that require extreme speed or complexity.
* [burp-exporter](https://github.com/artssec/burp-exporter) - Exporter is a Burp Suite extension to copy a request to a file or the clipboard as multiple programming languages functions.
* [Flow](https://portswigger.net/bappstore/ee1c45f4cc084304b2af4b7e92c0a49d) - History of all burp tools, extensions and tests. Handy to pull all your results together
* [Decoder Improved](https://portswigger.net/bappstore/0a05afd37da44adca514acef1cdde3b9) - Decoder Improved is a data transformation plugin for Burp Suite that better serves the varying and expanding needs of information security professionals.
* [WSDLer](https://portswigger.net/bappstore/594a49bb233748f2bc80a9eb18a2e08f) - This extension takes a WSDL request, parses out the operations that are associated with the targeted web service, and generates SOAP requests that can then be sent to the SOAP endpoints.
* [WSDL Wizard](https://portswigger.net/bappstore/ef2f3f1a593d417987bb2ddded760aee): This extension scans a target server for WSDL files. After performing normal mapping of an application’s content, right click on the relevant target in the site map, and choose “Scan for WSDL files” from the context menu. The extension will search the already discovered contents for URLs with the .wsdl file extension, and guess the locations of any additional WSDL files based on the file names known to be in use. The results of the scanning appear within the extension’s output tab in the Burp Extender tool.

## Burp Payloads

* [Payload Processing Rule in Burp suite (Part 1)](https://www.hackingarticles.in/payload-processing-rule-burp-suite-part-1/)
* [Payload Processing Rule in Burp suite (Part 2)](https://www.hackingarticles.in/payload-processing-rule-burp-suite-part-2/)
* [Beginners Guide to Burpsuite Payloads (Part 1)](https://www.hackingarticles.in/beginners-guide-burpsuite-payloads-part-1/)
* [Beginners Guide to Burpsuite Payloads (Part 2)](https://www.hackingarticles.in/beginners-guide-burpsuite-payloads-part-2/)

## **Burp Training**

* [https://tryhackme.com/room/burpsuitebasics](https://tryhackme.com/room/burpsuitebasics)
* [https://tryhackme.com/room/burpsuiterepeater](https://tryhackme.com/room/burpsuiterepeater)
* [https://tryhackme.com/module/learn-burp-suite](https://tryhackme.com/module/learn-burp-suite)

### **Burp Suite Essentials Series by PortSwigger**

{% embed url="https://youtu.be/ouDe5sJ_uC8" %}

### Advanced Burp Suite by Bugcrowd Univeristy

{% embed url="https://youtu.be/kbi2KaAzTLg" %}

### Hacker101 Burp Suite Series

* [https://www.hacker101.com/playlists/burp\_suite.html](https://www.hacker101.com/playlists/burp\_suite.html) - 3 video series by Hacker101

### Portswigger's Web Security Academy

* [https://portswigger.net/web-security](https://portswigger.net/web-security) - The big training platform for Web Security Testing by the makers of Burp Suite.
