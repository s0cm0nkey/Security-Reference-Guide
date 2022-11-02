---
description: Offensive Security and Penetration Testing
---

# Red - Offensive Operations

## **Intro**

Offensive security is a huge realm with dozens of different paths and specialties for aspiring hackers of all types. It can be daunting at first, with the sheer volume of tools you can use, technologies you have to learn about, processes,  and procedures. For those getting started, under stand one thing: If it works, then its the right thing for you! As the saying goes, "there are many ways to skin a cat". Same goes for hacking your target.\
My personal advice is to try test every tool and technique you come across. There are gems hidden out there that work famously or will work famously for you. Even if it fails, you will learn the technical reason why and that can even lead you to developing your own cool hacking tool!

## Resources: Offensive Security/ Penetration Testing&#x20;

When on an offensive security team, there are different levels of engagement that you will have, as well as different sets of rules you must follow, sometimes from engagement to engagement. Of those, one of the most common you will face is a simple Vulnerability assessment. This is little more than testing for the presence of a vulnerability. Sometimes its for a popular vulnerability that is trending in the news, or for an outdated server that reported poorly on the last vulnerability scan. Either way, they are quick, easy, but tedious and tend to have plenty of paperwork to go along with them.\
The other type of tasks will be a full penetration test. Some times its a white box test with full knowledge of your target, as well as the target having full knowledge of you. Other times it will be a black box stealth mission to see how badly you can compromise your target.

When performing a structured penetration test, following/documenting proper procedure will be key to explaining your success and justifying your findings. Below are some formal and informal resources that should help you set up your own processes, toolkit, and documentation.

<details>

<summary>Official Penetration Testing Guides</summary>

* Pen Test Standard Guide - [http://www.pentest-standard.org/index.php/PTES\_Technical\_Guidelines](http://www.pentest-standard.org/index.php/PTES\_Technical\_Guidelines)
* Vulnerability Assessment Guide - [http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html)
* OSSTMM3 - [https://www.isecom.org/OSSTMM.3.pdf](https://www.isecom.org/OSSTMM.3.pdf)
* [NIST SP:800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) - Technical Guide to Information Security Testing and Assessment

</details>

<details>

<summary>Researcher Developed Guides and Resources</summary>

* [https://book.hacktricks.xyz](https://book.hacktricks.xyz)&#x20;
* [https://www.thehacker.recipes/](https://www.thehacker.recipes/)
* [https://www.ired.team/](https://www.ired.team/)
* [https://guif.re/](https://guif.re/)
* [https://www.0daysecurity.com/penetration-testing/penetration.html](https://www.0daysecurity.com/penetration-testing/penetration.html)
* Hacking without Metasploit - [https://hakluke.medium.com/haklukes-guide-to-hacking-without-metasploit-1bbbe3d14f90](https://hakluke.medium.com/haklukes-guide-to-hacking-without-metasploit-1bbbe3d14f90)
* [https://github.com/nixawk/pentest-wiki](https://github.com/nixawk/pentest-wiki)
* [https://danielmiessler.com/projects/webappsec\_testing\_resources/](https://danielmiessler.com/projects/webappsec\_testing\_resources/)
* [https://threatexpress.com/blogs/2019/penetration-testing-pasties/](https://threatexpress.com/blogs/2019/penetration-testing-pasties/)
* [https://kwcsec.gitbook.io/the-red-team-handbook/](https://kwcsec.gitbook.io/the-red-team-handbook/)

</details>

<details>

<summary>CheatSheets</summary>

* [https://github.com/coreb1t/awesome-pentest-cheat-sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets)
* [https://owasp.org/www-project-cheat-sheets/](https://owasp.org/www-project-cheat-sheets/)
* [https://github.com/OlivierLaflamme/Cheatsheet-God](https://github.com/OlivierLaflamme/Cheatsheet-God)
* [https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)
* [https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/)

</details>

## Notekeeping/Report Writing

Notekeeping becomes incredibly important in recreating exploits, storing essential findings, keeping screenshots, common commands you ran to reach an outcome and more. Without sufficient notekeeping you’re only setting yourself up to fail.

<details>

<summary>Report Writing Guides</summary>

* [https://www.trustedsec.com/tools/physical-security-assessment-documentation/](https://www.trustedsec.com/tools/physical-security-assessment-documentation/)
* [https://www.blackhillsinfosec.com/tag/pentest-reports/](https://www.blackhillsinfosec.com/tag/pentest-reports/)
* [https://zeltser.com/writing-tips-for-it-professionals/](https://zeltser.com/writing-tips-for-it-professionals/)
* [https://zeltser.com/security-assessment-report-cheat-sheet/](https://zeltser.com/security-assessment-report-cheat-sheet/)
* [https://zeltser.com/human-communications-cheat-sheet/](https://zeltser.com/human-communications-cheat-sheet/)

</details>

{% tabs %}
{% tab title="Note Taking Apps" %}
* [CherryTree](https://www.giuspen.com/cherrytree/)
* [Joplin](https://joplinapp.org/)
* [OneNote](https://www.onenote.com)
* [Obsidian](https://obsidian.md/)
* Trilium: [https://github.com/zadam/trilium](https://github.com/zadam/trilium)
* KeepNote: [http://keepnote.org/](http://keepnote.org/)
* [https://asciinema.org/](https://asciinema.org/)
{% endtab %}

{% tab title="Screenshot Tools" %}
* [https://github.com/flameshot-org/flameshot](https://github.com/flameshot-org/flameshot)
* [https://getgreenshot.org/](https://getgreenshot.org/)
* Linux Native utility - Ctrl +Shift+PrintSreen
{% endtab %}

{% tab title="Report Generation Tools" %}
* [Ghostwriter](https://github.com/GhostManager/Ghostwriter) - The SpecterOps project management and reporting engine
* [APTRS](https://github.com/Anof-cyber/APTRS) - APTRS (Automated Penetration Testing Reporting System) is an automated reporting tool in Python and Django. The tool allows Penetration testers to create a report directly without using the Traditional Docx file. It also provides an approach to keeping track of the projects and vulnerabilities.
{% endtab %}

{% tab title="Templates/Examples" %}
* [https://github.com/nationalcptc/report\_examples](https://github.com/nationalcptc/report\_examples)
* [https://github.com/tjnull/TJ-JPT](https://github.com/tjnull/TJ-JPT)
* [https://noraj.github.io/OSCP-Exam-Report-Template-Markdown/](https://noraj.github.io/OSCP-Exam-Report-Template-Markdown/)
* [https://github.com/fransr/template-generator](https://github.com/fransr/template-generator)
* [https://github.com/ZephrFish/BugBountyTemplates](https://github.com/ZephrFish/BugBountyTemplates)
* [https://github.com/juliocesarfort/public-pentesting-reports](https://github.com/juliocesarfort/public-pentesting-reports)
* [https://411hall.github.io/assets/files/CTF\_template.ctb](https://411hall.github.io/assets/files/CTF\_template.ctb)
{% endtab %}
{% endtabs %}

## **Training and Resources**

For resources including offensive security courses, books, CTFs and much more, please check out the Training and Resources section of this guide.

## Section Contents

{% content-ref url="testing-methodology/" %}
[testing-methodology](testing-methodology/)
{% endcontent-ref %}

{% content-ref url="offensive-toolbox/" %}
[offensive-toolbox](offensive-toolbox/)
{% endcontent-ref %}

{% content-ref url="red-purple-teaming.md" %}
[red-purple-teaming.md](red-purple-teaming.md)
{% endcontent-ref %}

{% content-ref url="physical-security-testing.md" %}
[physical-security-testing.md](physical-security-testing.md)
{% endcontent-ref %}

{% content-ref url="wireless-hacking.md" %}
[wireless-hacking.md](wireless-hacking.md)
{% endcontent-ref %}

{% content-ref url="social-engineering.md" %}
[social-engineering.md](social-engineering.md)
{% endcontent-ref %}
