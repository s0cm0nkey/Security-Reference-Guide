---
description: Offensive Security and Penetration Testing
---

# Red - Offensive Operations

## **Intro**

Offensive security is a huge field with many specialties: reconnaissance, exploitation, web testing, Active Directory, cloud, wireless, physical security, social engineering, red teaming, and reporting. It can be daunting at first because there are so many tools, technologies, processes, and procedures to learn.

Start with methodology, not tool collecting. A good offensive operator understands the rules of engagement, documents clearly, tests safely, and can explain why a technique worked or failed. Try tools in a lab before using them on an engagement; even failed tests teach you something useful.

{% hint style="danger" %}
Only use the tools and techniques in this section in environments where you have explicit authorization.
{% endhint %}

## Resources: Offensive Security/ Penetration Testing&#x20;

When working on an offensive security team, the rules change from engagement to engagement. A vulnerability assessment is usually focused on confirming whether specific vulnerabilities exist. A penetration test is broader and may be white box, gray box, or black box depending on how much information and visibility the tester is given.

When performing a structured penetration test, methodology and documentation are what let you explain your success and justify your findings. The resources below can help you build a process, toolkit, and reporting style.

<details>

<summary>Official Penetration Testing Guides</summary>

* Pen Test Standard Guide - [http://www.pentest-standard.org/index.php/PTES\_Technical\_Guidelines](http://www.pentest-standard.org/index.php/PTES\_Technical\_Guidelines)
* Vulnerability Assessment Guide - [http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html)
* OSSTMM3 - [https://www.isecom.org/OSSTMM.3.pdf](https://www.isecom.org/OSSTMM.3.pdf)
* [NIST SP:800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) - Technical Guide to Information Security Testing and Assessment

</details>

<details>

<summary>Researcher Developed Guides and Resources</summary>

* [HackTricks](https://book.hacktricks.xyz)
* [The Hacker Recipes](https://www.thehacker.recipes/)
* [iRed.team](https://www.ired.team/)
* [Guif.re](https://guif.re/)
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

Notekeeping is essential for recreating exploits, storing findings, keeping screenshots, recording commands, and writing a report someone else can trust. Without good notes, even a successful test becomes hard to defend.

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
