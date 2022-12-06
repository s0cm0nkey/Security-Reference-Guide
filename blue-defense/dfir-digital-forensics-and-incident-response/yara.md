---
description: Virustotal's file scanning engine and ruleset
---

# YARA

### What is Yara?

YARA and its rules are a way of identifying malware (or other files) by creating rules that look for certain characteristics. It was developed with the idea to describe patterns that identify particular strains or entire families of malware.  Each rule has to start with the word rule, followed by the name or identifier. The identifier can contain any alphanumeric character and the underscore character, but the first character is not allowed to be a digit.\
\
Rules are composed of several sections.The condition section is the only one that is required. This section specifies when the rule result is true for the object (file) that is under investigation. It contains a Boolean expression that determines the result. Conditions are by design Boolean expressions and can contain all the usual logical and relational operators. You can also include another rule as part of your conditions. To give the condition section a meaning you will also need a strings section. The strings sections is where you can define the strings that will be looked for in the file.

There are several types of strings you can look for:\
&#x20;\- Hexadecimal, in combination with wild-cards, jumps, and alternatives.\
&#x20;\- Text strings, with modifiers: nocase, fullword, wide, and ascii.\
&#x20;\- Regular expressions, with the same modifiers as text strings.

Metadata can be added to help identify the files that were picked up by a certain rule. The metadata identifiers are always followed by an equal sign and the set value. The assigned values can be strings, integers, or a Boolean value. Note that identifier/value pairs defined in the metadata section can’t be used in the condition section, their only purpose is to store additional information about the rule.\
\
Data to look for:\
• meaningful domain names or IP addresses that the malware may connect out to\
• filenames that the malicious file references\
• any unusual API calls that the files reference\
• various version numbers inside the malware\
• any registry value that the malware references.

### Yara Rule Generators

* [halogen](https://github.com/target/halogen)
* [yarGen](https://github.com/Neo23x0/yarGen)&#x20;
* [YaraGenerator](https://github.com/Xen0ph0n/YaraGenerator)&#x20;
* [yarasilly2](https://github.com/YARA-Silly-Silly/yarasilly2)

Yara Rule Testing Tools

* [arya](https://github.com/claroty/arya) - Arya is a unique tool that produces pseudo-malicious files meant to trigger YARA rules. You can think of it like a reverse YARA.

### Resources

* [https://github.com/InQuest/awesome-yara](https://github.com/InQuest/awesome-yara)
* [https://yara.readthedocs.io/en/latest/](https://yara.readthedocs.io/en/latest/)
* [http://yara.readthedocs.io/en/v3.6.3/writingrules.html#id2](http://yara.readthedocs.io/en/v3.6.3/writingrules.html#id2)
* [https://github.com/EFForg/yaya](https://github.com/EFForg/yaya) - Automatically curate open source yara rules and run scans
* [https://yaraify.abuse.ch/](https://yaraify.abuse.ch/) - YARAify is a project from abuse.ch that allows anyone to scan suspicious files such as malware samples or process dumps against a large repository of YARA rules. With YARAhub, the platform also provides a structured way for sharing YARA rules with the community.
* [YaraHunter](https://github.com/deepfence/YaraHunter) - Deepfence YaraHunter scans container images, running Docker containers, and filesystems to find indicators of malware. It uses a [YARA ruleset](https://github.com/deepfence/yara-rules) to identify resources that match known malware signatures, and may indicate that the container or filesystem has been compromised.
* Writing Yara Rules
  * [https://resources.infosecinstitute.com/yara-simple-effective-way-dissecting-malware/](https://resources.infosecinstitute.com/yara-simple-effective-way-dissecting-malware/)
  * [https://securityintelligence.com/signature-based-detection-with-yara/](https://securityintelligence.com/signature-based-detection-with-yara/)
  * [https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)
  * [https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
  * [https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/](https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)
  * [https://www.intezer.com/blog/threat-hunting/yara-rules-minimize-false-positives/](https://www.intezer.com/blog/threat-hunting/yara-rules-minimize-false-positives/)
* Yara Training
  * [https://tryhackme.com/room/yara](https://tryhackme.com/room/yara)
* Yara rule collections
  * [https://github.com/elastic/protections-artifacts](https://github.com/elastic/protections-artifacts)
  * [https://yaraify.abuse.ch/yarahub/yaraify-rules.zip](https://yaraify.abuse.ch/yarahub/yaraify-rules.zip)
  * [https://www.nextron-systems.com/valhalla/](https://www.nextron-systems.com/valhalla/) - Huge YARA rule Repo
  * [https://github.com/deepfence/yara-rules](https://github.com/deepfence/yara-rules)
* _Operator Handbook: YARA - pg. 428_

![](<../../.gitbook/assets/image (16).png>)

