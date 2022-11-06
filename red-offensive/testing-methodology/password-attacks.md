---
description: Password1234!
---

# Password Attacks

## **Guides and Resources**

{% tabs %}
{% tab title="General Guides" %}
* [https://alexandreborgesbrazil.files.wordpress.com/2013/08/introduction\_to\_password\_cracking\_part\_1.pdf](https://alexandreborgesbrazil.files.wordpress.com/2013/08/introduction\_to\_password\_cracking\_part\_1.pdf)
* [https://medium.com/bugbountywriteup/pwning-wordpress-passwords-2caf12216956](https://medium.com/bugbountywriteup/pwning-wordpress-passwords-2caf12216956)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/cracking\_hashes/cracking\_hashes/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/cracking\_hashes/cracking\_hashes/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/cracking\_hashes/generate\_password\_list/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/cracking\_hashes/generate\_password\_list/)
* _Operator Handbook: Password Cracking Methodology - pg. 243_
* _Penetration Testing: Password Attacks - pg.197_
{% endtab %}

{% tab title="Default Passwords" %}
* [http://critifence.com/default-password-database/](http://critifence.com/default-password-database/)
* [https://default-password.info/](https://default-password.info/)
* [https://www.routerpasswords.com](https://www.routerpasswords.com)
* [http://www.phenoelit.org/dpl/dpl.html](http://www.phenoelit.org/dpl/dpl.html)
* [https://cirt.net/passwords](https://cirt.net/passwords)
* [https://192-168-1-1ip.mobi/default-router-passwords-list](https://192-168-1-1ip.mobi/default-router-passwords-list)
* [http://www.defaultpassword.com/](http://www.defaultpassword.com/)
{% endtab %}

{% tab title="WordLists" %}
* [Awesome Lists Collection: Wordlists](https://github.com/gmelodie/awesome-wordlists)
* [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - Daniel Miessler's gold standard of wordlists
* [berzerk0/Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists)
* [WeakPass](https://weakpass.com/wordlist) - Open source project containing collected wordlists from across the web
* [https://packetstormsecurity.com/Crackers/wordlists/](https://packetstormsecurity.com/Crackers/wordlists/)
* [https://www.openwall.com/wordlists/](https://www.openwall.com/wordlists/)
* [jeanphorn/wordlist](https://github.com/jeanphorn/wordlist)
* [Jhaddix's wordlist](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) - Bug Bounty master Jason Haddix's master wordlist made from every dns enumeration tool... ever. Please excuse the lewd entries =/
* [https://github.com/kaonashi-passwords/Kaonashi](https://github.com/kaonashi-passwords/Kaonashi) - Wordlist, rules and masks from Kaonashi project (RootedCON 2019)
{% endtab %}

{% tab title="Wordlist Generation Tools" %}
* [CEWL](https://digi.ninja/projects/cewl.php) - CeWL is a ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as [John the Ripper](http://www.openwall.com/john/).
  * [https://www.kali.org/tools/cewl/](https://www.kali.org/tools/cewl/)
* [Crunch](https://tools.kali.org/password-attacks/crunch) - Crunch is a wordlist generator where you can specify a standard character set or a character set you specify. crunch can generate all possible combinations and permutations.
  * [http://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-4-creating-custom-wordlist-with-crunch-0156817/](http://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-4-creating-custom-wordlist-with-crunch-0156817/)
* [BruteScrape](https://github.com/cheetz/brutescrape) - A web scraper for generating password files based on plain text found
* [Mentalist](https://github.com/sc0tfree/mentalist) - Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with [Hashcat](https://hashcat.net/hashcat) and [John the Ripper](http://www.openwall.com/john).

**Wordlist Rules**

* [https://github.com/hashcat/hashcat/tree/master/rules](https://github.com/hashcat/hashcat/tree/master/rules)
* [http://contest-2010.korelogic.com/rules-hashcat.html](http://contest-2010.korelogic.com/rules-hashcat.html)
* [https://github.com/cyberspacekittens/nsa-rules](https://github.com/cyberspacekittens/nsa-rules)
* [https://github.com/cyberspacekittens/Hob0Rules](https://github.com/cyberspacekittens/Hob0Rules)
* [https://github.com/cyberspacekittens/password\_cracking\_rules](https://github.com/cyberspacekittens/password\_cracking\_rules)
{% endtab %}
{% endtabs %}

## Tools

<details>

<summary>Hash Identification</summary>

* [http://www.101hacker.com/2010/12/hashes-and-seeds-know-basics.html](http://www.101hacker.com/2010/12/hashes-and-seeds-know-basics.html)
* [HashID](https://pypi.org/project/hashID/) - Identify the different types of hashes used to encrypt data and especially passwords.
* [haiti](https://github.com/noraj/haiti) - Hash Identification tool.
* [hash-identifier](https://www.kali.org/tools/hash-identifier/)

</details>

<details>

<summary>Password Spraying</summary>

* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) - Scripts to make password spraying attacks against Lync/S4B, OWA & O365 a lot quicker, less painful and more efficient
* [Trident](https://github.com/praetorian-inc/trident) - automated password spraying tool
  * [https://hakin9.org/trident-automated-password-spraying-tool/](https://hakin9.org/trident-automated-password-spraying-tool/)
* [CredKing](https://github.com/ustayready/CredKing) - Spray with AWS Lambda
* [Fireprox](https://github.com/ustayready/fireprox) - Spray with AWS proxies
* [SharpHose](https://github.com/ustayready/SharpHose) - C# spray utility for Cobalt Strike
* [Patator](https://github.com/lanjelot/patator) - flexible brute/spray tool
* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) - PS spray tool
* [Spray](https://github.com/Greenwolf/Spray) - A Password Spraying tool for Active Directory Credentials
* [Ruler](https://github.com/sensepost/ruler) - Remote exchange server spray and utility
* [kerbrute](https://github.com/ropnop/kerbrute) - A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication
* [brutespray](https://www.kali.org/tools/brutespray/) - This Python script takes nmap GNMAP/XML output and automatically brute-forces services with default credentials using Medusa.
* [o365spray](https://github.com/0xZDH/o365spray) - o365spray ia a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365).
* [ShadowSpray](https://github.com/Dec0ne/ShadowSpray) - A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.

Reference

* [Password Spraying Windows Active Directory Accounts - Tradecraft Security Weekly #5](https://www.youtube.com/watch?v=xB26QhnL64c)
* [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
* [Attacking Exchange with MailSniper](https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/)

</details>

<details>

<summary>Password Guessing Tools</summary>

* [Prince](https://github.com/hashcat/princeprocessor) - Standalone password candidate generator using the PRINCE algorithm
  * [https://reusablesec.blogspot.com/2014/12/tool-deep-dive-prince.html](https://reusablesec.blogspot.com/2014/12/tool-deep-dive-prince.html)

<!---->

* [Talon](https://github.com/optiv/Talon/) - A password guessing tool that targets the Kerberos and LDAP services within the Windows Active Directory environment.

<!---->

* [https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/melicher](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/melicher)
* [PassGAN](https://github.com/brannondorsey/PassGAN) - A Deep Learning Approach for Password Guessing

</details>

### Password Cracking

{% tabs %}
{% tab title="Online Cracking" %}
* [https://crackstation.net/](https://crackstation.net/)
* [https://www.cmd5.org/](https://www.cmd5.org/)
* [https://hashkiller.io/listmanager](https://hashkiller.io/listmanager)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
* [https://gpuhash.me/](https://gpuhash.me/)
* [https://crack.sh/](https://crack.sh/)
* [https://passwordrecovery.io/](https://passwordrecovery.io/)
* [http://cracker.offensive-security.com/](http://cracker.offensive-security.com/)
{% endtab %}

{% tab title="Offline Cracking" %}
* [HateCrack](https://github.com/trustedsec/hate\_crack) - A tool for automating cracking methodologies through Hashcat from the TrustedSec team.
* [Password Analysis and Cracking Kit ](https://github.com/iphelix/PACK)- Collection of utilities for analyzing passwords for cracking and guessing
* MDXFind - the CPU-based hash-cracking tool
  * [Tech Solvency - MDXfind mirror](https://www.techsolvency.com/pub/bin/mdxfind/)&#x20;
  * [MDXfind Bible | Infosec and Password Cracking Blog](https://0xln.pw/MDXfindbible)
  * _Operator Handbook: MDXFind - pg. 195_
* [Ciphey](https://github.com/Ciphey/Ciphey) - Fully automated decryption/decoding/cracking tool using natural language processing & artificial intelligence, along with some common sense.
* [cmospwd](https://www.kali.org/tools/cmospwd/) - a cross-platform tool to decrypt password stored in CMOS used to access a computer’s BIOS setup.
* [crack](https://www.kali.org/tools/crack/) - Crack is program designed to quickly locate vulnerabilities in Unix (or other) password files by scanning the contents of a password file, looking for users who have misguidedly chosen a weak login password.
* [rainbowcrack](https://www.kali.org/tools/rainbowcrack/)  - RainbowCrack is a general propose implementation of Philippe Oechslin’s faster time-memory trade-off technique. It crack hashes with rainbow tables.
* [hashview](https://github.com/hashview/hashview) - A web front-end for password cracking and analytics
  * [https://www.hashview.io/](https://www.hashview.io/)
{% endtab %}

{% tab title="Hashcat" %}
### [HashCat](https://github.com/hashcat/hashcat)&#x20;

World's fastest and most advanced password recovery utility

* HashCat Utilities - [https://github.com/hashcat/hashcat-utils](https://github.com/hashcat/hashcat-utils)
  * [https://www.kali.org/tools/hashcat-utils/](https://www.kali.org/tools/hashcat-utils/)
* HashCat Wiki - [https://hashcat.net/wiki/](https://hashcat.net/wiki/)
* [HAT- Hashcat Automation Tool](password-attacks.md#password-attack-tools) - An Automated Hashcat Tool for common wordlists and rules to speed up the process of cracking hashes during engagements.
* [crackerjack](https://www.contextis.com/en/resources/tools/crackerjack) - Web GUI for HashCat
* [hcxtools](https://www.kali.org/tools/hcxtools/) - Portable solution for capturing wlan traffic and conversion to hashcat formats (recommended by hashcat) and to John the Ripper formats.
* [https://www.blackhillsinfosec.com/hashcat-4-10-cheat-sheet-v-1-2018-1/](https://www.blackhillsinfosec.com/hashcat-4-10-cheat-sheet-v-1-2018-1/)
* [https://github.com/hashcat/hashcat/tree/master/rules](https://github.com/hashcat/hashcat/tree/master/rules)
* [http://contest-2010.korelogic.com/rules-hashcat.html](http://contest-2010.korelogic.com/rules-hashcat.html)
* _Operator Handbook: Hashcat - pg. 90_

GPU cracking:

```
$ hashcat -m 500 -a 0 -o output.txt -remove hashes.txt /usr/share/wordlists/rockyou.txt
```
{% endtab %}

{% tab title="JohnTheRipper" %}
### JohnTheRipper

[John The Ripper](https://www.offensive-security.com/metasploit-unleashed/john-ripper/) - The John The Ripper module is used to identify weak passwords that have been acquired as hashed files (loot) or raw LANMAN/NTLM hashes (hashdump). The goal of this module is to find trivial passwords in a short amount of time. To crack complex passwords or use large wordlists, John the Ripper should be used outside of Metasploit.

* [https://github.com/openwall/john](https://github.com/openwall/john)
* [https://tryhackme.com/room/johntheripper0](https://tryhackme.com/room/johntheripper0)
* Jumbo John - John the Ripper distro with added features
* [https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip)
* Operator Handbook: John the Ripper - pg. 104

**Useage**

* Basic usage with auto guessing of hash type
  * \#john --wordlist=/usr/share/wordlists/rockyou.txt hash\_to\_crack.txt
* ID Hash type
  * `#wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py`
  * &#x20;\#`python3 hash-identifier.py`
* Specific format hash crack
  * \#john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash\_to\_crack.txt
  * Crack NTLM Hashes
    * \--format=NT
* Cracking /etc/shadow hashes
  * The unshadow tool can crack an encrypted copy of the /etc/shadow file with a copy of the /etc/passwd file
  * &#x20;\# unshadow local\_passwd local\_shadow > unshadowed.txt
  * &#x20;\# john --format=sha512crypt unshadowed.txt
* Single Crack Mode
  * Used for Word mangling using the username
  * &#x20;\# john --single --format=raw-sha256 hashes.txt
* Cracking a Zip File
  * Use zip2john tool to convert the zip file into a hash format that john can use.
  * \#zip2john \[opt] \[zip file] > \[out file]
  * \#john --wordlist=/word/list.txt out\_file.txt
* Cracking a RAR archive
  * rar2john will convert hte rar file into a hash that john can crack
  * \#rar2john \[rarfile] > \[out file]
  * \#john --wordlist=/word/list.txt out\_file.txt
  * \#unrar -p password out\_file.txt
{% endtab %}
{% endtabs %}

### Password Brute Forcing

<details>

<summary>Password Brute Forcing</summary>

* [Cerbrutus-BruteForcer](https://github.com/Cerbrutus-BruteForcer/cerbrutus) - The fastest brute-forceing and spraying tool available. Currently supports SSH and FTP with other protocols in development.
* [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Super powerful, multi-protocol password brute forceing tool
* [Medusa](http://h.foofus.net/?page\_id=51) -  Medusa is a speedy, parallel, and modular, login brute-forcer. The goal is to support as many services which allow remote authentication as possible.
* [Crowbar](https://github.com/galkan/crowbar) - Crowbar **** _(formally known as Levye)_ is a brute forcing tool that can be used during penetration tests. It was developed to brute force some protocols in a different manner according to other popular brute forcing tools.
  * [https://www.kali.org/tools/crowbar/](https://www.kali.org/tools/crowbar/)
* [WBruter](https://github.com/wuseman/WBRUTER) - wbruter is is the first tool which has been released as open source wich can guarantee 100% that your pin code will be cracked as long as usb debugging has been enable. wbruter also includes some other brute methods like dictionary attacks for gmail, ftp, rar, zip and some other file extensions.

</details>

### **RSA Tools**

<details>

<summary>RSA Tools</summary>

* [RSA Calculator](https://www.cs.drexel.edu/\~jpopyack/IntroCS/HW/RSAWorksheet.html)
* [RSACTFTool](https://github.com/Ganapati/RsaCtfTool) - RSA multi attacks tool : uncipher data from weak public key and try to recover private key Automatic selection of best attack for the given public key
* [RSATool](https://github.com/ius/rsatool) - rsatool calculates RSA (p, q, n, d, e) and RSA-CRT (dP, dQ, qInv) parameters given either two primes (p, q) or modulus and private exponent (n, d). Resulting parameters are displayed and can optionally be written as an OpenSSL compatible DER or PEM encoded RSA private key.
* RSA Theory - [https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/)

</details>

### **Rainbow Table Attacks**

* [Rainbow Crack](http://project-rainbowcrack.com/table.htm) - RainbowCrack is a general propose implementation of Philippe Oechslin's faster [time-memory trade-off](https://en.wikipedia.org/wiki/Space-time\_tradeoff) technique. It crack hashes with [rainbow tables](https://en.wikipedia.org/wiki/Rainbow\_table).
* [dcipher](https://github.com/k4m4/dcipher) - Decipher hashes using online rainbow & lookup table attack services.
