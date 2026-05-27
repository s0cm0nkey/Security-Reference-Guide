---
description: Code, command-line, Bash, PowerShell, regex, scripting, and data-transformation resources for security analysts and practitioners.
---

# Yellow - Code and CLI

You do not need to be a full-time developer to be good at security, but you do need enough code and command-line literacy to recognize what scripts, commands, logs, and snippets are doing. This section is for that foundation: CLI skills, scripting references, regex, code-learning resources, and small utilities that help analysts understand or transform data.

Deep security tool categories live in their own sections. Code scanning and dependency risk belong in vulnerability management, reverse engineering belongs in DFIR, shellcode and exploit development belong in Red Offensive, and log parsing belongs in Security Logging.

## Secure Coding

* [DevSecOps Playbook](https://github.com/6mile/DevSecOps-Playbook)
* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/) - Quick reference guide for secure coding practices.
* [CWE - Common Weakness Enumeration](https://cwe.mitre.org/) - Community-developed list of software and hardware weakness types.
* [SANS Secure Coding Resources](https://www.sans.org/secure-coding/) - Secure coding training and resources.

## Command Shells

{% embed url="https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltea7de5267932e94b/5eb08aafcf88d36e47cf0644/Cheatsheet_SEC301-401_R7.pdf" %}

### Bash

{% content-ref url="bash/" %}
[bash](bash/)
{% endcontent-ref %}

### PowerShell

{% content-ref url="powershell/" %}
[powershell](powershell/)
{% endcontent-ref %}

### Windows CLI

* _Operator Handbook: Windows_Commands - pg. 328_

## CLI Assistance Tools

* [commandlinefu](https://www.commandlinefu.com/) - Repository of useful command-line snippets.
* [explainshell](https://explainshell.com/) - Explains command-line arguments from man page text.
* [cheat.sh](https://github.com/chubin/cheat.sh) - Community-driven command-line cheatsheet tool.
* [tldr](https://tldr.sh/) - Simplified, example-focused man pages.
* [thefuck](https://github.com/nvbn/thefuck) - Corrects errors in previous console commands.

## Code Reference Tools

* [Stack Overflow](https://stackoverflow.com/) - Programming Q&A community.
* [ASCII Table](https://theasciicode.com.ar/) - ASCII characters, codes, symbols, and signs.
* [Devhints](https://devhints.io/) - Coding cheatsheets and guides.
* [PublicWWW](https://publicwww.com/) - Source code search engine for public websites.
* [Microsoft Learn Code Samples](https://learn.microsoft.com/en-us/samples/browse/) - Microsoft documentation samples.
* [Ryan's Tutorials](https://ryanstutorials.net/) - Introductory tutorials for Linux command line, Bash, HTML/CSS, number systems, and regex.
* [Markdown Guide](https://www.markdownguide.org/) - Markdown reference guide.
* [GitHub Docs](https://docs.github.com/) - GitHub, Git, and version control documentation.
* [Can I Use](https://caniuse.com/) - Browser compatibility tables for web technologies.
* [Replit](https://replit.com/) - Collaborative in-browser IDE.

{% content-ref url="learn-to-code.md" %}
[learn-to-code.md](learn-to-code.md)
{% endcontent-ref %}

## Code Libraries and Collections

Awesome lists are allowed to repeat locally because they are useful entry points into a topic.

* [Awesome Python](https://github.com/vinta/awesome-python)
* [Python-Pentest-Tools](https://github.com/dloss/python-pentest-tools)
* [Awesome PHP](https://github.com/ziadoz/awesome-php/)
* [Awesome JavaScript](https://github.com/sorrycc/awesome-javascript#readme)
* [Awesome Swift](https://github.com/matteocrippa/awesome-swift#readme)
* [Awesome Go](https://github.com/avelino/awesome-go#readme)
* [Awesome C](https://github.com/inputsh/awesome-c#readme)
* [Awesome C++](https://github.com/fffaraz/awesome-cpp#readme)
* [Awesome Perl](https://github.com/hachiojipm/awesome-perl#readme)
* [Awesome Rust](https://github.com/rust-unofficial/awesome-rust#readme)
* [Awesome Java](https://github.com/akullpp/awesome-java#readme)
* [Awesome HTML5](https://github.com/diegocard/awesome-html5#readme)
* [Awesome CSS](https://github.com/awesome-css-group/awesome-css#readme)
* [Awesome DevSecOps](https://github.com/devsecops/awesome-devsecops)

## Regex

{% content-ref url="regex.md" %}
[regex.md](regex.md)
{% endcontent-ref %}

## Data Transformation Utilities

Use these tools for encoding, decoding, formatting, and quick data transformation. CyberChef also appears in event analysis and DFIR contexts because it is useful in many workflows.

* [CyberChef](https://gchq.github.io/CyberChef/) - Encoding, decoding, compression, encryption, and data transformation workbench.
  * [CyberChef recipes](https://github.com/mattnotmax/cyberchef-recipes)
  * [Michael Der's CyberChef gists](https://gist.github.com/michaelder) - Includes Cobalt Strike decoding recipes.
* [Hackvertor](https://hackvertor.co.uk/public) - Multi-function conversion tool.
* [String Manipulation](https://manytools.org/http-html-text/string-manipulation/) - Text manipulation utilities.
* [encoding.tools](https://encoding.tools/) - HTML decoding and hash conversion utilities.
* [dCode](https://www.dcode.fr/tools-list) - Large toolkit for encoders, ciphers, puzzles, and data conversion.
* [quipqiup](https://quipqiup.com/) - Cryptogram solver.
* [RapidTables Hex to ASCII](https://www.rapidtables.com/convert/number/hex-to-ascii.html) - Hex/text conversion.
* [DDecode](http://ddecode.com/hexdecoder/) - Hex, octal, and HTML decoder.
* [AES Encryption](https://aesencryption.net/) - AES encryption/decryption utility.
* [Google Encode/Decode](https://toolbox.googleapps.com/apps/encode_decode/) - Google encoding and decoding utility.
* [Base64 Decode and Encode](https://www.base64decode.org/) - Base64 encoder and decoder.
* [JWT.io](https://jwt.io/) - JSON Web Token decoder, verifier, and generator.
* [Online JavaScript Beautifier](https://beautifier.io/) - Beautify and unpack JavaScript, HTML, JSON, and JSONP.
* [UnPacker](http://matthewfl.com/unPacker.html) - JavaScript unpacking and formatting.
* [Advanced obfuscated JavaScript analysis](https://isc.sans.edu/diary/Advanced+obfuscated+JavaScript+analysis/4246) - SANS ISC diary entry.
* [JavaScript Obfuscation](https://secniche.blogspot.com/2012/04/javascript-obfuscation-manual-armor-1.html) - Malware-focused JavaScript obfuscation notes.
* [JS NICE](http://www.jsnice.org/) - JavaScript renaming, type inference, and deobfuscation.

## Command-Line Data Tools

* [jq](https://jqlang.github.io/jq/) - Lightweight command-line JSON processor.
* [yq](https://github.com/mikefarah/yq) - Command-line YAML, JSON, and XML processor.
* [ShellCheck](https://www.shellcheck.net/) - Static analysis tool for shell scripts.

## Related Sections

* Code, dependency, container, and secret scanning tools live in Asset and Vulnerability Management.

{% content-ref url="../blue-defense/vulnerability-management.md" %}
[vulnerability-management.md](../blue-defense/vulnerability-management.md)
{% endcontent-ref %}

* Grok parsing and log pipeline tooling live in Security Logging.

{% content-ref url="../security-logging/" %}
[security-logging](../security-logging/)
{% endcontent-ref %}

* Hex editors, deobfuscators, Ghidra, radare2, and binary analysis tools live in DFIR.

{% content-ref url="../dfir-digital-forensics-and-incident-response/binary-analysis-reverse-engineering.md" %}
[binary-analysis-reverse-engineering.md](../dfir-digital-forensics-and-incident-response/binary-analysis-reverse-engineering.md)
{% endcontent-ref %}

* Shellcode and exploit-development references live in Red Offensive.

{% content-ref url="../red-offensive/testing-methodology/exploit-research.md" %}
[exploit-research.md](../red-offensive/testing-methodology/exploit-research.md)
{% endcontent-ref %}

* Password cracking and hash recovery tools live in Password Attacks.

{% content-ref url="../red-offensive/testing-methodology/password-attacks.md" %}
[password-attacks.md](../red-offensive/testing-methodology/password-attacks.md)
{% endcontent-ref %}

## Legacy / Deprecated Tools

* [FindBugs](http://findbugs.sourceforge.net/) - Legacy Java static analysis tool replaced by SpotBugs.
* [Frhed](http://frhed.sourceforge.net/en/) - Older Windows hex editor. Consider ImHex or HexEd.it in DFIR workflows.
* [NRE Labs](https://labs.networkreliability.engineering/) - Network automation learning platform that has been discontinued.
* [Pythonidae](https://github.com/svaksha/pythonidae) - Archived Python resource collection.

## Honorable Mention

* [Ciphey](https://github.com/ciphey/ciphey) - Automated decryption, decoding, and cracking tool using natural language processing and heuristics.
* [bytecode-viewer](https://www.kali.org/tools/bytecode-viewer/) - Java bytecode viewer, Java decompiler, and bytecode editor.
