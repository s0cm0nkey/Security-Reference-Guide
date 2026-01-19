---
description: Virustotal's file scanning engine and ruleset
---

# YARA

### What is YARA?

YARA is a tool aimed at (but not limited to) helping malware researchers identify and classify malware samples. It has been described as "grep for malware." YARA allows you to create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns.

A rule is the fundamental unit of YARA. Each rule resembles a struct in C and starts with the keyword `rule` followed by an identifier.

**Structure of a Rule:**
1.  **Meta (Optional)**: Provides details about the rule (author, description, date, etc.) but does not affect the matching logic.
2.  **Strings (Optional)**: Defines the patterns (text, hex, or regex) to look for in the file.
3.  **Condition (Required)**: A Boolean expression that determines if the rule matches based on the found strings.

```yara
rule Example_Malware_Rule {
    meta:
        description = "Detects example malicious pattern"
        author = "Analyst Name"
        date = "2023-01-01"

    strings:
        $hex_string = { E2 34 A1 ?? C8 }
        $text_string = "suspicious_function" nocase
        $regex_string = /md5: [0-9a-fA-F]{32}/

    condition:
        $hex_string and ($text_string or $regex_string)
}
```

### Rule Components

**Strings Section**
*   **Hexadecimal strings**: Defined in curly braces `{}`. They support wildcards (`?`), jumps (`[n-m]`), and alternatives (`( aa | bb )`).
*   **Text strings**: Defined in double quotes `""`. Modifiers include:
    *   `nocase`: Case-insensitive matching.
    *   `fullword`: Matches only if the string is delimited by non-alphanumeric characters.
    *   `wide`: Searches for the string encoded in 2 bytes per character (standard in Windows Unicode).
    *   `ascii`: Searches for the string encoded in 1 byte per character (default).
*   **Regular expressions**: Defined in forward slashes `/.../`.

**Condition Section**
This section contains the logic. It uses Boolean operators (`and`, `or`, `not`), relational operators (`>`, `<`, `==`), and arithmetic operators. It can also check for file size (`filesize`), entry point (`entrypoint`), and string counts (`#string_id`).

**Metadata Section**
Metadata identifiers are followed by an equal sign and a value (string, integer, or boolean). These are strictly for descriptive purposes.

### Data to Target
When writing rules, look for unique artifacts that are unlikely to change or distinct enough to avoid false positives:
*   Meaningful **domain names** or **IP addresses** (C2 infrastructure).
*   **CreateMutex** or **CreateFile** names unique to the malware family.
*   **PDB paths** (debug information) left in the binary.
*   Unusual **User-Agent** strings.
*   Specific **registry keys** created or queried.
*   **Typos** in error messages or strings.
*   **Cryptographic constants** or custom alphabets.

### YARA Rule Generators & Tools

**Active Tools**
*   [yarGen](https://github.com/Neo23x0/yarGen) - A generator for YARA rules. The most popular tool for automatic rule generation.
*   [halogen](https://github.com/target/halogen) - A tool for automating YARA rule generation for image files (specifically embedded JPGs).
*   [Loki](https://github.com/Neo23x0/Loki) - A free and simple IOC scanner (using YARA) to scan your endpoints.
*   [YARAify](https://yaraify.abuse.ch/) - A platform by abuse.ch to scan files against a massive public repository of YARA rules.
*   [YaraHunter](https://github.com/deepfence/YaraHunter) - Scans container images and filesystems for malware indicators.

**Testing Tools**
*   [arya](https://github.com/claroty/arya) - Generates pseudo-malicious files to trigger specific YARA rules (Reverse YARA).
*   [CyberChef](https://gchq.github.io/CyberChef/) - Useful for testing regex logic or extracting strings before writing rules.

### Legacy / Deprecated Tools
*These tools may no longer be actively maintained but are historically significant.*
*   [YaraGenerator](https://github.com/Xen0ph0n/YaraGenerator) - An older automatic rule generator.
*   [yarasilly2](https://github.com/YARA-Silly-Silly/yarasilly2) - An older rule generator.

### Resources

*   [Awesome YARA](https://github.com/InQuest/awesome-yara) - A curated list of YARA resources.
*   [YARA Official Documentation](https://yara.readthedocs.io/en/latest/)
    *   [Writing Rules Guide](https://yara.readthedocs.io/en/latest/writingrules.html)
*   [Yaya](https://github.com/EFForg/yaya) - Yet Another Yara Automaton (EFF).
*   [Valhalla](https://www.nextron-systems.com/valhalla/) - A massive database of curated YARA rules by Nextron Systems.

**Tutorials & Guides**
*   [YARA - A Simple and Effective Way of Dissecting Malware](https://resources.infosecinstitute.com/yara-simple-effective-way-dissecting-malware/)
*   [How to Write Simple but Sound YARA Rules (Part 1)](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)
*   [How to Write Simple but Sound YARA Rules (Part 2)](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
*   [How to Write Simple but Sound YARA Rules (Part 3)](https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)
*   [Minimize False Positives in YARA](https://www.intezer.com/blog/threat-hunting/yara-rules-minimize-false-positives/)

**Rule Collections**
*   [Elastic Protection Artifacts](https://github.com/elastic/protections-artifacts)
*   [Deepfence YARA Rules](https://github.com/deepfence/yara-rules)
*   [DaysOfYARA](https://github.com/shellcromancer/DaysOfYARA-2023)

_Operator Handbook: YARA - pg. 428_

![](<../.gitbook/assets/image (16).png>)

