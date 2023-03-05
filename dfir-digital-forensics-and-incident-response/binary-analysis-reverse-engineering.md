# Reverse Engineering

Binary analysis and Reverse Engineering is taking our malware/file analysis to the next level. When we have a suspicious executable where we need to know not only is it malicious, but what exactly it does, we attempt to disassemble and/or reverse engineer the file to better understand its functions. There are different types of tools that can be used for this. While you can use a whole slew of coding support tools, most of the below tools have a specific context to reverse engineering and analyzing malware.

## **Radare2**

[Radare2](https://github.com/radare/radare2)  is a considerable open-source reverse engineering framework with a hex editor and debugger at its core, multiple supporting tools to assist in analysis, and even plugins for enhancing your reversing tasks.&#x20;

### Components

* R2agent – Remote managing engine within Radare2
* Rabin2 – Binary information retrieval engine; used to find out basic information about a file
* Radare2 – Full reverse engineering framework
* Radiff2 – Comparing engine within Radare2; used to compare different files
* Rafind2 – The search engine used within Radare2; allows searching for strings and sequences of bytes
* Rahash2 – Hashing engine within radare2; used for computing checksums
* Rarun2 – Specified execution environment engine within Radare2; allows changing of environment variables and other boundary conditions
* Rasm2 – Assembler and disassembler engine within Radare2
* Rax2 – The expression evaluator engine within Radare2; used to make base conversions to execute
* [radare2-cutter](https://www.kali.org/tools/radare2-cutter/) - Cutter is a Qt based GUI for reverse engineering binaries, which makes use of the radare2 framework. Advanced users are expected to use the radare2 CLI tools instead, which are much more powerful.

### Basic Use

* \#radare2 \<filename> - This launches the Radare engine with the specified file
* To check what commands are available to you at any time, simply enter ‘?’
  * This will show you various available tools and each letter corresponds to a tooling engine; for example, to use the rabin2 engine inside Radare2, simply enter ‘i’. Enter ‘i?’ to see further functionality.
* $rabin2 -I \<binary name> -  pull important overview info about the binary
* $rabin2 -z \<binary name> -  List all strings from the data section of the binary
* $rabin2 -zz \<binary name> - List all strings in the binary
* $r2 \<binary> -  launch radare2 to view assembly code

### Resources

* [Introduction - The Official Radare2 Book](https://book.rada.re/)
* [https://r2wiki.readthedocs.io/en/latest/](https://r2wiki.readthedocs.io/en/latest/)
* [https://radare.gitbooks.io/radare2book/content/refcard/intro.html](https://radare.gitbooks.io/radare2book/content/refcard/intro.html)
* [https://www.megabeets.net/a-journey-into-radare-2-part-1/](https://www.megabeets.net/a-journey-into-radare-2-part-1/)
* [https://tryhackme.com/room/ccradare2](https://tryhackme.com/room/ccradare2)
* [https://artik.blue/reversing](https://artik.blue/reversing) - Reverse engineering with radare2 course.

{% embed url="https://www.youtube.com/watch?v=8rLhX_v66O4" %}

## **Other Reverse Engineering Frameworks**

* [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - Ghidra is a software reverse engineering (SRE) framework created and maintained by the [National Security Agency](https://www.nsa.gov) Research Directorate. This framework includes a suite of full-featured, high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, macOS, and Linux.
  * [https://www.intezer.com/blog/intezer-analyze/community-ghidra-plugin-is-here/](https://www.intezer.com/blog/intezer-analyze/community-ghidra-plugin-is-here/)
  * [https://ghidra-sre.org/CheatSheet.html](https://ghidra-sre.org/CheatSheet.html)
  * [https://www.shogunlab.com/blog/2019/12/22/here-be-dragons-ghidra-1.html](https://www.shogunlab.com/blog/2019/12/22/here-be-dragons-ghidra-1.html)
  * [https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra](https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra)
  * [https://tryhackme.com/room/ccghidra](https://tryhackme.com/room/ccghidra)
  * _Operator Handbook: Ghidra - pg. 76_

{% embed url="https://www.youtube.com/watch?v=d4Pgi5XML8E" %}

* [IDA ](https://hex-rays.com/IDA-pro/)- IDA Pro as a disassembler is capable of creating maps of their execution to show the binary instructions that are actually executed by the processor in a symbolic representation (assembly language).
  * [ Awesome Lists Collection: IDA](https://github.com/xrkk/awesome-ida/blob/master/Readme\_en.md)
  * [Gepetto](https://github.com/JusticeRage/Gepetto) - IDA plugin which queries OpenAI's gpt-3.5-turbo language model to speed up reverse-engineering
* [bincat](https://github.com/airbus-seclab/bincat) - Binary code static analyser, with IDA integration. Performs value and taint analysis, type reconstruction, use-after-free and double-free detection
* [Rizin](https://github.com/rizinorg/rizin) - Rizin is a fork of the radare2 reverse engineering framework with a focus on usability, working features and code cleanliness.
* [Frida](https://frida.re/) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. Can be used offesively for injecting code into running processes.
* [BARF](https://github.com/programa-stic/barf-project) - An open source binary analysis framework that aims to support a wide range of binary code analysis tasks that are common in the information security discipline.
* [ODA](https://onlinedisassembler.com) - A lightweight, online service for when you don’t have the time, resources, or requirements to use a heavier-weight alternative. Explore executables by dissecting its sections, strings, symbols, raw hex and machine level instructions.
* [retoolkit](https://github.com/mentebinaria/retoolkit) - Reverse Engineer's Toolkit
* [alexey-kleymenov/reverse\_engineering\_tools](https://github.com/alexey-kleymenov/reverse\_engineering\_tools) - Various code samples and useful tips and tricks from reverse engineering and malware analysis fields.

## **Hex Editors**

* [HexEdit.js](https://hexed.it/) – Browser-based hex editing.
* [Hexinator](https://hexinator.com/) – World’s finest (proprietary, commercial) Hex Editor.
* [Frhed](http://frhed.sourceforge.net/) – Binary file editor for Windows.

## **Binary Analysis and Parsing Tools**

* [capstone](https://www.kali.org/tools/capstone/) - a lightweight multi-platform, multi-architecture disassembly framework.
  * This package contains cstool, a command-line tool to disassemble hexadecimal strings.
* [Kaitai Struct](http://kaitai.io/) – File formats and network protocols dissection language and web IDE, generating parsers in C++, C#, Java, JavaScript, Perl, PHP, Python, Ruby.
* [Veles](https://codisec.com/veles/) – Binary data visualization and analysis tool.
* [Hachoir](https://github.com/vstinner/hachoir) – Python library to view and edit a binary stream as the tree of fields and tools for metadata extraction.

## **Resources**

* Resource and Tool Collections
  * [https://github.com/wtsxDev/reverse-engineering](https://github.com/wtsxDev/reverse-engineering)
  * [https://github.com/mytechnotalent/Reverse-Engineering](https://github.com/mytechnotalent/Reverse-Engineering)
  * [MalwareUnicorn's tool collection](https://malwareunicorn.org/#/resources) - Tools used by one of the best malware analysts in the field.
    * [https://malwareunicorn.org/#/](https://malwareunicorn.org/#/) - Malware Blog, tools, and training
* Reference Material
  * [https://strontic.github.io/xcyclopedia/](https://strontic.github.io/xcyclopedia/) - Encyclopedia that attempts to document all executable binaries (and eventually scripts) that reside on a typical operating system.
  * [https://www.cybrary.it/wp-content/uploads/2017/11/cheat-sheet-reverse-v6.png](https://www.cybrary.it/wp-content/uploads/2017/11/cheat-sheet-reverse-v6.png)
  * [https://digital-forensics.sans.org/media/reverse-engineering-malicious-code-tips.pdf?msc=Cheat+Sheet+Blog](https://digital-forensics.sans.org/media/reverse-engineering-malicious-code-tips.pdf?msc=Cheat+Sheet+Blog)
  * _Attacking Network Protocols: Application Reverse Engineering - pg. 111_
* RE Guides
  * [Reverse Engineering for Beginners](http://beginners.re) - Dennis Yurichev (PDF)
  * [Hacking the Xbox: An Introduction to Reverse Engineering](https://www.nostarch.com/xboxfree/) - Andrew "bunnie" Huang
  * [BIOS Disassembly Ninjutsu Uncovered 1st Edition](http://bioshacking.blogspot.co.uk/2012/02/bios-disassembly-ninjutsu-uncovered-1st.html) - Darmawan Salihun (PDF)
  * [iOS App Reverse Engineering](https://github.com/iosre/iOSAppReverseEngineering) (PDF)
  * [ProgrammingGroundUp.pdf](https://download-mirror.savannah.gnu.org/releases/pgubook/ProgrammingGroundUp-1-0-booksize.pdf)
  * [Reversing-Secrets-Engineering](https://www.amazon.com/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817)
* RE Training Courses
  * [https://guyinatuxedo.github.io/?mc\_cid=d676bd61c6\&mc\_eid=c18a7def31](https://guyinatuxedo.github.io/?mc\_cid=d676bd61c6\&mc\_eid=c18a7def31) - Nightmare
  * [https://malwareunicorn.org/workshops/re101.html#0](https://malwareunicorn.org/workshops/re101.html#0)
  * [https://www.begin.re/](https://www.begin.re/) - Reverse Engineering for Beginners
  * [https://beginners.re/main.html](https://beginners.re/main.html) - Understanding Assembly Language
  * [https://github.com/mytechnotalent/Reverse-Engineering](https://github.com/mytechnotalent/Reverse-Engineering) - A FREE comprehensive reverse engineering tutorial covering x86, x64, 32-bit ARM & 64-bit ARM architectures.
  * [https://fumalwareanalysis.blogspot.com/p/malware-analysis-tutorials-reverse.html](https://fumalwareanalysis.blogspot.com/p/malware-analysis-tutorials-reverse.html)
  * [https://tryhackme.com/room/introtox8664](https://tryhackme.com/room/introtox8664)
  * [https://tryhackme.com/room/basicmalwarere](https://tryhackme.com/room/basicmalwarere)
  * [https://tryhackme.com/room/reverseengineering](https://tryhackme.com/room/reverseengineering)
