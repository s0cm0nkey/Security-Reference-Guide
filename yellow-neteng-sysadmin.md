---
description: Networking, protocol, operating system, Windows, Linux, macOS, Active Directory, sysadmin, and infrastructure references for security practitioners.
---

# Yellow - NetEng/SysAdmin

This page is for the fundamentals behind security work: networking, protocols, operating systems, automation, and systems administration. Keep hands-on offensive tradecraft in Red, detection and hardening in Blue, DFIR workflows in DFIR, and courses or labs in Training.

## Networking

### Core Learning

* [GeeksforGeeks computer network tutorials](https://www.geeksforgeeks.org/computer-network-tutorials/) - Broad networking tutorial collection.
* [The TCP/IP Guide](http://www.tcpipguide.com/free/t_toc.htm) - Free online version of the No Starch Press book.
* [An Introduction to Computer Networks](http://intronetworks.cs.luc.edu) - Free networking textbook.
* [Bits, Signals, and Packets](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-02-introduction-to-eecs-ii-digital-communication-systems-fall-2012/readings/) - MIT OpenCourseWare reading.
* [Computer Networking: Principles, Protocols and Practice](http://cnp3book.info.ucl.ac.be/1st/html/index.html)
* [Computer Networks: A Systems Approach](https://book.systemsapproach.org) - Larry Peterson and Bruce Davie.
* [The System Design Primer](https://github.com/donnemartin/system-design-primer)
* [Awesome Scalability](https://github.com/binhnguyennus/awesome-scalability)
* [Web Architecture 101](https://engineering.videoblocks.com/web-architecture-101-a3224e126947?gi=a896808d22a)

### IP Addressing and Protocols

* [Understanding IP Addressing](http://pages.di.unipi.it/ricci/501302.pdf)
* [IPv6 for IPv4 Experts](https://sites.google.com/site/yartikhiy/home/ipv6book)
* [Introduction to HTTP](https://launchschool.com/books/http)
* [How HTTPS Works](https://howhttps.works)
* [HTTP Succinctly](https://www.syncfusion.com/resources/techportal/ebooks/http)
* [HTTP/2 Explained](http://daniel.haxx.se/http2/)

### Distributed Systems and Infrastructure

* [Distributed Systems for Fun and Profit](http://book.mixu.net/distsys/single-page.html)
* [High-Performance Browser Networking](https://hpbn.co)
* [Kafka: The Definitive Guide](https://assets.confluent.io/m/1b509accf21490f0/original/20170707-EB-Confluent_Kafka_Definitive-Guide_Complete.pdf)
* [Code Connected vol. 1](http://hintjens.wdfiles.com/local--files/main%3Afiles/cc1pe.pdf) - ZeroMQ.

### Automation and Infrastructure as Code

* [Ansible](https://www.ansible.com/) - Configuration management and automation.
* [Terraform](https://www.terraform.io/) - Infrastructure as code.

### Training

Training platforms and labs are maintained in the Training section.

{% content-ref url="training/" %}
[training](training/)
{% endcontent-ref %}

### IP Range Reference

* [Tenable Cloud Scanner IP ranges](https://docs.tenable.com/tenableio/Content/Settings/CloudSensors.htm)
* [Google Cloud IP ranges JSON](https://www.gstatic.com/ipranges/cloud.json)
* [Azure IP ranges and service tags](https://www.microsoft.com/en-us/download/details.aspx?id=56519)

## Operating Systems

### Linux

* [Linux Journey](https://linuxjourney.com/) - Introductory Linux learning path.
* [Linux Basics for Hackers](https://nostarch.com/linuxbasicsforhackers) - Offensive-security-focused Linux book.
* [Cisco NDG Linux Unhatched](https://www.netacad.com/courses/os-it/ndg-linux-unhatched)
* [Roppers Computing Fundamentals](https://www.roppers.org/courses/computing-fundamentals)
* [Kali Linux Revealed](https://kali.training/downloads/Kali-Linux-Revealed-1st-edition.pdf)
* _Operator Handbook: Linux_Defend - pg. 122_
* _Operator Handbook: Linux_Ports - pg. 133_
* _Operator Handbook: Linux_Structure - pg. 143_

Linux CLI and Bash references live in Code and CLI.

{% content-ref url="code-tools/bash/" %}
[bash](code-tools/bash/)
{% endcontent-ref %}

### Windows

* [Windows components](https://learn.microsoft.com/en-us/windows/win32/)
* _Operator Handbook: Windows_Structure - pg. 413_
* _Operator Handbook: Windows_Ports - pg. 365_
* [Windows local file systems](https://learn.microsoft.com/en-us/windows/win32/fileio/file-systems)
* [Windows registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
  * [The Defender's Guide to the Windows Registry](https://posts.specterops.io/the-defenders-guide-to-the-windows-registry-febe241abc75?gi=6e7da1428d77)
  * _Operator Handbook: Windows_Registry - pg. 370_
* [Windows administration tools](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)
* [Active Directory Domain Services overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

Active Directory attack methodology is maintained in Red Offensive.

{% content-ref url="red-offensive/testing-methodology/active-directory.md" %}
[active-directory.md](red-offensive/testing-methodology/active-directory.md)
{% endcontent-ref %}

Windows command-line and PowerShell references live in Code and CLI.

{% content-ref url="code-tools/powershell/" %}
[powershell](code-tools/powershell/)
{% endcontent-ref %}

Windows Event ID references and defensive use cases are maintained in Blue/DFIR.

{% content-ref url="dfir-digital-forensics-and-incident-response/windows-event-logs.md" %}
[windows-event-logs.md](dfir-digital-forensics-and-incident-response/windows-event-logs.md)
{% endcontent-ref %}

### macOS

* [All About macOS](https://edu.gcfglobal.org/en/macosbasics/all-about-macos/1/)
* [New to Mac guide](https://macpaw.com/how-to/new-to-mac)
* [Getting started in macOS security](https://theevilbit.github.io/posts/getting_started_in_macos_security/)
* _Operator Handbook: MacOS_Commands - pg. 154_
* _Operator Handbook: MacOS_Defend - pg. 162_
* _Operator Handbook: MacOS_Ports - pg. 181_
* _Operator Handbook: MacOS_Structure - pg. 186_

macOS DFIR commands are maintained in DFIR.

{% content-ref url="dfir-digital-forensics-and-incident-response/macos-dfir-commands.md" %}
[macos-dfir-commands.md](dfir-digital-forensics-and-incident-response/macos-dfir-commands.md)
{% endcontent-ref %}

## Computer Science and OS Design

* [Computer Science from the Bottom Up](http://www.bottomupcs.com)
* [GeeksforGeeks](https://www.geeksforgeeks.org)
* [A Short Introduction to Operating Systems](http://markburgess.org/os/os.pdf)
* [Think OS](http://www.greenteapress.com/thinkos/index.html)
* [Operating Systems and Middleware](https://gustavus.edu/mcs/max/os-book/)
* [Operating Systems: Three Easy Pieces](http://pages.cs.wisc.edu/~remzi/OSTEP/)
* [How to write a simple operating system in assembly language](http://mikeos.sourceforge.net/write-your-own-os.html)
* [How to Make a Computer Operating System](https://github.com/SamyPesse/How-to-Make-a-Computer-Operating-System)
* [Project Oberon](http://people.inf.ethz.ch/wirth/ProjectOberon/index.html)
* [The Little Book About OS Development](https://littleosbook.github.io)
* [Writing a Simple Operating System from Scratch](http://www.cs.bham.ac.uk/~exr/lectures/opsys/10_11/lectures/os-dev.pdf)
* [Practical File System Design: The Be File System](http://www.nobius.org/~dbg/practical-file-system-design.pdf)
* [The Art of Unix Programming](http://catb.org/esr/writings/taoup/html/)
* [UNIX Application and System Programming lecture notes](http://www.compsci.hunter.cuny.edu/~sweiss/course_materials/unix_lecture_notes.php)
* [xv6, a simple Unix-like teaching operating system](https://pdos.csail.mit.edu/6.828/2012/xv6.html)

## Adjacent Yellow Sections

### Cloud

{% content-ref url="cloud.md" %}
[cloud.md](cloud.md)
{% endcontent-ref %}

### Containers

{% content-ref url="containers.md" %}
[containers.md](containers.md)
{% endcontent-ref %}

### Logging and Security Architecture

{% content-ref url="security-logging/" %}
[security-logging](security-logging/)
{% endcontent-ref %}

### Infrastructure Monitoring

* [Netdata](https://github.com/netdata/netdata) - Real-time infrastructure monitoring and troubleshooting for systems, hardware, containers, applications, cloud deployments, and edge/IoT devices.
  * [Netdata Cloud](https://www.netdata.cloud/)
