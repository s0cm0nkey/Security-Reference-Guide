# Special Targets

## IPV6 and ICMPV6

* [thc-ipv6](https://www.kali.org/tools/thc-ipv6/) - Attack toolkit for testing IPv6 and ICMPv6 protocol weaknesses.
  * www.thc.org/thc-ipv6/

## Cisco Products

### [Cisco OCS Scanner](https://www.kali.org/tools/cisco-ocs/)

A mass Cisco scanning tool.

```
# cisco-ocs [Start IP] [Stop IP]
```

### [Cisco Auditing Tool (CAT)](https://www.kali.org/tools/cisco-auditing-tool/)

Perl script which scans cisco routers for common vulnerabilities.

```
# CAT -h 192.168.99.230 -p 23 -a /usr/share/wordlists/nmap.lst
```

### [cisco-global-exploiter](https://www.kali.org/tools/cisco-global-exploiter/)

Cisco Global Exploiter (CGE), is an advanced, simple and fast security testing tool.

```
# Show all available Attacks
# cge.pl -h
# Attack
# cge.pl [Target IP] [Attack ID]
```

### [cisco-torch](https://www.kali.org/tools/cisco-torch/)

Cisco device vulnerability scanner

```
# cisco-torch -A [Target IP]
```

### Cisco [copy-router-config](https://www.kali.org/tools/copy-router-config/)

Copies configuration files from Cisco devices running SNMP.

```
# copy-router-config.pl [Router IP] [TFTP Server IP] [Community String]
```

## VoIP (SIP)

* [SeeYouCM-Thief](https://github.com/trustedsec/SeeYouCM-Thief) - Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials. Will also optionally enumerate active directory users from the UDS API.
  * [https://www.trustedsec.com/blog/seeyoucm-thief-exploiting-common-misconfigurations-in-cisco-phone-systems/](https://www.trustedsec.com/blog/seeyoucm-thief-exploiting-common-misconfigurations-in-cisco-phone-systems/)
* [sipvicious](https://github.com/EnableSecurity/sipvicious) - SIPVicious OSS is a set of security tools that can be used to audit SIP based VoIP systems. Specifically, it allows you to find SIP servers, enumerate SIP extensions and finally, crack their password.
  * [https://www.kali.org/tools/sipvicious/](https://www.kali.org/tools/sipvicious/)
* [protos-sip](https://www.kali.org/tools/protos-sip/) - The purpose of this test-suite is to evaluate implementation level security and robustness of Session Initiation Protocol (SIP) implementations.
* [iaxflood](https://www.kali.org/tools/iaxflood/) -  Voip flooding tool
* [ohrwurm](https://www.kali.org/tools/ohrwurm/) - ohrwurm is a small and simple RTP fuzzer that has been successfully tested on a small number of SIP phones.
* [siparmyknife](https://www.kali.org/tools/siparmyknife/) - SIP Army Knife is a fuzzer that searches for cross site scripting, SQL injection, log injection, format strings, buffer overflows, and more.
* [sipp](https://www.kali.org/tools/sipp/) - SIPp is a free Open Source test tool / traffic generator for the SIP protocol.
* [sipsak](https://www.kali.org/tools/sipsak/) - sipsak is a small command line tool for developers and administrators of Session Initiation Protocol (SIP) applications. It can be used for some simple tests on SIP applications and devices.
* [https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Endler.pdf](https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Endler.pdf)
* [https://downloads.avaya.com/elmodocs2/mm\_r2\_0/cd\_frontend/a\_mss\_mas/se\_pbxsec.htm](https://downloads.avaya.com/elmodocs2/mm\_r2\_0/cd\_frontend/a\_mss\_mas/se\_pbxsec.htm)
* [**Penetration Testing on VoIP Asterisk Server**](https://www.hackingarticles.in/penetration-testing-on-voip-asterisk-server/)
  * [**Penetration Testing on VoIP Asterisk Server (Part 2)**](https://www.hackingarticles.in/penetration-testing-on-voip-asterisk-server-part-2/)

## Lync Server

* [lyncsmash](https://github.com/nyxgeek/lyncsmash) - A collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
* [LyncSniper](https://github.com/mdsecresearch/LyncSniper) - LyncSniper is a tool for penetration testing Lync and Skype for Business deployments hosted either on premise or in Office 365.
* [https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/](https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/)

## Thick Clients

* [https://www.netspi.com/blog/technical/thick-application-penetration-testing/introduction-to-hacking-thick-clients-part-1-the-gui/](https://www.netspi.com/blog/technical/thick-application-penetration-testing/introduction-to-hacking-thick-clients-part-1-the-gui/)
* [https://resources.infosecinstitute.com/topic/practical-thick-client-application-penetration-testing-using-damn-vulnerable-thick-client-app-part-1/](https://resources.infosecinstitute.com/topic/practical-thick-client-application-penetration-testing-using-damn-vulnerable-thick-client-app-part-1/)
* [https://github.com/secvulture/dvta](https://github.com/secvulture/dvta) - Damn Vulnerable Thick Client App
* [**Thick Client Penetration Testing: Information Gathering**](https://www.hackingarticles.in/thick-client-penetration-testing-information-gathering/)
* [**Thick Client Pentest Lab Setup: DVTA (Part 2)**](https://www.hackingarticles.in/thick-client-pentest-lab-setup-dvta-part-2/)
* [**Thick Client Penetration Testing on DVTA**](https://www.hackingarticles.in/thick-client-penetration-testing-on-dvta/)
* [**Thick Client Penetration Testing: Traffic Analysis**](https://www.hackingarticles.in/thick-client-penetration-testing-traffic-analysis/)
* [**Thick Client Pentest Lab Setup: DVTA**](https://www.hackingarticles.in/thick-client-pentest-lab-setup-dvta/)

## Mobile Devices

* [https://akenofu.gitbook.io/hackallthethings/mobile-applications/android](https://akenofu.gitbook.io/hackallthethings/mobile-applications/android)
* [https://owasp.org/www-project-mobile-security-testing-guide/](https://owasp.org/www-project-mobile-security-testing-guide/)
* [OWASP Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/) - Bernhard Mueller et al.
* [Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
  * [https://opensecurity.in/](https://opensecurity.in)
* [quark-engine](https://www.kali.org/tools/quark-engine/) - Quark-Engine is a full-featured Android analysis framework written in Python for hunting threat intelligence inside the APK, DEX files.
* _Hacking: The next generation - Abusing mobile devices: Targeting your mobile workforce, pg. 149_

## Networking Devices

* [RouterHunterBR](https://github.com/googleinurl/RouterHunterBR) - Unauthenticated Remote DNS change/ users & passwords.
* [routersploit](https://github.com/threat9/routersploit) - an open-source exploitation framework dedicated to embedded devices

{% embed url="https://youtu.be/wyjM_P7Axa8" %}

## Printers

* [https://tryhackme.com/room/printerhacking101](https://tryhackme.com/room/printerhacking101)
