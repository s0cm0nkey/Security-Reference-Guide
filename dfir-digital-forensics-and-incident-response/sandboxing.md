# Sandboxing

## Overview

**Online Sandboxes -** The "Easy Button" for Malware Analysis.

The first step in analyzing any potentially malicious file often involves running it through a sandbox. Sandboxes provide detailed analysis of the file, its structure, its contents, its metadata, and can even "detonate" (execute) the file to observe the activity resulting from opening or running it.

Malware analysis typically falls into two categories:

*   **Static Analysis**: The contents and structure of the file are analyzed for indicators of purpose or nature without executing the code. This includes hashing, string extraction, and analyzing file headers. If the file is an executable, code structure can be analyzed via disassembly (though this often crosses into Reverse Engineering).
*   **Dynamic Analysis (Behavioral Analysis)**: The file is opened or executed in a controlled environment (sandbox) to determine what actions it performs. This allows analysts to observe network connections, file system changes, and process injections without risking the host device.

Use discretion when choosing a tool. A simple scan might not reveal complex malware.

## Online Sandbox Services

For analyzing potentially malicious files, a common workflow starts with submitting the file to services like **JoeSandbox**, **Hybrid-Analysis**, or **Any.run**. These platforms provide detailed reports on the file's nature, contents, and related threat intelligence.

*   **Hybrid-Analysis** and **JoeSandbox** are excellent for deep static and dynamic analysis.
*   **Any.run** provides an interactive dynamic environment, allowing you to manipulate the VM while the malware runs (useful for malware requiring user interaction, like installers or password-protected docs).

{% hint style="warning" %}
\*\*\*WARNING - OPSEC & Privacy\*\*\*
Do **NOT** submit a document to a public sandbox if it might contain Personally Identifiable Information (PII) or sensitive corporate data.
Submitting a file to a public sandbox (like VirusTotal or Hybrid-Analysis) shares that file with the security community and potentially the public. This can be considered a data leak.
If you need to inspect a sensitive file:
1. Use a premium sandboxing service with a "private" submission option.
2. Use a local sandboxing tool on an isolated virtual machine.
{% endhint %}

### General Purpose Sandboxes
*   [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/) (Powered by Falcon Sandbox)
*   [https://www.joesandbox.com](https://www.joesandbox.com)
*   [https://app.any.run/](https://app.any.run/) (Interactive Sandbox)
*   [https://tria.ge/](https://tria.ge/) (High-speed malware analysis)
*   [https://analyze.intezer.com](https://analyze.intezer.com) (Code reuse analysis)
*   [https://intelligence.gatewatcher.com/](https://intelligence.gatewatcher.com/) (Threat Intelligence & Sandbox)
*   [https://labs.inquest.net/dfi](https://labs.inquest.net/dfi) (Deep File Inspection)
*   [https://manalyzer.org/](https://manalyzer.org/)
*   [https://threatpoint.checkpoint.com/ThreatPortal/emulation](https://threatpoint.checkpoint.com/ThreatPortal/emulation)
*   [https://pandora.circl.lu/submit](https://pandora.circl.lu/submit)
*   [https://exchange.xforce.ibmcloud.com/](https://exchange.xforce.ibmcloud.com/)

### Specialized Analysis (Firmware, Android, Configs)
*   [https://koodous.com/](https://koodous.com/) - APK (Android) Sandbox
*   [http://firmware.re/](http://firmware.re/) - Firmware Analysis
*   [https://malwareconfig.com/](https://malwareconfig.com/) - Extract configuration from RATs/C2s
*   [https://id-ransomware.malwarehunterteam.com/](https://id-ransomware.malwarehunterteam.com/) - Identify Ransomware variants
*   [https://yaraify.abuse.ch/](https://yaraify.abuse.ch/) - Scan files against public YARA rules

### Community & Legacy Instances
*   [https://sandbox.pikker.ee/](https://sandbox.pikker.ee/)
*   [https://sandbox.anlyz.io/dashboard](https://sandbox.anlyz.io/dashboard)
*   [https://iris-h.services/pages/submit](https://iris-h.services/pages/submit)
*   [https://virusscan.jotti.org/en](https://virusscan.jotti.org/en) (Multi-engine scanner, primarily static)

## **Local Sandbox Tools**

Local sandboxes are the preferred method when handling PII or highly sensitive targeted malware. They run on your own infrastructure, ensuring data does not leave your control.

*   **[CAPE Sandbox](https://github.com/kevoreilly/CAPEv2)** - CAPE (Config And Payload Extraction) is a major fork of Cuckoo Sandbox designed to extract payloads and configurations from malware automatically. It is currently more actively maintained than the original Cuckoo v2.
*   **[Cuckoo Sandbox](https://cuckoosandbox.org/)** - The classic standard for local automated malware analysis.
    *   [cuckoo3](https://github.com/cert-ee/cuckoo3) - The next generation (Python 3) of Cuckoo.
*   **[Mandiant Flare-VM](https://github.com/mandiant/flare-vm)** - (Previously FireEye) A fully customizable, Windows-based security distribution for malware analysis, incident response, and penetration testing. It runs as a virtual machine, allowing you to detonate malware without impacting your host OS.
*   **[REMnux](https://remnux.org/)** - A Linux toolkit for reverse engineering and analyzing malicious software. Often used in tandem with Flare-VM to analyze Linux malware or to provide network services (DNS, HTTP) to the Windows malware victim.

### Analysis Utilities & Frameworks
*   **[Pandora](https://github.com/pandora-analysis/pandora)** - An analysis framework to discover if a file is suspicious and conveniently show the results.
*   **[ThePhish](https://github.com/emalderson/ThePhish)** - An automated phishing email analysis tool based on [TheHive](https://github.com/TheHive-Project/TheHive), [Cortex](https://github.com/TheHive-Project/Cortex/) and [MISP](https://github.com/MISP/MISP).
*   **[Fiddler](https://www.telerik.com/fiddler)** - A web debugging proxy. While not a sandbox, it is essential for dynamic analysis. run Fiddler in your VM to intercept and inspect HTTP/HTTPS traffic generated by the malware.
*   **[DNSChef](https://github.com/iphelix/dnschef)** - A highly configurable DNS proxy for Penetration Testers and Malware Analysts.

## **Manual Dynamic Analysis**
A simple yet effective way to analyze malware is to manually detonate it in a controlled VM (like Flare-VM).
1.  **Isolate**: ensure the VM has no path to your production network (Host-only networking or strictly controlled NAT).
2.  **Instrumentation**: Open monitoring tools (Process Monitor, Process Hacker, Fiddler, Wireshark).
3.  **Detonate**: Run the suspicious file.
4.  **Observe**: Watch for process creation, registry changes, and outbound network requests.

![Analysis Flow](<../../.gitbook/assets/image (8) (1).png>)

![Dashboard Example](<../../.gitbook/assets/image (9) (1).png>)

