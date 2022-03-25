# Sandboxing

## Online Sandbox Services

**Online Sandboxes -** The malware analysis easy button

The first step in analyzing any potentially malicious file is running it through a sandbox. Sandboxes can provide detailed analysis of the file, its structure, its contents, its metadata, and even detonate the file to see what activity comes from opening/running the file.

There are two types of analysis on files that can be performed:

* Static analysis - Where the contents and structure of the file are analyzed for indicators of purpose or nature. If the file is an executable in an uncompiled state, the code structure can also be analyzed.&#x20;
* Dynamic analysis - Where the files is opened or executed, to determine what action it performs. This is usually done in a sandboxed environment, in order to prevent any potentially harmful actions being performed on the host device.

For analyzing potentially malicious files, i usually start with submitting the file to JoeSandbox and Hybrid-Analysis. These two provide detailed reports about the nature of the file, its contents, and intelligence available on the file, and so much more. If these two do not yield the answers needed, Any.run will provide a dynamic environment to detonate the file and monitor the actions it performs.

All of the below online sandboxes can provide detailed analysis with one or more popular engines. Remember, just because its not found to be malicious by the scanner, does not mean it is 100% safe. Always use discretion.

{% hint style="warning" %}
\*\*\*WARNING - Do NOT submit a document to a public sandbox that might contain PII. This can be considered a data leak and could violate company policy. If you need to inspect a file that might have PII, use either a premium sandboxing service that does not disclose analysis results/contents, or use a sandboxing tool on your own local virtual machine.
{% endhint %}

* [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com)
* [https://www.joesandbox.com](https://www.joesandbox.com)
* [https://app.any.run/](https://app.any.run)
* [https://sandbox.anlyz.io/dashboard](https://sandbox.anlyz.io/dashboard)
* [https://sandbox.pikker.ee/](https://sandbox.pikker.ee) (Online version of cuckoo)
* [https://analyze.intezer.com](https://analyze.intezer.com)
* [https://iris-h.services/pages/submit](https://iris-h.services/pages/submit)
* [https://intelligence.gatewatcher.com/](https://intelligence.gatewatcher.com)
* [https://tria.ge/](https://tria.ge)
* [https://labs.inquest.net/dfi](https://labs.inquest.net/dfi)
* [https://manalyzer.org/](https://manalyzer.org)
* [https://threatpoint.checkpoint.com/ThreatPortal/emulation](https://threatpoint.checkpoint.com/ThreatPortal/emulation)
* [http://firmware.re/](http://firmware.re)
* [https://malwareconfig.com/](https://malwareconfig.com)
* [https://id-ransomware.malwarehunterteam.com/](https://id-ransomware.malwarehunterteam.com)
* [https://virusscan.jotti.org/en](https://virusscan.jotti.org/en)
* [https://pandora.circl.lu/submit](https://pandora.circl.lu/submit)

## **Local Sandbox tools**

Local sandboxes - There are a few options for local sandboxing that can help you. Cuckoo sandbox is the standard for local automated malware analysis. This is a great option for when you need to analyze a file that might contain PII that you do not want disclosed to a public sandbox. Another great option is to use Fireeye's Flare-VM. Not only does it come loaded with a slew of malware analysis tools, it runs as a virtual machine where malware can be analyzed and event detonated with out fear of impacting the host operating system. You will encounter files that pass muster with most automated analysis tools and the only way to determine what it does, is to detonate it. A great and simple way to do this, is to load the suspicious file into your Flare-VM, turn on a web proxy like fiddler to monitor your outdoing web requests, open local tools like event viewer or a process monitor, and detonate the file to see if it makes any unwanted actions on the device.

* [https://github.com/pandora-analysis/pandora](https://github.com/pandora-analysis/pandora) - Pandora is an analysis framework to discover if a file is suspicious and conveniently show the results.
* [https://cuckoosandbox.org/](https://cuckoosandbox.org) - The standard for local sandboxing and analysis.
  * [cuckoo3](https://github.com/cert-ee/cuckoo3) - Cuckoo 3 is a Python 3 open source automated malware analysis system.
* [https://github.com/fireeye/flare-vm](https://github.com/fireeye/flare-vm) - The fireeye VM for malware analysis.&#x20;
* [ThePhish](https://github.com/emalderson/ThePhish) - ThePhish is an automated phishing email analysis tool based on [TheHive](https://github.com/TheHive-Project/TheHive), [Cortex](https://github.com/TheHive-Project/Cortex/) and [MISP](https://github.com/MISP/MISP). It is a web application written in Python 3 and based on Flask that automates the entire analysis process starting from the extraction of the observables from the header and the body of an email to the elaboration of a verdict which is final in most cases.
  * [https://secsi.io/blog/thephish-an-automated-phishing-email-analysis-tool/](https://secsi.io/blog/thephish-an-automated-phishing-email-analysis-tool/)
* [https://www.telerik.com/fiddler](https://www.telerik.com/fiddler) - While not a sandbox, it is a simple web proxy that can be used with any other VM. By detonating your target file in a cirtual machine with this running, you can see if the file makes any outbound web requests when it is opened.
