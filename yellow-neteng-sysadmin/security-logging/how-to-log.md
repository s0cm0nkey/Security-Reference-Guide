# How create a logging strategy

What can we say about logs? Well, logging strategies are complex with no single one-size-fits-all solution. There are many premium and open source options for all the different tools that make up a proper structure for logging. We will expound on the different strategies, but understand one very important thing: Logging is not a "there or not" technology. Logs have a quality associated with them, and with Logging, quality is ALWAYS better than quantity.

## **Logging strategy**

&#x20;Most organizations pick up a SIEM to process their security logging as a compliance requirement. Sadly, when this is the focus, it is often implemented improperly and inefficiently. This ends up costing the organization more than it should, as well as having poor security. So what should we focus on when looking to bring in logs for security monitoring? First we talk about how to collect the logs. This comes in a couple of approaches:

* Volume logging (input focused) - Log all the things, let the analysts sort it out.
* Selective logging (output focused) - Pick and choose what logs you want, and how you want them, and hope you didn't forget anything.

Honestly, the best option is a hybrid. Start with volume logging and implement a process of constant tuning and pruning. It will take more ongoing maintenance, but you will have more data you might not know you need, with out having to pay for the storage/license of logging everything. Remember, that the use of human processes and procedures will be cheaper and more effective than relying on a tool, every time.\
When looking at tuning and pruning, one of the best approaches is to start with removing the most frequent events that you will see, as they are the least likely to have any significant security value. Many folks will say that you can reduce the volume of your logs by 80-90% and retain security value, with this simple method.

One large factor you should consider is the purpose behind the logging. This will vary greatly depending on who will be using the logs and what tasks they will need them for. Typically these will come down to three implementations.

* Security Alerts Only - With this approach, you only log events and data fields that are directly used for generating security alerts. Short, sweet, and to the point, this option will give you the smallest overall volume if your organization has concerns about storage, or license if you use a premium SIEM.
* Security Relevant logs. - These would be all of the data you need for alerts, as well as any data that would be useful for a security investigation. Not all data can be used to generate alerts, but can still provide immense value for threat hunting and incident response scenarios.
* All Operational logs - This is common when the security team and the network operations team is working off of the same data, in the same tool. For simplicity's sake, all logs relevant to both security and network operations are logged into the platform of choice, and the respective teams parse through what is relevant to them. This is handy for larger organizations with thier own internal SOC and NOC teams, but does ingest a much larger volume of data.

## **What logs should you collect?**

Relevant logs come from all types of sources, and you should never discount the power of a log that doesn't come from a security related device. Compliance is a great starting point for what logs you should collect, but compliance is ONLY a starting point. It should never be the goal. It will come down to your organization on what to prioritize, but there are a few interesting data points that can get you heading in the right direction.

When looking at what to prioritize for detection, one of the most common methods is to see what solutions and data can match to your MITRE ATT\&CK Framework coverage. While you should always look for more than simply checking a tactic or technique off of a list, it is still a great starting place when developing your strategy. I have recently taken a CSV of the Mitre attack framework and performed some statistical analysis on some of the newer data points they have added: Data Sources, and Data Objects. These new data points allow us to see what we need log in order to detect the documented techniques and sub-techniques within the frame work. Here are a few interesting statistics from my research:

* As of writing this, Mitre has 552 techniques and sub-techniques, 80 of which by definition cannot be detected by current means.
* It defines 30 different data sources, and 99 data objects used for detection.
* 125 techniques and sub-techniques apply only to Windows Operating systems, 16 to MacOS, and 9 to Linux. All others either overlap operating systems or apply to a specific application or tool.

Now for the fun part: Which data source and object pairs cover the most techniques and sub-techniques

| Command: Command Execution               | 243 |
| ---------------------------------------- | --- |
| Process: Process Creation                | 197 |
| File: File Modification                  | 95  |
| Network Traffic: Network Traffic Content | 89  |
| Network Traffic: Network Traffic Flow    | 84  |

Interesting right? Almost half of the document techniques require command line logging to detect! Well if we are developing a strategy focused on technique coverage, then this is where I would start. Even better, we can use this data to prioritize not just log sources to ingest but security tools to purchase and deploy. The top three on that list are all data objects that can be collected by an EDR solution, which tells me, EDR is the first thing I should look at if I want to improve my coverage.

Log prioritization can be complex, but when all else fails, Don Murdoch, the author of the Blue Team Handbook said it best: _"If you have to make a choice, use user attributable data over all others"_

For more details on my MITRE ATT\&CK analysis, please see the below PDF.

{% file src="../../.gitbook/assets/mitre_data_source_analysis.pdf" %}

## **Calculating logging infrastructure needs**

When creating out our logging strategy it is crucially important to plan our the hardware and software needed to support both the logging operation itself as well as the storage for the logs collected. The best method of gauging what we need, is with a Proof-of-Concept. In a POC, we can take a sampling of log data and easily calculate certain needed data points:

* EPD: Events per day - Used for calculating overall storage capacity.
* EPS: Events per second - Used for calculating the network and tool throughput required.
* Peak EPS - Used for calculating maximum surge throughput needed at one time.

If a POC of regular traffic is not feasible, it is possible to deploy scripts can pull the appropriate logs to help gauge and effective EPS.Another method for sizing EPS is by using estimation from third party research. While easy, it is not an advised method as estimations can vary wildly between sources. These options are handy and easier to use, but typically a POC for calculating event throughput is the only way to properly size log storage needs with any accuracy.

* [SANS: Benchmarking SIEM](https://apps.es.vt.edu/confluence/download/attachments/460849213/sans%20siem%20benchmarking.pdf?api=v2)
* [https://content.solarwinds.com/creative/pdf/Whitepapers/estimating\_log\_generation\_white\_paper.pdf](https://content.solarwinds.com/creative/pdf/Whitepapers/estimating\_log\_generation\_white\_paper.pdf)

## **Types of Log Storage**

A data retention policy is always an important item to plan out when developing your logging strategy. In security, you must always be thinking about how far back in your logs will you need to go to effectively investigate a security incident. If we take [Mandiant's calculation](https://www.fireeye.com/blog/threat-research/2020/02/mtrends-2020-insights-from-the-front-lines.html) of an average 56 days to detect an intrusion, logic would dictate that we would need at least that. Anything beyond that length of time, is determined by your budget.

There are three types of log storage that we would typically see and deal with when managing logs in a SIEM:

* Hot - These are your most recent and active logs. Typically saved on SSD's for the fastest response, retention on these disks are recommended for a minimum of 7 days, preferably 30 or more.
* Warm - Once past the time frame of the most use, logs can be moved from SSDs to slower but larger mediums like Hard Disk or Tape. Some SIEMs have a function that allows transfer of data from these disks to SDD for faster searches on necessary data. These are typically stored for at least 90 days.
* Cold - Beyond the first 90 days, the chances of needing a particular log file is slim, but not none. Cold storage is a cheap long term solution, but will take a long time to spool back up for use if needed.

## **Log Collection Methodology**

Determining how you collect your logs depends greatly on the log you are trying to capture.&#x20;

* Application/device logs - These logs will come from a single source. These can be easily captured by native logging utilities within the device/application, a logging agent installed on the device, or some of the many options for syslog or other agentless logging. You mileage may vary, but be sure to investigate all of the options available to determine the right methodology for you.
* Service Logs - Service logs are a slightly different animal that the above logs. With service logs, you might not know exactly where the logs are coming from, or the the utility to capture them is not easy to use. These logs will come down to a few different methodologies:
  * Native logging of services built into the devices that use them.
    * This has a high degree of fidelity as well as you can custom tailor the quality of logging at the device itself.
    * The biggest drawback is the volume of configuration you must do set up all of the devices for logging. You must also be prepared to collect those logs from multiple different sources, which introduces networking issues as well as dealing with multiple different log formats.
  * Logging via network monitoring tools to capture all related traffic.
    * By using fantastic tools like [ZEEK](https://zeek.org) or [Corelight](https://corelight.com), you can collect all of the different services you need to create logs for, with one tool and one log collection location, drastically increasing simplicity without sacrificing quality.
    * This will generate logs for systems you are unaware of, as well as provide a consistent logging format.
    * The difficulty here is more political as it usually requires a network tap, an additional server, and usually permissions to get the required level of visibility.
  * Other options
    * Network devices such as Next-Gen firewalls can often be able to create similar network traffic monitoring. These options will work but tend to have inferior logging quality. Certain protocols will have sufficient detail of logging, such as HTTP. Data for other protocols such as HTTPS and DNS are typically insufficient.

## **Final Note**

Logging solutions are the gas in the tank behind SIEMs and their proper implementation is critical to success. Once they are up, they are like a Bonzai tree; needing constant pruning and care to thrive. The biggest key to deploying and maintaining a logging solution is providing sufficient resourcing in time and staff. As always, no tool or tech, can replace solid personnel and procedures.
