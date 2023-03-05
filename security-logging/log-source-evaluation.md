---
description: Introducing DeTTECT!
---

# Log Source Evaluation

## Intro

When managing out log sources, we must often evaluate them for their detection capabilities. We know that not all log sources are created equally, but how can we tell? Well we can do this two ways:\
\
First, we can see if ther are any standards of logging that we can hold our logs to. For example, if you are a Splunk user, you can use thier CIM, Common information Model to define all of the pertinent data points you need to log, (Per splunk's opinion).

Second, we can evaluate our logs by scoring and comparing your logs to known standards such as Mitre Attack, to determine the level and quality of detection coverage.

## DeTTECT

On of the best tools to help with this is [DeTTECT](https://github.com/rabobank-cdc/DeTTECT). DeTTECT aims to assist blue teams using ATT\&CK to score and compare data log source quality, visibility coverage, detection coverage, and threat actor behaviors. All of which can help, in different ways, to get more resilient detection techniques against attacks targeting your organization. The DeTTECT framework consists of a Python tool, YAML administration files, the DeTTECT Editor, and scoring tables for the different aspects.

DeTTECT provides the following functionality:&#x20;

* Administrate and score the quality of your data sources.&#x20;
* Get insight on the visibility you have on for example endpoints.&#x20;
* Map your detection coverage.&#x20;
* Map threat actor behaviors.&#x20;
* Compare visibility, detections, and threat actor behaviors to uncover possible improvements in detection and visibility. This can help you to prioritize your blue teaming efforts.

DeTTECT Resources

* Wiki - [https://github.com/rabobank-cdc/DeTTECT/wiki/Getting-started](https://github.com/rabobank-cdc/DeTTECT/wiki/Getting-started)
* Video Presentation - [https://www.youtube.com/watch?v=\_kWpekkhomU](https://www.youtube.com/watch?v=\_kWpekkhomU)
* Video Guide - [https://www.youtube.com/watch?v=EXnutTLKS5o](https://www.youtube.com/watch?v=EXnutTLKS5o)
* [https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack](https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack)
* [https://www.siriussecurity.nl/blog/2019/5/8/mapping-your-blue-team-to-mitre-attack](https://www.siriussecurity.nl/blog/2019/5/8/mapping-your-blue-team-to-mitre-attack)
* [https://github.com/siriussecurity/dettectinator](https://github.com/siriussecurity/dettectinator) - The Python library to your DeTT\&CT YAML files.
  * [https://blog.nviso.eu/2023/01/04/dettct-automate-your-detection-coverage-with-dettectinator/](https://blog.nviso.eu/2023/01/04/dettct-automate-your-detection-coverage-with-dettectinator/)

## ATTACKDataMap

This is an amazing tool written by the Sysmon Guru Olaf Hartong, for mapping data sources and their tracked events to Mitre coverage.

* [ATTACKdatamap](https://github.com/olafhartong/ATTACKdatamap) - A datasource assessment on an event level to show potential coverage or the MITRE ATT\&CK framework
* [https://medium.com/@olafhartong/assess-your-data-potential-with-att-ck-datamap-f44884cfed11](https://medium.com/@olafhartong/assess-your-data-potential-with-att-ck-datamap-f44884cfed11)
* [https://github.com/OTRF/OSSEM-DM](https://github.com/OTRF/OSSEM-DM)

## Misc

* [https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/)

{% embed url="https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5b8f091c0ebbe8644d3a886c/1536100639356/Windows+ATT%26CK_Logging+Cheat+Sheet_ver_Sept_2018.pdf" %}
