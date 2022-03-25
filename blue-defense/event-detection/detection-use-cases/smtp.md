---
description: Detection, Enrichment, and Use cases
---

# Email

## **Email Server/Security Application - Use Cases**

* Built-in tool alerts - These typically include responses for detection of malicious attachments, known malicious senders, and potentially malicious sender domains or URLs within the email itself. Please refer to the tool itself for documentation on its alerting capabilities.

## **SMTP - Use Cases**

* Fuzzy search phishing domain detection
  * Fuzzy searching of email domains - Use fuzzy searching utilities of your SIEM or supplementary tool like [fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) to calculate Levenshtien distance of a string and detect similar domains. This use case should return nothing unless a potential typo-squatting domain is detected. This technique is extremely effective against phishing domains and targeted attacks.
    * Elastisearch:
      * `tags:smtp domain:SEARCHDOMAIN.com~ -domain:SEARCHDOMAIN.com`
      * The \~ character indicates a fuzzy search. You will also remove the searched domain itself from the search results.
    * Splunk:
      * Use either [Fuzzy Search for Splunk](https://splunkbase.splunk.com/app/3109/) app, or [fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) via an API call.
    * \#NOTE: This can also be done with DNS records, but will create a significantly higher rate of false positives.
  * Domain match with [DNStwist](https://github.com/elceef/dnstwist) domain list - Used for expanded searching beyond the 1-2 character difference of fuzzy searching. Also allows for searching of Homograph domain usage. The best use is to use DNStwist to create a domain list as a lookup file and dynamically alert based on matches to traffic containing these domains.
* Bulk phishing detection
  * Search for large amounts of emails from an external address sent within a short time frame. Will require adjustment to find the correct emails per minute threshold for your organization.
  * Will be made MUCH easier to make allow/deny lists by adding enrichment fields such as ASN and other results from WHOIS/RDAP lookups. These can be used to easily filter out known email marketing companies.
* Spearphishing/Whaling detection
  * By referencing a list of executives and VIPs within your organization, you can set up alerting for external domains that try to leverage their names.
* Unauthorized outbound SMTP detection
  * Email should only be coming from authorized sources. We can detect unauthorized mail relays and potential C2 activity, by limiting SMTP traffic to mail servers and other pre-approved tools, while alerting on anything else.
* Unauthorized SMTP user agent detection
  * By looking for unwanted user agents, we can detect un approved outbound email applications. This is handy for alerting when an authorized system is compromised.
* Outbound SMTP traffic anomaly detection
  * Either by baselining or machine learning, if we can establish a normal pattern and volume of outbound email traffic, we can set up alerting around any strange spikes in outbound email traffic that might indicate a compromised system using SMTP for a c2 channel or for further phishing activities.
