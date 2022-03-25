# HTTP(S)

## **HTTP Detection Use Cases**

* Unauthorized proxy detection and WPAD attacks
  * If the XFF field is present, a proxy is being used. We can look for the presence of the XFF field in HTTP logs where the source IP does not match approved Web Servers. This will discover policy violations, and WPAD based MITM attacks
* Meterpreter over HTTP
  * Default Merterpreter configurations will perform an HTTP GET request about every 3 seconds and will continue constantly
* Scan/crawl of a web server detection by HTTP Method
  * \~1000 get requests in a 5 minute period
  * \>100 POST requests in a 5 minute period
  * While these are general guidelines, it is wise to establish HTTP method thresholds to monitor, based on normal activity within your environment.
* Subdomain Bruting/Vuln Scanner detection via HTTP Response code 404.
  * HTTP response code 404 identifies an unavailable or non-existent resource. While these can happen on occasion due to typos and other one-off errors, large volumes of these, especially in a short time is strange. By monitoring large spikes in 404 errors, we can detect web crawlers and vulnerability scanners interacting with our network.
* Web Crawling detection via HTTP Response code 200
  * If one of your web servers is being crawled, there will be a large number of 200 OK results associated with a large number of unique URIs for hosted domains. We can detect this activity by looking at large numbers of successfully requested unique URIs for a single server in a short amount of time.
  * We can further enhance this detected as well as improve web server security by deploying a handy tool called [WebLabyrinth](https://github.com/mayhemiclabs/weblabyrinth). This tool causes an infinite scan loop for web crawlers, which not only slows down their scanning, but helps create a huge number of the requests that satisfy this search, making detection even easier.
* Naked IP use
  * It is very rare that web requests will be made directly to an IP rather than to a domain. HTTP logs can be used to detect these direct requests as they can indicate malware connections.
* URL Length
  * While most legitimate website access and interaction typically deals with a low character count for the URL string, we can detect certain attacks like SQL injection, by looking for abnormally long URLs, as the injection or attack code is typically appended to the URL itself.
  * A good starting place is looking at URL lengths of over 250 characters, but may require tuning per your environment.
  * Note: This is intended for organization controlled Web Servers. Using this technique to monitor standard HTTP traffic will yield a ton of noise, as many ad domains have long URLs.
* Malicious/Unauthorized User-Agent
  * A high-value add data point, User-Agents can be used to identify sloppy malware, where the User-agent has a typo in it, or the malware author is so bold they even put its name in the User-Agent field.
  * Older User-agents can be used to identify older operating systems that might have slipped past Vulnerability management.
  * While this Use Case does require the creation of an allow list based on expected traffic within your organization, it will be a high fidelity alert for all unauthorized traffic.Most websites tend to fall below a certain URL character length. Certain web attacks like SQL injection will make the URL length quite large, especially when using HTML encoding to bypass any SQL injection defenses. This is usually a built in use case for most Web App Firewalls, but if you do not have one, it is still an easy use case to implement.

## **HTTPS DETECTION Use Cases - Certificates**

* Meterpreter detection - Default Meterpreter configuration
  * By default, meterpreter will use a self-signed certificate, a random common name, and multiple certificate fields will be missing. We can detect its use by the presence of these in used SSL certificates.
* Potential Malware SSL Certificate
  * One or more missing fields - Similar to Meterpreter, many types of malware will use a self-signed certificate and be missing one or more common fields. These are typically Organization, Organization Unit, State, and Country code.&#x20;
  * Improper field content - We can also look at improper data in fields such as Country Code. Simply looking at the country code field for non existent country codes, can be rather effective.
  * Uncommon Common Names - The Common Name fields often look liek DNS domains. Malware can sometimes generate Common names that dismiss the TLD suffix. Simply, finding a certificate with a common name missing a "." is abnormal.
  * We can look at malware dumps like [Contagio](https://contagiodump.blogspot.com) for evidence of the disparity of presence of certificate fields. Country code and Organization fields are missing in about 33% of malware certificates, and state/country code are missing in almost 75%.&#x20;
  * Certificates should constantly be inspected for field combinations that would raise suspicion.
* Expired SSL Certificate
  * Sometimes legitimate certificates can be collected by malicious actors by various means and used long after they have expired. Sometimes the use of an expired SSL certificate can indicate interaction with an older machine that has not been maintained and may be compromised. Either way, there is little to no justification for legitimate interaction with a device that uses an expired SSL Certificate.
* Known malicious or revoked certificate
  * Certificate Authorities that manage certificate IDs, will have a CRL: Certificate Revocation List, where a certificate has been reported as malicious and then registered as such with the CA, or the former owner of the certificate has requested that the CA revoke it for a given reason. Either way, We can detect these certificates simply by checking the certificate against the CA.
* Self-Signed Certificate
  * While this Use Case will require filtering and tuning, it is rare that you will see legitimate external traffic using a self-signed SSL certificate. Internal traffic will take some work to filter out as internal traffic has a higher occurrence of using self-signed certificates. That being said, you should do all you can to limit self-signed certificate use within your organization.
* Unauthorized certificate issuer
  * Signed certificates dont mean anything if we do not trust the Certificate Authority that signed them. It is possible to find and export a list of trusted root certificate authorities that can be used as a lookup and white list. Conversely, a blacklist could be made for those that we would not trust.
  * Beware of free CAs like Let's Encrypt that are becoming increasingly more popular. They allow [malware and phishing campaigns](https://www.trendmicro.com/en\_us/research/16/a/lets-encrypt-now-being-abused-by-malvertisers.html) to use legitimately signed certificates.
* High entropy of Certificate field entries
  * As mentioned with the Meterpreter Use Case, some malware will create a random string to fill in certificate data fields. We can use frequency analysis tools like [freq.py](https://github.com/markbaggett/freq) to calculate entropy of the field.
