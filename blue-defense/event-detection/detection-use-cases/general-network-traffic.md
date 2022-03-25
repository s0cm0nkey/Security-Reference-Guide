# General Network Traffic

**Network Baselining - Anomaly Reports**

When monitoring network traffic, we can identify anomalies of traffic by statistical outliers. These are important to review regularly for suspicious activity as well as for opportunities to add to any available white/black lists.These are typically a very large amount of data to return, so it is recommended to use these detections as regularly scheduled reports to be reviewed, rather than alerts.

* **Large Volumes of Internal Blocked Traffic -** Traffic within your network should all be legitimate and not require any blocking. That being said, a default network setup will have TONS of internal blocked traffic. Vuln scanners, default Windows utilities, Broadcast/multicast traffic, etc. Tune these out before enabling this use case.
  * Great for detecting unauthorized internal recon and pivoting.
  * Requirements
    * Tuning out of known sources of noise traffic.
    * Disabling of unused network utilities such as SSDP, LLMNR, Browser, NetBIOS, Dropbox LAN Sync, etc.) [https://its.uiowa.edu/support/article/3576](https://its.uiowa.edu/support/article/3576)
  * Logic
    * Where
      * Action=Blocked
      * AND
      * Source is
        * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
      * AND
      * Destination is&#x20;
        * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
* **New Applications -** Easy and dirty detection, but new applications in a locked down, allow list environment should always be suspect. This can be easily detected with Next Gen Firewalls that can identify applications used in the network.
  * Requirements
    * Documented application whitelist
    * 90 days of detected applications to compare to.
* **Long standing connections -** Network connections with an exceptionally long duration can indicate multiple potentially malicious activities, such as threat actor connections, large file transfers, etc.
  * Logic
    * Look for network connections, or the sum of like network connections that start/stop in sequence that add up to anything longer than 24 hours.
* **Top Connections** - Reviewing top source and destination IPs can identify potentially unauthorized or malicious network traffic. This is  further enhanced if you can see a trendline of the traffic to detect abnormal spikes in activity.
* **Potential Data Exfiltration -** Looking at the summed byte count of of traffic between a source and destination where the session appears to be the same, can potentially expose large, unauthorized file transfers.&#x20;
* **Abnormal Upload/Download Ratio** - Depending on the purpose of the device, connections will typically have an upload/download ratio that reflect that purpose. Example: Most end user devices will have web requests that are heavily trended towards download rather than upload. If that changes, it could undicate beaconing or exfiltration. This should always be correlated with spikes in connection counts as well.
* **Per subnet event count anomalies.**

**Unauthorized RDP Use**

* Theory
  * RDP is a powerful  remote access tool that is far too frequently overlooked. RDP should never be used outside of the network. Internal RDP connections should be restricted and heavily monitored.
* Requirement
  * Logging of EventID 4624: Account was successfully logged on.
* Logic 1 - Unauthorized internal RDP connections
  * Where
    * Detected use of RDP
      * EventID with Logon type 10 (RemoteInteractive)
      * OR
      * Dest Port = 3389
    * AND
    * Source is not an authorized user of RDP
* Logic 2 - Unauthorized RDP in/out of the network
  * Where
    * Detected use of RDP
      * EventID with Logon type 10 (RemoteInteractive)
      * OR
      * Dest Port = 3389
    * AND
    * Source is
      * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
      * AND
      * Destination is NOT
        * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
    * OR&#x20;
    * Source is NOT
      * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
      * AND
      * Destination is
        * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8

**Unauthorized SMB activity**

* Theory
  * SMB is an integral tool within a windows network, but can have serious security flaws if not hardened properly. Restricting SMB access, versions, and enabling SMB signing can help tremendously.
* Requirements
* Logic 1 - SMB in/out of the network
  * Where
    * Detected use of SMB
      * EventID 4624
      * OR
      * Dest Port = 3389
    * AND
    * Source is
      * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
      * AND
      * Destination is NOT
        * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
    * OR&#x20;
    * Source is NOT
      * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
      * AND
      * Destination is
        * 192.168.0.0/16 OR 172.16.0.0/12 OR 10.0.0.0/8
* Logic 2 - SMB Version 1/2 Use
* Logic 3 - Unsigned SMB Traffic

**Traffic to New Port**

* Theory
  * Business activity is regular and repetitive. One a device is fully deployed in a network, it will rarely see connections with previously unused ports. By detecting connections with ports that have never previously been used, we can detect various types of potentially malicious traffic within our network.
* Requirements
* Logic
  * Where
    * Internal asset and traffic destination port combination has not been seen wihtin the past 90 days.

