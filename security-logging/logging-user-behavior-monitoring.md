# Logging - User Behavior Monitoring

While UBA (User Behavior Analytics) or UEBA (User and Entity Behavior Analytics), is a detection methodology typically used in more mature security operations, it still can be incredibly beneficial if deployed properly. The only caveat to this, is that it requires large amounts of data and tuning in order to be successful. This is NOT a plug and play security solution.

"If you do not know your environment and you have not implemented a basic defensible posture, do not start with these types of products" - SANS SEC555

**UBA Components**

User behavior monitoring typically involves 3 separate tasks:

* Allow lists of user activities - Start with general activity accepted by all users. This is further enhanced with tagging and definitions of user groups.
* Deny list of user activities - As above, start with general activity accepted by all users. This is further enhanced with tagging and definitions of user groups.
* Identifying deviations from normal user activity. Most people are creatures of habit. This also extends to roles. While system admins may perform previously unseen tasks are regular intervals, the accounting department does not tend to stray from the same actions and applications.

**UBA Tools**

* UBA/UEBA Tools built into you SIEM - Many SIEMs have built in UEBA utilities like [Splunk's UEBA](https://www.splunk.com/en\_us/data-insider/user-behavior-analytics-ueba.html).
* [OpenUBA](https://github.com/GACWR/OpenUBA)[https://openuba.org/](https://openuba.org/)
* [Microsoft Advanced Threat Analytics (ATA)](https://docs.microsoft.com/en-us/advanced-threat-analytics/what-is-ata) - Microsoft's behavioral analytics tool that has recently been made EOL and is being replaced with [Identity Defender](https://www.microsoft.com/en-us/security/business/threat-protection/identity-defender)
  * Requires 21 days with 12 days of activity from the target users - Open source data science project for user behavior monitoring.&#x20;
* [User-Behavior-Mapping-Tool](https://github.com/trustedsec/User-Behavior-Mapping-Tool) -Project aims to map out common user behavior on the computer. Most of the code is based on the research by kacos2000 found here: [https://github.com/kacos2000/WindowsTimeline](https://github.com/kacos2000/WindowsTimeline)
  * [https://www.trustedsec.com/blog/oh-behave-figuring-out-user-behavior/](https://www.trustedsec.com/blog/oh-behave-figuring-out-user-behavior/)
