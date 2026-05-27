# Logging - User Behavior Monitoring

User Behavior Analytics (UBA) and User and Entity Behavior Analytics (UEBA) compare current activity against expected behavior for a user, role, host, or peer group. These systems can be useful, but they require clean identity data, enough historical activity, and sustained tuning.

Do not start with UEBA if the environment does not have basic asset inventory, identity hygiene, endpoint logging, and defensible baselines.

## UBA Components

* **Allowed activity models** - Expected applications, logon patterns, locations, devices, and administrative tasks.
* **Denied or high-risk activity models** - Actions that are never expected for a user, group, asset, or environment.
* **Deviation detection** - Identification of activity that differs from normal behavior for a user or peer group.
* **Entity context** - Device, user, role, group, location, and asset criticality context that makes deviations meaningful.

## UBA and UEBA Tools

* SIEM-native UEBA features - Many SIEMs include behavior analytics, such as [Splunk UEBA](https://www.splunk.com/en_us/data-insider/user-behavior-analytics-ueba.html).
* [OpenUBA](https://github.com/GACWR/OpenUBA) - Open source user behavior analytics project. Appears unmaintained; validate before use. The project historically expected multiple weeks of activity before useful baselines.
* [Microsoft Advanced Threat Analytics](https://learn.microsoft.com/en-us/advanced-threat-analytics/what-is-ata) - Deprecated Microsoft behavioral analytics product. Microsoft Defender for Identity is the replacement.
* [Microsoft Defender for Identity](https://www.microsoft.com/en-us/security/business/threat-protection/identity-defender)
* [User-Behavior-Mapping-Tool](https://github.com/trustedsec/User-Behavior-Mapping-Tool) - TrustedSec project for mapping common user behavior on Windows systems.
  * [TrustedSec: Oh Behave! Figuring Out User Behavior](https://www.trustedsec.com/blog/oh-behave-figuring-out-user-behavior/)

## Related Pages

Behavior analytics depends on device inventory and endpoint logging.

{% content-ref url="device-discovery-and-asset-inventory.md" %}
[device-discovery-and-asset-inventory.md](device-discovery-and-asset-inventory.md)
{% endcontent-ref %}

{% content-ref url="logging-guide-windows-endpoint-logs.md" %}
[logging-guide-windows-endpoint-logs.md](logging-guide-windows-endpoint-logs.md)
{% endcontent-ref %}

Detection use cases belong in Blue Defense.

{% content-ref url="../blue-defense/event-detection/" %}
[event-detection](../blue-defense/event-detection/)
{% endcontent-ref %}
