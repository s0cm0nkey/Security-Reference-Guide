---
description: Cloud audit, identity, activity, and flow logging
---

# Logging - Cloud

Cloud logging should capture identity activity, control-plane API calls, workload/network activity, security findings, and SaaS audit records. Keep posture management, hardening, and offensive cloud testing on the main Cloud page.

{% content-ref url="../cloud.md" %}
[cloud.md](../cloud.md)
{% endcontent-ref %}

## Microsoft 365, Entra ID, and Azure

* [Microsoft Purview: Search the audit log](https://learn.microsoft.com/en-us/purview/audit-log-search)
* [Office 365 Management Activity API schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema)
* [Enable Unified Audit Log for delegated Microsoft 365 tenants](https://gcits.com/knowledge-base/enabling-unified-audit-log-delegated-office-365-tenants-via-powershell/)
* [Everything you wanted to know about security and audit logging in Office 365](https://thecloudtechnologist.com/2021/10/15/everything-you-wanted-to-know-about-security-and-audit-logging-in-office-365/amp/)
* [Microsoft-365-Extractor-Suite](https://github.com/invictus-ir/Microsoft-365-Extractor-Suite) - Collection tooling for Microsoft 365 investigation and audit data.
* [Unified Audit Logs in Microsoft 365](https://www.youtube.com/watch?v=c1kId_esv0k)
* [The basics of modern authentication - Microsoft identity platform](https://www.youtube.com/watch?v=tkQJSHFsduY)
* [Azure Monitor Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
* [Azure diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings)
* [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/)

## AWS

* [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) - Control-plane API logging.
* [AWS CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html) - Queryable CloudTrail event lake.
* [Amazon VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) - Network flow metadata for VPCs, subnets, and interfaces.
* [Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html) - Managed threat detection findings.
* [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html) - Aggregates security findings and posture signals.
* [AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html) - Configuration history and compliance records.

## Google Cloud

* [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) - Admin activity, data access, system event, and policy denied logs.
* [VPC Flow Logs](https://cloud.google.com/vpc/docs/flow-logs) - Network flow metadata.
* [Cloud Logging](https://cloud.google.com/logging/docs) - Centralized logging platform.
* [Security Command Center](https://cloud.google.com/security-command-center/docs) - Findings and cloud security posture signals.

## Cross-Cloud Collection Notes

* Centralize identity and control-plane logs first.
* Enable network flow logs where investigations require cloud east-west visibility.
* Normalize account, subscription, project, region, resource ID, principal, source IP, action, result, and user-agent fields.
* Export logs to durable storage when retention requirements exceed native platform defaults.
* Treat SaaS audit logs as first-class sources, especially for identity, mailbox, file-sharing, and administrative actions.
