---
description: Cloud security resources for AWS, Azure, Google Cloud, Microsoft 365, cloud hardening, cloud logging, and authorized cloud testing.
---

# Yellow - Cloud

This page is the cloud security hub for AWS, Microsoft Azure/Microsoft 365, Google Cloud, and multi-cloud tooling. Keep provider-specific administration, hardening, and authorized testing references here; move logging, SIEM, DFIR, password spraying, and general training resources to their dedicated sections when they are not cloud-specific.

## Related Sections

Cloud logging and audit collection are maintained in Security Logging.

{% content-ref url="security-logging/logging-cloud.md" %}
[logging-cloud.md](security-logging/logging-cloud.md)
{% endcontent-ref %}

KQL and SIEM query examples belong with Blue Defense.

{% content-ref url="blue-defense/query-languages.md" %}
[query-languages.md](blue-defense/query-languages.md)
{% endcontent-ref %}

Cloud posture assessment tools such as Prowler, ScoutSuite, and Cloudsplaining are also indexed with hardening resources.

{% content-ref url="blue-defense/device-hardening/" %}
[device-hardening](blue-defense/device-hardening/)
{% endcontent-ref %}

Cloud training and certification resources belong in Training.

{% content-ref url="training/" %}
[training](training/)
{% endcontent-ref %}

## General Cloud

### Cloud Basics and Design

* [Cloud Computing for Science and Engineering](https://cloud4scieng.org/chapters/) - Ian Foster and Dennis B. Gannon.
* [Cloud Design Patterns](https://learn.microsoft.com/en-us/azure/architecture/patterns/) - Microsoft architecture guidance for resilient cloud systems.
* [Designing Distributed Systems](https://azure.microsoft.com/en-us/resources/designing-distributed-systems/) - Free Microsoft ebook; account may be required.
* [Multi-tenant Applications for the Cloud, 3rd Edition](https://www.microsoft.com/en-us/download/details.aspx?id=29263) - Microsoft guide to multi-tenant application design.
* [CloudSecDocs](https://cloudsecdocs.com/) - Detailed references for cloud and container security.
* [CloudSecWiki](https://cloudsecwiki.com/) - Curated cloud security notes and hardening tips.
* [ATT&CK for Cloud](https://medium.com/mitre-engenuity/research-partnership-matures-att-ck-for-cloud-d232998968ce) - MITRE Engenuity note on cloud technique coverage.

### Cloud Security and Hardening

* [SANS Cloud Security](https://www.sans.org/cloud-security/) - Cloud security training and guidance. The old checklist URL now redirects to a broader SANS cloud landing page.
* [CloudFrontier](https://github.com/riskprofiler/CloudFrontier) - Monitors internet-facing attack surface across AWS, GCP, Azure, DigitalOcean, and Oracle Cloud.
* [Cloud Conformity Azure knowledge base](https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/) - Trend Micro Cloud One Conformity replaced the old Cloud Conformity branding.
* [Cloud Conformity AWS knowledge base](https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/) - Trend Micro Cloud One Conformity AWS best-practice checks.

### Cloud Pentesting

* [Awesome Cloud PenTest](https://github.com/CyberSecurityUP/Awesome-Cloud-PenTest) - Large collection of offensive cloud tools and resources.
* [Hacking the Cloud](https://hackingthe.cloud/) - Cloud pentesting methodology, tradecraft, and tooling.
* [Cloud Pentest Cheatsheets](https://github.com/dafthack/CloudPentestCheatsheets) - Cheatsheets for cloud provider testing workflows.
* _Hacking: The Next Generation - Cloud Insecurity: Sharing the Cloud with Your Enemy, pg. 121_

### Multi-Cloud Tools

* [cloudfox](https://github.com/BishopFox/cloudfox) - Finds exploitable paths in unfamiliar AWS, Azure, GCP, and Kubernetes environments.
  * [Introducing CloudFox](https://bishopfox.com/blog/introducing-cloudfox)
* [cloud-enum](https://www.kali.org/tools/cloud-enum/) - Enumerates public cloud resources from keywords.
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security posture assessment and reporting.
  * [ScoutSuite overview video](https://www.youtube.com/watch?v=k8CQhvQAu7E)
* [SkyArk](https://github.com/cyberark/SkyArk) - Discovers privileged entities in Azure and AWS.
* [PMapper](https://github.com/nccgroup/PMapper) - Models AWS IAM principals and privilege escalation paths.
* [GitOops](https://github.com/ovotech/gitoops) - Finds lateral movement and privilege escalation paths in GitHub organizations through CI/CD and access-control abuse.
* [cloudbrute](https://www.kali.org/tools/cloudbrute/) - Discovers public cloud infrastructure, files, and apps.
  * [Introducing CloudBrute](https://0xsha.io/posts/introducing-cloudbrute-wild-hunt-on-the-clouds)
* [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud security posture checks by Aqua. Treat this as a defensive CSPM project rather than an offensive framework.
* [serverless-prey](https://github.com/pumasecurity/serverless-prey) - Serverless functions for authorized introspection of cloud function runtimes.

## Microsoft Azure and Microsoft 365

### Basics

* [Azure documentation](https://github.com/MicrosoftDocs/azure-docs)
* [Microsoft Cloud Penetration Testing Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement)
* [Microsoft Azure IP Ranges and Service Tags](https://www.microsoft.com/en-us/download/details.aspx?id=56519) - Official source for Azure service tag JSON.
* [Microsoft cloud security benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/) - Replaces older Azure Security Benchmark links.
* [Azure AD deployment plans](https://github.com/AzureAD/Deployment-Plans)
* [ATT&CK for Azure AD](https://attack.mitre.org/matrices/enterprise/cloud/azuread/)
* [ATT&CK for Office 365](https://attack.mitre.org/matrices/enterprise/cloud/office365/)
* [reprise99 Azure security resources](https://github.com/reprise99)
* [Awesome Azure Security](https://github.com/kmcquade/awesome-azure-security)
* [Azure Network Security](https://github.com/Azure/Azure-Network-Security)
* [Common Azure security vulnerabilities](https://rhinosecuritylabs.com/cloud-security/common-azure-security-vulnerabilities/) - Rhino Security Labs.
* [Top 20 Microsoft Azure Vulnerabilities and Misconfigurations](https://www.infosecmatter.com/top-20-microsoft-azure-vulnerabilities-and-misconfigurations/) - InfosecMatter.
* [AADInternals OSINT](https://aadinternals.com/osint/) - Tenant lookup and Azure AD OSINT. This also fits the OSINT domain/tenant workflow.

### Azure Training

* [The Developer's Guide to Azure](https://azure.microsoft.com/en-us/campaigns/developer-guide/) - Free Microsoft Azure training.
* [Awesome Azure Learning](https://github.com/ddneves/awesome-azure-learning) - Azure learning and certification resources.
* [AZ-500 Azure Security Technologies labs](https://microsoftlearning.github.io/AZ500-AzureSecurityTechnologies/)
  * [Azure AZ-500 Study Guide](https://github.com/AzureMentor/Azure-AZ-500-Study-Guide)
  * [Azure AZ-500 labs by Microsoft](https://github.com/MicrosoftLearning/AZ500-AzureSecurityTechnologies)
* [Breaking and Pwning Apps and Servers on AWS and Azure](https://github.com/appsecco/breaking-and-pwning-apps-and-servers-aws-azure-training)
* [Learn Azure in a Month of Lunches](https://azure.microsoft.com/mediahandler/files/resourcefiles/learn-azure-in-a-month-of-lunches/Learn_Azure_in_a_Month_of_Lunches.pdf)
* [Azure for Architects, Third Edition](https://azure.microsoft.com/en-us/resources/azure-for-architects/) - Account may be required.
* [Azure Functions Succinctly](https://www.syncfusion.com/ebooks/azure-functions-succinctly) - Syncfusion ebook.

### Azure CLI and Administration

* [Azure CLI documentation](https://learn.microsoft.com/en-us/cli/azure/)
* [Azure CLI cheatsheet](https://github.com/ferhaty/azure-cli-cheatsheet)
* _Operator Handbook: Azure CLI - pg. 39_
* Find whether a target organization has Azure AD:
  * `https://login.microsoftonline.com/getuserrealm.srf?login=username@<victimorganization>.onmicrosoft.com&xml=1`
* [Azure Active Directory documentation](https://learn.microsoft.com/en-us/azure/active-directory/)
* [Attacking and Defending the Microsoft Cloud](https://adsecurity.org/wp-content/uploads/2019/08/2019-BlackHat-US-Metcalf-Morowczynski-AttackingAndDefendingTheMicrosoftCloud.pdf)
* [AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)

### Microsoft Sentinel and KQL

Microsoft Sentinel was formerly named Azure Sentinel. Keep cloud SIEM architecture and logging under Security Logging; keep KQL references in Blue Defense.

* [Microsoft Sentinel overview](https://learn.microsoft.com/en-us/azure/sentinel/overview)
* [Microsoft Sentinel service page](https://azure.microsoft.com/en-us/products/microsoft-sentinel/)
* [Microsoft Sentinel hunting queries](https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries)
* [Microsoft Sentinel notebooks](https://github.com/Azure/Azure-Sentinel-Notebooks)
* [Microsoft Sentinel To-Go](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/azure-sentinel-to-go-part1-a-lab-w-prerecorded-data-amp-a-custom/ba-p/1260191)
* [KQL quick reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
* [KQL cheat sheet](https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet.pdf)
* [Kqlmagic](https://learn.microsoft.com/en-us/azure/data-explorer/kqlmagic)
* [AzSentinel PowerShell module](https://www.powershellgallery.com/packages/AzSentinel) - Historical community module; verify current maintenance before building workflows around it.

### Microsoft Defender for Cloud

Azure Security Center and Azure Defender are now part of Microsoft Defender for Cloud.

* [Microsoft Defender for Cloud overview](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)
* [Microsoft Defender for Cloud repository](https://github.com/Azure/Microsoft-Defender-for-Cloud)
* [Azure security basics: Log Analytics, Security Center, and Sentinel](https://defensiveorigins.com/azure-security-basics-log-analytics-security-center-sentinel/) - Older naming, still useful as historical context.
* [Detecting Microsoft 365 and Azure Active Directory backdoors](https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors) - FireEye/Mandiant research.

### Azure Pentesting Guides

* [PayloadsAllTheThings - Azure Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)
* [Pentest Book - Azure](https://pentestbook.six2dez.com/enumeration/cloud/azure)
* [Azure Testing guide](https://github.com/LennonCMJ/pentest_script/blob/master/Azure_Testing.md)
* [Azure AD Introduction for Red Teamers](https://www.synacktiv.com/en/publications/azure-ad-introduction-for-red-teamers.html)
* [Hacking Azure AD via Active Directory](https://www.slideshare.net/DirkjanMollema/im-in-your-cloud-reading-everyones-email-hacking-azure-ad-via-active-directory)
* [Utilizing Azure Services for Red Team Engagements](https://blog.netspi.com/utiilzing-azure-for-red-team-engagements/) - Older article; URL typo is preserved by the source.
* [Blue Cloud of Death: Red Teaming Azure](https://speakerdeck.com/tweekfawkes/blue-cloud-of-death-red-teaming-azure-1)
* [Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* [Red Teaming Microsoft: AD leaks via Azure](https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/)
* [How to create a backdoor to Azure AD](https://o365blog.com/post/aadbackdoor/)
* [AzureHound collection](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html)
  * [AzureHound Cypher Cheatsheet](https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/)
* [Keys of the Kingdom: Playing God as Global Admin](https://o365blog.com/post/admin/)
* [The Attacker's Guide to Azure AD Conditional Access](https://danielchronlund.com/2022/01/07/the-attackers-guide-to-azure-ad-conditional-access/)
* [Check for Azure blobs](https://xapax.github.io/security/#attacking_cloud_environment/attacking_azure/check_for_blobs/)
  * [Video walkthrough](https://www.youtube.com/watch?v=AWhag2K3AS8)
* [Abusing Azure AD SSO with the Primary Refresh Token](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
* [Attacking Azure Cloud Shell](https://blog.netspi.com/attacking-azure-cloud-shell/)
* [Nuking all Azure Resource Groups under all Azure Subscriptions](https://kmcquade.com/2020/11/nuking-all-azure-resource-groups-under-all-azure-subscriptions/)
* [Privilege Escalation and Lateral Movement on Azure](https://medium.com/xm-cyber/privilege-escalation-and-lateral-movement-on-azure-part-1-47e128cfdc06)
* [Privilege Escalation in Azure AD](https://emptydc.com/2020/12/10/privilege-escalation-in-azure-ad/)
* [Azure privilege escalation via Azure API permissions abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48?gi=89b4a351f786)
* [Making clouds rain RCE in Office 365](https://srcincite.io/blog/2021/01/12/making-clouds-rain-rce-in-office-365.html)
* [Backdooring Azure applications](https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html)
* [Backdooring Office 365 and Active Directory](https://www.inversecos.com/2021/09/backdooring-office-365-and-active.html)
* [Office 365 attacks: bypassing MFA and persistence](https://www.inversecos.com/2021/09/office365-attacks-bypassing-mfa.html)
* [Spoofing Microsoft 365 Like It's 1995](https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/)
* _Operator Handbook: Azure_Exploit - pg. 44_

### Azure and Microsoft 365 Tools

#### Offensive

* [BlobHunter](https://github.com/cyberark/BlobHunter) - Scans Azure blob storage accounts for public blobs.
* [o365recon](https://github.com/nyxgeek/o365recon) - Retrieves O365 information with valid credentials.
* [Get-AzureADPSPermissionGrants.ps1](https://gist.github.com/psignoret/9d73b00b377002456b24fcb808265c23) - Lists delegated and application permission grants.
* [PowerZure](https://github.com/hausec/PowerZure) - Azure and Azure AD assessment and exploitation framework.
  * [Introducing PowerZure](https://hausec.com/2020/01/31/attacking-azure-azure-ad-and-introducing-powerzure/)
* [MicroBurst](https://github.com/NetSPI/MicroBurst) - Azure discovery, auditing, and post-exploitation PowerShell toolkit.
* [lava](https://github.com/mattrotlevi/lava) - Microsoft Azure exploitation framework.
* [XMGoat](https://www.xmcyber.com/xmgoat-an-open-source-pentesting-tool-for-azure/) - Azure misconfiguration lab.
* [AADInternals](https://github.com/Gerenios/AADInternals) - Azure AD and Microsoft 365 administration and assessment module.
* [Stormspotter](https://github.com/Azure/Stormspotter) - Graphs Azure and Azure AD objects for red-team analysis.
* [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD framework including ROADrecon.
* [adconnectdump](https://github.com/fox-it/adconnectdump) - Azure AD Connect password extraction.
* [TeamFiltration](https://github.com/Flangvik/TeamFiltration) - Enumerates, sprays, exfiltrates, and backdoors O365/AAD accounts.
* Microsoft 365 password spraying belongs with Password Attacks:

{% content-ref url="red-offensive/testing-methodology/password-attacks.md" %}
[password-attacks.md](red-offensive/testing-methodology/password-attacks.md)
{% endcontent-ref %}

#### Defensive and DFIR

* [CRT](https://github.com/CrowdStrike/CRT) - CrowdStrike Reporting Tool for Azure.
* [AzureADRecon](https://github.com/adrecon/AzureADRecon) - Azure AD tenant reporting.
* [azucar](https://github.com/nccgroup/azucar) - Security auditing tool for Azure environments.
* [AzureADAssessment](https://github.com/AzureAD/AzureADAssessment) - Azure AD tenant assessment tooling.
* [AzureHunter](https://github.com/darkquasar/AzureHunter) - Azure and O365 threat hunting playbooks.
  * [AzureHunter documentation](https://azurehunter.readthedocs.io/)
* [Sparrow](https://github.com/cisagov/Sparrow) - CISA cloud forensics tool for M365/Azure account and application compromise.
* [Hawk](https://github.com/T0pCyber/hawk) - PowerShell collection tool for O365 intrusion investigation.
  * [Cloud Forensicator](https://cloudforensicator.com/)
* [DFIR-O365RC](https://github.com/ANSSI-FR/DFIR-O365RC) - Collects Microsoft 365 logs for Business Email Compromise investigations.
* [Azure AD Incident Response PowerShell Module](https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module)
  * [PowerShell Gallery package](https://www.powershellgallery.com/packages/AzureADIncidentResponse/)

## AWS - Amazon Web Services

### Basics

* [AWS security study plan](https://github.com/jassics/security-study-plan/blob/main/aws-security-study-plan.md)
* [AWS documentation](https://docs.aws.amazon.com/)
* [AWS documentation GitHub organization](https://github.com/awsdocs)
* [AWS IP ranges JSON](https://ip-ranges.amazonaws.com/ip-ranges.json)
* [amazon-ec2-user-guide](https://github.com/toniblyx/amazon-ec2-user-guide)
* [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework)
* [AWS Security Reference Architecture examples](https://github.com/aws-samples/aws-security-reference-architecture-examples)
* [AWS Security Hub CIS standards](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-cis.html)
* [Finding evil in AWS](https://expel.io/blog/finding-evil-in-aws/)
* [Generating AWS security signals from CloudTrail](https://expel.io/blog/following-cloudtrail-generating-aws-security-signals-sumo-logic/)
* _Operator Handbook: AWS Terms - pg. 35_

### AWS CLI

* [AWS CLI](https://aws.amazon.com/cli/)
* [AWS CLI getting started](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)
* [AWS CheatSheet](https://github.com/eon01/AWS-CheatSheet)
* _Operator Handbook: AWS CLI - pg. 20_

### AWS Pentesting Guides

* [AWS Customer Support Policy for Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
* [PayloadsAllTheThings - AWS Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md)
* [AWS IAM explained for Red and Blue teams](https://medium.com/bugbountywriteup/aws-iam-explained-for-red-and-blue-teams-2dda8b20fbf7)
* [AWS S3 penetration testing](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - Rhino Security Labs.
* [AWS Penetration Testing Part 1: S3 Buckets](https://www.virtuesecurity.com/aws-penetration-testing-part-1-s3-buckets/)
* [AWS Penetration Testing Part 2: S3, IAM, EC2](https://www.virtuesecurity.com/aws-penetration-testing-part-2-s3-iam-ec2/)
* [Pentest Book - AWS](https://pentestbook.six2dez.com/enumeration/cloud/aws)
* [AWS penetration testing guide](https://www.getastra.com/blog/security-audit/aws-penetration-testing/)
* _Operator Handbook: AWS Tips and Tricks - pg. 20_
* _The Hacker Playbook 3: Cloud Recon and Enumeration - pg. 37_

### AWS Services and Attack Surfaces

| AWS Service | Testing focus |
| --- | --- |
| EC2 | Public service exposure, OS vulnerabilities, instance metadata access, and STS credential paths. |
| S3 | Anonymous access, broad bucket policies, object ACLs, public snapshots, and authenticated-user exposure. |
| ELB/ALB | HTTP request smuggling and load-balancer parsing differences. |
| SNS/SQS | Misconfigured topics and queues that allow unauthorized subscribe, publish, or receive actions. |
| RDS/Aurora/Redshift | Public exposure, weak access controls, and snapshot sharing. |
| EBS | Public snapshots and leaked sensitive data. |
| Cognito Authentication | Self-signup, weak app-client settings, token handling, and missing advanced security features. |

### AWS Tools

#### Offensive

* [Bucket_finder](https://digi.ninja/projects/bucket_finder.php) - Finds and tests Amazon buckets.
  * [What's in Amazon's buckets?](https://digi.ninja/blog/whats_in_amazons_buckets.php)
* [bucket-stream](https://github.com/eth0izzle/bucket-stream) - Finds S3 buckets by watching certificate transparency logs.
* [S3Scanner](https://github.com/sa7mon/S3Scanner) - Scans for open S3 buckets and dumps contents.
* [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework for authorized testing.
  * [Pacu wiki](https://github.com/RhinoSecurityLabs/pacu/wiki/)
  * [Kali Pacu package](https://www.kali.org/tools/pacu/)
  * [Pacu overview](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/)
  * _Operator Handbook: Pacu - pg. 31_
* [Nimbostratus](https://github.com/andresriancho/nimbostratus) - AWS fingerprinting and exploitation.
  * _Operator Handbook: Nimbostratus - pg. 30_
* [weirdAAL](https://github.com/carnal0wnage/weirdAAL) - AWS Attack Library.
  * [weirdAAL wiki](https://github.com/carnal0wnage/weirdAAL/wiki)

#### Defensive, DFIR, and Hunting

* [Arsenal of AWS Tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
  * [aws-security-toolbox](https://github.com/toniblyx/aws-security-toolbox)
  * [aws-forensic-tools](https://github.com/toniblyx/aws-forensic-tools)
* [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - AWS IAM least-privilege assessment.
  * [Cloudsplaining documentation](https://cloudsplaining.readthedocs.io/en/latest/)
* [Prowler](https://github.com/prowler-cloud/prowler) - AWS security best-practice assessment, audits, IR, continuous monitoring, and hardening.
* [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud Security Posture Management checks.
* [CloudMapper](https://github.com/duo-labs/cloudmapper) - AWS environment analysis.
* [cloudtracker](https://github.com/duo-labs/cloudtracker) - Compares CloudTrail logs with IAM policies to find over-privileged roles and users.
* [aws-recon](https://github.com/darkbitio/aws-recon) - Multi-threaded AWS inventory collection.
* [review-security-groups](https://github.com/MrSecure/review-security-groups) - Summarizes AWS Security Groups and visualizes rules.
* [cloudtrail2sightings](https://github.com/zmallen/cloudtrail2sightings) - Converts CloudTrail data to MITRE ATT&CK Sightings.
* [aws_ir](https://github.com/ThreatResponse/aws_ir) - AWS incident response utility.
* [acquire-aws-ec2](https://github.com/telekom-security/acquire-aws-ec2) - Captures EC2 instances during IR.
* [Incident Response in AWS](https://www.chrisfarris.com/post/aws-ir/)
* [AWS threat hunting repo](https://github.com/schwartz1375/aws)

### AWS Training

* [Cloud Hacking](https://www.udemy.com/course/cloud-hacking/)
* [AWS Security Fundamentals](https://cloudacademy.com/course/aws-security-fundamentals/introduction-74/)

## Google Cloud

### Guides and Reference

* [GCP cheat sheet](https://cheatsheet.dennyzhang.com/cheatsheet-gcp-a4)
* [Security controls and forensic analysis for GKE apps](https://cloud.google.com/architecture/security-controls-and-forensic-analysis-for-GKE-apps)
* [Pub/Sub quickstart CLI](https://cloud.google.com/pubsub/docs/quickstart-cli)
* [Google Cloud penetration testing rules](https://support.google.com/cloud/answer/6262505?hl=en)
* [Pentest Book - GCP](https://pentestbook.six2dez.com/enumeration/cloud/gcp)
* [gcp_security](https://github.com/irgoncalves/gcp_security)
* [GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)
* [Hardening your GKE cluster](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
* _Operator Handbook: GCP CLI - pg. 70_
* _Operator Handbook: GCP Exploit - pg. 75_
