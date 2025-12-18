# Username/Email

## Usernames and Email Addresses

Corporate usernames have become increasingly predictable, following standardized naming conventions such as FIRSTNAME.LASTNAME@CORP.com. This consistency extends to account management systems, which often derive usernames from the email prefix. Security professionals can leverage these patterns to identify:

* Accounts on other services using the same username
* Credentials exposed in data breaches
* Associated websites, social media profiles, and online tools
* Linked accounts across multiple platforms

Username and email enumeration is a fundamental OSINT technique that can reveal substantial intelligence about individuals and organizations.

## Username and Email Address Analysis Tools

**Username.html and Email.html**

These complementary tools often produce overlapping results, but it's best practice to search both the username and email address separately to capture any discrepancies. These tools perform two primary functions:

1. **Presence Detection**: Verify if the username or email exists on various platforms
2. **Exposure Analysis**: Identify any publicly available or leaked information associated with the credentials

{% file src="../../.gitbook/assets/Username (1).html" %}

{% file src="../../.gitbook/assets/Email.html" %}

<details>

<summary>Username Search Tools</summary>

* [WhatsMyName](https://whatsmyname.app/) - Enumerate usernames across multiple websites and platforms
  * [GitHub Repository](https://github.com/WebBreacher/WhatsMyName)
* [UserSearch.org](https://usersearch.org/) - Dedicated search engine for username discovery
* [NameChk](https://namechk.com/) - Check username availability across multiple platforms simultaneously
* [Namecheckr](https://www.namecheckr.com/) - Check username and domain availability across social media and web
* [Sherlock](https://github.com/sherlock-project/sherlock) - Hunt down social media accounts by username across [400+ social networks](https://github.com/sherlock-project/sherlock/blob/master/sites.md)
  * [Kali Tools Documentation](https://www.kali.org/tools/sherlock/)
* [Maigret](https://github.com/soxoj/maigret) - Collect information about username across 2500+ sites, improved fork of Sherlock
* [socialscan](https://github.com/iojw/socialscan) - Python library and CLI for accurately querying username and email usage on online platforms
* [Blackbird](https://github.com/p1ngul1n0/blackbird) - Search for usernames across 600+ social networks and websites
* [AnalyzeID](https://analyzeid.com/username/) - Check username availability across social media platforms and gather basic profile information
* [IDCrawl](https://www.idcrawl.com/) - Free people search engine aggregating social network information, deep web data, phone numbers, and email addresses
* [Instant Username Search](https://instantusername.com/) - Check username availability across multiple social media platforms instantly
* [KnowEm](https://knowem.com/) - Check username or real name availability across 500+ popular and emerging social media platforms

</details>

<details>

<summary>Email Address Search Tools</summary>

* [MXToolBox](https://mxtoolbox.com/) - Comprehensive suite of tools for gathering data about email addresses and domains
* [Seon Email Analysis](https://seon.io/intelligence-tool/#email-analysis-module) - Enrich user profiles and gather intelligence based on a single email address
* [Epieos Tools](https://tools.epieos.com/) - Suite of tools for email address investigation including account discovery and Google ID lookup
  * [Holehe GitHub](https://github.com/megadose/holehe) - CLI tool for checking email registration across 120+ platforms
* [EmailRep.io](https://emailrep.io/) - Query email reputation and registration data across multiple platforms
* [OSINT Industries](https://osint.industries/) - Email and username lookup across breaches and online accounts

</details>

<details>

<summary>Breach Data and Credential Exposure</summary>

Identify whether usernames or email addresses have been exposed in data breaches:

* [Have I Been Pwned](https://haveibeenpwned.com/) - Check if an email address has been compromised in a data breach. Includes API access for automated queries (API key required).
* [DeHashed](https://dehashed.com/) - Search engine for leaked credentials and breach data across thousands of databases (paid subscription required for full access)
* [LeakCheck](https://leakcheck.io/) - Database of leaked credentials with detailed breach information and search capabilities (paid plans for detailed results)
* [IntelligenceX](https://intelx.io/) - Search engine for leaked databases, documents, and credentials (free tier available with limitations)
* [Snusbase](https://snusbase.com/) - Comprehensive breach data search engine with advanced filtering options (paid subscription required)
* [LeakIX](https://leakix.net/) - Search engine for open databases and data leaks
* [Dehashed API Tool](https://github.com/hmaverickadams/DeHashed-API-Tool) - Python CLI tool to query DeHashed API (requires DeHashed subscription)
* [BreachDirectory API](https://breachdirectory.org/) - Free API access to breach data for checking email compromise

</details>

<details>

<summary>Email Address Enumeration Tools</summary>

Use these tools when you have identified a target but need to discover their email address:

* [Hunter.io](https://hunter.io/) - Discover email addresses by company name or domain (free tier has limited searches)
* [Voila Norbert](https://www.voilanorbert.com/) - Email discovery service using company name or individual details (now VoilaNorbert by Kaspr, requires account)
* [Clearbit Connect](https://connect.clearbit.com/) - Powerful email discovery tool (Chrome extension required, limited free searches)
* [Email Format](https://www.email-format.com/) - Identify email address format patterns used by specific companies or domains
* [Snov.io Email Finder](https://snov.io/email-finder) - Locate employee email addresses using domain names (requires account for full functionality)
* [RocketReach](https://rocketreach.co/) - Professional email finder with extensive database (limited free searches)
* [Apollo.io](https://www.apollo.io/) - Sales intelligence platform with email discovery features

</details>

<details>

<summary>Email Verification Tools</summary>

Verify whether an email address is valid and actively registered before conducting further investigation:

* [Email Hippo](https://tools.verifyemailaddress.io/) - Connects to mail servers to verify whether an email address and mailbox actually exist
* [Verify Email](https://verify-email.org/) - Validates email addresses by connecting directly to mail servers and checking mailbox existence
* [Email Checker](https://www.emailchecker.com/) - Real-time email validation that confirms address correctness and active status without sending messages
* [NeverBounce](https://neverbounce.com/) - Enterprise-grade email verification service with real-time validation
* [ZeroBounce](https://www.zerobounce.net/) - Email validation and deliverability service with detailed verification

</details>

<details>

<summary>CLI Email Intelligence Tools</summary>

* [TheHarvester](https://github.com/laramies/theharvester) - Industry-standard tool for email intelligence gathering that aggregates information from numerous sources. Supports API integration with services like Censys and Shodan (API keys required). Highly effective when combined with web-based tools listed above.
* [Infoga](https://github.com/m4ll0k/Infoga) - Gathers comprehensive email account information (IP address, hostname, country) from multiple public sources including search engines, PGP key servers, and Shodan. Includes breach detection via haveibeenpwned.com API. Note: Repository not actively maintained but tool remains functional.
* [email2phonenumber](https://github.com/martinvigo/email2phonenumber) - OSINT tool for obtaining a target's phone number from their email address through Google services correlation. Note: Effectiveness has decreased due to Google privacy changes.
* [GHunt](https://github.com/mxrch/GHunt) - Google account information scraper that extracts publicly available data from Google accounts (actively maintained)
* [h8mail](https://github.com/khast3x/h8mail/) - Email OSINT and password breach hunting tool supporting both local and premium service searches. Features related email tracking and correlation. (Note: Some data sources may require updates)
* [EmailFinder](https://github.com/Josue87/EmailFinder) - Discovers email addresses associated with a domain using search engine queries
* [Crosslinked](https://github.com/m8r0wn/crosslinked) - LinkedIn enumeration tool to extract valid employee names from an organization for email permutation

</details>

<details>

<summary>Comprehensive OSINT Frameworks</summary>

These frameworks automate multiple OSINT techniques including username and email enumeration:

* [SpiderFoot](https://github.com/smicallef/spiderfoot) - Automated OSINT reconnaissance tool that integrates with 200+ data sources. Performs comprehensive email, username, and domain analysis.
* [Recon-ng](https://github.com/lanmaster53/recon-ng) - Full-featured web reconnaissance framework with modules for email harvesting, breach data searches, and account enumeration
* [Maltego](https://www.maltego.com/) - Data mining and link analysis tool excellent for visualizing relationships between usernames, emails, domains, and social media accounts
* [OSINT Framework](https://osintframework.com/) - Comprehensive directory of OSINT tools organized by category (reference this for additional username/email tools)
* [Sn1per](https://github.com/1N3/Sn1per) - Automated pentest reconnaissance scanner with OSINT capabilities including email and username discovery

</details>

<details>

<summary>Profile Picture and Avatar Analysis</summary>

Profile pictures can be used to correlate accounts across platforms:

* [Gravatar Search](https://en.gravatar.com/) - Search for profile pictures associated with email addresses via Gravatar service
* [PimEyes](https://pimeyes.com/) - Reverse image search specifically for faces (paid subscription required for full results)
* [TinEye](https://tineye.com/) - Reverse image search to track where profile pictures appear online
* [Google Images](https://images.google.com/) - Reverse image search functionality for finding profile picture matches
* [Social Searcher](https://www.social-searcher.com/) - Free social media search engine to find profile pictures and posts

</details>

## Email Permutation and Enumeration Techniques

### Common Email Format Patterns

When enumerating corporate email addresses, test these common patterns:

* `firstname.lastname@company.com` (most common)
* `firstnamelastname@company.com`
* `firstname_lastname@company.com`
* `f.lastname@company.com`
* `flastname@company.com`
* `firstname.l@company.com`
* `firstname@company.com`
* `lastname.firstname@company.com`
* `firstinitiallastname@company.com`

### Email Verification via SMTP Commands

SMTP servers can be queried to verify email existence (note: many modern servers disable these for security):

* **VRFY** - Verify if an email address exists
* **EXPN** - Expand mailing list membership
* **RCPT TO** - Check if server accepts mail for an address

### Google Dorking for Email Discovery

Advanced Google search operators for finding email addresses:

```
site:company.com intext:"@company.com"
site:linkedin.com "@company.com"
filetype:pdf "@company.com"
site:github.com "@company.com"
site:pastebin.com "@company.com"
```

### Username Correlation Techniques

1. **Pattern Analysis**: Identify naming patterns from known accounts
2. **Cross-Platform Validation**: Verify same username exists on multiple platforms
3. **Temporal Analysis**: Check account creation dates for correlation
4. **Behavior Correlation**: Match posting times, language patterns, and interests
5. **Bio/Description Matching**: Compare profile descriptions for similar content

---

## Deprecated or Unreliable Tools

<details>

<summary>Tools No Longer Recommended</summary>

These tools were previously included but are now deprecated, shut down, or have become unreliable. They are kept here for historical reference.

**Email Enumeration:**
* [Phonebook.cz](https://phonebook.cz/) - Service has been shut down and is no longer accessible. Consider using IntelligenceX or Hunter.io as alternatives.
* [EmailCrawlr](https://emailcrawlr.com/) - Service appears to be offline or unreliable. Use Hunter.io or Apollo.io instead.
* [Public Mail Records](https://publicemailrecords.com/) - Service reliability has declined significantly.

**Email Verification:**
* [TruMail](https://trumail.io/) - API service is no longer reliably accessible. Use Email Hippo or NeverBounce as alternatives.

**Username Search:**
* [Lullar Search](https://www.lullar.com/) - Service functionality has declined and results are often limited.
* [Stalker](https://gitlab.com/Pxmme/stalker) - GitLab repository appears inactive; tool may not be maintained.
* [finduser](https://github.com/xHak9x/finduser) - Repository archived and no longer maintained. Use Sherlock, Maigret, or Blackbird instead.

**Note:** When a tool becomes unavailable, consider using comprehensive frameworks like SpiderFoot or Recon-ng which aggregate multiple data sources and are regularly maintained.

</details>

---

{% embed url="https://youtu.be/VytCL2ujjcA" %}

## Investigation Mind Maps

![](../../.gitbook/assets/proxy-image.png)

![](<../../.gitbook/assets/image (34).png>)
