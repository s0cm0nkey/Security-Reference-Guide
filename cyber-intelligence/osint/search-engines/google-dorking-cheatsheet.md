# Google Dorking

Google Dorking (also known as Google Hacking) is a technique that uses advanced search operators to find specific information indexed by Google. This technique is commonly used in security assessments, penetration testing, and OSINT investigations to discover exposed sensitive information, vulnerable systems, and misconfigured websites.

## Google Dork Collections

* [https://github.com/BullsEye0/google\_dork\_list](https://github.com/BullsEye0/google\_dork\_list)
* [https://github.com/rootac355/SQL-injection-dorks-list](https://github.com/rootac355/SQL-injection-dorks-list)
* [https://github.com/unexpectedBy/SQLi-Dork-Repository](https://github.com/unexpectedBy/SQLi-Dork-Repository)
* [https://github.com/thomasdesr/Google-dorks](https://github.com/thomasdesr/Google-dorks)
* [https://github.com/arimogi/Google-Dorks](https://github.com/arimogi/Google-Dorks)
* [https://github.com/aleedhillon/7000-Google-Dork-List](https://github.com/aleedhillon/7000-Google-Dork-List)
* Bug Bounty Dorks
  * [https://github.com/sushiwushi/bug-bounty-dorks](https://github.com/sushiwushi/bug-bounty-dorks)
  * [https://github.com/hackingbharat/bug-bounty-dorks-archive/blob/main/bbdorks](https://github.com/hackingbharat/bug-bounty-dorks-archive/blob/main/bbdorks)
  * [https://github.com/Vinod-1122/bug-bounty-dorks/blob/main/Dorks.txt](https://github.com/Vinod-1122/bug-bounty-dorks/blob/main/Dorks.txt)
* Backlinks
  * [https://github.com/alfazzafashion/Backlink-dorks](https://github.com/alfazzafashion/Backlink-dorks)
  * [https://www.techywebtech.com/2021/08/backlink-dorks.html](https://www.techywebtech.com/2021/08/backlink-dorks.html)
  * [https://www.blackhatworld.com/seo/get-backlinks-yourself-1150-dorks-for-forum-hunting.380843/](https://www.blackhatworld.com/seo/get-backlinks-yourself-1150-dorks-for-forum-hunting.380843/)
  * CMS Dorks
    * Wordpress [https://pastebin.com/A9dsmgHQ](https://pastebin.com/A9dsmgHQ)
    * Magento [https://pastebin.com/k75Y2QhF](https://pastebin.com/k75Y2QhF)
    * Joomla [https://pastebin.com/vVQFTzVC](https://pastebin.com/vVQFTzVC)

## Google Dorking Cheatsheet

### Basic Search Operators

* **@[username]** - Searches for social media tags or usernames
  * Example: `@twitter` or `@johndoe`
  * Results vary by platform and context
* **"search term"** - Searches for an exact phrase match
* **"search * term"** - Uses asterisk (*) as a wildcard to match any word
* **-[term]** - Excludes a specific term from search results
* **term1 | term2** - Boolean OR operator; finds pages with either term
* **OR** - Alternative syntax for the | operator (e.g., `term1 OR term2`)
* **(term1 | term2)** - Parentheses group multiple queries together
* **#..#** - Number range operator; finds numbers within a range
  * Example: `camera $200..$500` finds cameras priced between $200-$500
  * Much more reliable than the deprecated `numrange:` operator
* **AROUND(X)** - Proximity search; finds pages where terms appear within X words of each other
  * Example: `security AROUND(3) breach` finds pages where "security" and "breach" are within 3 words
  * Note: This operator is not officially documented and may have inconsistent results in standard Google Search
  * Works more reliably in Google Scholar and Google Books

### Advanced Search Operators

* **site:[domain]** - Limits results to a specific domain or website
  * Example: `site:example.com` or `site:.gov`
  * One of the most reliable and useful operators for security research
* **info:[url]** - Shows information Google has about a specific URL
  * Example: `info:example.com`
  * Note: This operator's functionality has been reduced and may simply redirect to a search for the URL

### Content-Specific Operators

* **intitle:[string]** - Shows pages with the specified term in the HTML title
  * Example: `intitle:"index of"`
* **allintitle:[string]** - Shows pages with all specified terms in the HTML title
* **inurl:[string]** - Searches for the specified term in the URL
  * Example: `inurl:admin` or `inurl:login.php`
* **allinurl:[string]** - Shows pages with all specified terms in the URL
* **intext:[string]** - Searches for the specified term in the page content
  * Example: `intext:"index of /"`
* **allintext:[string]** - Shows pages with all specified terms in the page content
* **filetype:[extension]** - Searches for specific file types
  * Example: `filetype:pdf`, `filetype:xls`, `filetype:sql`, `filetype:env`
  * Note: `ext:` is sometimes mentioned as an alternative but is not officially documented; use `filetype:` for reliability
  * Extremely powerful for finding exposed documents and configuration files
  * Common security-relevant extensions: `env`, `config`, `log`, `bak`, `sql`, `conf`, `yml`, `yaml`

### Additional Useful Operators

* **before:[date]** and **after:[date]** - Filters results by publication date
  * Example: `data breach after:2024-01-01 before:2024-12-31`
  * Format: YYYY-MM-DD
  * More reliable than the deprecated `daterange:` operator

### Advanced Combination Techniques

These examples demonstrate powerful combinations of multiple operators:

* **Finding exposed credentials and sensitive files:**
  * `site:pastebin.com "password" "@company.com"`
  * `filetype:env "DB_PASSWORD"`
  * `filetype:sql intext:"INSERT INTO" intext:"password"`
  * `site:github.com "api_key" OR "apikey" -example -sample`

* **Discovering subdomains and related infrastructure:**
  * `site:*.example.com -www`
  * `site:example.com inurl:admin OR inurl:login OR inurl:dashboard`
  * `inurl:example.com -site:example.com` (finds references to the domain elsewhere)

* **Finding specific vulnerabilities or technologies:**
  * `intitle:"index of" site:example.com filetype:log`
  * `inurl:"/phpinfo.php" "PHP Version"`
  * `intitle:"Apache Status" "Apache Server Status for"`
  * `inurl:wp-admin site:*.edu` (finds WordPress admin pages on .edu domains)

* **Locating exposed documents with sensitive data:**
  * `filetype:xlsx site:gov.uk intext:"confidential"`
  * `filetype:pdf "internal use only" AROUND(5) budget`
  * `(filetype:doc OR filetype:docx) "not for distribution"`

* **Finding exposed cameras and IoT devices:**
  * `intitle:"webcamXP 5" OR intitle:"webcam 7"`
  * `inurl:"/view/index.shtml" "Network Camera"`
  * `intitle:"Axis Video Server" | intitle:"Live View"`

* **Excluding common false positives:**
  * `security breach -example -sample -test -demo`
  * `api key site:github.com -tutorial -"how to" -documentation`

### Operators with Limited Reliability

These operators may still work but have known issues or inconsistent behavior:

* **cache:[url]** - Previously displayed Google's cached version of a specific page
  * **Status**: Google removed the cache link from search results in February 2024
  * **Issue**: While the operator may still work occasionally, it's no longer officially supported
  * **Alternative**: Use [Archive.org Wayback Machine](https://web.archive.org/) or [archive.today](https://archive.today/) for historical page snapshots
  * **Recommendation**: Don't rely on this operator; use dedicated archiving services instead

* **numrange:[#]..[#]** - Searches for numbers within a specified range
  * **Status**: Inconsistent behavior across different searches
  * **Issue**: Often returns irrelevant results or fails to properly filter by the specified range
  * **Alternative**: Combine multiple searches with specific numbers or use site-specific search features
  * **Recommendation**: Test thoroughly if you need to use this; consider it unreliable for production use

* **daterange:[startdate]-[enddate]** - Filters results by date range using Julian dates
  * **Status**: Julian date format support has degraded significantly
  * **Issue**: Complex date format (days since 4713 B.C.) is unintuitive and no longer processes reliably
  * **Alternative**: Use Google's built-in date filter (Tools → Any time → Custom range)
  * **Recommendation**: Always use the native UI date filter instead; it's more reliable and user-friendly

### Deprecated Operators (No Longer Functional)

These operators have been officially removed by Google and will not return results:

* **phonebook:[name]** - Previously searched phone book listings
  * **Deprecated**: 2010
  * **Reason**: Privacy concerns and shift away from public directory services
  * **Alternative**: Use specialized people search services or OSINT tools like Pipl, Spokeo, or WhitePages

* **related:[url]** - Previously found websites similar to a specified URL
  * **Deprecated**: 2017
  * **Reason**: Google discontinued this feature without official explanation
  * **Alternative**: Use [SimilarWeb](https://www.similarweb.com/) or manual analysis of competing sites

* **link:[url]** - Previously showed pages that link to a specified URL
  * **Deprecated**: Gradually phased out around 2017-2019
  * **Reason**: Incomplete data and potential for abuse in SEO manipulation
  * **Alternative**: Use professional SEO tools:
    * [Ahrefs](https://ahrefs.com/) - Comprehensive backlink analysis
    * [SEMrush](https://www.semrush.com/) - Backlink checker and competitor analysis
    * [Google Search Console](https://search.google.com/search-console) - Official Google tool for your own sites
    * [Moz Link Explorer](https://moz.com/link-explorer) - Free limited backlink data
  * **Note**: For security research, backlink analysis can reveal relationships between domains and potential attack vectors

### Practical Examples for Security Research

#### Finding Exposed Directories
* `intitle:"index of" "parent directory"`
* `inurl:"index of /" site:example.com`

#### Discovering Login Pages
* `inurl:admin.php site:example.com`
* `intitle:"login" inurl:admin`

#### Identifying Exposed Files
* `filetype:sql "INSERT INTO" password`
* `filetype:inc intext:mysql_connect`
* `filetype:sql + "IDENTIFIED BY" -cvs`

#### Finding Vulnerable Servers
* `inurl:8080 -intext:8080` - Servers listening on port 8080
* `intitle:"VNC viewer"` - VNC remote access interfaces

#### Searching for Email Addresses
* `site:example.com "@example.com"`
* `intext:"@example.com" filetype:xls`

#### Refining Search Results
* `site:example.com -site:obvious.example.com` - Excludes obvious/known subdomains to surface hidden content

### Advanced Techniques

#### Case Variation
* Varying the case of file extensions can help bypass some search restrictions
* Example: `admin.php`, `admin.PhP`, `admin.PHP`
* Note: This technique is less effective than it used to be as Google's search is increasingly case-insensitive

#### Query Optimization Tips
* **Use wildcards strategically**: `"admin * panel"` is more flexible than `"admin panel"`
* **Combine site with minus**: `site:.gov -site:.mil` searches government sites excluding military
* **Stack multiple file types**: `(filetype:sql OR filetype:db OR filetype:mdb)` finds multiple database file types
* **Use parentheses for complex logic**: `site:example.com (inurl:admin | inurl:login) -inurl:demo`

#### Relationship Mapping
* `site:target.com -site:www.target.com` - Finds subdomains and related infrastructure
* `"target.com" -site:target.com` - Finds external references to the target domain
* `site:*.target.com` - Discovers all indexed subdomains
* `"contact@target.com" OR "@target.com" -site:target.com` - Finds employee email addresses on external sites

#### Multi-Operator Searches for Comprehensive Recon
* `site:target.com (inurl:admin OR inurl:login OR inurl:panel) (intext:username OR intext:password)`
* `site:target.com (filetype:php OR filetype:asp OR filetype:aspx) inurl:id=`
* `site:target.com (filetype:pdf OR filetype:doc OR filetype:xls) (confidential OR internal OR private)`

## Important Notes for Security Professionals

### Legal and Ethical Considerations
* **Always get authorization**: Only perform Google dorking on systems you have permission to test
* **Respect robots.txt**: Google respects robots.txt for crawling, but indexed content may still appear in search results
* **Responsible disclosure**: If you discover exposed sensitive data, follow responsible disclosure practices
* **Automation concerns**: Excessive automated queries may trigger Google's CAPTCHA or rate limiting

### Best Practices
* **Document your findings**: Keep detailed logs of your queries and results for reporting
* **Use VPN/proxies for sensitive searches**: Protect your identity when researching threat actors
* **Combine with other OSINT tools**: Google dorking is most effective as part of a comprehensive reconnaissance strategy
* **Stay updated**: Google frequently changes how operators work; always verify current functionality
* **Alternative search engines**: Consider using Bing, DuckDuckGo, or specialized search engines like Shodan for different perspectives

---

**Sources:**
* [Bishop Fox Breaking and Entering Pocket Guide](https://know.bishopfox.com/hubfs/mkt-coll/Bishop-Fox-Breaking-and-Entering-Pocket-Guide.pdf)
* [Google Search Operators Documentation](https://support.google.com/websearch/)
* Community-contributed techniques and best practices

