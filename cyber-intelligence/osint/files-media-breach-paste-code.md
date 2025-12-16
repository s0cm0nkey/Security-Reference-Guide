# Files/Media/Breach/Paste/Code

## Files and Documents

Files and media are among the most valuable targets to investigate when planning a penetration test. Companies that regularly publish content to the web frequently overlook sensitive information that should never have left the organization. Common discoveries include email distribution lists, internal-only email addresses perfect for phishing campaigns, personnel information, client communications, and more. Don't forget to check public-facing FTP servers—they often contain sensitive data hidden in plain sight.

**Documents.html**

Documents.html is a tool that enables you to search for various file types associated with a target-related search term. Choose terms that are as unique as possible while remaining relevant to the target, such as company names, platform identifiers, application names, or client references. For optimal coverage, perform multiple searches using different search terms.

<details>

<summary>Document Search Tools</summary>

* [Google Custom Search Engine for Documents](https://cse.google.com/cse?cx=001580308195336108602:vvchyaurf\_4#gsc.tab=0)
* [PowerMeta](https://github.com/dafthack/PowerMeta) - PowerMeta searches for publicly available files hosted on various websites for a particular domain by using specially crafted Google, and Bing searches. It then allows for the download of those files from the target domain. After retrieving the files, the metadata associated with them can be analyzed by PowerMeta. Some interesting things commonly found in metadata are usernames, domains, software titles, and computer names.
* [goofile](https://www.kali.org/tools/goofile/) - Use this tool to search for a specific file type in a given domain.
* [FilePhish](https://cartographia.github.io/FilePhish/) - A simple OSINT Google query builder for fast and easy document and file discovery.
* [MetaFinder](https://github.com/Josue87/MetaFinder) - Search for documents in a domain through Search Engines (Google, Bing and Baidu). The objective is to extract metadata
* [Archive.org Wayback Machine](https://web.archive.org/) - Access historical versions of websites and documents that may no longer be publicly available. Essential for finding deleted or modified content.
* [FOCA](https://github.com/ElevenPaths/FOCA) - Fingerprinting Organizations with Collected Archives. Extracts metadata and hidden information from documents.

</details>

{% file src="../../.gitbook/assets/Documents (1).html" %}

<details>

<summary>Public Directory, FTP, and Cloud</summary>

* [https://www.filechef.com](https://www.filechef.com) - Search for open directories and files on the web or in Google Drives via keywords. Including document, video, audio, image and executable files. Uses Google dorks.
* [Napalm FTP Indexer](https://www.searchftps.net/) - Search for documents in public FTP servers
* [MMNT](https://www.mmnt.ru/) - Russian FTP indexer
* [GrayHatWarfare](https://buckets.grayhatwarfare.com/) - Search for publicly accessible AWS S3 buckets, Azure blobs, and Google Cloud Storage buckets.
* [MS Azure Portal](https://ms.portal.azure.com/) - Search for public blobs
* [https://osint.sh/buckets/](https://osint.sh/buckets/) - Find public AWS and Azure buckets and documents via keyword.
* [https://www.gdrivesearch.com/](https://www.gdrivesearch.com/) - A simple and fast tool that allows you to search Google Drive for files.
* [https://www.reddit.com/r/opendirectories/](https://www.reddit.com/r/opendirectories/) - Unprotected directories of pics, vids, music, software and otherwise interesting files.

</details>

<details>

<summary>Article, Presentation, and Book search</summary>

* [https://libgen.rs/](https://libgen.rs/) - This is the largest free library in human history. Giving the world free access to over 84 million scholarly journals, over 6.6 million academic and general-interest books, over 2.2 million comics, and over 381 thousand magazines. Commonly referred to as "Libgen" for short. Libgen has zero regard for copyright.
* [Sci-Hub](https://sci-hub.se/) - A "shadow library" that provides free access to millions of research papers and books by bypassing paywalls. Note: Domain frequently changes due to legal actions. Current mirrors can be found via search engines. Sci-Hub has zero regard for copyright.
* [https://the-eye.eu/public](https://the-eye.eu/public) - An open directory data archive dedicated to the long-term preservation of any and all data including websites, books, games, software, video, audio, other digital-obscura and ideas. Currently hosts over 140TB of data for free.
  * [https://eyedex.org](https://eyedex.org) - A searchable index of the-eye.eu. Much faster than manually digging through subfolders or using Google dorks.
* [https://doaj.org](https://doaj.org) - Search over 16,000 journals, over 6.5 million articles in 80 different languages from 129 different countries.
* [https://www.slideshare.net/](https://www.slideshare.net/) - Allows users to upload content including presentations, infographics, documents, and videos. Users can upload files privately or publicly in PowerPoint, Word, PDF, or OpenDocument format. Note: SlideShare is now part of Scribd.

</details>

## **Images/Videos**

Michael Bazzell's **Images.html** and **Videos.html** tools help search for visual content across multiple platforms. Whether you're looking for employee faces, photos of security badges that could be replicated, or images containing extractable metadata, starting with a comprehensive image search is essential. While Google's image search is highly effective, alternative platforms can yield unique and valuable discoveries.

**Note:** These tools are designed to find images associated with search terms. If you already have an image and need to extract information from it, refer to the Image Analysis and Forensics section below or the dedicated Forensics section of this guide.

* [OSHINT IMGINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/imagery-intelligence-imint)

<details>

<summary>Image Analysis and Forensics</summary>

* [FotoForensics](https://fotoforensics.com/) - Free and public photo forensics tools.
* [https://www.imageforensic.org/](https://www.imageforensic.org/) - Image Metadata Analysis tool
* [https://github.com/GuidoBartoli/sherloq](https://github.com/GuidoBartoli/sherloq) - An open-source digital image forensic toolset
* [https://www.peteyvid.com/](https://www.peteyvid.com/) - A video and audio search engine that searches over 70 different platforms.
* [CameraTrace](http://www.cameratrace.com/trace)  - Trace the location a camera has been by the metadata it embeds in photos that end up on the internet.
* [ExifTool](https://exiftool.org/) - Platform-independent library and command-line application for reading, writing and editing metadata in a wide variety of files.
* [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi) - Online tool for viewing and analyzing image metadata.
* [InVID/WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) - Browser plugin for video and image verification, useful for detecting manipulated media.

</details>

<details>

<summary>Reverse Image Search</summary>

* [The Wolfram Language Image Identification Project](https://www.imageidentify.com/)&#x20;
* [Yandex Images](https://yandex.com/images/) — Often superior to Google for reverse image search, particularly for non-Western content
* [Bing Visual Search](https://www.bing.com/visualsearch) — Microsoft's reverse image search with strong results for product identification
* [pic.sogou.com](https://pic.sogou.com/) — chinese reverse image search engine
* [Image So Search](https://image.so.com/) — Qihoo 360 Reverse Images Search
* [Revesearch.com](https://revesesearch.com) — allows to upload an image once and immediately search for it in #Google, #Yandex, and #Bing.
* [Pixsy](https://pixsy.com) — allows to upload pictures from computer, social networks or cloud storages, and then search for their duplicates and check if they are copyrighted
* [Image Search Assistant](https://chrome.google.com/webstore/detail/image-search-assistant/kldhhobmmejaeaiilomaibhjlcfpceac/related) — searches for a picture, screenshot or fragment of a screenshot in several search engines and stores at once
* [openi.nlm.nih.gov](https://openi.nlm.nih.gov/gridquery) — Reverse image search engine for scientific and medical images
* [DepositPhotos Reverse Image Search](https://ru.depositphotos.com/search/by-images.html) — tool for reverse image search (strictly from DepositPhoto's collection of 222 million files).
* [EveryPixel](https://www.everypixel.com/) — Reverse image search engine. Search across 50 leading stock images agencies. It's possible to filter only free or only paid images.
* [https://tineye.com/](https://tineye.com/) - Image search engine.

</details>

<details>

<summary>Facial Recognition</summary>

* [PimEyes](https://pimeyes.com/en) - Powerful facial recognition and reverse image search engine. Requires paid subscription for detailed results and alerts.
* [FindFace](https://findface.pro/) - Russian face search engine. Searches VK and other Russian social networks.
* [Face Recognition](https://github.com/ageitgey/face\_recognition) — facial recognition api for Python and the command line
* [Search4faces.com](https://search4faces.com/) — search people in VK, Odnoklassniki, TikTok and ClubHouse by photo or identikit

</details>

<details>

<summary>Misc Utility</summary>

Clothing/Shopping

* [Searchbyimage.app](https://searchbyimage.app/) — search clothes in online shops
* [Aliseeks.com](https://www.aliseeks.com/search) — search items by photo in AliExpress and Ebay
* [lykdat.com](https://lykdat.com/) — clothing reverse image search services

</details>

{% file src="../../.gitbook/assets/Images.html" %}

{% file src="../../.gitbook/assets/Videos (1).html" %}

## **Breach/Leak/Paste data**&#x20;

Data breaches provide a treasure trove of information including credentials, linked data, and password hashes. These breaches often expose individuals and organizations with poor cybersecurity hygiene. Credentials from major breaches frequently become the basis for password lists used in attacks, such as the infamous rockyou.txt wordlist originating from a 2009 breach.

The tools and resources below can be used to search known data breaches and leaks, as well as to monitor and receive alerts when credentials appear in newly reported breach data.\
\
Paste sites like Pastebin have recently restricted their search capabilities. Pastebin itself has removed the ability to directly search its pastes. However, you can still search for breach data using Google dorks by including "site:pastebin.com" in your search query.

<details>

<summary>Breach Report and Search Tools</summary>

* [DeHashed](https://www.dehashed.com/) - Premium breach search engine (paid subscription required). Search by email, username, IP address, physical address, phone, domain, VIN, and more. One of the most comprehensive breach databases available.
* [Have I Been Pwned](https://haveibeenpwned.com/) - Free service to check if your email or phone has been compromised in a data breach. Created by Troy Hunt. Includes Pwned Passwords API.&#x20;
* [Scylla](https://scylla.so/) - Community-driven breach data search platform. Free to use with registration.
* [https://leak-lookup.com/](https://leak-lookup.com/) - Leak-Lookup allows you to search across thousands of data breaches to stay on top of credentials that may have been compromised, allowing you to proactively stay on top of the latest data leaks with ease. AKA Citadel&#x20;
* [https://breachdirectory.org](https://breachdirectory.org) - Search via email address, username or phone number to see censored passwords. They also provide the full password as a SHA-1 hash, which can easily be cracked.
* [https://leaked.site/](https://leaked.site/) - Leaked database search with extensive coverage. Requires paid subscription.
* [Snusbase](https://snusbase.com/) - Breach database search with frequent updates and large collection. Paid subscription required.
* [LeakCheck.io](https://leakcheck.io/) - Breach database search service. Offers both API access and web interface. Paid plans available.
* [BreachForums](https://breached.to/) - Community forum for breach discussions and data sharing. Domain may change due to law enforcement actions. Exercise caution.
* [Intelligence X](https://intelx.io/) - Search engine and data archive with breach data, darknet sources, pastes, and historical internet data. Offers free searches with limitations and paid plans.
* [Pwndb](http://pwndb2am4tzkvold.onion/) - Tor-based breach database search (requires Tor browser)
* [h8mail](https://github.com/khast3x/h8mail) - Email OSINT and breach hunting tool that queries multiple breach data sources via API
* [http://4wbwa6vcpvcr3vvf4qkhppgy56urmjcj2vagu2iqgp3z656xcmfdbiqd.onion/](http://4wbwa6vcpvcr3vvf4qkhppgy56urmjcj2vagu2iqgp3z656xcmfdbiqd.onion/) - An .onion site that allows you to search through the full 2019 Facebook data breach.

</details>

{% file src="../../.gitbook/assets/Breaches.html" %}

<details>

<summary>Paste Search Tools</summary>

* [https://psbdmp.ws/](https://psbdmp.ws/) - Pastebin dump search and monitoring service. Indexes pastes in real-time.
* [Pastebin.com](https://pastebin.com/) - Popular paste hosting site. Direct search functionality removed; use Google dorks with `site:pastebin.com` to search.
* [https://redhuntlabs.com/online-ide-search](https://redhuntlabs.com/online-ide-search) - Search and find strings across multiple IDEs, code aggregators and paste sites.
* [https://doxbin.org](https://doxbin.org) - A document sharing and publishing website which invites users to contribute personally identifiable information (PII), or a "dox" of any person of interest. It previously operated on the darknet as a TOR hidden service.
  * Search for Doxbin/Databin in TOR
* [https://cipher387.github.io/pastebinsearchengines/](https://cipher387.github.io/pastebinsearchengines/) - 5 Google Custom Search Engine for search 48 pastebin sites
* [Rentry.co](https://rentry.co/) - Markdown-based pastebin gaining popularity as an alternative to traditional paste sites
* [Justpaste.it](https://justpaste.it/) - Popular paste site frequently used for leak distribution
* [Telegram](https://t.me/) - Many data leaks and breach discussions now occur in Telegram channels. Search for relevant channels using keywords.
* [Discord](https://discord.com/) - Discord servers frequently host breach discussions and data sharing. Use server discovery tools to find relevant communities.

</details>

<details>

<summary>Misc Tools and Resources</summary>

* [Search WikiLeaks](https://search.wikileaks.org/)&#x20;
* [Cryptome](https://cryptome.org/) - Archive of publicly leaked documents since 1996. Usually government and intelligence-related.
* [Breach Alarm Sources](https://breachalarm.com/sources) - Comprehensive, easy-to-read list tracking known data breaches.
* [Firefox Monitor](https://monitor.firefox.com/) - Mozilla's free breach monitoring service. Checks if your accounts appear in known data breaches and provides alerts for new breaches. Powered by Have I Been Pwned data.
* [Analysis Information Leak framework](https://github.com/ail-project/ail-framework) - AIL is a modular framework to analyze potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams.
* [breach-parse](https://github.com/hmaverickadams/breach-parse) - A tool for parsing breached passwords by The Cyber Mentor. Repo also contains large breach data collections.
* [https://www.reddit.com/r/DataHoarder/](https://www.reddit.com/r/DataHoarder/) - This is a sub that aims at bringing data hoarders together to share their passion with like minded people.
* [https://www.reddit.com/r/DHExchange/](https://www.reddit.com/r/DHExchange/) - Exchange and Sharing sub for /r/DataHoarder

</details>



## Code Repositories

Code repositories represent a goldmine for security reconnaissance. Despite growing awareness, many organizations still lack mature DevSecOps practices. Software engineers frequently commit sensitive information to public repositories—whether storing code snippets for later use or posting configuration files on forums when seeking help. Often, these seemingly innocent posts inadvertently expose credentials and other sensitive data. Repository searches are particularly valuable during penetration tests against organizations with active software development teams.&#x20;

While numerous code repository platforms exist, the following are considered essential for security reconnaissance:

* Github - [https://github.com/](https://github.com/)
* GitLab - [https://about.gitlab.com/](https://about.gitlab.com/)
* Bitbucket - [https://bitbucket.org/](https://bitbucket.org/)
* Stack Overflow - [https://stackoverflow.com/](https://stackoverflow.com/)
* Source Forge - [https://sourceforge.net/](https://sourceforge.net/)
* Gitea - [https://gitea.io/](https://gitea.io/) - Self-hosted Git service; many organizations run public instances

You can manually parse these by user or subject but there are some handy tools that can help search and keep track.

**Important Search Techniques:**
* **Certificate Transparency Logs** - Use [crt.sh](https://crt.sh/) to find subdomains that may host development servers or exposed repositories
* **Archive.org for Deleted Content** - Check archived versions of repository pages or organization profiles for deleted repos or commits
* **GitHub Gist Search** - Don't forget GitHub Gists, which often contain sensitive snippets: `site:gist.github.com "company-name"`
* **Docker Hub Search** - [hub.docker.com](https://hub.docker.com/) may reveal organization repositories with embedded secrets in container images
* **NPM/PyPI Package Search** - Check package registries for organization-published packages that may contain sensitive configuration

<details>

<summary>Code Repo Search Tools</summary>

* [OSINT Stuff's CSE for search 20 source code hosting services](https://cipher387.github.io/code\_repository\_google\_custom\_search\_engines/)
* [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Actively maintained and recommended. Searches git repositories for secrets across commit history and branches. Features 700+ credential detectors, high-entropy string detection, and verification of findings.
* [Gitleaks](https://www.kali.org/tools/gitleaks/) - Fast SAST tool for detecting hardcoded secrets like passwords, API keys, and tokens in git repos. Supports custom rules and integrates with CI/CD pipelines.
* [GitDorker](https://github.com/obheda12/GitDorker) - Python tool to scrape secrets from GitHub using an extensive dork repository. Useful for automated GitHub reconnaissance.
* [Repo Supervisor](https://github.com/auth0/repo-supervisor) - Find secrets and passwords in your code&#x20;
* [Watchman](https://papermtn.co.uk/gitlab-github-watchman/) - Git change monitor&#x20;
* [https://grep.app/](https://grep.app/) - A search engine for contents of Git Repos
* [gitoops](https://github.com/ovotech/gitoops) - GitOops is a tool to help attackers and defenders identify lateral movement and privilege escalation paths in GitHub organizations by abusing CI/CD pipelines and GitHub access controls.
* [https://searchcode.com/](https://searchcode.com/) - Search 75 billion lines of code from 40 million projects
* [Sourcegraph](https://sourcegraph.com/search) - Universal code search across multiple repositories with powerful search syntax
* [GitHub Advanced Search](https://github.com/search/advanced) - GitHub's native advanced search with extensive filters and operators
* [Semgrep](https://semgrep.dev/) - Static analysis tool for finding code patterns, useful for identifying security issues across repositories
* [https://publicwww.com/](https://publicwww.com/) - Source code search engine that lets you find any alphanumeric snippet in web page HTML, JS, and CSS code
* [https://pentestbook.six2dez.com/enumeration/webservices/github](https://pentestbook.six2dez.com/enumeration/webservices/github)

</details>

<details>

<summary>Github Dorking</summary>

* [https://github.com/techgaun/github-dorks](https://github.com/techgaun/github-dorks)
* [https://github.com/jcesarstef/ghhdb-Github-Hacking-Database](https://github.com/jcesarstef/ghhdb-Github-Hacking-Database)
* [https://github.com/H4CK3RT3CH/github-dorks](https://github.com/H4CK3RT3CH/github-dorks)
* [https://github.com/Vaidik-pandya/Github\_recon\_dorks/blob/main/gitdork.txt](https://github.com/Vaidik-pandya/Github\_recon\_dorks/blob/main/gitdork.txt) (for finding files)

</details>

<details>

<summary>Dorking Word List</summary>

​ ".mlab.com password" "access\_key" "access\_token" "amazonaws" "api.googlemaps AIza" "api\_key" "api\_secret" "apidocs" "apikey" "apiSecret" "app\_key" "app\_secret" "appkey" "appkeysecret" "application\_key" "appsecret" "appspot" "auth" "auth\_token" "authorizationToken" "aws\_access" "aws\_access\_key\_id" "aws\_key" "aws\_secret" "aws\_token" "AWSSecretKey" "bashrc password" "bucket\_password" "client\_secret" "cloudfront" "codecov\_token" "config" "conn.login" "connectionstring" "consumer\_key" "credentials" "database\_password" "db\_password" "db\_username" "dbpasswd" "dbpassword" "dbuser" "dot-files" "dotfiles" "encryption\_key" "fabricApiSecret" "fb\_secret" "firebase" "ftp" "gh\_token" "github\_key" "github\_token" "gitlab" "gmail\_password" "gmail\_username" "herokuapp" "internal" "irc\_pass" "JEKYLL\_GITHUB\_TOKEN" "key" "keyPassword" "ldap\_password" "ldap\_username" "login" "mailchimp" "mailgun" "master\_key" "mydotfiles" "mysql" "node\_env" "npmrc \_auth" "oauth\_token" "pass" "passwd" "password" "passwords" "pem private" "preprod" "private\_key" "prod" "pwd" "pwds" "rds.amazonaws.com password" "redis\_password" "root\_password" "secret" "secret.password" "secret\_access\_key" "secret\_key" "secret\_token" "secrets" "secure" "security\_credentials" "send.keys" "send\_keys" "sendkeys" "SF\_USERNAME salesforce" "sf\_username" "site.com" FIREBASE\_API\_JSON= "site.com" vim\_settings.xml "slack\_api" "slack\_token" "sql\_password" "ssh" "ssh2\_auth\_password" "sshpass" "staging" "stg" "storePassword" "stripe" "swagger" "testuser" "token" "x-api-key" "xoxb " "xoxp" \[WFClient] Password= extension:ica access\_key bucket\_password dbpassword dbuser extension:avastlic "support.avast.com" extension:bat extension:cfg extension:env extension:exs extension:ini extension:json api.forecast.io extension:json googleusercontent client\_secret extension:json mongolab.com extension:pem extension:pem private extension:ppk extension:ppk private extension:properties extension:sh extension:sls extension:sql extension:sql mysql dump extension:sql mysql dump password extension:yaml mongolab.com extension:zsh filename:.bash\_history filename:.bash\_history DOMAIN-NAME filename:.bash\_profile aws filename:.bashrc mailchimp filename:.bashrc password filename:.cshrc filename:.dockercfg auth filename:.env DB\_USERNAME NOT homestead filename:.env MAIL\_HOST=smtp.gmail.com filename:.esmtprc password filename:.ftpconfig filename:.git-credentials filename:.history filename:.htpasswd filename:.netrc password filename:.npmrc \_auth filename:.pgpass filename:.remote-sync.json filename:.s3cfg filename:.sh\_history filename:.tugboat NOT \_tugboat filename:\_netrc password filename:apikey filename:bash filename:bash\_history filename:bash\_profile filename:bashrc filename:beanstalkd.yml filename:CCCam.cfg filename:composer.json filename:config filename:config irc\_pass filename:config.json auths filename:config.php dbpasswd filename:configuration.php JConfig password filename:connections filename:connections.xml filename:constants filename:credentials filename:credentials aws\_access\_key\_id filename:cshrc filename:database filename:dbeaver-data-sources.xml filename:deployment-config.json filename:dhcpd.conf filename:dockercfg filename:environment filename:express.conf filename:express.conf path:.openshift filename:filezilla.xml filename:filezilla.xml Pass filename:git-credentials filename:gitconfig filename:global filename:history filename:htpasswd filename:hub oauth\_token filename:id\_dsa filename:id\_rsa filename:id\_rsa or filename:id\_dsa filename:idea14.key filename:known\_hosts filename:logins.json filename:makefile filename:master.key path:config filename:netrc filename:npmrc filename:pass filename:passwd path:etc filename:pgpass filename:prod.exs filename:prod.exs NOT prod.secret.exs filename:prod.secret.exs filename:proftpdpasswd filename:recentservers.xml filename:recentservers.xml Pass filename:robomongo.json filename:s3cfg filename:secrets.yml password filename:server.cfg filename:server.cfg rcon password filename:settings filename:settings.py SECRET\_KEY filename:sftp-config.json filename:sftp-config.json password filename:sftp.json path:.vscode filename:shadow filename:shadow path:etc filename:spec filename:sshd\_config filename:token filename:tugboat filename:ventrilo\_srv.ini filename:WebServers.xml filename:wp-config filename:wp-config.php filename:zhrc HEROKU\_API\_KEY language:json HEROKU\_API\_KEY language:shell HOMEBREW\_GITHUB\_API\_TOKEN language:shell jsforce extension:js conn.login language:yaml -filename:travis msg nickserv identify filename:config org:Target "AWS\_ACCESS\_KEY\_ID" org:Target "list\_aws\_accounts" org:Target "aws\_access\_key" org:Target "aws\_secret\_key" org:Target "bucket\_name" org:Target "S3\_ACCESS\_KEY\_ID" org:Target "S3\_BUCKET" org:Target "S3\_ENDPOINT" org:Target "S3\_SECRET\_ACCESS\_KEY" password path:sites databases password private -language:java PT\_TOKEN language:bash redis\_password root\_password secret\_access\_key SECRET\_KEY\_BASE= shodan\_api\_key language:python WORDPRESS\_DB\_PASSWORD= xoxp OR xoxb OR xoxa s3.yml .exs beanstalkd.yml deploy.rake .sls

</details>

## **Training**

* [https://tryhackme.com/room/geolocatingimages](https://tryhackme.com/room/geolocatingimages)
* [https://tryhackme.com/room/searchlightosint](https://tryhackme.com/room/searchlightosint)

---

## **Deprecated/Legacy Tools**

The following tools are no longer maintained, have been shut down, or have better alternatives. They are listed here for historical reference and in case they become available again.

<details>

<summary>Deprecated Document Search Tools</summary>

* [UVRX.com](http://www.uvrx.com/) - File storage search engine (Site defunct/unreliable)
* [Palined.com](http://palined.com/search/) - Open directory search (Site defunct)

</details>

<details>

<summary>Deprecated Image/Video Tools</summary>

* [Portrait Matcher](http://zeus.robots.ox.ac.uk/portraitmatcher/index?error=agree) - Face to painting matcher (Service no longer available)
* [Pictriev](http://pictriev.com/) - Face search engine (Service frequently unavailable/unreliable)

</details>

<details>

<summary>Deprecated Breach Search Tools</summary>

* [WeLeakInfo.to](https://weleakinfo.to/) - Seized by law enforcement in 2020. Was a major breach database search site.
* [GhostProject.fr](https://ghostproject.fr/) - Free breach database search (Site frequently unavailable/unreliable)
* [MyPwd.io](https://mypwd.io/) - Password leak monitoring (Service status unreliable)
* [pwd query](https://pwdquery.xyz/) - Password breach checking (Site frequently down)

</details>

<details>

<summary>Deprecated Paste Search Tools</summary>

* [Pastebin.ga](https://pastebin.ga/) - Multi-paste site search (Site defunct)
* [PasteLert](https://andrewmohawk.com/pasteLert/) - Paste monitoring service (Service no longer maintained)

</details>

<details>

<summary>Deprecated Code Repository Tools</summary>

* [Gitrob](https://github.com/michenriksen/gitrob) - No longer maintained. Use TruffleHog or GitLeaks instead.
* [Git-all-secrets](https://github.com/anshumanbh/git-all-secrets) - No longer actively maintained. Consider alternatives like TruffleHog.
* [TruffleHog Legacy](https://github.com/dxa4481/truffleHog) - Original version, superseded by TruffleHog v3+
* [trufflehog3](https://github.com/feeltheajf/trufflehog3) - Enhanced fork, but official TruffleHog now incorporates similar features

</details>

<details>

<summary>Deprecated Presentation Tools</summary>

* [Slideshare-downloader](https://slideshare-downloader.herokuapp.com/) - Heroku free tier deprecated, service may be unreliable

</details>
