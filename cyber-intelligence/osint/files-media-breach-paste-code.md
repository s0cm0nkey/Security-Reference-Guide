# Files/Media/Breach/Paste/Code

## Files and Documents

Files and Media are one of the more juicy targets to look for when planning a penetration test. For companies that publish things to the web on a regular basis, there is constantly information that is overlooked and should not have been sent out of the organization. I have found things like email distribution lists, Internal only email addresses perfect for phishing, personnel information, client communications, etc. Dont forget public facing FTP servers. They always seem to have something juicy hidden in them.

**Documents.html**

Documents.html is a tool that allows you to take a search term related to your target, and search for various file types associated with the term. The term should be something as unique as possible, but still related to the target: company name, platform, application, client, etc. Perform multiple searches for various terms for the best coverage.

{% file src="../../.gitbook/assets/Documents (1).html" %}

* [Google Custom Search Engine for Documents](https://cse.google.com/cse?cx=001580308195336108602:vvchyaurf\_4#gsc.tab=0)
* [http://www.uvrx.com/](http://www.uvrx.com) - The most comprehensive online file storage search engine. They have individual search engines for badongo, Mediafire, Zshare, 4shared and taringa. They also provide a search all function that searches filefactory, depositfiles, easy-share, sharedzilla, sendspace, yousendit, letitbit, drop, sharebee, rapidspread, and many others.
* [PowerMeta](https://github.com/dafthack/PowerMeta) - PowerMeta searches for publicly available files hosted on various websites for a particular domain by using specially crafted Google, and Bing searches. It then allows for the download of those files from the target domain. After retrieving the files, the metadata associated with them can be analyzed by PowerMeta. Some interesting things commonly found in metadata are usernames, domains, software titles, and computer names.
* [goofile](https://www.kali.org/tools/goofile/) - Use this tool to search for a specific file type in a given domain.
* [FilePhish](https://cartographia.github.io/FilePhish/) - A simple OSINT Google query builder for fast and easy document and file discovery.
* [MetaFinder](https://github.com/Josue87/MetaFinder) - Search for documents in a domain through Search Engines (Google, Bing and Baidu). The objective is to extract metadata

### Public Directory, FTP, and Cloud

* [http://palined.com/search/](http://palined.com/search/) - Search for files and open directories via keyword. Uses a Google CSE.
* [https://www.filechef.com](https://www.filechef.com) - Search for open directories and files on the web or in Google Drives via keywords. Including document, video, audio, image and executable files. Uses Google dorks.
* [Napalm FTP Indexer](https://www.searchftps.net) - Search for documents in public FTP servers
* [MMNT](https://www.mmnt.ru) - Russian FTP indexer
* [GreyhatWarfare Public AWS Buckets](https://buckets.grayhatwarfare.com) - Search for publically acessible AWS S3 buckets.
* [MS Azure Portal](https://ms.portal.azure.com) - Search for public blobs
* [https://osint.sh/buckets/](https://osint.sh/buckets/) - Find public AWS and Azure buckets and documents via keyword.
* [https://www.gdrivesearch.com/](https://www.gdrivesearch.com) - A simple and fast tool that allows you to search Google Drive for files.
* [https://www.reddit.com/r/opendirectories/](https://www.reddit.com/r/opendirectories/) - Unprotected directories of pics, vids, music, software and otherwise interesting files.

### Article, Presentation, and Book search

* [https://libgen.rs/](https://libgen.rs) - This is the largest free library in human history. Giving the world free access to over 84 million scholarly journals, over 6.6 million academic and general-interest books, over 2.2 million comics, and over 381 thousand magazines. Commonly referred to as "Libgen" for short. Libgen has zero regard for copyright.
* [https://sci-hub.se/](https://sci-hub.se) - A "shadow library" that provides free access to millions of research papers and books by bypassing paywalls. SciHub has zero regard for copyright.
* [https://the-eye.eu/public](https://the-eye.eu/public) - An open directory data archive dedicated to the long-term preservation of any and all data including websites, books, games, software, video, audio, other digital-obscura and ideas. Currently hosts over 140TB of data for free.
  * [https://eyedex.org](https://eyedex.org) - A searchable index of the-eye.eu. Much faster than manually digging through subfolders or using Google dorks.
* [https://doaj.org](https://doaj.org) - Search over 16,000 journals, over 6.5 million articles in 80 different languages from 129 different countries.
* [https://www.slideshare.net/](https://www.slideshare.net) - Allows users to upload content including presentations, infographics, documents, and videos. Users can upload files privately or publicly in PowerPoint, Word, PDF, or OpenDocument format
  *   [https://slideshare-downloader.herokuapp.com](https://slideshare-downloader.herokuapp.com) - Enter the URL of any Slideshare document and this tool will download it for you.

      ​

## **Images/Videos**

While having other functionality Michael Bazzell's **Images.html** and **Videos.html** tool helps search for image terms across multiple platforms. Looking for faces of employees? Maybe a picture of their security badge you can copy? Image of a target you can extract metadata from later? Start with a good image search. Google is hard to beat for this but there are other platforms that can lead to some interesting discoveries.

\*Note - this tool is only to find images associated with a search term. If you have an image and you would like to find out more information about it, that will be discussed under the Forensics section.

* [OSHINT IMGINT Links](https://ohshint.gitbook.io/oh-shint-its-a-blog/osint-web-resources/imagery-intelligence-imint)

{% file src="../../.gitbook/assets/Images.html" %}

{% file src="../../.gitbook/assets/Videos (1).html" %}

* [CameraTrace](http://www.cameratrace.com/trace)  - Trace the location a camera has been by the metadata it embeds in photos that end up on the internet.
* [FotoForensics](https://fotoforensics.com) - Free and public photo forensics tools.
* [https://www.imageforensic.org/](https://www.imageforensic.org) - Image Metadata Analysis tool
* [https://github.com/GuidoBartoli/sherloq](https://github.com/GuidoBartoli/sherloq) - An open-source digital image forensic toolset
* [https://www.peteyvid.com/](https://www.peteyvid.com) - A video and audio search engine that searches over 70 different platforms.
* Reverse Image Search
  * [The Wolfram Language Image Identification Project](https://www.imageidentify.com)&#x20;
  * [pic.sogou.com](https://pic.sogou.com) — chinese reverse image search engine
  * [Image So Search](https://image.so.com) — Qihoo 360 Reverse Images Search
  * [Revesearch.com](https://revesesearch.com) — allows to upload an image once and immediately search for it in #Google, #Yandex, and #Bing.
  * [Pixsy](https://pixsy.com) — allows to upload pictures from computer, social networks or cloud storages, and then search for their duplicates and check if they are copyrighted
  * [Image Search Assistant](https://chrome.google.com/webstore/detail/image-search-assistant/kldhhobmmejaeaiilomaibhjlcfpceac/related) — searches for a picture, screenshot or fragment of a screenshot in several search engines and stores at once
  * [openi.nlm.nih.gov](https://openi.nlm.nih.gov/gridquery) — Reverse image search engine for scientific and medical images
  * [DepositPhotos Reverse Image Search](https://ru.depositphotos.com/search/by-images.html) — tool for reverse image search (strictly from DepositPhoto's collection of 222 million files).
  * [EveryPixel](https://www.everypixel.com) — Reverse image search engine. Search across 50 leading stock images agencies. It's possible to filter only free or only paid images.
* Facial Recognition
  * [pictriev](http://pictriev.com)  - Search engine for faces. Upload the picture of choice and find links to other pictures with similar people.
  * [PimEyes](https://pimeyes.com/en) - Facial recognition and reverse image search
  * [Portrait Matcher](http://zeus.robots.ox.ac.uk/portraitmatcher/index?error=agree) — Upload a picture of a face and get three paintings that show similar people.
  * [FindFace](https://findface.pro) - Russian face search engine.
  * [Face Recognition](https://github.com/ageitgey/face\_recognition) — facial recognition api for Python and the command line
  * [Search4faces.com](https://search4faces.com) — search people in VK, Odnoklassniki, TikTok and ClubHouse by photo or identikit
* Clothing/Shopping
  * [Searchbyimage.app](https://searchbyimage.app) — search clothes in online shops
  * [Aliseeks.com](https://www.aliseeks.com/search) — search items by photo in AliExpress and Ebay
  * [lykdat.com](https://lykdat.com) — clothing reverse image search services

## **Breach/Leak/Paste data**&#x20;

Looking for easy creds? Linked data? Password hash? Breaches can be a trove for low hanging fruit for those targeting those not diligent with their cyber hygiene. Often times, the credentials found in large data breaches will turn into password lists such as the infamous rockyou.txt password list that came from a sizeable breach in 2009.

The below tools and links can be used to parse data in known data breaches and leaks, or be used for detection and alert for the presence of credentials when new breach data is reported.\
\
Paste sites like Pastebin have recently changed their ability to be parsed. Pastebin itself has removed the ability to to search its pastes. However, with a bit of clever google dorking, you can still search for breach data by submitting your search along with "insite:pastebin.com"

* [https://www.dehashed.com/](https://www.dehashed.com) - Premium but well worth it, Breach data site. Can search by multiple types of indicators like email, IP, address, domain, even password.
* [Have I Been Pwned](https://haveibeenpwned.com) - Check if your email has been compromised in a data breach&#x20;
* [Scylla](https://scylla.so) - One of the greatest breach parsing tools available.
* [https://leak-lookup.com/](https://leak-lookup.com) - Leak-Lookup allows you to search across thousands of data breaches to stay on top of credentials that may have been compromised, allowing you to proactively stay on top of the latest data leaks with ease. AKA Citadel&#x20;
* [https://breachdirectory.org](https://breachdirectory.org) - Search via email address, username or phone number to see censored passwords. They also provide the full password as a SHA-1 hash, which can easily be cracked.
* [https://mypwd.io/](https://mypwd.io) - A tool for monitoring leaked passwords for accounts linked to emails. Actually shows you the leaked passwords.
* [https://leaked.site/](https://leaked.site) - Another leaked database search. Requires a paid subscription.
* [https://weleakinfo.to/](https://weleakinfo.to) - Provides you the best leaked breached databases downloads. Requires a paid subscription.
* [http://4wbwa6vcpvcr3vvf4qkhppgy56urmjcj2vagu2iqgp3z656xcmfdbiqd.onion/](http://4wbwa6vcpvcr3vvf4qkhppgy56urmjcj2vagu2iqgp3z656xcmfdbiqd.onion) - An .onion site that allows you to search through the full 2019 Facebook data breach.

{% file src="../../.gitbook/assets/Breaches.html" %}

### Paste Tools

* [https://psbdmp.ws/](https://psbdmp.ws) - Pastebin search tool
* [Pastebin.com - #1 paste tool since 2002!](https://pastebin.com) - Search through Paste dumps for various data.
* [https://pastebin.ga](https://pastebin.ga) - Allows you to search over 33 different paste sites. Uses a Google CSE.
* [https://redhuntlabs.com/online-ide-search](https://redhuntlabs.com/online-ide-search) - Search and find strings across multiple IDEs, code aggregators and paste sites.
* [https://doxbin.org](https://doxbin.org) - A document sharing and publishing website which invites users to contribute personally identifiable information (PII), or a "dox" of any person of interest. It previously operated on the darknet as a TOR hidden service.
  * Search for Doxbin/Databin in TOR
* [https://cipher387.github.io/pastebinsearchengines/](https://cipher387.github.io/pastebinsearchengines/) - 5 Google Custom Search Engine for search 48 pastebin sites

### Misc Tools and Resources

* [Search WikiLeaks](https://search.wikileaks.org)&#x20;
* [Cryptome](https://cryptome.org) - Archive of publicly leaked documents. Usually government related.
* [easy-to-read breach list](https://breachalarm.com/sources) - Easy and helpful tracker for breach data.
* [Firefox Monitor](https://monitor.firefox.com) - Great tool for searching if your accounts have been found in a breach and can alert you when new breaches are discovered and parsed.
* [pwd query](https://pwdquery.xyz) - Check if your passwords have been compromised from a data leak...
* [Analysis Information Leak framework](https://github.com/ail-project/ail-framework) - AIL is a modular framework to analyze potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams.
* [breach-parse](https://github.com/hmaverickadams/breach-parse) - A tool for parsing breached passwords by The Cyber Mentor. Repo also contains large breach data collections.
* [https://www.reddit.com/r/DataHoarder/](https://www.reddit.com/r/DataHoarder/) - This is a sub that aims at bringing data hoarders together to share their passion with like minded people.
* [https://www.reddit.com/r/DHExchange/](https://www.reddit.com/r/DHExchange/) - Exchange and Sharing sub for /r/DataHoarder

## Code Repositories

Ah the gold mine of git repositories. So at the time of writing this, we are still in the golden age of security ignorance in coding. DevSecOps has not yet fully caught on, and software engineers everywhere post up this tid-bits of insecure code for storage later, or post a bit if their config file on a forum asking for help. Little did they realize that in that bit of the config file, they accidentally posted their creds! These are a few examples of the fun things we can find when checking code repositories. Now searching for these is usually limited to the context of a penetration test against an organization where you know they have software engineers bust creating the next great thing.&#x20;

There are many great options out there for code repositories, but there are 4 that are the gold standard for checking.

* Github - [https://github.com/](https://github.com)
* GitLab - [https://about.gitlab.com/](https://about.gitlab.com)
* Stack Overflow - [https://stackoverflow.com/](https://stackoverflow.com)
* Source Forge - [https://sourceforge.net/](https://sourceforge.net)

You can manually parse these by user or subject but there are some handy tools that can help search and keep track.

* [OSINT Stuff's CSE for search 20 source code hosting services](https://cipher387.github.io/code\_repository\_google\_custom\_search\_engines/)
* [Gitrob](https://github.com/michenriksen/gitrob) - Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github.
* [Git all secrets](https://github.com/anshumanbh/git-all-secrets) - Clone different gits and automatically scan them for secrets.
* [Truffle Hog](https://github.com/dxa4481/truffleHog) - Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
* [gitleaks](https://www.kali.org/tools/gitleaks/) - This package contains a SAST tool for detecting hardcoded secrets like passwords, API keys, and tokens in git repos. Gitleaks aims to be the easy-to-use, all-in-one solution for finding secrets, past or present, in your code.
* [GitDorker](https://github.com/obheda12/GitDorker) - A Python program to scrape secrets from GitHub through usage of a large repository of dorks.
  * [https://youtu.be/UwzB5a5GrZk](https://youtu.be/UwzB5a5GrZk)
* [Repo Supervisor](https://github.com/auth0/repo-supervisor) - Find secrets and passwords in your code&#x20;
* [Watchman](https://papermtn.co.uk/gitlab-github-watchman/) - Git change monitor&#x20;
* [https://grep.app/](https://grep.app) - A search engine for contents of Git Repos
* [gitoops](https://github.com/ovotech/gitoops) - GitOops is a tool to help attackers and defenders identify lateral movement and privilege escalation paths in GitHub organizations by abusing CI/CD pipelines and GitHub access controls.
* [https://searchcode.com/](https://searchcode.com) - Search 75 billion lines of code from 40 million projects
* [https://pentestbook.six2dez.com/enumeration/webservices/github](https://pentestbook.six2dez.com/enumeration/webservices/github)

## **Training**

* [https://tryhackme.com/room/geolocatingimages](https://tryhackme.com/room/geolocatingimages)
* [https://tryhackme.com/room/searchlightosint](https://tryhackme.com/room/searchlightosint)

## Github dorking

* [https://github.com/techgaun/github-dorks](https://github.com/techgaun/github-dorks)
* [https://github.com/jcesarstef/ghhdb-Github-Hacking-Database](https://github.com/jcesarstef/ghhdb-Github-Hacking-Database)
* [https://github.com/H4CK3RT3CH/github-dorks](https://github.com/H4CK3RT3CH/github-dorks)
* [https://github.com/Vaidik-pandya/Github\_recon\_dorks/blob/main/gitdork.txt](https://github.com/Vaidik-pandya/Github\_recon\_dorks/blob/main/gitdork.txt) (for finding files)

".mlab.com password" "access\_key" "access\_token" "amazonaws" "api.googlemaps AIza" "api\_key" "api\_secret" "apidocs" "apikey" "apiSecret" "app\_key" "app\_secret" "appkey" "appkeysecret" "application\_key" "appsecret" "appspot" "auth" "auth\_token" "authorizationToken" "aws\_access" "aws\_access\_key\_id" "aws\_key" "aws\_secret" "aws\_token" "AWSSecretKey" "bashrc password" "bucket\_password" "client\_secret" "cloudfront" "codecov\_token" "config" "conn.login" "connectionstring" "consumer\_key" "credentials" "database\_password" "db\_password" "db\_username" "dbpasswd" "dbpassword" "dbuser" "dot-files" "dotfiles" "encryption\_key" "fabricApiSecret" "fb\_secret" "firebase" "ftp" "gh\_token" "github\_key" "github\_token" "gitlab" "gmail\_password" "gmail\_username" "herokuapp" "internal" "irc\_pass" "JEKYLL\_GITHUB\_TOKEN" "key" "keyPassword" "ldap\_password" "ldap\_username" "login" "mailchimp" "mailgun" "master\_key" "mydotfiles" "mysql" "node\_env" "npmrc \_auth" "oauth\_token" "pass" "passwd" "password" "passwords" "pem private" "preprod" "private\_key" "prod" "pwd" "pwds" "rds.amazonaws.com password" "redis\_password" "root\_password" "secret" "secret.password" "secret\_access\_key" "secret\_key" "secret\_token" "secrets" "secure" "security\_credentials" "send.keys" "send\_keys" "sendkeys" "SF\_USERNAME salesforce" "sf\_username" "site.com" FIREBASE\_API\_JSON= "site.com" vim\_settings.xml "slack\_api" "slack\_token" "sql\_password" "ssh" "ssh2\_auth\_password" "sshpass" "staging" "stg" "storePassword" "stripe" "swagger" "testuser" "token" "x-api-key" "xoxb " "xoxp" \[WFClient] Password= extension:ica access\_key bucket\_password dbpassword dbuser extension:avastlic "support.avast.com" extension:bat extension:cfg extension:env extension:exs extension:ini extension:json api.forecast.io extension:json googleusercontent client\_secret extension:json mongolab.com extension:pem extension:pem private extension:ppk extension:ppk private extension:properties extension:sh extension:sls extension:sql extension:sql mysql dump extension:sql mysql dump password extension:yaml mongolab.com extension:zsh filename:.bash\_history filename:.bash\_history DOMAIN-NAME filename:.bash\_profile aws filename:.bashrc mailchimp filename:.bashrc password filename:.cshrc filename:.dockercfg auth filename:.env DB\_USERNAME NOT homestead filename:.env MAIL\_HOST=smtp.gmail.com filename:.esmtprc password filename:.ftpconfig filename:.git-credentials filename:.history filename:.htpasswd filename:.netrc password filename:.npmrc \_auth filename:.pgpass filename:.remote-sync.json filename:.s3cfg filename:.sh\_history filename:.tugboat NOT \_tugboat filename:\_netrc password filename:apikey filename:bash filename:bash\_history filename:bash\_profile filename:bashrc filename:beanstalkd.yml filename:CCCam.cfg filename:composer.json filename:config filename:config irc\_pass filename:config.json auths filename:config.php dbpasswd filename:configuration.php JConfig password filename:connections filename:connections.xml filename:constants filename:credentials filename:credentials aws\_access\_key\_id filename:cshrc filename:database filename:dbeaver-data-sources.xml filename:deployment-config.json filename:dhcpd.conf filename:dockercfg filename:environment filename:express.conf filename:express.conf path:.openshift filename:filezilla.xml filename:filezilla.xml Pass filename:git-credentials filename:gitconfig filename:global filename:history filename:htpasswd filename:hub oauth\_token filename:id\_dsa filename:id\_rsa filename:id\_rsa or filename:id\_dsa filename:idea14.key filename:known\_hosts filename:logins.json filename:makefile filename:master.key path:config filename:netrc filename:npmrc filename:pass filename:passwd path:etc filename:pgpass filename:prod.exs filename:prod.exs NOT prod.secret.exs filename:prod.secret.exs filename:proftpdpasswd filename:recentservers.xml filename:recentservers.xml Pass filename:robomongo.json filename:s3cfg filename:secrets.yml password filename:server.cfg filename:server.cfg rcon password filename:settings filename:settings.py SECRET\_KEY filename:sftp-config.json filename:sftp-config.json password filename:sftp.json path:.vscode filename:shadow filename:shadow path:etc filename:spec filename:sshd\_config filename:token filename:tugboat filename:ventrilo\_srv.ini filename:WebServers.xml filename:wp-config filename:wp-config.php filename:zhrc HEROKU\_API\_KEY language:json HEROKU\_API\_KEY language:shell HOMEBREW\_GITHUB\_API\_TOKEN language:shell jsforce extension:js conn.login language:yaml -filename:travis msg nickserv identify filename:config org:Target "AWS\_ACCESS\_KEY\_ID" org:Target "list\_aws\_accounts" org:Target "aws\_access\_key" org:Target "aws\_secret\_key" org:Target "bucket\_name" org:Target "S3\_ACCESS\_KEY\_ID" org:Target "S3\_BUCKET" org:Target "S3\_ENDPOINT" org:Target "S3\_SECRET\_ACCESS\_KEY" password path:sites databases password private -language:java PT\_TOKEN language:bash redis\_password root\_password secret\_access\_key SECRET\_KEY\_BASE= shodan\_api\_key language:python WORDPRESS\_DB\_PASSWORD= xoxp OR xoxb OR xoxa s3.yml .exs beanstalkd.yml deploy.rake .sls
