# Google Dorking Cheatsheet

### Google Dorking Cheatsheet

* @\[Search term] Searches a keyword on social media
* “Search term” Searches an exact match
* “Search \* term” Searches the \* for any wildcard
* (+) (-) (“) (.) (\*) (|) (“String” | String) Force inclusion of something common Exclude a search term Use quotes around a search phrase A single-character wildcard Any word boolean ‘OR‘ Parenthesis group queries 06 cache:\[url] Searches for cached versions of a site or page
* numrange\[#]..\[#]
* daterange:startdate-enddate Must be expressed in \*Julian time (and only in integers)
  * The number of days that have passed since January 1, 4713 B.C. unlike Gregorian days (those on the calendar)
* link: \[url] Shows links to the URL and helps determine site relation- ships and more importantly trust relationships; this gets treated like normal search text (not a modifier) when com- bined with other search terms though.
* related: \[url] Searches related to your search term
* intitle: string to search Show only those pages that have the term in their html title
* allintitle:\[string] Similar to intitle, but looks for all the specified terms in the title
* inurl: \[string] Searches for the specified term in the url; for example inurl:”login.php”. (Can also do :port)
* allinurl:\[url] Same as inurl, but searches for all terms in the url
* intext:“String to search” Searches the content of the page and similar to a plain Google search; for example intext:”index of /”.
* allintext: “String to search” Similar to intext, but searches for all terms to be present in the text 07 filetype: \[xls] Searches for specific file types; filetype:pdf will looks for pdf files in websites.
* phonebook:\[name]
* \[URL]\&strip=1 Added to the end of a cached URL only shows Google’s text, not the target’s; perform a Google search, right-click copy/ paste the link and then paste the URL adding \&strip=1
* site.com/search?q=inurl:admin.PhP\&start=10 Changing your query to vary the extension case and modifying the query can help defeat some of Google’s blockers which work to defeat your search query
* site.com/search?q=@email.com Searching for email addresses
* site:site.com -site:obivousresult.com Eliminates obvious results, reducing most public, top ‘ranked’ unwanted results and bringing more useful results to the top of the search; you are looking for the relation- ship of links in both inbound and outbound directions
* inurl: Port scanning, can be combined with the site operator
* inurl:8080 -intext:8080 Servers listening on port 8080 removing results with 8080 in the page
* filetype:inc intext:mysql\_connect filetype:sql + “IDENTIFIED BY” -cvs Search combinations that goes after files with cleartext SQL passwords and credentials
* intitle:”VNC viewer” Example of a search for sites that launch a VNC client

**Source:** [**https://know.bishopfox.com/hubfs/mkt-coll/Bishop-Fox-Breaking-and-Entering-Pocket-Guide.pdf**](https://know.bishopfox.com/hubfs/mkt-coll/Bishop-Fox-Breaking-and-Entering-Pocket-Guide.pdf)****
