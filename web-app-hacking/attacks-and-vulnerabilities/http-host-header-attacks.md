# HTTP Host Header Attacks

## How it works

### **Basics**

* The HTTP Host header is a mandatory request header as of HTTP/1.1. It specifies the domain name that the client wants to access
* The purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with. This can occur with a single server hosting multiple domains or when websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system. This could be a simple load balancer or a reverse proxy server of some kind.
* In any scenario, the Host header specifies the intended recipient.
* HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior. Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks.
* &#x20;As the Host header is in fact user controllable, this practice can lead to a number of issues. If the input is not properly escaped or validated, the Host header is a potential vector for exploiting a range of other vulnerabilities, most notably:
  * &#x20;Web cache poisoning
  * &#x20;Business [logic flaws](https://portswigger.net/web-security/logic-flaws) in specific functionality
  * &#x20;Routing-based SSRF
  * &#x20;Classic server-side vulnerabilities, such as SQL injection

### **Reference**

* [https://portswigger.net/web-security/host-header](https://portswigger.net/web-security/host-header)
* [https://www.intruder.io/research/practical-http-header-smuggling](https://www.intruder.io/research/practical-http-header-smuggling)

## Recon and Identification

### Give an arbitrary Host header and Check for flawed validation

*   &#x20;You should try to understand how the website parses the Host header. This can sometimes reveal loopholes that can be used to bypass the validation. For example, some parsing algorithms will omit the port from the Host header, meaning that only the domain name is validated. If you are also able to supply a non-numeric port, you can leave the domain name untouched to ensure that you reach the target application, while potentially injecting a payload via the port.

    &#x20;`GET /example HTTP/1.1`\
    &#x20;`Host: vulnerable-website.com:bad-stuff-here`
*   You may be able to bypass the validation entirely by registering an arbitrary domain name that ends with the same sequence of characters as a whitelisted one:

    &#x20;`GET /example HTTP/1.1`\
    &#x20;`Host: notvulnerable-website.com`
*   You could take advantage of a less-secure subdomain that you have already compromised:

    &#x20;`GET /example HTTP/1.1`\
    &#x20;`Host: hacked-subdomain.vulnerable-website.com`

### Send ambiguous requests

* Inject duplicate headers
  * &#x20;`GET /example HTTP/1.1`\
    &#x20;`Host: vulnerable-website.com`\
    &#x20;`Host: bad-stuff-here`
* Send Absolute URLs in the Header
  * `GET https://vulnerable-website.com/ HTTP/1.1`\
    &#x20;`Host: bad-stuff-here`
* Add line wrapping
* Misc HTTP request smuggling techniques

### Inject override headers

* You can sometimes use `X-Forwarded-Host` to inject your malicious input while circumventing any validation on the Host header itself.
* &#x20;`GET /example HTTP/1.1`\
  &#x20;`Host: vulnerable-website.com`\
  &#x20;`X-Forwarded-Host: bad-stuff-here`
* Although `X-Forwarded-Host` is the de facto standard for this behavior, you may come across other headers that serve a similar purpose, including:
  * &#x20;`X-Host`
  * &#x20;`X-Forwarded-Server`
  * &#x20;`X-HTTP-Host-Override`
  * &#x20;`Forwarded`

## **HTTP Header Attacks**

**\*\*\*** In Burp Suite, you can use the [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension's "Guess headers" function to automatically probe for supported headers using its extensive built-in wordlist.\*\*\*

### **Password Reset poisoning**

* Attack Process
  1. &#x20;The attacker obtains the victim's email address or username, as required, and submits a password reset request on their behalf. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control. For this example, we'll use `evil-user.net`.
  2. &#x20;The victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and, crucially, contains a valid password reset token that is associated with their account. However, the domain name in the URL points to the attacker's server:\
     &#x20;`https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j`
  3. &#x20;If the victim clicks this link (or it is fetched in some other way, for example, by an antivirus scanner) the password reset token will be delivered to the attacker's server.
  4. &#x20;The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter. They will then be able to reset the user's password to whatever they like and subsequently log in to their account.
* [https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)

### **Web Cache Poisoning via Host Header**

* &#x20;**** To construct a web cache poisoning attack, you need to elicit a response from the server that reflects an injected payload. The challenge is to do this while preserving a cache key that will still be mapped to other users' requests. If successful, the next step is to get this malicious response cached. It will then be served to any users who attempt to visit the affected page.
* [https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)

### **Classic Server-Side Vulnerabilities** - SQL Injection via the Host Header

### **Accessing Restricted Functionality**

* Some websites' access control features make flawed assumptions that allow you to bypass these restrictions by making simple modifications to the Host header.
* [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass)

### **Accessing Internal Websites via Host Brute-Forcing**

*   &#x20;Companies sometimes make the mistake of hosting publicly accessible websites and private, internal sites on the same server. Servers typically have both a public and a private IP address. As the internal hostname may resolve to the private IP address, this scenario can't always be detected simply by looking at DNS records:

    &#x20;`www.example.com: 12.34.56.78`\
    &#x20;`intranet.example.com: 10.0.0.132`
* In some cases, the internal site might not even have a public DNS record associated with it. Nonetheless, an attacker can typically access any virtual host on any server that they have access to, provided they can guess the hostnames.

### **Routing Based SSRF**

* It is possible to use the Host header to launch high-impact, routing-based SSRF attacks. These are sometimes known as "Host header SSRF attacks".
* &#x20;You can use Burp Collaborator to help identify these vulnerabilities. If you supply the domain of your Collaborator server in the Host header, and subsequently receive a DNS lookup from the target server or another in-path system, this indicates that you may be able to route requests to arbitrary domains.
* &#x20;Having confirmed that you can successfully manipulate an intermediary system to route your requests to an arbitrary public server, the next step is to see if you can exploit this behavior to access internal-only systems. To do this, you'll need to identify private IP addresses that are in use on the target's internal network. In addition to any IP addresses that are leaked by the application, you can also scan hostnames belonging to the company to see if any resolve to a private IP address. If all else fails, you can still identify valid IP addresses by simply brute-forcing standard private IP ranges, such as `192.168.0.0/16`.
* [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)
* [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing)

### **SSRF via Malformed Request Line**

* &#x20;Custom proxies sometimes fail to validate the request line properly, which can allow you to supply unusual, malformed input with unfortunate results.
*   &#x20;For example, a reverse proxy might take the path from the request line, prefix it with `http://backend-server`, and route the request to that upstream URL. This works fine if the path starts with a `/` character, but what if starts with an `@` character instead?

    &#x20;`GET @private-intranet/example HTTP/1.1`
* &#x20;The resulting upstream URL will be `http://backend-server@private-intranet/example`, which most HTTP libraries interpret as a request to access `private-intranet` with the username `backend-server`.

## **HTTP Header Attack Protection**

* **Protect absolute URLs -** When you have to use absolute URLs, you should require the current domain to be manually specified in a configuration file and refer to this value instead of the Host header. This approach would eliminate the threat of password reset poisoning, for example.
* **Validate the Host header -** If you must use the Host header, make sure you validate it properly. This should involve checking it against a whitelist of permitted domains and rejecting or redirecting any requests for unrecognized hosts. You should consult the documentation of your framework for guidance on how to do this. For example, the Django framework provides the `ALLOWED_HOSTS` option in the settings file. This approach will reduce your exposure to Host header injection attacks.
* **Don't support Host override headers -** It is also important to check that you do not support additional headers that may be used to construct these attacks, in particular `X-Forwarded-Host`. Remember that these may be supported by default.
* **Whitelist permitted domains -** To prevent routing-based attacks on internal infrastructure, you should configure your load balancer or any reverse proxies to forward requests only to a whitelist of permitted domains.
* **Be careful with internal-only virtual hosts -** When using virtual hosting, you should avoid hosting internal-only websites and applications on the same server as public-facing content. Otherwise, attackers may be able to access internal domains via Host header manipulation.
