# OAuth 2.0

## Basics

[https://oauth.net/2/](https://oauth.net/2/)

{% tabs %}
{% tab title="Definitions" %}
* &#x20;**Client application** - The website or web application that wants to access the user's data.
* &#x20;**Resource owner** - The user whose data the client application wants to access.
* &#x20;**OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.
* **Scope** - The range of data for which access is requested.
{% endtab %}

{% tab title="OAuth Grant Types" %}
&#x20; ****  The ways that OAuth can be implemented.

* Authorization Code - the client application and OAuth service first use redirects to exchange a series of browser-based HTTP requests that initiate the flow. The user is asked whether they consent to the requested access. If they accept, the client application is granted an "authorization code". The client application then exchanges this code with the OAuth service to receive an "access token", which they can use to make API calls to fetch the relevant user data.
* Implicit - the client application receives the access code immediately after the user gives their consent.
* [https://oauth.net/2/grant-types/authorization-code/](https://oauth.net/2/grant-types/authorization-code/)
* [https://portswigger.net/web-security/oauth/grant-types](https://portswigger.net/web-security/oauth/grant-types)
{% endtab %}

{% tab title="Resources" %}
* [https://pentestbook.six2dez.com/enumeration/webservices/oauth](https://pentestbook.six2dez.com/enumeration/webservices/oauth)
* [https://owasp.org/www-pdf-archive/20151215-Top\_X\_OAuth\_2\_Hacks-asanso.pdf](https://owasp.org/www-pdf-archive/20151215-Top\_X\_OAuth\_2\_Hacks-asanso.pdf)
* [https://medium.com/@lokeshdlk77/stealing-facebook-mailchimp-application-oauth-2-0-access-token-3af51f89f5b0](https://medium.com/@lokeshdlk77/stealing-facebook-mailchimp-application-oauth-2-0-access-token-3af51f89f5b0)
* [https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)
* [https://gauravnarwani.com/misconfigured-oauth-to-account-takeover/](https://gauravnarwani.com/misconfigured-oauth-to-account-takeover/)
* [https://medium.com/@Jacksonkv22/oauth-misconfiguration-lead-to-complete-account-takeover-c8e4e89a96a](https://medium.com/@Jacksonkv22/oauth-misconfiguration-lead-to-complete-account-takeover-c8e4e89a96a)
* [https://medium.com/@logicbomb\_1/bugbounty-user-account-takeover-i-just-need-your-email-id-to-login-into-your-shopping-portal-7fd4fdd6dd56](https://medium.com/@logicbomb\_1/bugbounty-user-account-takeover-i-just-need-your-email-id-to-login-into-your-shopping-portal-7fd4fdd6dd56)
* [https://medium.com/@protector47/full-account-takeover-via-referrer-header-oauth-token-steal-open-redirect-vulnerability-chaining-324a14a1567](https://medium.com/@protector47/full-account-takeover-via-referrer-header-oauth-token-steal-open-redirect-vulnerability-chaining-324a14a1567)
* [https://hackerone.com/reports/49759](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://hackerone.com/reports/131202](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://hackerone.com/reports/6017](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://hackerone.com/reports/7900](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://hackerone.com/reports/244958](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://hackerone.com/reports/405100](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://ysamm.com/?p=379](https://hackerone.com/reports/49759https:/hackerone.com/reports/131202https:/hackerone.com/reports/6017https:/hackerone.com/reports/7900https:/hackerone.com/reports/244958https:/hackerone.com/reports/405100https:/ysamm.com/?p=379)
* [https://www.amolbaikar.com/facebook-oauth-framework-vulnerability/](https://www.amolbaikar.com/facebook-oauth-framework-vulnerability/)
* [http://blog.intothesymmetry.com/2014/02/oauth-2-attacks-and-bug-bounties.html](http://blog.intothesymmetry.com/2014/02/oauth-2-attacks-and-bug-bounties.html)
* [https://xploitprotocol.medium.com/exploiting-oauth-2-0-authorization-code-grants-379798888893](https://xploitprotocol.medium.com/exploiting-oauth-2-0-authorization-code-grants-379798888893)
* [https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html](https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html)
* [https://portswigger.net/research/hidden-oauth-attack-vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
* Burp Training - [https://portswigger.net/web-security/oauth](https://portswigger.net/web-security/oauth)
* Protecting against OAuth Attacks - [https://portswigger.net/web-security/oauth/preventing](https://portswigger.net/web-security/oauth/preventing)
{% endtab %}
{% endtabs %}

<details>

<summary>Identification and Recon</summary>

* If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.
* Proxy your traffic through something like Burp or ZAP and check the corresponding HTTP messages when you attempt to login. Regardless of which OAuth grant type is being used, the first request of the flow will always be to `/authorization` with a number of query parameters used specifically for OAuth. Make sure you look out for the `client_id`, `redirect_uri`, and `response_type` parameters.`GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1`\
  &#x20;`Host: oauth-authorization-server.com`
* Once you know the hostname of the auth server, you should test it with a `GET` request to these standard endpoints:
  * &#x20;`/.well-known/oauth-authorization-server`
  * &#x20;`/.well-known/openid-configuration`
* If there is a response from the auth server, often times it will reply with a JSON file ripe with information that we can use, such as leads to a larger attack surface and config information.&#x20;

</details>

## OAuth Attacks

{% tabs %}
{% tab title="Client Application Attacks" %}
* Improper implementation of the Implicit Grant type.
  * The client application will often submit a UserID and Access token to the server in a `POST` request, in order to be assigned a session cookie, essentially logging them in.
  * If the client application doesn't properly check that the access token matches the other data in the request, an attacker can manipulate the contents of the post request to impersonate any other user they choose.
  * Change the UserID value in the POST request to see if you can impersonate other users.
  * [https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
* Flawed CSRF Protection
  * The optional `state` parameter of the OAuth request, is often users as a CSRF token for the client application.&#x20;
  * If the `state`parameter is not set, you can perform an attack similar to a traditional CSRF, where an attacker can initiate an OAuth flow themselves before tricking a user's browser into completing it.
  * [https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
{% endtab %}

{% tab title="Service Vulnerabilities" %}
* Leaking auth codes and access tokens
  * Depending on the grant type, either a code or token is sent via the victim's browser to the `/callback` endpoint specified in the `redirect_uri` parameter of the authorization request. If the OAuth service fails to validate this URI properly, an attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled `redirect_uri`
  * When auditing an OAuth flow, you should try experimenting with the `redirect_uri` parameter to understand how it is being validated.
  * [https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
  * Stealing Auth codes via a proxy page
    * If you cannot change the domain in the `redirect_uri` , You may be able to change parameters within the URI structure itself.
    * Try URI manipulation attacks like directory transversals.
    * [https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)
  * Other Vulnerabilities
    * Look for any other vulnerabilities that allow you to extract the code or token and send it to an external domain.
    * JS queries that handles URI parameters, XSS injections, HTML injections, etc.
    * [https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
* Flawed scope validation
  * Generally, when a token is granted, it is only for the scope defined in the request. However it is possible to "upgrade" the scope of access by exploiting a flawed OAuth implimentation.
  * With the authorization code flow, it may be possible for an attacker to register their own client application with the OAuth service.
  * With the implicit grant flow, tokens are sent via the browser and an attacker can steal tokens associated with innocent client applications and use them directly. Once they have stolen an access token, they can send a normal browser-based request to the OAuth service's `/userinfo` endpoint, manually adding a new `scope` parameter in the process.
* Unverified user registration
  * Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address.
{% endtab %}

{% tab title="Misconfigurations" %}
* OAuth token stealing: Changing redirect\_uri to attacker(.)com(Use IDN Homograph or common bypasses).
* Change Referral header to attacker(.)com while requesting OAuth.
* Create an account with victim@gmail(.)com with normal functionality. Create account with victim@gmail(.)com using OAuth functionality. Now try to login using previous credentials.
* OAuth Token Re-use.
* Missing or broken state parameter.
* Lack of origin check.
* Open Redirection on another endpoint > Use it in redirect\_uri
* If there is an email parameter after signin then try to change the email parameter to victim's one.
* Try to remove email from the scope and add victim's email manually.
* Only company's email is allowed? > Try to replace hd=company(.)com to hd=gmail(.)com
* Check if its leaking client\_secret parameter.
* Go to the browser history and check if the token is there.
{% endtab %}

{% tab title="Reference" %}
* [https://xapax.github.io/security/#attacking\_web\_applications/oauth\_attacks/](https://xapax.github.io/security/#attacking\_web\_applications/oauth\_attacks/)
* [https://twitter.com/tuhin1729\_/status/1417843523177484292](https://twitter.com/tuhin1729\_/status/1417843523177484292)
{% endtab %}
{% endtabs %}

## **OpenID**

&#x20;**** [https://portswigger.net/web-security/oauth/openid](https://portswigger.net/web-security/oauth/openid)

* OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication layer that sits on top of the basic OAuth implementation.
* OpenID Connect slots neatly into the normal OAuth flows. From the client application's perspective, the key difference is that there is an additional, standardized set of scopes that are the same for all providers, and an extra response type: `id_token`.

{% tabs %}
{% tab title="OpenID Roles" %}
* &#x20;Relying party - The application that is requesting authentication of a user. This is synonymous with the OAuth client application.
* &#x20;End user - The user who is being authenticated. This is synonymous with the OAuth resource owner.
* &#x20;OpenID provider - An OAuth service that is configured to support OpenID Connect.
{% endtab %}

{% tab title="OpenID Claims and Scopes" %}
* The term "claims" refers to the `key:value` pairs that represent information about the user on the resource server.
* Unlike basic OAuth, whose scopes are unique to each provider, all OpenID Connect services use an identical set of scopes. In order to use OpenID Connect, the client application must specify the scope `openid` in the authorization request.
* They can then include one or more of the other standard scopes:`profile, email, address,` `phone`
{% endtab %}

{% tab title="ID Token" %}
* &#x20;The other main addition provided by OpenID Connect is the `id_token` response type. This returns a JSON web token (JWT) signed with a JSON web signature (JWS). The JWT payload contains a list of claims based on the scope that was initially requested. It also contains information about how and when the user was last authenticated by the OAuth service.


{% endtab %}

{% tab title="OpenID Vulnerabilities" %}
* Unprotected dynamic client registration
  * If dynamic client registration is supported, the client application can register itself by sending a `POST` request to a dedicated `/registration` endpoint. The name of this endpoint is usually provided in the configuration file and documentation.
  * In the request body, the client application submits key information about itself in JSON format.
  * some providers will allow dynamic client registration without any authentication, which enables an attacker to register their own malicious client application.
  * [https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration)
{% endtab %}
{% endtabs %}
