# Broken Authentication

## Tools and Resources

* Burp Guide - [https://portswigger.net/web-security/authentication](https://portswigger.net/web-security/authentication)
* [Comprehensive Guide on Broken Authentication & Session Management](https://www.hackingarticles.in/comprehensive-guide-on-broken-authentication-session-management/)
* [https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html)
* [Fuzzhttpbypass](https://github.com/carlospolop/fuzzhttpbypass) - This tool use fuzzing to try to bypass unknown authentication methods, who knows...

## **Session Token Attacks**

<details>

<summary>Session Token Attacks</summary>

* Session tokens should be randomized and not easily guessed.&#x20;
* Session tokens should properly track a user.&#x20;
* When we capture an authentication process, we can see  that there is a set-cookie value for the tokens.&#x20;
  * Proxy tab -> History&#x20;
* We can right click the raw response and send it to Burp Sequencer&#x20;
  * &#x20;Start live capture to start generating session tokens&#x20;
  * After a certain number of tokens it will give a summary of entropy, char level analysis and bit level analysis.

</details>

## **Password-Based Logins**

<details>

<summary>Brute Force Attacks</summary>

* Brute-forcing usernames - Check for any accidental public disclosure, email addresses
* Brute forcing passwords
* Username Enumeration
  * Observe changes in the websites behavior depending on input
  * Notice changes in Status Codes, Error Messages, and [Response times](https://app.gitbook.com/s/-MQCNQTNhvnXD58Vo8Mf/web-app-hacking/Web\_Applications--Attack\_types--OWASP\_2\_-\_Broken\_Auth\_Attacks--Vuls\_in\_password-based\_login--Username\_enumeration\_via\_different\_responses.html)

</details>

<details>

<summary>Flawed Brute Force Protection</summary>

* Two most common ways to protect: Locking the account and blocking the remote users IP
* Ip blocking
  * Sometimes can be bypassed by ever so often logging in to a legitimate account
* Account Locking
  * This approach provides decent protection against specific account, but less so if an attacker is trying to get access to any account they can
  * Example:
    * Create a list of usernames that are likely valid
    * Create a shortlist of passwords. Quantity should match the lockout attempts
    * Use intruder to try each of the passwords with each candidate
* Credential Stuffing
  * Massive dictionary of username/passwrod pairs
  * Account locking does not protect against this
* User Rate Limiting
  * In this case, making too many login requests within a short period of time causes your IP address to be blocked
  * Can only be unblocked by: After a certain amount of time, by an admin, by the user after a successful CAPCHA
* HTTP Basic Auth
  * `Authorization: Basic base64(username:password)`
  * Easy to decrypt
  * HTTP basic authentication is also particularly vulnerable to session-related exploits, notably [CSRF](https://portswigger.net/web-security/csrf), against which it offers no protection on its own.&#x20;

</details>

## **MultiFactor Authentication**

MFA -mandatory and optional two-factor authentication (2FA) based on something you know and something you have.

Two-Factor Tokens - Many high-security websites now provide users with a dedicated device for this purpose, such as the RSA token or keypad device that you might use to access your online banking or work laptop

### Bypassing 2fa

If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step.

Mind Map: [https://www.mindmeister.com/1736437018?t=SEeZOmvt01](https://www.mindmeister.com/1736437018?t=SEeZOmvt01)

#### Resources

* [https://mrd0x.com/bypass-2fa-using-novnc/](https://mrd0x.com/bypass-2fa-using-novnc/) - Steal credentials and bypass 2FA by giving users remote access to your server via an HTML5 VNC client that has a browser running in kiosk mode.
* [https://infosecwriteups.com/methods-to-bypass-two-factor-authentication-bc2bd35bd44e?source=rss----7b722bfd1b8d---4\&gi=d1d4b1015e30](https://infosecwriteups.com/methods-to-bypass-two-factor-authentication-bc2bd35bd44e?source=rss----7b722bfd1b8d---4\&gi=d1d4b1015e30)
* [https://research.nccgroup.com/2021/06/10/testing-two-factor-authentication/](https://research.nccgroup.com/2021/06/10/testing-two-factor-authentication/)

{% tabs %}
{% tab title="Response manipulation" %}
* The response is

```
HTTP/1.1 404 Not Found
...
{"code": false}
```

Try this to bypass

```
HTTP/1.1 404 Not Found
...
{"code": true}
```
{% endtab %}

{% tab title="Status code manipulation" %}
The response is

```
HTTP/1.1 404 Not Found
...
{"code": false}
```

Try this to bypass

```
HTTP/1.1 200 OK
...
{"code": false}
```
{% endtab %}

{% tab title="2FA Code in Response" %}
Always check the response!

```
POST /req-2fa/
Host: vuln.com
...
email=victim@gmail.com
```

The response is

```
HTTP/1.1 200 OK
...
{"email": "victim@gmail.com", "code": "101010"}
```
{% endtab %}

{% tab title="Missing  integrity validation" %}
#### Missing 2FA Code integrity validation, code for any user account can be used

```
POST /2fa/
Host: vuln.com
...
email=attacker@gmail.com&code=382923
```

```
POST /2fa/
Host: vuln.com
...
email=victim@gmail.com&code=382923
```

* No CSRF protection on disabling 2FA, also there is no auth confirmation.
* 2FA gets disabled on password change/email change.
* Clickjacking on 2FA disabling page, by iframing the 2FA Disabling page and lure the victim to disable the 2FA.
* Enabling 2FA doesn't expire previously active sessions, if the session is already hijacked and there is a session timeout vuln.
* 2FA code reusability, same code can be reused.
* Enter code 000000

```
POST /2fa/
Host: vuln.com
...
code=00000
```

* Enter code "null"

```
POST /2fa/
Host: vuln.com
...
code=null
```

Source: [Harsh Bothra](https://twitter.com/harshbothra\_) and [https://github.com/daffainfo/AllAboutBugBounty/blob/master/Bypass/Bypass%202FA.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Bypass/Bypass%202FA.md)
{% endtab %}
{% endtabs %}

### Flawed 2FA logic

<details>

<summary>Flawed 2FA logic</summary>

* Sometimes flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step.
* This is extremely dangerous if the attacker is then able to [brute-force](https://portswigger.net/web-security/authentication/password-based) the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username.
* Brute forceing 2FA
  * This is especially important because the code is often a simple 4 or 6-digit number. Without adequate brute-force protection, cracking such a code is trivial.
  * Some websites attempt to prevent this by automatically logging a user out if they enter a certain number of incorrect verification codes. This is ineffective in practice because an advanced attacker can even automate this multi-step process by [creating macros](https://portswigger.net/burp/documentation/desktop/options/sessions#macros) for Burp Intruder. The [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988) extension can also be used for this purpose.
* Reference
  * [https://www.perfecto.io/blog/two-factor-authentication](https://www.perfecto.io/blog/two-factor-authentication)
  * [https://cheatsheetseries.owasp.org/cheatsheets/Logging\_Vocabulary\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Logging\_Vocabulary\_Cheat\_Sheet.html)
  * [https://research.nccgroup.com/2021/06/10/testing-two-factor-authentication/](https://research.nccgroup.com/2021/06/10/testing-two-factor-authentication/)

</details>

## Other Vulnerabilities

<details>

<summary>The "Remember me" or "Keep me logged in" feature</summary>

* This is usually set by a persistent cookie
* If you can obtain or guess the cookie, the login process can be bypassed entirely
* If the creation of this cookie is based off of simple rules, it cna be guessed or brute forced.
* Even if the attacker is not able to create their own account, they may still be able to exploit this vulnerability. Using the usual techniques, such as [XSS](https://portswigger.net/web-security/cross-site-scripting), an attacker could steal another user's "remember me" cookie and deduce how the cookie is constructed from that. If the website was built using an open-source framework, the key details of the cookie construction may even be publicly documented.

</details>

<details>

<summary>Resetting User passwords</summary>

* [https://github.com/daffainfo/AllAboutBugBounty/blob/master/Misc/Password%20Reset%20Flaws.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Misc/Password%20Reset%20Flaws.md)
* Sending passwords by email
  * It should go without saying that sending users their current password should never be possible if a website handles passwords securely in the first place. Instead, some websites generate a new password and send this to the user via email.\
    &#x20;Generally speaking, sending persistent passwords over insecure channels is to be avoided. In this case, the security relies on either the generated password expiring after a very short period, or the user changing their password again immediately. Otherwise, this approach is highly susceptible to man-in-the-middle attacks.\
    &#x20;Email is also generally not considered secure given that inboxes are both persistent and not really designed for secure storage of confidential information. Many users also automatically sync their inbox between multiple devices across insecure channels.

<!---->

* Resetting passwords using a URL
  * A more robust method of resetting passwords is to send a unique URL to users that takes them to a password reset page. Less secure implementations of this method use a URL with an easily guessable parameter to identify which account is being reset
  * An attacker could change the `user` parameter to refer to any username they have identified. They would then be taken straight to a page where they can potentially set a new password for this arbitrary user.
  * A better implementation of this process is to generate a high-entropy, hard-to-guess token and create the reset URL based on that. In the best case scenario, this URL should provide no hints about which user's password is being reset.
  * However, some websites fail to also validate the token again when the reset form is submitted. In this case, an attacker could simply visit the reset form from their own account, delete the token, and leverage this page to reset an arbitrary user's password.

</details>

<details>

<summary>Password reset poisoning</summary>

* The attacker first enters the victim's username and requests a password reset. They then intercept this request using Burp. If certain headers are supported, the attacker may be able to utilize them to override the hostname for the generated URL. They may even be able to simply change the value of the `Host` header directly.
* If the attacker changes the `Host` to a domain that they control, such as `evil-user.net`, the victim would then receive an email similar to the following:\
  &#x20;`Dear Dave,`\
  &#x20;`It looks like you have forgotten your password. To reset it, please click the link below:`\
  &#x20;`http://evil-user.net/password-reset?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8`\
  &#x20;This would be a genuine email from the website and, importantly, would contain the valid token required to reset this user's password. However, as the URL points to the attacker's website, clicking this link would cause the user to expose their reset token to the attacker. By visiting the real URL with the user's leaked token, the attacker could subsequently reset the victim's password unimpeded.

</details>

<details>

<summary>Changing user passwords</summary>

* Typically, changing your password involves entering your current password and then the new password twice. These pages fundamentally rely on the same process for checking that usernames and current passwords match as a normal login page does. Therefore, these pages can be vulnerable to the same techniques.
* Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user. For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords.

</details>

<details>

<summary>User registration sanitization</summary>

* If you can discover a valid username, attempt to create a new user with the same name preceeded by a space

</details>
