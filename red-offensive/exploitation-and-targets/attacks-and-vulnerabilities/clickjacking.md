# Clickjacking

## Basics

* Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website.
* The technique depends upon the incorporation of an invisible, actionable web page (or multiple pages) containing a button or hidden link, say, within an iframe. The iframe is overlaid on top of the user's anticipated decoy web page content.
* [https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected)
* [https://portswigger.net/web-security/clickjacking](https://portswigger.net/web-security/clickjacking)
* [https://owasp.org/www-community/attacks/Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)

## Methodology

### Prefilled form input

* Some websites that require form completion and submission permit prepopulation of form inputs using GET parameters prior to submission. Other websites might require text before form submission. As GET values form part of the URL then the target URL can be modified to incorporate values of the attacker's choosing and the transparent "submit" button is overlaid on the decoy site as in the basic clickjacking example.
* [https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input)

### Frame busting scripts

* Frame busting techniques are often browser and platform specific and because of the flexibility of HTML they can usually be circumvented by attackers. As frame busters are JavaScript then the browser's security settings may prevent their operation or indeed the browser might not even support JavaScript. An effective attacker workaround against frame busters is to use the HTML5 iframe `sandbox` attribute. When this is set with the `allow-forms` or `allow-scripts` values and the `allow-top-navigation` value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window.
* [https://portswigger.net/web-security/clickjacking/lab-frame-buster-script](https://portswigger.net/web-security/clickjacking/lab-frame-buster-script)

### Clickjacking + DOM XSS

* The true potency of clickjacking is revealed when it is used as a carrier for another attack such as a [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) attack. Implementation of this combined attack is relatively straightforward assuming that the attacker has first identified the XSS exploit. The XSS exploit is then combined with the iframe target URL so that the user clicks on the button or link and consequently executes the DOM XSS attack.
* [https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss](https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss)

### Multi-step clickjacking

* [https://portswigger.net/web-security/clickjacking/lab-multistep](https://portswigger.net/web-security/clickjacking/lab-multistep)

## Preventing Clickjacking

* X-Frame Options - Header that provides the website owner with control over the use of iframes or objects so that a webpage with an iframe can be prohibited with the `deny` directive.
* CSP: Content Security policy - A detection and prevention mechanism that provides mitigation against attacks such as XSS and clickjacking. CSP is usually implemented in the web server as a return header of the form.
  * [https://portswigger.net/web-security/cross-site-scripting/content-security-policy#protecting-against-clickjacking-using-csp](https://portswigger.net/web-security/cross-site-scripting/content-security-policy#protecting-against-clickjacking-using-csp)
* [https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking\_Defense\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking\_Defense\_Cheat\_Sheet.html)
