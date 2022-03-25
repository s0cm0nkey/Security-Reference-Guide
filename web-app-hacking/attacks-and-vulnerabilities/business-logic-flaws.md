# Business Logic Flaws

## Basics

Business logic vulnerabilities often arise because the design and development teams make flawed assumptions about how users will interact with the application. These bad assumptions can lead to inadequate validation of user input. For example, if the developers assume that users will pass data exclusively via a web browser, the application may rely entirely on weak client-side controls to validate input. These are easily bypassed by an attacker using an intercepting proxy.

One of the best starting places for looking for logic flaws, is to navigate  through the application, mapping out all of the paths you can take. This is called spidering, for which there are many tools and even a Burp function.&#x20;

### **Points of interest**

* Forms
* Web Services
* Password Recovery
* User Registration
* Data shared between apps: Hashes, Tokens, Data, etc.

### **How to Find**

1. Review Functionality
   * Some applications have an option where verified reviews are marked with some tick or it's mentioned. Try to see if you can post a review as a Verified Reviewer without purchasing that product.
   * Some app provides you with an option to provide a rating on a scale of 1 to 5, try to go beyond/below the scale-like provide 0 or 6 or -ve.
   * Try to see if the same user can post multiple ratings for a product. This is an interesting endpoint to check for Race Conditions.
   * Try to see if the file upload field is allowing any exts, it's often observed that the devs miss out on implementing protections on such endpoints.
   * Try to post reviews like some other users.
   * Try performing CSRF on this functionality, often is not protected by tokens
2. Coupon Code Functionality
   * Apply the same code more than once to see if the coupon code is reusable.
   * If the coupon code is uniquely usable, try testing for Race Condition on this function by using the same code for two accounts at a parallel time.
   * Try Mass Assignment or HTTP Parameter Pollution to see if you can add multiple coupon codes while the application only accepts one code from the Client Side.
   * Try performing attacks that are caused by missing input sanitization such as XSS, SQLi, etc. on this field
   * Try adding discount codes on the products which are not covered under discounted items by tampering with the request on the server-side.
3. Delivery Charges Abuse
   * Try tampering with the delivery charge rates to -ve values to see if the final amount can be reduced.
   * Try checking for the free delivery by tampering with the params.
4. Currency Arbitrage
   * Pay in 1 currency say USD and try to get a refund in EUR. Due to the diff in conversion rates, it might be possible to gain more amount.
5. Premium Feature Abuse
   * Try forcefully browsing the areas or some particular endpoints which come under premium accounts.
   * Pay for a premium feature and cancel your subscription. If you get a refund but the feature is still usable, it's a monetary impact issue.
   * Some applications use true-false request/response values to validate if a user is having access to premium features or not.
   * Try using Burp's Match & Replace to see if you can replace these values whenever you browse the app & access the premium features.
   * Always check cookies or local storage to see if any variable is checking if the user should have access to premium features or not.
6. Refund Feature Abuse
   * Purchase a product (usually some subscription) and ask for a refund to see if the feature is still accessible.
   * Try for currency arbitrage explained yesterday.
   * Try making multiple requests for subscription cancellation (race conditions) to see if you can get multiple refunds.
7. Cart/Wishlist Abuse
   * Add a product in negative quantity with other products in positive quantity to balance the amount.
   * Add a product in more than the available quantity.
   * Try to see when you add a product to your wishlist and move it to a cart if it is possible to move it to some other user's cart or delete it from there.
8. Thread Comment Functionality
   * Unlimited Comments on a thread
   * Suppose a user can comment only once, try race conditions here to see if multiple comments are possible.
   * Suppose there is an option: comment by the verified user (or some privileged user) try to tamper with various parameters in order to see if you can do this activity.
   * Try posting comments impersonating some other users.
9. Parameter Tampering
   * Tamper Payment or Critical Fields to manipulate their values
   * Add multiple fields or unexpected fields by abusing HTTP Parameter Pollution & Mass Assignment
   * Response Manipulation to bypass certain restrictions such as 2FA Bypass

### **Links and Resources**

* [https://portswigger.net/web-security/logic-flaws](https://portswigger.net/web-security/logic-flaws)
* [https://portswigger.net/web-security/logic-flaws/examples](https://portswigger.net/web-security/logic-flaws/examples)
* [https://github.com/daffainfo/AllAboutBugBounty/blob/master/Business%20Logic%20Errors.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Business%20Logic%20Errors.md)
* [@harshbothra\_](https://twitter.com/harshbothra\_)

## **Examples of Logic Vulnerabilities**

### **Excessive trust in client-side controls**

* A fundamentally flawed assumption is that users will only interact with the application via the provided web interface. This is especially dangerous because it leads to the further assumption that client-side validation will prevent users from supplying malicious input. However, an attacker can simply use tools such as Burp Proxy to tamper with the data after it has been sent by the browser but before it is passed into the server-side logic. This effectively renders the client-side controls useless.
* [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls)
* [https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

### **Failing to handle unconventional input**

* If an application doesn't perform adequate server-side validation and reject characters and input outside expected formats, an attacker may be able to pass in a negative value and induce unwanted behavior.
* When auditing an application, you should use tools such as Burp Proxy and Repeater to try submitting unconventional values. In particular, try input in ranges that legitimate users are unlikely to ever enter. This includes exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields. You can even try unexpected data types. By observing the application's response, you should try and answer the following questions:
  * &#x20;Are there any limits that are imposed on the data?
  * &#x20;What happens when you reach those limits?
  * &#x20;Is any transformation or normalization being performed on your input?
* [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level)
* [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)
* [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)
* **Making flawed assumptions about user behavior**
  * Trusted users wont always remain trustworthy
    * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)
  * Users wont alwasy supply mandatory input
    * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint)
    * [https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)
  * Users wont always follow the intended sequence
    * [https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)
    * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation)
    * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine)
* **Domain -specific flaws**
  * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules)
  * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money)
* **Providing an encryption oracle**
  * Dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way. This kind of input is sometimes known as an "encryption oracle". An attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key.
  * [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle)
