# Web Sockets

## How it works

* WebSockets are widely used in modern web applications. They are initiated over HTTP and provide long-lived connections with asynchronous communication in both directions.
* WebSockets are used for all kinds of purposes, including performing user actions and transmitting sensitive information. Virtually any web security vulnerability that arises with regular HTTP can also arise in relation to WebSockets communications.
* WebSocket connections are normally created using client-side JavaScript like the following:
  * `var ws = new WebSocket("wss://normal-website.com/chat");`
* Several features of the WebSocket handshake messages are worth noting:
  * The `Connection` and `Upgrade` headers in the request and response indicate that this is a WebSocket handshake.
  * The `Sec-WebSocket-Version` request header specifies the WebSocket protocol version that the client wishes to use. This is typically `13`.
  * The `Sec-WebSocket-Key` request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
  * The `Sec-WebSocket-Accept` response header contains a hash of the value submitted in the `Sec-WebSocket-Key` request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.

## Cross-site Web Socket Hijack

Cross-site WebSocket hijacking (also known as cross-origin WebSocket hijacking) involves a [cross-site request forgery](https://portswigger.net/web-security/csrf) (CSRF) vulnerability on a [WebSocket handshake](https://portswigger.net/web-security/websockets/what-are-websockets#how-are-websocket-connections-established). It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any [CSRF tokens](https://portswigger.net/web-security/csrf/tokens) or other unpredictable values.

* An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.
* Since a cross-site WebSocket hijacking attack is essentially a [CSRF vulnerability](https://portswigger.net/web-security/csrf) on a WebSocket handshake, the first step to performing an attack is to review the WebSocket handshakes that the application carries out and determine whether they are protected against CSRF.
* In terms of the [normal conditions for CSRF attacks](https://portswigger.net/web-security/csrf#how-does-csrf-work), you typically need to find a handshake message that relies solely on HTTP cookies for session handling and doesn't employ any tokens or other unpredictable values in request parameters.&#x20;

### Reference

* [https://portswigger.net/burp/documentation/desktop/tools/proxy/options#intercepting-websocket-messages](https://portswigger.net/burp/documentation/desktop/tools/proxy/options#intercepting-websocket-messages)
* [https://xapax.github.io/security/#attacking\_web\_applications/cross\_site\_web\_socket\_hijack/](https://xapax.github.io/security/#attacking\_web\_applications/cross\_site\_web\_socket\_hijack/)

## Exploitation

### Manipulating WebSocket messages to exploit vulnerabilities

* The majority of input-based vulnerabilities affecting WebSockets can be found and exploited by tampering with the contents of WebSocket messages.
  * Changing messages to insert an XSS attack
  * XSS script must be in the “\<XSS code>” format

### **Manipulating the WebSocket handshake to exploit vulnerabilities**

* Misplaced trust in HTTP headers to perform security decisions, such as the `X-Forwarded-For` header.
* Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
* Attack surface introduced by custom HTTP headers used by the application.
