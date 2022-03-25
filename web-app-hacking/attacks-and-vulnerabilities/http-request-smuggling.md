# HTTP Request Smuggling

## Tools and Resources

* [smuggler](https://github.com/defparam/smuggler) - An HTTP Request Smuggling / Desync testing tool written in Python 3.

```
python3 smuggler.py -q -u https://example.com/
```

Attacking through command line a HTTPS vulnerable service. Good for persistence when no one believes in you.

```
echo 'UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiB5b3VyLWxhYi1pZC53ZWItc2VjdXJpdHktYWNhZGVteS5uZXQNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkDQpDb250ZW50LUxlbmd0aDogNg0KVHJhbnNmZXItRW5jb2Rpbmc6IGNodW5rZWQNCg0KMA0KDQpH' | base64 -d | timeout 1 openssl s_client -quiet -connect your-lab-id.web-security-academy.net:443 &>/dev/null

```

* [http2smugl](https://github.com/neex/http2smugl) - This tool helps to detect and exploit HTTP request smuggling in cases it can be achieved via HTTP/2 -> HTTP/1.1 conversion by the frontend server.

```
http2smugl detect https://example.com/
```

* [h2csmuggler](https://github.com/BishopFox/h2csmuggler) - h2cSmuggler smuggles HTTP traffic past insecure edge-server proxy\_pass configurations by establishing HTTP/2 cleartext (h2c) communications with h2c-compatible back-end servers, allowing a bypass of proxy rules and access controls.

```
h2csmuggler.py -x https://example.com/ --test
```

* [websocket-smuggle](https://github.com/0ang3el/websocket-smuggle) - Smuggling HTTP requests over fake WebSocket connection.
* [http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler) - This is an extension for Burp Suite designed to help you launch HTTP Request Smuggling attacks, originally created during HTTP Desync Attacks research. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.
* [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
* [https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142](https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142)\
  This is how I was able to exploit a HTTP Request Smuggling in some Mobile Device Management (MDM) servers and send any MDM command to any device enrolled on them for a private bug bounty program.
* [https://www.intruder.io/research/practical-http-header-smuggling](https://www.intruder.io/research/practical-http-header-smuggling) - Modern web applications typically rely on chains of multiple servers, which forward HTTP requests to one another. The attack surface created by this forwarding is increasingly receiving more attention, including the recent popularisation of cache poisoning and request smuggling vulnerabilities. Much of this exploration, especially recent request smuggling research, has developed new ways to hide HTTP request headers from some servers in the chain while keeping them visible to others – a technique known as "header smuggling". This paper presents a new technique for identifying header smuggling and demonstrates how header smuggling can lead to cache poisoning, IP restriction bypasses, and request smuggling.
* [https://docs.google.com/presentation/d/1DV-VYkoEsjFsePPCmzjeYjMxSbJ9PUH5EIN2ealhr5I/](https://docs.google.com/presentation/d/1DV-VYkoEsjFsePPCmzjeYjMxSbJ9PUH5EIN2ealhr5I/) - Two Years Ago @albinowax Shown Us A New Technique To PWN Web Apps So Inspired By This Technique AND @defparam's Tool , I Have Been Collecting A Lot Of Mutations To Achieve Request Smuggling.
* [https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142](https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142)
* [https://www.slideshare.net/neexemil/http-request-smuggling-via-higher-http-versions](https://www.slideshare.net/neexemil/http-request-smuggling-via-higher-http-versions)
