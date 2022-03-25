# SSL/TLS and Certificates

## Tools

* [SSL Cipher Suite Enum](https://github.com/portcullislabs/ssl-cipher-suite-enum) - ssl-cipher-suite enum is a Perl script to enumerate supported SSL cipher suites supported by network services (principally HTTPS)
  * &#x20;[https://labs.portcullis.co.uk/tools/ssl-cipher-suite-enum/](https://labs.portcullis.co.uk/tools/ssl-cipher-suite-enum/)
* Testssl.sh - a common tool used to audit the ciphers and protocols supported by remote servers, allowing people to determine if a secure configuration is enforced or not.
* [sslScrape](https://github.com/cheetz/sslScrape) - strips hostnames form certs over port 443 connections
* [SSLYZE ](https://github.com/nabla-c0d3/sslyze)- TLS/SSL config analyzer
* [tls\_prober](https://github.com/WestpointLtd/tls\_prober) - A tool to fingerprint SSL/TLS servers
* [testssl.sh](https://github.com/drwetter/testssl.sh)&#x20;
* [https://github.com/IBM/tls-vuln-cheatsheet](https://github.com/IBM/tls-vuln-cheatsheet)

## OpenSSL

* [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)

Used to create self signed certificates for SSL encryption

```
# openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out cirtificate.crt
```

* Tags
  * req - initiate a new certificate signing request
  * newkey - generate a new private key
  * rsa:2048 - use RSA encryption with a 2,048-bit key length
  * \-nodes - store the private key without passphrase protection
  * \-keyout - save the key to a file
  * \-x509 - output a self-signed cert instead of a certificate request
  * \-days - set validity period
  * \-out - save this certificate to a file
* Generate a self signed Certificate for a CA

```
# cat certificate.key certificate.crt > certificate.pem
```

* Create a .pem file for use with tools like socat

```
# openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf
```

* You will be prompted for certain pieces of information as well as a password which can be used when signing certificates in the future, so do not forget this! Two files will be outputted: `ca.key` which contains the CA’s private key, and `ca.crt` which contains the CA’s public key certificate.
* _Attacking Network Protocols - pg.200_
