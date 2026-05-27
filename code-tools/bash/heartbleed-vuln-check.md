# Heartbleed Vulnerability Check

This page is preserved as a historical reference for CVE-2014-0160, better known as Heartbleed. The previous page contained a long Python 2 scanner that was truncated and no longer suitable as a current code example.

## Current Guidance

Use maintained scanners and platform vulnerability management for Heartbleed checks rather than old standalone Python 2 scripts.

* [Nmap ssl-heartbleed NSE script](https://nmap.org/nsedoc/scripts/ssl-heartbleed.html)
* [Mozilla: Testing for Heartbleed without exploiting the server](https://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server/)
* [CVE-2014-0160](https://www.cve.org/CVERecord?id=CVE-2014-0160)

For broader vulnerability scanning methodology, use Scanning and Active Recon.

{% content-ref url="../../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../../red-offensive/scanning-active-recon/)
{% endcontent-ref %}

## Historical Notes

The original script was based on a non-exploitative Heartbleed check that sent a heartbeat request intended not to leak memory. It relied on Python 2 syntax, `optparse`, and byte handling patterns that are obsolete in modern Python.

Keep the lesson, not the script: old proof-of-concept tools can teach vulnerability mechanics, but they should not be presented as current operational guidance unless they are maintained and tested.
