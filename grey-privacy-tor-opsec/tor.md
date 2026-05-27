---
description: Tor fundamentals, privacy routing, bridges, onion-service notes, and safe references.
---

# Tor

Tor privacy work should start with the official Tor Browser, Tails, or Whonix documentation. Dark-web search, onion indexing, and threat-intelligence feeds live in Cyber Intelligence; Tor-based routing for authorized offensive testing lives in Red Offensive.

## Official References

* [Tor Project](https://www.torproject.org/)
* [Tor Browser](https://www.torproject.org/download/)
* [Check Tor](https://check.torproject.org/) - Verify that your browser is using Tor.
* [Tor Metrics](https://metrics.torproject.org/) - Tor relay and network statistics.
* [ExoneraTor](https://metrics.torproject.org/exonerator.html) - Check whether an IP address was a Tor relay on a specific date.
* [EFF Surveillance Self-Defense: How to use Tor](https://ssd.eff.org/en/module/how-use-tor-windows)

## Privacy Routing Tools

* [Tails](https://tails.net/) - Amnesic live operating system that routes connections through Tor.
* [Whonix](https://www.whonix.org/) - Tor-focused desktop OS using gateway/workstation isolation.
* [I2P](https://geti2p.net/en/) - Separate anonymity network. See Cyber Intelligence for I2P search resources.
* [nipe](https://github.com/htrgouvea/nipe) - Routes Linux traffic through Tor. Use carefully; Tor Browser/Tails/Whonix are safer defaults for most users.
  * [Hackersploit nipe guide](https://youtu.be/ec37is2yyMo)
* [torrouters.com](https://torrouters.com/) - Hardware Tor router project. Verify current availability before purchasing.

## Bridges and Pluggable Transports

Bridges are Tor entry points that are not listed in the public relay directory. They help when a network blocks known Tor relays.

* [Tor Browser bridge documentation](https://support.torproject.org/censorship/censorship-7/)
* [Tor bridges](https://bridges.torproject.org/bridges)
* [Tails bridge mode](https://tails.net/doc/anonymous_internet/tor/index.en.html#bridges)
* Modern bridge workflows generally use pluggable transports such as **obfs4**, **meek**, or **Snowflake**. Older obfs2/obfs3 instructions are deprecated.
* To request bridges by email, follow the current Tor Project instructions rather than copying old transport-specific examples.

## Onion Service Operators

* [vanguards](https://github.com/mikeperry-tor/vanguards) - Onion-service defense tooling.
* [Onionbalance](https://onionbalance.readthedocs.io/en/latest/) - Load balances onion services across multiple backends.

## Self-Checks

* [DNS Leak Test](https://www.dnsleaktest.com/) - Check whether DNS requests leak outside the intended resolver path.
* [ipleak.net](https://ipleak.net/) - Check IP, DNS, WebRTC, and browser fingerprint exposure.
* [BrowserLeaks](https://browserleaks.com/) - Browser privacy and fingerprinting checks.
* [Cover Your Tracks](https://coveryourtracks.eff.org/) - EFF browser tracking and fingerprinting test.

## Dark-Web Search and OSINT

Dark-web investigation resources are maintained in Cyber Intelligence. Use them as untrusted data sources, and expect onion links to churn frequently.

{% content-ref url="../cyber-intelligence/osint/dark-web-search.md" %}
[dark-web-search.md](../cyber-intelligence/osint/dark-web-search.md)
{% endcontent-ref %}

{% content-ref url="../cyber-intelligence/intel-feeds-and-sources.md" %}
[intel-feeds-and-sources.md](../cyber-intelligence/intel-feeds-and-sources.md)
{% endcontent-ref %}

## Authorized Offensive Routing

Tor routing tools used for labs, pivoting, or offensive infrastructure belong with Red Offensive. Do not treat pentest routing utilities as personal anonymity guarantees.

{% content-ref url="../red-offensive/testing-methodology/lateral-movement.md" %}
[lateral-movement.md](../red-offensive/testing-methodology/lateral-movement.md)
{% endcontent-ref %}

{% content-ref url="../red-offensive/offensive-toolbox/" %}
[offensive-toolbox](../red-offensive/offensive-toolbox/)
{% endcontent-ref %}

## Training

{% content-ref url="../training/" %}
[training](../training/)
{% endcontent-ref %}
