---
description: Privacy, Tor, PGP, and personal OPSEC references.
---

# Grey - Privacy/Tor/OPSEC

Grey is for personal privacy, anonymity, secure communication, Tor, PGP, and operational safety for legitimate research. Dark-web search and OSINT sources belong in Cyber Intelligence; offensive routing, evasion, and command-history hiding belong in Red Offensive.

## Start Here

{% embed url="https://www.amazon.com/Extreme-Privacy-Takes-Disappear-America/dp/1093757620" %}
Read this first.
{% endembed %}

{% content-ref url="tor.md" %}
[tor.md](tor.md)
{% endcontent-ref %}

{% content-ref url="pgp-guide.md" %}
[pgp-guide.md](pgp-guide.md)
{% endcontent-ref %}

{% content-ref url="jolly-rogers-security-for-beginners.md" %}
[jolly-rogers-security-for-beginners.md](jolly-rogers-security-for-beginners.md)
{% endcontent-ref %}

The Jolly Roger page is preserved as a historical archive and should not be modernized in place.

## Privacy Guides and Reference

<details>

<summary>General Guides</summary>

* [Hitchhiker's Guide to Online Anonymity](https://anonymousplanet.github.io/thgtoa/guide.html)
* [Infosec Reference: Anon/OPSEC/Privacy](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/AnonOpSecPrivacy.md)
* [Personal Security Checklist](https://github.com/Lissy93/personal-security-checklist)
* [Prism Break](https://prism-break.org/en/) - Alternatives focused on reducing data collection.
* [Privacy Guides](https://www.privacyguides.org/) - Successor community to the old privacytools.io project.
* [Electronic Frontier Foundation](https://www.eff.org/)
* [EFF Surveillance Self-Defense](https://ssd.eff.org/)
* [Crash Override DIY Security Guides](https://www.crashoverridenetwork.com/resources.html)
* [Security-in-a-Box](https://securityinabox.org/en/)
* [Exposing the Invisible: Watching Out for Yourself](https://exposingtheinvisible.org/resources/watching-out-yourself/) - Personal security guide for investigators.
* [SafetyDetectives VPN list](https://www.safetydetectives.com/best-vpns/) - Commercial review list; verify recommendations independently before trusting them.

</details>

## Browser Privacy and Leak Checks

<details>

<summary>Browser Checks</summary>

Use Tor Browser, Firefox, Mullvad Browser, or another privacy-focused browser with a configuration that matches your threat model. Chrome and other Chromium browsers can be hardened, but their defaults are not privacy-first.

* [Firefox](https://www.mozilla.org/en-US/firefox/)
* Firefox secure install and setup - _Extreme Privacy: What it Takes to Disappear, 5th edition, pg. 39_
* [DuckDuckGo](https://duckduckgo.com/) - Private search engine.
* [SearXNG](https://docs.searxng.org/) - Self-hostable metasearch engine.
* [Cover Your Tracks](https://coveryourtracks.eff.org/) - EFF browser tracking and fingerprinting test. Replaces the older Panopticlick branding.
* [AmIUnique](https://amiunique.org/) - Browser fingerprint uniqueness check.
* [Privacy Analyzer](https://privacy.net/analyzer/) - Browser data exposure check.
* [Browser Mirror](https://centralops.net/asp/co/BrowserMirror.vbs.asp) - Shows browser headers and exposed client data.
* [Webkay](https://webkay.robinlinus.com/) - Demonstrates what browser APIs expose.
* [IntelTechniques Logger](https://inteltechniques.com/logger/) - Shows trackable browser data.
* [GRC ShieldsUP](https://www.grc.com/shieldsup) - Internet connection and router exposure check.
* [ipleak.net](https://ipleak.net/) - IP, DNS, WebRTC, and user-agent leak checks.
* [BrowserLeaks](https://browserleaks.com/) - Browser security and privacy testing tools.
* [SOCRadar VPNRadar](https://socradar.io/labs/vpnradar/) - VPN privacy checker.
* [Tenta browser test](https://tenta.com/test/) - Historical leak-check tool; verify current availability before relying on it.
* [Shut Up Trackers browser tweaks](https://shutuptrackers.com/browser/tweaks.php) - Older Firefox tweak list. Prefer current Firefox/Mullvad/arkenfox guidance for maintained hardening.

</details>

## Privacy Apps

<details>

<summary>General Tools</summary>

* [Awesome Anti-Censorship](https://github.com/danoctavian/awesome-anti-censorship)
* [Awesome Anti-Forensics](https://github.com/shadawck/awesome-anti-forensic) - Awesome list; duplicate allowed by the guide's Awesome List exception.
* [OneRep](https://onerep.com/) - Data broker removal service.
* [SnowHaze Browser](https://www.snowhaze.com/en/browser.html) - iOS privacy browser.
* [MySudo](https://mysudo.com/) - Creates alternate phone/email identities.
* [Privacy.com](https://privacy.com/) - Virtual payment cards.
* [Burner](https://www.burnerapp.com/) - Temporary phone numbers.
* [Syncthing](https://syncthing.net/) - Open source file synchronization.
* [Tails](https://tails.net/) - Portable privacy-focused live OS.
* [Anonymouse.org](http://anonymouse.org/anonwww.html) - Legacy anonymous proxy; not recommended for serious privacy.
* [Privoxy](https://www.privoxy.org/) - Filtering web proxy.
* [Kali Anonsurf](https://github.com/Und3rf10w/kali-anonsurf) - Kali port of ParrotSec Anonsurf.
  * [ParrotSec Anonsurf](https://github.com/ParrotSec/anonsurf)
* [cryptsetup-nuke-password](https://www.kali.org/tools/cryptsetup-nuke-password/) - Kali package that can destroy encrypted partition keys with a special passphrase.

</details>

<details>

<summary>Secure Communications</summary>

Primary tools:

* [Signal](https://www.signal.org/) - Encrypted communications app.
  * Secure setup - _Extreme Privacy: What it Takes to Disappear, 5th edition, pg. 130_
  * [Molly](https://molly.im/) - Hardened Signal fork for Android.
* [Wire](https://wire.com/en/) - E2EE collaboration and messaging platform. Verify the current plan and identity model before selecting it for sensitive use.

Alternatives:

* [Threema](https://threema.ch/en)
* [Matrix](https://matrix.org/)
* [Session](https://getsession.org/)

Deprecated or high-risk:

* [TorChat](https://github.com/prof7bit/TorChat) - Abandoned Tor-based messenger. Keep only as historical context.
* Wickr Me - Discontinued for consumers.
* WhatsApp - Strong message encryption but high metadata and account-linkage concerns.
* Telegram - Standard chats are not end-to-end encrypted; secret chats have different behavior and limitations.

</details>

<details>

<summary>Secure File Transfer and Webmail</summary>

* [Proton Drive](https://proton.me/drive)
* [Tresorit](https://tresorit.com/)
* [CounterMail](https://countermail.com/)
* [Mail2Tor](http://mail2tor.com/) - Historically used anonymous email service; verify current trust and availability before use.
* [Tutanota/Tuta](https://tuta.com/)
* [Proton Mail](https://proton.me/mail)
* [StartMail](https://www.startmail.com/en/)

</details>

<details>

<summary>Altnets</summary>

* [Whonix ZeroNet guide](https://www.whonix.org/wiki/ZeroNet) - ZeroNet is largely historical; verify project activity before using it.
* [FidoNet node history](https://nodehist.fidonet.org.ua) - Historical/alternative network reference.
* [NZBFriends](https://nzbfriends.com/) - Usenet search engine.

</details>

## Personal Network Security

The old page used a hotlinked 2015 image for this section. Prefer current router and home-network guidance:

* Update router firmware and replace unsupported hardware.
* Use WPA2/WPA3 with a strong passphrase.
* Disable WPS.
* Separate guest, IoT, and trusted devices where possible.
* Review UPnP, port forwards, DNS settings, and admin-interface exposure.
* Run leak checks from the Browser Privacy section after VPN/Tor changes.

## OPSEC

* [IntelTechniques OPSEC Prep Checklist](https://inteltechniques.com/EP/tasks.pdf)
* [Exposing the Invisible Kit](https://kit.exposingtheinvisible.org/en/) - Investigation and verification training.
* [A 5-minute guide to creating a covert account for internet investigations](https://www.intelligencewithsteve.com/post/a-5-minute-guide-to-creating-a-covert-account-for-internet-investigations-osint) - Maintained under Cyber Intelligence because it is an OSINT persona workflow.

{% content-ref url="../cyber-intelligence/osint/" %}
[osint](../cyber-intelligence/osint/)
{% endcontent-ref %}

### Historical Dread OPSEC Guide

The old Dread OPSEC material mixed useful browser/Tails/Whonix advice with darknet-market framing, stale onion links, and outdated CCleaner-style footprint cleanup. Preserve it only as historical context; use the maintained Tor, Tails, Whonix, and browser references above for current workflows.

### Device OPSEC

<details>

<summary>macOS</summary>

* _Extreme Privacy: What it Takes to Disappear, 5th edition, pg. 39_
* [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) - Commercial macOS network monitor/firewall. It is not open source.
* [Objective-See Tools](https://objective-see.org/tools.html)
  * [LuLu](https://objective-see.org/products/lulu.html) - Open source macOS firewall.
  * [KnockKnock](https://objective-see.org/products/knockknock.html) - Reveals persistent software.

</details>

<details>

<summary>Linux</summary>

* _Extreme Privacy: What it Takes to Disappear, 5th edition, pg. 21_
* [Pop!_OS](https://pop.system76.com/)
* [OpenSnitch](https://github.com/evilsocket/opensnitch) - Linux application firewall.

</details>

<details>

<summary>Mobile</summary>

* _Extreme Privacy: What it Takes to Disappear, 5th edition, pg. 75 and pg. 117_
* [GrapheneOS](https://grapheneos.org/) - Privacy and security focused Android distribution for supported Pixel devices.

</details>

## Web OPSEC Basics

* Disable JavaScript for high-risk Tor browsing when your workflow allows it.
* Use the Tor Browser security slider for riskier browsing.
* Do not mix personal browsing sessions with research or anonymity sessions.
* Restart Tor Browser regularly to clear state.
* Prefer Tor Browser/Tails/Whonix defaults over hand-rolled browser hardening for anonymity work.
* Treat old v2 onion addresses and clearnet onion proxy links as stale or unsafe by default.

## File Verification and Encryption

* [Gpg4win](https://www.gpg4win.org/) - Windows OpenPGP tooling.
* Prefer OpenPGP signatures and SHA-256 or stronger hashes.
* Treat MD5 and SHA-1 as legacy integrity checks, not secure verification.

{% content-ref url="pgp-guide.md" %}
[pgp-guide.md](pgp-guide.md)
{% endcontent-ref %}

## Offensive OPSEC and Evasion

Command-history hiding, log tampering, process masquerading, PowerShell logging bypasses, and similar material belong in Red Offensive and should only be used in explicitly authorized labs or engagements.

{% content-ref url="../red-offensive/testing-methodology/post-exploitation/defense-evasion.md" %}
[defense-evasion.md](../red-offensive/testing-methodology/post-exploitation/defense-evasion.md)
{% endcontent-ref %}

{% content-ref url="../red-offensive/testing-methodology/lateral-movement.md" %}
[lateral-movement.md](../red-offensive/testing-methodology/lateral-movement.md)
{% endcontent-ref %}
