# TOR

[TOR](https://www.torproject.org)

### TOR Tools

* [Awesome Lists Collection: TOR](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/AnonOpSecPrivacy.md)
* [https://geti2p.net/en/](https://geti2p.net/en/) - Kinda like TOR?
* [nipe](https://github.com/htrgouvea/nipe) - Tool to make TOR your default gateway
  * [Hackersploit nipe guide](https://youtu.be/ec37is2yyMo)
* [onionscan.org](https://onionscan.org/) - OnionScan is a free and open source tool for investigating the Dark Web.
* [dos-over-tor](https://github.com/skizap/dos-over-tor)
* [Kalitorify](https://github.com/brainfuckSec/kalitorify) - Transparent proxy through Tor for Kali Linux OS
* [vanguards](https://github.com/mikeperry-tor/vanguards) - Onion services defense tools
* [OnionBalence](https://onionbalance.readthedocs.io/en/latest/) - Onionbalance is the best way to load balance onion services across multiple backend Tor instances.
* [multitor](https://github.com/trimstray/multitor) - Create multiple TOR instances with a load-balancing
* [CrowdStrike/Tortilla](https://github.com/CrowdStrike/Tortilla) - Route all network through Tor.
  * [Hackersploit's guide to Tortilla](https://youtu.be/hcKpROGDXOM)
* [https://iaca-darkweb-tools.com](https://iaca-darkweb-tools.com) - A collection of darkweb search tools. Allows you to query .onion search engines, marketplaces and social media sites. -&#x20;
* [https://torrouters.com/](https://torrouters.com/) - THOR is a hardware version of the Tor (The Onion Router) bundle, which provides you with anonymity and privacy you need to bypass any ISP restrictions and enhance your privacy online.

### Tor Bridges - alternative entry points for Tor that are not listed

* [https://tails.boum.org/doc/first\_steps/startup\_options/bridge\_mode/index.en.html](https://tails.boum.org/doc/first_steps/startup_options/bridge_mode/index.en.html)
* [https://bridges.torproject.org/bridges](https://bridges.torproject.org/bridges)
* Some networks may block port TCP 9050 or even dynamically blacklist all Tor nodes in an attempt to prevent thier users from accessing the Tor network and get around access control
* This can be over come by useing Tor bridges.
* This can be configured to use by adding the bridge information to the torrc file like below
  * \#Bridge fte 128.105.214.163:8080 \[hash]
* Obfuscated bridges - bridges that use special plug-ins called pluggable transports which obfuscate the traffic flow of Tor making its detection harder
  * [https://www.torproject.org/docs/bridges#PluggableTransports](https://www.torproject.org/docs/bridges#PluggableTransports)
  * Get these by requesting one by using a gmail/yahoo account and email bridges@bridges.torproject.org and enter “transport obfs3”
  * Tor Pluggable Transports Tor Browser Bundle

### Interesting Tor pages

* [Hidden Wiki](https://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion.pet/wiki/index.php/Main_Page) - A large and neatly organized directory of .onion sites.
  * [Darknet Version](https://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php/Main_Page)
* [https://hidden-services.today](https://hidden-services.today) - Place with fresh links to TOR services hidden that is free of spam and scam sites. Only trusted and safe links are provided.
* [https://www.hunch.ly/darkweb-osint/](https://www.hunch.ly/darkweb-osint/) - Identify new hidden services, or find investigation targets that you might not have otherwise known about. It is 100% free and every day you will receive a link to a spreadsheet you can download or view online. Requires you to provide an email address to join their mailing list.
* [TOR66](http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/fresh) - An onion site that lists newly discovered onion sites that have been submitted from a variety of different clearnet platforms.
* [H-Indexer](http://jncyepk6zbnosf4p.onion/onions.html) - Another onion site that offers a list of fresh onions. Beware, results are often uncensored, so you may encounter illegal material.
* &#x20;[https://osint.party/api/rss/fresh](https://osint.party/api/rss/fresh) - An amazing RSS feed of fresh and newly discovered .onion sites. Be careful, this feed remains uncensored, so you may encounter illegal content.
* [https://www.bigdatacloud.com/insights/tor-exit-nodes](https://www.bigdatacloud.com/insights/tor-exit-nodes)
* [Dread](https://www.deeponionweb.com/dread-forum/) - Reddit of the darkweb
  * [https://cafedread.com](https://cafedread.com) - A read-only archive of the Dread forum. Read the latest posts and comments. Also supports reading via Atom feeds.
* [http://hacktownpagdenbb.onion/HackTown.html](http://hacktownpagdenbb.onion/HackTown.html) - One of my favorite sites on learning the operations of a black hat.
* [https://metrics.torproject.org/exonerator.html](https://metrics.torproject.org/exonerator.html) - Enter an IP address and date to find out whether that address was used as a Tor relay.

### Check yourself

* [https://www.dnsleaktest.com/results.html](https://www.dnsleaktest.com/results.html) - Check for DNS leaks in your TOR connection
* [https://check.torproject.org/](https://check.torproject.org/) - Are you connected to TOR? Are you sure?

### Misc Reference

* [Darknet Markey Buyers Guide](http://biblemeowimkh3utujmhm6oh2oeb3ubjw2lpgeq3lahrfr2l6ev6zgyd.onion/content/index.html) - The buyer’s DNM bible aims to be a complete guide that covers all steps that users have to take in order to buy securely from darknet markets. It orientates itself on OPSEC best practices and, if exactly followed, will greatly minimize the risk of you getting caught.
  * [https://archive.org/details/darknet-market-buyers-bible](https://archive.org/details/darknet-market-buyers-bible)



### Learn to TOR

* [https://tryhackme.com/room/torforbeginners](https://tryhackme.com/room/torforbeginners)
