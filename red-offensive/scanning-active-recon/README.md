# Reconnaissance and Scanning

This page focuses on active reconnaissance and scanning during authorized offensive testing. Passive OSINT, breach lookups, reputation checks, and general domain intelligence are maintained under Cyber Intelligence.

{% content-ref url="../../cyber-intelligence/osint/" %}
[osint](../../cyber-intelligence/osint/)
{% endcontent-ref %}

For multi-tool recon suites and attack surface management platforms, use the Recon Frameworks page.

{% content-ref url="recon-frameworks.md" %}
[recon-frameworks.md](recon-frameworks.md)
{% endcontent-ref %}

Web application scanning has its own section so web tooling does not get mixed into general network reconnaissance.

{% content-ref url="../../web-app-hacking/scanning-utilities.md" %}
[scanning-utilities.md](../../web-app-hacking/scanning-utilities.md)
{% endcontent-ref %}

## Attack Surface Mapping

Attack surface mapping identifies exposed assets, services, and technologies that may be in scope for testing. Some tools combine passive discovery with active probing, so validate each tool against the engagement rules before running it.

* [Awesome Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
* [OWASP Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
* [RedHunt Labs](https://redhuntlabs.com/)
* [Frameworthy](https://github.com/hasr00t/Frameworthy) - Collection of attack surface management tooling.
* [Amass](https://github.com/OWASP/Amass) - Network mapping and external asset discovery using open source information gathering and active reconnaissance techniques.
  * [Hakluke's Amass Guide](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
  * [Dionach: How to Use OWASP Amass](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [ProjectDiscovery](https://projectdiscovery.io/#/) - Open source tools often chained for bug bounty and external recon workflows.
  * [nuclei](https://github.com/projectdiscovery/nuclei)
  * [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  * [subfinder](https://github.com/projectdiscovery/subfinder)
  * [naabu](https://github.com/projectdiscovery/naabu)
  * [httpx](https://github.com/projectdiscovery/httpx)
  * [dnsx](https://github.com/projectdiscovery/dnsx)
* [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) - Expands a target seed into related domains, hosts, and exposed services.
* [IVRE](https://ivre.rocks/) - Network recon framework built around Nmap, Masscan, ZGrab2, ZDNS, and Zeek.
* [Goby](https://github.com/gobysec/Goby) - Network security assessment tool for asset and vulnerability discovery.

### Legacy or Caution

* [Intrigue Core](https://core.intrigue.io/) - Historical attack surface discovery framework. The open source component has not been actively maintained on GitHub since 2021 and has license caveats.
* [CloudFrontier](https://github.com/riskprofiler/CloudFrontier) - Cloud attack surface monitor with stale open issues and limited recent activity.
* [eReKon](https://github.com/slithery0/eReKon) - Web reconnaissance tool that appears incomplete or under active development; validate before relying on it.
* RiskIQ is now part of Microsoft. Treat older RiskIQ links as legacy branding and prefer current Microsoft Defender External Attack Surface Management references when needed.

## Host and Asset Discovery

Host discovery identifies live systems and services before deeper enumeration or exploitation.

* [HackTricks: Discovering Hosts](https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts)
* [fierce](https://www.kali.org/tools/fierce/) - Locates non-contiguous IP space and hostnames before running heavier scanners.
* [hosthunter](https://www.kali.org/tools/hosthunter/) - Maps IP addresses to virtual hostnames using OSINT-style techniques.
* [arp-scan](https://www.kali.org/tools/arp-scan/) - Sends ARP requests on local networks.
* [netdiscover](https://www.kali.org/tools/netdiscover/) - Active/passive ARP reconnaissance.

### Quick Commands

```bash
nmap --script broadcast-dhcp-discover
nmap -sn 192.168.0.0/24
fping -sagq 192.168.0.0/24
sudo arp-scan -l
netdiscover -r 192.168.0.0/24
```

### Active Directory DNS SRV Discovery

```bash
nslookup -type=srv _ldap._tcp.pdc._msdcs.$FQDN_DOMAIN
nslookup -type=srv _ldap._tcp.dc._msdcs.$FQDN_DOMAIN
nslookup -type=srv gc._msdcs.$FQDN_DOMAIN
nslookup -type=srv _kerberos._tcp.$FQDN_DOMAIN
nslookup -type=srv _kpasswd._tcp.$FQDN_DOMAIN
nslookup -type=srv _ldap._tcp.$FQDN_DOMAIN
nmap --script dns-srv-enum --script-args dns-srv-enum.domain=$FQDN_DOMAIN
```

### Wake-on-LAN

Wake-on-LAN magic packets are usually sent as Ethernet type `0x0842` or UDP port 9. Verify this is in scope before testing it on a real network.

```bash
wol.eth [MAC]
wol.udp [MAC]
```

### Responder Analyze Mode

Responder belongs with network poisoning and MITM techniques, but its analyze mode can be useful during discovery.

```bash
sudo responder -I eth0 -A
```

{% content-ref url="../post-exploitation/network-attacks-harvesting-mitm.md" %}
[network-attacks-harvesting-mitm.md](../post-exploitation/network-attacks-harvesting-mitm.md)
{% endcontent-ref %}

## Port Scanning

Port scanning identifies exposed services and helps prioritize enumeration. Tune rate, timing, and scan type to the rules of engagement.

{% content-ref url="nmap.md" %}
[nmap.md](nmap.md)
{% endcontent-ref %}

### Common Tools

* [Masscan](https://github.com/robertdavidgraham/masscan) - Internet-scale TCP port scanner.
* [RustScan](https://github.com/RustScan/RustScan) - Fast port scanner that can hand results to Nmap.
* [naabu](https://github.com/projectdiscovery/naabu) - Fast ProjectDiscovery port scanner.
* [Unicornscan](https://www.kali.org/tools/unicornscan/) - User-land distributed TCP/IP stack scanner.
* [Scantron](https://github.com/rackerlabs/scantron) - Distributed Nmap/Masscan scanning platform.
* [Scanless](https://github.com/vesche/scanless) - Uses third-party websites to perform port scans.
* [unimap](https://github.com/Edu4rdSHL/unimap) - Reduces duplicate scans across large target sets.
* [AMAP](https://www.kali.org/tools/amap/) - Identifies applications running on non-standard ports.

```bash
sudo masscan -p 80,443,445 10.0.0.0/24 --rate 1000
rustscan -a 10.10.10.10 -- -sV
naabu -host 10.10.10.10
nc -v 10.10.10.10 443
telnet 10.10.10.10 25
amap -d 10.10.10.10 8080
```

### Probe Response Cheat Sheet

* Open: `SYN -> SYN/ACK -> RST`
* Closed: `SYN -> RST/ACK`
* Filtered: no response or ICMP unreachable message.

## Active DNS Recon

Use this section for DNS queries, brute forcing, and active resolution tied to an authorized target. Passive DNS history and domain investigation belong under Cyber Intelligence.

{% content-ref url="../../cyber-intelligence/osint/domain.md" %}
[domain.md](../../cyber-intelligence/osint/domain.md)
{% endcontent-ref %}

* [DNSRecon](https://github.com/darkoperator/dnsrecon)
* [dnsenum](https://www.kali.org/tools/dnsenum/)
* [dnsmap](https://www.kali.org/tools/dnsmap/)
* [dnsx](https://github.com/projectdiscovery/dnsx)
* [massdns](https://github.com/blechschmidt/massdns)
* [shuffledns](https://github.com/projectdiscovery/shuffledns)
* [Knock](https://github.com/guelfoweb/knock)
* [HostileSubBruteforcer](https://github.com/nahamsec/HostileSubBruteforcer)
* [altdns](https://www.kali.org/tools/altdns/)
* [assetfinder](https://www.kali.org/tools/assetfinder/)
* [Sublist3r](https://github.com/aboul3la/Sublist3r)
* [zdns](https://github.com/zmap/zdns)
* [aiodnsbrute](https://github.com/blark/aiodnsbrute)
* [Findomain](https://github.com/Findomain/Findomain)
* [Dome](https://github.com/v4d1/Dome)

Subdomain screenshot and flyover tools overlap with web application recon. Keep the detailed workflow in Web App Hacking.

{% content-ref url="../../web-app-hacking/scanning-utilities.md" %}
[scanning-utilities.md](../../web-app-hacking/scanning-utilities.md)
{% endcontent-ref %}

## Vulnerability Scanning

Vulnerability scanners identify known weaknesses, exposed versions, misconfigurations, and risky defaults. They can be noisy, so validate scope, rate limits, and maintenance windows before running them.

* [Nessus Professional](https://www.tenable.com/products/nessus/nessus-professional)
* [Nessus Essentials](https://www.tenable.com/products/nessus/nessus-essentials)
* [Nessus Downloads](https://www.tenable.com/downloads/nessus)
* [OpenVAS](https://github.com/greenbone/openvas) / [Greenbone Community Edition](https://greenbone.github.io/docs/latest/)
* [Kali GVM package](https://www.kali.org/tools/gvm/)
* [Nmap NSE Scripts](https://nmap.org/nsedoc/)
* [ReconMap](https://reconmap.org/)
* [Vulmap](https://github.com/vulmon/Vulmap)
* [Vuls](https://github.com/future-architect/vuls)
* [Tsunami Scanner](https://github.com/google/tsunami-security-scanner)
* [Flan Scan](https://github.com/cloudflare/flan)

### Example Commands

```bash
sudo apt install ./Nessus-X.X.X.deb
sudo systemctl start nessusd
sudo gvm-setup
sudo gvm-check-setup
sudo runuser -u _gvm -- greenbone-feed-sync
nmap --script-help default
nmap --script vuln 10.10.10.10
```

Nessus commonly listens on `https://localhost:8834`. Greenbone/GVM web UI ports vary by package and configuration, so check the local service output instead of relying on old OpenVAS port references.

## TLS and Service Configuration Checks

For HTTPS-specific testing, use the Web Technologies SSL/TLS page. The tools below are also useful for non-HTTP TLS services.

{% content-ref url="../../web-app-hacking/web-technologies/ssl-tls-and-certificates.md" %}
[ssl-tls-and-certificates.md](../../web-app-hacking/web-technologies/ssl-tls-and-certificates.md)
{% endcontent-ref %}

* [testssl.sh](https://github.com/drwetter/testssl.sh)
* [SSLYZE](https://github.com/nabla-c0d3/sslyze)
* [ssl-cipher-suite-enum](https://github.com/portcullislabs/ssl-cipher-suite-enum)
* [TLS Prober](https://github.com/WestpointLtd/tls_prober)

## Honeypot and Filtering Awareness

These tools can help identify defensive traps or filtering behavior during authorized testing. Use them carefully and document assumptions; a honeypot score is not proof.

* [HoneyCaught](https://github.com/aswinmguptha/HoneyCaught)
* [Sniffing Bear](https://github.com/MrSuicideParrot/SniffingBear)
* [Shodan Honeyscore](https://honeyscore.shodan.io/)
* [firewalk](https://www.kali.org/tools/firewalk/)
* [ftester](https://www.kali.org/tools/ftester/)

## Default Credential Checks

* [changeme](https://www.kali.org/tools/changeme/) - Default credential scanner for HTTP(S), MSSQL, MySQL, PostgreSQL, SSH, and SSH keys.

For deeper password attacks, use the Password Attacks page.

{% content-ref url="../testing-methodology/password-attacks.md" %}
[password-attacks.md](../testing-methodology/password-attacks.md)
{% endcontent-ref %}

## Training

Training rooms and labs for passive recon, active recon, RustScan, OpenVAS, and Sublist3r live in Training.

{% content-ref url="../../training/" %}
[training](../../training/)
{% endcontent-ref %}
