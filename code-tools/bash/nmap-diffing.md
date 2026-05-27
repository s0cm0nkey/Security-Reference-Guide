# Nmap Diffing

This script runs a daily Nmap scan and uses `ndiff` to show what changed compared with yesterday's scan. It is useful for defensive asset monitoring when you already have authorization to scan the network.

```bash
#!/bin/bash
mkdir -p /opt/nmap_diff
d=$(date +%Y-%m-%d)
y=$(date -d yesterday +%Y-%m-%d)
/usr/bin/nmap -T4 -oX /opt/nmap_diff/scan_$d.xml 10.100.100.0/24 > /dev/null 2>&1
if [ -e /opt/nmap_diff/scan_$y.xml ]; then
    /usr/bin/ndiff /opt/nmap_diff/scan_$y.xml /opt/nmap_diff/scan_$d.xml > /opt/nmap_diff/diff.txt
fi
```

For Nmap scanning methodology and scan options, use Scanning and Active Recon.

{% content-ref url="../../red-offensive/scanning-active-recon/" %}
[scanning-active-recon](../../red-offensive/scanning-active-recon/)
{% endcontent-ref %}
