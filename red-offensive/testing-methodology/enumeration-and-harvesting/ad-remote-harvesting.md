# AD/Remote Harvesting

## Remote Harvesting Tools

* [Red Snarf](https://github.com/nccgroup/redsnarf) - RedSnarf is a pen-testing / red-teaming tool by Ed Williams for retrieving hashes and credentials from Windows workstations, servers and domain controllers using OpSec Safe Techniques
  * [https://www.kali.org/tools/redsnarf/](https://www.kali.org/tools/redsnarf/)
* Impacket Tools
  * [impacket/mimikatz.py](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/mimikatz.py)
  * [impacket/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/secretsdump.py)
* [Snaffler](https://github.com/SnaffCon/Snaffler) - It gets a list of Windows computers from Active Directory, then spreads out its snaffly appendages to them all to figure out which ones have file shares, and whether you can read them.
* [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Utility to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory but also perform pass-the-hash, pass-the-ticket or build Golden tickets
  * [SafetyKatz](https://github.com/GhostPack/SafetyKatz) - SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader.
  * [spraykatz](https://www.kali.org/tools/spraykatz/) - This package contains a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) - Active Directory information dumper via LDAP
* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - A PowerShell Toolkit for Attacking SQL Server

## AD Credential Harvesting

* [AD-006 - Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

### Passwords in AD Attributes

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/passwords\_in\_active\_directory\_attributes/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/passwords\_in\_active\_directory\_attributes/)

### Mining SMB Shares

* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/smb\_shares\_mining/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/smb\_shares\_mining/)

### Scripts stored in SYSVOL

* [https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_scripts\_on\_sysvol/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/check\_for\_scripts\_on\_sysvol/)

### Passwords in GPO

* [https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/passwords\_in\_group\_policy\_preferences/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/active\_directory\_privilege\_escalation/passwords\_in\_group\_policy\_preferences/)

### NTDS.DIT Password Extraction

* [How Attackers Pull the Active Directory Database (NTDS.dit) from a Domain Controller](https://adsecurity.org/?p=451)
* [Extracting Password Hashes From The Ntds.dit File](https://blog.stealthbits.com/extracting-password-hashes-from-the-ntds-dit-file/)

### SAM (Security Accounts Manager)

* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
* [GhostPack/Koh](https://github.com/GhostPack/Koh) - Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
  * [https://posts.specterops.io/koh-the-token-stealer-41ca07a40ed6?gi=be2457d740ab](https://posts.specterops.io/koh-the-token-stealer-41ca07a40ed6?gi=be2457d740ab)

### Windows Credential Manager/Vault

* [Operational Guidance for Offensive User DPAPI Abuse](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/)
* [Jumping Network Segregation with RDP](https://rastamouse.me/blog/rdp-jump-boxes/)

### DCSync

* [Mimikatz and DCSync and ExtraSids, Oh My](https://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
* [Mimikatz DCSync Usage, Exploitation, and Detection](https://adsecurity.org/?p=1729)
* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)
