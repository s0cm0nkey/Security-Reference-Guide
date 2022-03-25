# Utility Commands

There are far too many command options to list here. However there is a handy resource when looking for the command syntax for what you are trying to accomplish. [Commandlinefu](https://www.commandlinefu.com/commands/browse) is an amazing repository of command strings accomplishing different tasks. Simply search the task and see what commands have worked for others.

* [https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltea7de5267932e94b/5eb08aafcf88d36e47cf0644/Cheatsheet\_SEC301-401\_R7.pdf](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltea7de5267932e94b/5eb08aafcf88d36e47cf0644/Cheatsheet\_SEC301-401\_R7.pdf)
* [https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltf146e4f361db3938/5e34a7bc946d717e2eab6139/power-shell-cheat-sheet-v41.pdf](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltf146e4f361db3938/5e34a7bc946d717e2eab6139/power-shell-cheat-sheet-v41.pdf)

## **Linux**

* &#x20;Open file you do not have permission for
  * In the folder, view owner, permissions and UUID
    * \# ls -la
  * Add new user
    * \# sudo add user pwn
  * Change the UUID of the new user to that of the user that created the file
    * \# sudo sed -i -e ‘s/\[pwnUUID]/\[targetUUID]/g’ /etc/passwd
  * Check the new UUID
    * \# cat /etc/passwd | grep pwn
* _RTFM: Linux Utility Commands - pg. 6_
* _PTFM: Linux Utility Commands - pg. 78_
* _Operator Handbook: Linux\_Commands - pg. 118_
* _Operator Handbook: Linux\_tricks - pg. 147_

## **Windows**

* Add user to administrator group
  * \> net user \<name> \<pass> /add
  * \> net localgroup “Administrators" \<user> add
* Disable firewall
  * \> netsh advfirewall set currentprofile state off
  * \> netsh advfirewall set allprofiles state off
* Uninstall patch to exploit a vulnerability
  * Display all patches
    * \> dir /a /b c:\windows\kb\*
  * Uninstall patch
    * \> Wusa.exe /uninstall /kb:<###>
* _RTFM: Windows Utility Commands - pg. 17_
* _RTFM: Powershell Commands - pg. 22_
* _PTFM: Windows Utility Commands - pg. 1_
* _Operator Handbook: Windows\_Commands - pg. 328_
* _Operator Handbook: Windows Tricks - pg.415_

## **MacOS**

* _Operator Handbook: MacOS Commands - pg. 154_
* _Operator Handbook: MacOS Tricks - pg. 189_

## **WMIC**

* Impacket scripts
  * [wmiquery.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/wmiquery.py) It allows to issue WQL queries and get description of WMI objects at the target system (e.g. select name from win32\_account).
  * [wmipersist.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/wmipersist.py) This script creates/removes a WMI Event Consumer/Filter and link between both to execute Visual Basic based on the WQL filter or timer spec
* _RTFM: WMIC Commands - pg. 20_
