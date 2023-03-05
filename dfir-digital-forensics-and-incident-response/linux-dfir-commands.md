# Linux DFIR Commands

## Dumping Memory <a href="#dumping-memory" id="dumping-memory"></a>

```
dd if=/dev/kmem of=/root/kmem
dd if=/dev/mem of=/root/mem
```

[LiME](https://github.com/504ensicsLabs/LiME/releases)

```
sudo insmod ./lime.ko "path=./Linmen.mem format=raw"
```

[LinPMem](https://github.com/Velocidex/c-aff4/releases/)

```
./linpmem -o memory.aff4
./linpmem memory.aff4 -e PhysicalMemory -o memory.raw
```

## Taking Image <a href="#taking-image" id="taking-image"></a>

```
fdisk -l
dd if=/dev/sda1 of=/[outputlocation]
```

## Misc Useful Tools <a href="#misc-useful-tools" id="misc-useful-tools"></a>

[FastIR](https://github.com/SekoiaLab/Fastir\_Collector\_Linux)

```
python ./fastIR_collector_linux.py
```

[LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

```
./linenum.sh
./linenum.sh -t
```

## Live Triage <a href="#live-triage" id="live-triage"></a>

### System Information <a href="#system-information-1" id="system-information-1"></a>

```
date
uname –a
hostname
cat /proc/version
lsmod
```

### Account Information <a href="#account-information" id="account-information"></a>

```
cat /etc/passwd
cat /etc/shadow
cat /etc/sudoers
cat /etc/sudoers.d/*
cut -d: -f1 /etc/passwd
getent passwd | cut -d: -f1
compgen -u
```

### Current user <a href="#current-user" id="current-user"></a>

```
whoami
who
```

### Last logged on users <a href="#last-logged-on-users" id="last-logged-on-users"></a>

```
last
lastb
cat /var/log/auth.log
```

### Initialization Files <a href="#initialisation-files" id="initialisation-files"></a>

```
cat /etc/bash.bashrc
cat ~/.bash_profile 
cat ~/.bashrc 
```

### Environment and Startup Programs <a href="#environment-and-startup-programs" id="environment-and-startup-programs"></a>

```
cat /etc/profile
ls /etc/profile.d/
cat /etc/profile.d/*
```

### Scheduled Tasks <a href="#scheduled-tasks" id="scheduled-tasks"></a>

```
ls /etc/cron.*
ls /etc/cron.*/*
cat /etc/cron.*/*
cat /etc/crontab
```

### SSH Keys and Authorized Users <a href="#ssh-keys-and-authorised-users" id="ssh-keys-and-authorised-users"></a>

```
cat /etc/ssh/sshd_config
```

Note: This specifies where the SSH daemon will look for keys. Generally this will be as below.

```
ls /home/*/.ssh/*
cat /home/*/.ssh/id_rsa.pub
cat /home/*/.ssh/authorized_keys
```

### Sudoers File (who who can run commands as a different user) <a href="#sudoers-file-who-who-can-run-commands-as-a-different-user" id="sudoers-file-who-who-can-run-commands-as-a-different-user"></a>

```
cat /etc/sudoers
```

### Configuration Information <a href="#configuration-information" id="configuration-information"></a>

```
ls /etc/*.d
cat /etc/*.d/*
```

### Network Connections / Socket Stats <a href="#network-connections--socket-stats" id="network-connections--socket-stats"></a>

```
netstat
netstat -apetul
netstat -plan
netstat -plant
ss
ss -l
ss -ta
ss -tp
```

### IP Table Information <a href="#ip-table-information" id="ip-table-information"></a>

```
ls /etc/iptables
cat /etc/iptables/*.v4
cat /etc/iptables/*.v6
iptables -L
```

### Network Configuration <a href="#network-configuration" id="network-configuration"></a>

```
ifconfig -a
```

### Browser Plugin Information <a href="#browser-plugin-information" id="browser-plugin-information"></a>

```
ls -la ~/.mozilla/plugins
ls -la /usr/lib/mozilla/plugins
ls -la /usr/lib64/mozilla/plugins
ls -la ~/.config/google-chrome/Default/Extensions/
```

### Kernel Modules and Extensions/ <a href="#kernel-modules-and-extensions" id="kernel-modules-and-extensions"></a>

```
ls -la /lib/modules/*/kernel/*
```

### Process Information <a href="#process-information-2" id="process-information-2"></a>

```
ps -s
ps -l
ps -o
ps -t
ps -m
ps -a
top
```

### Search files recursively in directory for keyword <a href="#search-files-recursively-in-directory-for-keyword" id="search-files-recursively-in-directory-for-keyword"></a>

```
grep -H -i -r "password" /
```

### Process Tree <a href="#process-tree" id="process-tree"></a>

```
ps -auxwf
```

### Open Files and space usage <a href="#open-files-and-space-usage" id="open-files-and-space-usage"></a>

```
lsof
du
```

### Pluggable Authentication Modules (PAM) <a href="#pluggable-authentication-modules-pam" id="pluggable-authentication-modules-pam"></a>

```
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

### Disk / Partition Information <a href="#disk--partition-information" id="disk--partition-information"></a>

```
fdisk -l
```

### [System Calls / Network Traffic](https://bytefreaks.net/gnulinux/how-to-capture-all-network-traffic-of-a-single-process) <a href="#system-calls--network-traffic" id="system-calls--network-traffic"></a>

```
strace -f -e trace=network -s 10000 <PROCESS WITH ARGUMENTS>;
strace -f -e trace=network -s 10000 -p <PID>;
```

Note: Below material with thanks to [Craig Rowland - Sandfly Security](https://blog.apnic.net/2019/10/14/how-to-basic-linux-malware-process-forensics-for-incident-responders/)

### Detailed Process Information <a href="#detailed-process-information" id="detailed-process-information"></a>

```
ls -al /proc/[PID]
```

**Note:**

* CWD = Current Working Directory of Malware
* EXE = Binary location and whether it has been deleted
* Most Common Timestamp = When process was created

### Recover deleted binary which is currently running <a href="#recover-deleted-binary-which-is-currently-running" id="recover-deleted-binary-which-is-currently-running"></a>

```
cp /proc/[PID]/exe /[destination]/[binaryname]
```

### Capture Binary Data for Review <a href="#capture-binary-data-for-review" id="capture-binary-data-for-review"></a>

```
cp /proc/[PID]/ /[destination]/[PID]/
```

### Binary hash information <a href="#binary-hash-information" id="binary-hash-information"></a>

```
sha1sum /[destination]/[binaryname]
md5sum /[destination]/[binaryname]
```

### Process Command Line Information <a href="#process-command-line-information" id="process-command-line-information"></a>

```
cat /proc/[PID]/cmdline
cat /proc/[PID]/comm
```

**Note:**

* Significant differences in the above 2 outputs and the specified binary name under /proc/\[PID]/exe can be indicative of malicious software attempting to remain undetected.

### Process Environment Variables (incl user who ran binary) <a href="#process-environment-variables-incl-user-who-ran-binary" id="process-environment-variables-incl-user-who-ran-binary"></a>

```
strings /proc/[PID]/environ
cat /proc/[PID]/environ
```

### Process file descriptors/maps (what the process is ‘accessing’ or using) <a href="#process-file-descriptorsmaps-what-the-process-is-accessing-or-using" id="process-file-descriptorsmaps-what-the-process-is-accessing-or-using"></a>

```
ls -al /proc/[PID]/fd
cat /proc/[PID]/maps
```

### Process stack/status information (may reveal useful elements) <a href="#process-stackstatus-information-may-reveal-useful-elements" id="process-stackstatus-information-may-reveal-useful-elements"></a>

```
cat /proc/[PID]/stack
cat /proc/[PID]/status
```

### Deleted binaries which are still running <a href="#deleted-binaries-which-are-still-running" id="deleted-binaries-which-are-still-running"></a>

```
ls -alr /proc/*/exe 2> /dev/null |  grep deleted
```

### Process Working Directories (including common targeted directories) <a href="#process-working-directories-including-common-targeted-directories" id="process-working-directories-including-common-targeted-directories"></a>

```
ls -alr /proc/*/cwd
ls -alr /proc/*/cwd 2> /dev/null | grep tmp
ls -alr /proc/*/cwd 2> /dev/null | grep dev
ls -alr /proc/*/cwd 2> /dev/null | grep var
ls -alr /proc/*/cwd 2> /dev/null | grep home
```

### Hidden Directories and Files <a href="#hidden-directories-and-files" id="hidden-directories-and-files"></a>

```
find / -type d -name ".*"
```

### Immutable Files and Directories (Often Suspicious) <a href="#immutable-files-and-directories-often-suspicious" id="immutable-files-and-directories-often-suspicious"></a>

```
lsattr / -R 2> /dev/null | grep "\----i"
```

### SUID/SGID and Sticky Bit Special Permissions <a href="#suidsgid-and-sticky-bit-special-permissions" id="suidsgid-and-sticky-bit-special-permissions"></a>

```
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
```

### File and Directories with no user/group name <a href="#file-and-directories-with-no-usergroup-name" id="file-and-directories-with-no-usergroup-name"></a>

```
find / \( -nouser -o -nogroup \) -exec ls -lg  {} \;
```

### File types in current directory <a href="#file-types-in-current-directory" id="file-types-in-current-directory"></a>

```
file * -p
```

### Executables on file system <a href="#executables-on-file-system" id="executables-on-file-system"></a>

```
find / -type f -exec file -p '{}' \; |  grep ELF
```

### Hidden Executables on file system <a href="#hidden-executables-on-file-system" id="hidden-executables-on-file-system"></a>

```
find / -name ".*" -exec file -p '{}' \; | grep ELF
```

### Files modified within the past day <a href="#files-modified-within-the-past-day" id="files-modified-within-the-past-day"></a>

```
find / -mtime -1
```

### Persistent Areas of Interest <a href="#persistent-areas-of-interest" id="persistent-areas-of-interest"></a>

```
/etc/rc.local
/etc/initd
/etc/rc*.d
/etc/modules
/etc/cron*
/var/spool/cron/*
/usr/lib/cron/
/usr/lib/cron/tabs
```

### Audit Logs <a href="#audit-logs" id="audit-logs"></a>

```
ls -al /var/log/*
ls -al /var/log/*tmp
utmpdump /var/log/btmp
utmpdump /var/run/utmp
utmpdump /var/log/wtmp
```

### Installed Software Packages <a href="#installed-software-packages" id="installed-software-packages"></a>

```
ls /usr/bin/
ls /usr/local/bin/
```
