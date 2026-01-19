# Linux DFIR Commands

## Memory Acquisition

```bash
dd if=/dev/kmem of=/root/kmem
dd if=/dev/mem of=/root/mem
```

[LiME](https://github.com/504ensicsLabs/LiME/releases)

```bash
sudo insmod ./lime.ko "path=./lime.mem format=raw"
```

[LinPMem](https://github.com/Velocidex/c-aff4/releases/)

```bash
./linpmem -o memory.aff4
./linpmem memory.aff4 -e PhysicalMemory -o memory.raw
```

## Disk Imaging

```bash
fdisk -l
dd if=/dev/sda1 of=/[outputlocation]
```

## Misc Useful Tools

[FastIR](https://github.com/SekoiaLab/Fastir\_Collector\_Linux)

```bash
python ./fastIR_collector_linux.py
```

[LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

```bash
./linenum.sh
./linenum.sh -t
```

## Live Triage

### System Information

```bash
date
uname –a
hostname
cat /proc/version
lsmod
```

### Account Information

```bash
cat /etc/passwd
cat /etc/shadow
cat /etc/sudoers
cat /etc/sudoers.d/*
cut -d: -f1 /etc/passwd
getent passwd | cut -d: -f1
compgen -u
lastlog
```

### Current User

```bash
whoami
who
w
```

### Last Logged On Users

```bash
last
lastb
cat /var/log/auth.log
```

### Initialization Files

```bash
cat /etc/bash.bashrc
cat ~/.bash_profile 
cat ~/.bashrc
cat ~/.zshrc
cat ~/.zprofile
```

### Environment and Startup Programs

```bash
cat /etc/profile
ls /etc/profile.d/
cat /etc/profile.d/*
```

### Scheduled Tasks

```bash
ls /etc/cron.*
ls /etc/cron.*/*
cat /etc/cron.*/*
cat /etc/crontab
```

### SSH Keys and Authorized Users

```bash
cat /etc/ssh/sshd_config
```

Note: This specifies where the SSH daemon will look for keys. Generally this will be as below.

```bash
ls /home/*/.ssh/*
cat /home/*/.ssh/id_rsa.pub
cat /home/*/.ssh/authorized_keys
```

### Sudoers File (Checking who can run commands as a different user)

```bash
cat /etc/sudoers
```

### Configuration Information

```bash
ls /etc/*.d
cat /etc/*.d/*
```

### Network Connections

```bash
ss
ss -l
ss -ta
ss -tp
lsof -i
lsof -iP -n
```

### IP Tables

```bash
ls /etc/iptables
cat /etc/iptables/*.v4
cat /etc/iptables/*.v6
iptables -L
iptables-save
```

### Network Configuration

```bash
ip addr show
ip route show
ip neigh show
```

### Browser Extensions and Plugins

```bash
ls -la ~/.mozilla/plugins
ls -la /usr/lib/mozilla/plugins
ls -la /usr/lib64/mozilla/plugins
ls -la ~/.config/google-chrome/Default/Extensions/
```

### Kernel Modules

```bash
ls -la /lib/modules/*/kernel/*
lsmod
```

### Process Listing

```bash
ps -s
ps -l
ps -o
ps -t
ps -m
ps -a
top
```

### Searching Files

```bash
grep -H -i -r "password" /
```

### Process Tree

```bash
ps -auxwf
```

### Open Files and Space Usage

```bash
lsof
du
```

### Pluggable Authentication Modules (PAM)

```bash
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

### Disk and Partition Information

```bash
fdisk -l
lsblk
mount
df -h
```

### [System Calls and Network Traffic](https://bytefreaks.net/gnulinux/how-to-capture-all-network-traffic-of-a-single-process)

```bash
strace -f -e trace=network -s 10000 <PROCESS WITH ARGUMENTS>;
strace -f -e trace=network -s 10000 -p <PID>;
```

Note: Below material with thanks to [Craig Rowland - Sandfly Security](https://blog.apnic.net/2019/10/14/how-to-basic-linux-malware-process-forensics-for-incident-responders/)

### Detailed Process Information

```bash
ls -al /proc/[PID]
```

**Note:**

* CWD = Current Working Directory of Malware
* EXE = Binary location and whether it has been deleted
* Most Common Timestamp = When process was created

### Recovering Deleted Binaries

```bash
cp /proc/[PID]/exe /[destination]/[binaryname]
```

### Capturing Binary Data

```bash
cp /proc/[PID]/ /[destination]/[PID]/
```

### Binary Hashing

```bash
sha1sum /[destination]/[binaryname]
md5sum /[destination]/[binaryname]
```

### Process Command Line

```bash
cat /proc/[PID]/cmdline
cat /proc/[PID]/comm
```

**Note:**

* Significant differences in the above 2 outputs and the specified binary name under /proc/\[PID]/exe can be indicative of malicious software attempting to remain undetected.

### Process Environment Variables

```bash
strings /proc/[PID]/environ
cat /proc/[PID]/environ
```

### Process File Descriptors and Maps

```bash
ls -al /proc/[PID]/fd
cat /proc/[PID]/maps
```

### Process Stack and Status

```bash
cat /proc/[PID]/stack
cat /proc/[PID]/status
```

### Identifying Deleted Binaries Still Running

```bash
ls -alr /proc/*/exe 2> /dev/null |  grep deleted
```

### Process Working Directories

```bash
ls -alr /proc/*/cwd
ls -alr /proc/*/cwd 2> /dev/null | grep tmp
ls -alr /proc/*/cwd 2> /dev/null | grep dev
ls -alr /proc/*/cwd 2> /dev/null | grep var
ls -alr /proc/*/cwd 2> /dev/null | grep home
```

### Hidden Directories and Files

```bash
find / -type d -name ".*"
```

### Immutable Files and Directories

```bash
lsattr / -R 2> /dev/null | grep "\----i"
```

### SUID/SGID and Sticky Bit Special Permissions

```bash
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
```

### Files and Directories with No User/Group

```bash
find / \( -nouser -o -nogroup \) -exec ls -lg  {} \;
```

### File Types

```bash
file * -p
```

### Finding Executables

```bash
find / -type f -exec file -p '{}' \; |  grep ELF
```

### Finding Hidden Executables

```bash
find / -name ".*" -exec file -p '{}' \; | grep ELF
```

### Recently Modified Files

```bash
find / -mtime -1
```

### Persistent Areas of Interest

```bash
/etc/rc.local
/etc/init.d
/etc/rc*.d
/etc/modules
/etc/cron*
/var/spool/cron/*
/usr/lib/cron/
/usr/lib/cron/tabs
```

### Log Analysis

```bash
ls -al /var/log/*
ls -al /var/log/*tmp
utmpdump /var/log/btmp
utmpdump /var/run/utmp
utmpdump /var/log/wtmp
dmesg
journalctl -xb
```

### Installed Software Packages

```bash
ls /usr/bin/
ls /usr/local/bin/
dpkg -l
rpm -qa
```

## Malware Scanning

```bash
rkhunter --check
chkrootkit
clamscan -r /
```

## Legacy Commands

These commands differ by distribution but are largely deprecated in favor of `ip` and `ss`.

### Network Information (Deprecated)

```bash
ifconfig -a
netstat -apetul
netstat -plan
netstat -plant
```
