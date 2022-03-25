# MacOS DFIR Commands

### Dumping Memory <a href="#dumping-memory-1" id="dumping-memory-1"></a>

[OSXPMem](https://github.com/wrmsr/pmem/tree/master/OSXPMem)

[MacPmem](https://github.com/google/rekall/releases/download/1.7.2rc1/rekall-OSX-1.7.2rc1.zip)

```
sudo kextload MacPmem.kext
sudo dd if=/dev/pmem of=memorydump.raw
```

### Live Mac IR / Triage <a href="#live-mac-ir--triage" id="live-mac-ir--triage"></a>

#### System Information <a href="#system-information-2" id="system-information-2"></a>

```
date
sw_vers
uname –a
hostname
cat /System/Library/CoreServices/SystemVersion.plist
cat /private/var/log/daily.out
cat /Library/preferences/.Globalpreferences.plist
```

#### Network Connections <a href="#network-connections-1" id="network-connections-1"></a>

```
netstat –an
netstat –anf
lsof -i
```

#### Routing Table <a href="#routing-table" id="routing-table"></a>

```
netstat –rn
```

#### Network Information <a href="#network-information-2" id="network-information-2"></a>

```
arp –an
ndp -an
ifconfig
```

#### Open Files <a href="#open-files" id="open-files"></a>

```
lsof
```

#### File System Usage <a href="#file-system-usage" id="file-system-usage"></a>

```
sudo fs_usage
sudo fs_usage [process] 
sudo fs_usage -f network
sudo fs_usage pid [PID]
```

#### Bash History <a href="#bash-history" id="bash-history"></a>

```
cat ~/.bash_history
history
```

#### User Logins <a href="#user-logins" id="user-logins"></a>

```
who -a
w
last
```

#### Running Processes <a href="#running-processes" id="running-processes"></a>

```
ps aux
```

#### System Profiler <a href="#system-profiler" id="system-profiler"></a>

```
system_profiler -xml -detaillevel full > systemprofiler.spx
```

#### Persistent Locations <a href="#persistent-locations" id="persistent-locations"></a>

[**Quick Overview (KnockKnock)**](https://www.objective-see.com/products/knockknock.html)

```
./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere > /path/to/some/file.json
```

**XPC Services**

```
ls Applications/<application>.app/Contents/XPCServices/
cat Applications/<application>.app/Contents/XPCServices/*.xpc/Contents/Info.plist
ls ~/System/Library/XPCServices/
```

**Launch Agents & Launch Daemons**

```
ls /Library/LaunchAgents/
ls /System/Library/LaunchAgents/
ls /System/Library/LaunchDaemons/
ls /Library/LaunchDaemons/
ls /users/*/Library/LaunchAgents/
ls /users/*/Library/LaunchDaemons/
```

**LoginItems**

```
cat ~/Library/Preferences/com.apple.loginitems.plist
ls <application>.app/Contents/Library/LoginItems/
```

#### Disable Persistent Launch Daemon <a href="#disable-persistent-launch-daemon" id="disable-persistent-launch-daemon"></a>

```
sudo launchctl unload -w /Library/LaunchDaemons/<name>.plist
sudo launchctl stop /Library/LaunchDaemons/<name>.plist
```

#### Web Browsing Preferences <a href="#web-browsing-preferences" id="web-browsing-preferences"></a>

```
cat ~/Library/Preferences/com.apple.Safari.plist 
ls ~/Library/Application Support/Google/Chrome/Default/Preferences
ls ~/Library/Application Support/Firefox/Profiles/********.default/prefs.js
```

#### Safari Internet History <a href="#safari-internet-history" id="safari-internet-history"></a>

```
cat ~/Library/Safari/Downloads.plist
cat ~/Library/Safari/History.plist 
cat ~/Library/Safari/LastSession.plist
ls ~/Library/Caches/com.apple.Safari/Webpage Previews/ 
sqlite3 ~/Library/Caches/com.apple.Safari/Cache.db  
```

#### Chrome Internet History <a href="#chrome-internet-history" id="chrome-internet-history"></a>

```
ls ~/Library/Application Support/Google/Chrome/Default/History
ls ~/Library/Caches/Google/Chrome/Default/Cache/
ls ~/Library/Caches/Google/Chrome/Default/Media Cache/
```

#### Firefox Internet History <a href="#firefox-internet-history" id="firefox-internet-history"></a>

```
sqlite3 ~/Library/Application Support/Firefox/Profiles/********.default/places.sqlite 
sqlite3 ~/Library/Application Support/Firefox/Profiles/********.default/downloads.sqlite
sqlite3 ~/Library/Application Support/Firefox/Profiles/********.default/formhistory.sqlite
ls ~/Library/Caches/Firefox/Profiles/********.default/Cache
```

#### Apple Email <a href="#apple-email" id="apple-email"></a>

```
cat ~/Library/Mail/V2/MailData/Accounts.plist
ls ~/Library/Mail/V2/
ls ~/Library/Mail Downloads/
ls ~/Downloads
cat ~/Library/Mail/V2/MailData/OpenAttachments.plist
```

#### Temporary / Cached <a href="#temporary--cached" id="temporary--cached"></a>

```
ls /tmp
ls /var/tmp 
ls /Users/<user>/Library/Caches/Java/tmp
ls /Users/<user>/Library/Caches/Java/cache
	/Applications/Utilities/Java Preferences.app
```

#### System and Audit Logs <a href="#system-and-audit-logs" id="system-and-audit-logs"></a>

```
ls /private/var/log/asl/
ls /private/var/audit/
cat /private/var/log/appfirewall.log
ls ~/Library/Logs
ls /Library/Application Support/<app> 
ls /Applications/ 
ls /Library/Logs/
```

#### Specific Log Analysis <a href="#specific-log-analysis" id="specific-log-analysis"></a>

```
bzcat system.log.1.bz2 
system.log.0.bz2 >> system_all.log 
cat system.log >> system_all.log
syslog -f <file>
syslog –T utc –F raw –d /asl
syslog -d /asl
praudit –xn /var/audit/*
sudo log collect
log show
log stream
```

#### Files Quarantined <a href="#files-quarantined" id="files-quarantined"></a>

```
ls ~/Library/Preferences/com.apple.LaunchServices.QuarantineEvents.V2
ls ~/Library/Preferences/com.apple.LaunchServices.QuarantineEvents 
```

#### User Accounts / Password Shadows <a href="#user-accounts--password-shadows" id="user-accounts--password-shadows"></a>

```
ls /private/var/db/dslocal/nodes/Default/users/ 
ls /private/var/db/shadow/<User GUID>
```

#### Pluggable Authentication Modules (PAM) <a href="#pluggable-authentication-modules-pam-1" id="pluggable-authentication-modules-pam-1"></a>

```
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

#### File Fingerprinting/Reversing <a href="#file-fingerprintingreversing" id="file-fingerprintingreversing"></a>

```
file <filename>
xxd <filename>
nm -arch x86_64 <filename>
otool -L <filename>
sudo vmmap <pid>
sudo lsof -p <pid>
xattr –xl <file>
```

#### Connected Disks and Partitions <a href="#connected-disks-and-partitions" id="connected-disks-and-partitions"></a>

```
diskutil list
diskutil info <disk>
diskutil cs
ap list
gpt –r show 
gpt -r show -l
```

#### Disk File Image Information <a href="#disk-file-image-information" id="disk-file-image-information"></a>

```
hdiutil imageinfo *.dmg
```

#### User Keychain Information <a href="#user-keychain-information" id="user-keychain-information"></a>

```
security list-keychains
security dump-keychains -d <keychain>
```

#### Spotlight Metadata <a href="#spotlight-metadata" id="spotlight-metadata"></a>

```
mdimport –X | -A
mdls <file>
```
