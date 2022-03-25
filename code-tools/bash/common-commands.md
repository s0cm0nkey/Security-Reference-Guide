# Common Commands

## Install and Update&#x20;

```
Update list of packages
# sudo apt update
Update all programs available in repo
# sudo apt upgrade 
Install specific package if found in repository 
# sudo apt install [package name] 
Install specific package offline version
#sudo dpkg -i [package.deb] 
```

## Understanding your device

```
Print working directory
#pwd
```

## Networking Commands

```
Show status of interfaces
#ifconfig
Show status of wireless interfaces
#iwconfig
```

## Services&#x20;

```
Show All
# systemctl list-unit-files 
```

### SSH Service

```
Start SSH Service
# sudo systemctl start ssh
Verify SSH is running and listening
# sudo ss -antlp | grep sshd
Start ssh on boot
# sudo systemctl enable ssh
```

### HTTP Service&#x20;

```
Start apache web service
# sudo systemctl start apache2
Verify http is up and listening
# sudo ss -antlp } grep apache
start apache web service on boot
# sudo systemctl enable apache2
```

## Processes&#x20;

```
List all processes
# ps -ef
Terminate process
# kill [pid]
Display all jobs running in current terminal sessions
# jobs
```

## Users and privileges

```
Adds user to sudoers file
# adduser (username)
# adduser (username) sudo
```

## File Manipulation

{% hint style="info" %}
Common Directories you will use:

/bin - basic programs (ls, cd, cat, etc...)\
/sbin - system programs (fdisk, mkfs, sysctl, etc...)\
/etc - config files\
/tmp - temporary files (typically deleted on boot)\
/usr/bin - applications (apt, ncat, nmap, etc...)\
/usr/share - application support and data files
{% endhint %}

### File Creation

```
Create new empty file
# touch (file name)
Create new dir in current working dir
# mkdir (dir name)
```

### File searching

```
Shows owners, permissions and size of files in current in the directory.
#ls -ahtl
Searches through the directories and displays path to requested file
# which (file name)
Quick search to display file path
# locate (file name)
Locate but with other file aspects like size or format
# find
```

### Text printing

```
Prints text to cmd line
# echo (text)
Append text to a file
# echo (text) >> (file name)
```

### File permissions

```
View permissions for file
# ls -l (file name)
Change file permissions
# chmod 777 (filename)
```

{% hint style="info" %}
For more info on the permissions codes, see here: [https://www.guru99.com/file-permissions.html](https://www.guru99.com/file-permissions.html)
{% endhint %}

### File manipulation and Searching in a file

```
Read text file
# cat (file name)
Search for string within given file
# grep (text string) (file name)
Search for all instances of old word in file name, and replace with new word
# sed ‘s/(old word)/(new word)/’ (file name)
Extracts a section of text from a line and output it to standard output
-f is field number, -d is field delimiter
#echo “text” | cut -f 2 -d “,” 
Used for pattern matching
#awk ( input)
```

### Comparing files

```
Compares two files and outputs resutls in 3 columns. first is unique to A, second is unique to B, third is shared
# comm [fileA.txt] [fileB.txt]
Compares two files
# diff -c [fileA.txt] [fileB.txt]
-c contect format - shows all entires in both files, “-” in the first, “+” in the second
-u unified format - same as above but does not show lines that match
```

### Monitoring files

```
Continuously displays when target file is updated.
# sudo tail -f [file]
Run designated command at each time interval
# watch -n [time in seconds] [command]
```

### &#x20;Downloading files

```
# wget [file url]
Accelerated download with multiple connections
# axel [file url]
-a for progress indicator
-n for number of connections
-o rename downloaded file
```

## Command History

* Commands entered in the terminal are tracked using the `HISTFILE` environment variable and are written to the `~/.bash_history` file when a user logs off.
* it is possible for credentials and passwords to be stored as plaintext in the `/.bash_history`
* Variables can also be seen when stored in the bash config file, .bashrc
* One way a user can prevent credentials from being recorded is by starting each command with a leading space character. For example the command `" echo 'hello world'"` will not be saved, whereas `"echo 'hello world'"` will be.
* To prevent users from hiding commands, the `HISTCONTROL` variable can be set to `"ignoredup"`, and users prevented from changing the environment variable. This will ensure all commands are captured and stored in the bash history.cat theywillneverfindmeheere

### Sudo History

* The amount of time that sudo credentials are cached for can be set using the `timestamp_timeout` variable. Setting the value of `timestamp_timeout` to `0` causes sudo to require a password every time it is executed; if no value is set, it will default to 5 or 15 minutes depending on the operating system.
* By default sudo will honour TTY session segregation, meaning that if you were to run `sudo` in one terminal window and then again in a separate one, you would have to authenticate both times. The `tty_tickets` flag can be used to disable session segregation, causing all sessions to use the same record.
* Session timeouts are tracked using file records. The location of these files can vary depending on the flavour of Linux but often reside at `/run/sudo/ts/<username>` (`/var/db/sudo`on macOS). The files used to track sessions persist beyond a user’s login session. If a user successfully authenticates using `sudo`, logs out, logs in again and runs `sudo` within the set timeout, they may not have to re-enter their password.
