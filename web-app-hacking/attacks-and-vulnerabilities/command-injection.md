# Command Injection

## Theory

Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine.  It is a web vulnerability that allows an attacker to take advantage of that made system call to execute operating system commands on the server.  Sometimes this won't always end in something malicious, like a whoami or just reading of files.  That isn't too bad.  But the thing about command injection is it opens up many options for the attacker.  The worst thing they could do would be to spawn a reverse shell to become the user that the web server is running as.  A simple ;nc -e /bin/bash is all that's needed and they own your server; some variants of netcat don't support the -e option. You can use a list of these reverse shells as an alternative. \
\
Blind command injection occurs when the system command made to the server does not return the response to the user in the HTML document.  Active command injection will return the response to the user.  It can be made visible through several HTML elements. \
Let's consider a scenario: EvilCorp has started development on a web based shell but has accidentally left it exposed to the Internet.  It's nowhere near finished but contains the same command injection vulnerability as before!  But this time, the response from the system call can be seen on the page!  They'll never learn!\
Just like before, let's look at the sample code from evilshell.php and go over what it's doing and why it makes it active command injection.  See if you can figure it out.  I'll go over it below just as before.

**EvilShell (evilshell.php) Code Example**

![](<../../.gitbook/assets/image (36).png>)

In pseudocode, the above snippet is doing the following:\
1\. Checking if the parameter "commandString" is set\
2\. If it is, then the variable `$command_string` gets what was passed into the input field\
3\. The program then goes into a try block to execute the function `passthru($command_string)`.  You can read the docs on `passthru()` on [PHP's website](https://www.php.net/manual/en/function.passthru.php), but in general, it is executing what gets entered into the input then passing the output directly back to the browser.\
4\. If the try does not succeed, output the error to page.  Generally this won't output anything because you can't output stderr but PHP doesn't let you have a try without a catch.

## **Detection**

**Ways to Detect Active Command Injection**\
We know that active command injection occurs when you can see the response from the system call.  In the above code, the function `passthru()` is actually what's doing all of the work here.  It's passing the response directly to the document so you can see the fruits of your labor right there.  Since we know that, we can go over some useful commands to try to enumerate the machine a bit further.  The function call here to `passthru()` may not always be what's happening behind the scenes, but I felt it was the easiest and least complicated way to demonstrate the vulnerability. &#x20;

## **Tools and Resources**

* [Commix](https://github.com/commixproject/commix) - Commix is an open source penetration testing tool that automates the detection and exploitation of [command injection](https://www.owasp.org/index.php/Command\_Injection) vulnerabilities.
  * [https://www.kali.org/tools/commix/](https://www.kali.org/tools/commix/)
  * [Command Injection to Meterpreter using Commix](https://www.hackingarticles.in/command-injection-meterpreter-using-commix/)
  * [Exploit Command Injection Vulnerability with Commix and Netcat](https://www.hackingarticles.in/exploit-command-injection-vulnearbility-commix-netcat/)
  * [Powershell Injection Attacks using Commix and Magic Unicorn](https://www.hackingarticles.in/powershell-injection-attacks-using-commix-magic-unicorn/)
  * [Commix-Command Injection Exploiter (Beginner’s Guide)](https://www.hackingarticles.in/commix-command-injection-exploiter-beginners-guide/)
* [OWASP Guide to Command Injection](https://owasp.org/www-community/attacks/Command\_Injection)&#x20;
* [Comprehensive Guide on OS Command Injection](https://www.hackingarticles.in/comprehensive-guide-on-os-command-injection/)
* [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list)
* [PayloadsAllTheThings/CommandInjection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
* [https://cheatsheetseries.owasp.org/cheatsheets/OS\_Command\_Injection\_Defense\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/OS\_Command\_Injection\_Defense\_Cheat\_Sheet.html)
* [https://tryhackme.com/room/injection](https://tryhackme.com/room/injection)
