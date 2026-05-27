# Common Commands

## Execution Policy

Execution policy is not a security boundary, but it can prevent accidental script execution and should not be set to `Unrestricted` as a default.

```powershell
Get-ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Variables

Variables in PowerShell are prefixed with `$` and assigned with `=`.

```powershell
$foo = "bar"
$foo
```

## File Manipulation

`Get-Content`, `Set-Content`, and `Add-Content` are useful for reading, writing, and appending files.

```powershell
Get-Content -Path .\MOCK_DATA.csv -TotalCount 5
Get-Content -Path .\MOCK_DATA.csv -Tail 5
Set-Content -Path .\test.txt -Value "This is a test"
Add-Content -Path .\test.txt -Value "Another line"
Select-String -Path .\MOCK_DATA.csv -Pattern "needle"
```

References:

* [Get-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content)
* [Set-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content)
* [Add-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content)
* [Select-String](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string)

## File Download

Use `Invoke-WebRequest` for normal administrative file downloads. Offensive file transfer patterns live in the Red Offensive post-exploitation pages.

```powershell
Invoke-WebRequest -Uri "https://example.com/file.txt" -OutFile ".\file.txt"
```

{% content-ref url="../../red-offensive/post-exploitation/file-transfer.md" %}
[file-transfer.md](../../red-offensive/post-exploitation/file-transfer.md)
{% endcontent-ref %}

## Module Manipulation

```powershell
Import-Module Microsoft.PowerShell.Management
Get-Module
Remove-Module Microsoft.PowerShell.Management
```

References:

* [Import-Module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module)
* [Get-Module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module)
* [Remove-Module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-module)

## Event Logs

Prefer `Get-WinEvent` for modern Windows event log queries. `Get-EventLog` still exists for classic logs, but it is older and less flexible.

```powershell
# List available logs.
Get-WinEvent -ListLog *

# Query recent System log events.
Get-WinEvent -LogName System -MaxEvents 50

# Filter System log events from the last hour.
$StartTime = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{LogName = "System"; StartTime = $StartTime}

# Group recent events by provider.
Get-WinEvent -LogName System -MaxEvents 1000 |
  Group-Object -Property ProviderName -NoElement |
  Sort-Object -Property Count -Descending

# Export events for later review.
Get-WinEvent -LogName Application -MaxEvents 100 |
  Export-Csv -Path .\application-events.csv -NoTypeInformation
```

Reference:

* [SANS Get-WinEvent Cheatsheet](https://wiki.sans.blue/Tools/pdfs/Get-WinEvent.pdf)
