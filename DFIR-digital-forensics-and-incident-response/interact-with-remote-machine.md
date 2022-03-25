# Interact with remote machine

## Set up connection

Enable Powershell remoting:

```
wmic /node:[IP] process call create "powershell enable-psremoting -force"
```

[Powershell](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-6):

```
Enter-PSSession -ComputerName [IP]
```

PSExec:

```
PsExec: psexec \\IP -c cmd.exe
```

### Enable PS Remoting using PsExec <a href="#enable-ps-remoting-using-psexec" id="enable-ps-remoting-using-psexec"></a>

```
psexec.exe \\TARGET -s powershell Enable-PSRemoting -Force;
```

### Setup logging for IR <a href="#setup-logging-for-ir" id="setup-logging-for-ir"></a>

Note: If you enter a PSSession, the logging won’t persist, so you will need to enable it on the remote host and pull the file back afterwards. Otherwise refer to PowerShell ♥ the Blue Team mentioned above.

```
Start-Transcript -Path "C:\[location]\investigation-1.log" -NoClobber
```

[Thanks Barnaby Skeggs](https://b2dfir.blogspot.com/2018/11/windows-powershell-remoting-host-based.html)

### Establish Remote Session <a href="#establish-remote-session" id="establish-remote-session"></a>

```
$s1 = New-PSsession -ComputerName remotehost -SessionOption (New-PSSessionOption -NoMachineProfile) -ErrorAction Stop
```

### Enter or exit remote session <a href="#enter-or-exit-remote-session" id="enter-or-exit-remote-session"></a>

```
Enter-PSSession -Session $s1
Exit-PSSEssion
```

### Issuing remote command/shell <a href="#issuing-remote-commandshell" id="issuing-remote-commandshell"></a>

```
Invoke-Command -ScriptBlock {whoami} -Session $s1
Invoke-Command -file file.ps1 -Session $s1
```

### Retrieving/downloading files <a href="#retrievingdownloading-files" id="retrievingdownloading-files"></a>

```
Copy-Item -Path "[RemoteHostFilePath]" -Destination "[LocalDestination]" -FromSession $s1
```

## Credentials and Exposure <a href="#credentials-and-exposure" id="credentials-and-exposure"></a>

When investigating a compromised asset, it’s important to know what remote triage methods leave your credentials on the infected endpoint, and what ones don’t. Reference can be found on [Microsoft Documentation](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#administrative-tools-and-logon-types)

| Connection Method                       | Logon Type           | Reusable credentials on destination | Notes                                                                                     |
| --------------------------------------- | -------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------- |
| Logon via console                       | Interactive          | Y                                   | Includes hardware remote access/network KVM/lights-out cards                              |
| RUNAS                                   | Interactive          | Y                                   | Nil                                                                                       |
| RUNAS/NETWORK                           | NewCredentials       | Y                                   | Clones LSA session, but uses new creds when connecting to network resources.              |
| Remote Desktop                          | RemoteInteractive    | Y                                   | Nil                                                                                       |
| Remote Desktop Failure                  | RemoteInteractive    | N                                   | Only stored briefly                                                                       |
| Net Use \* \SERVER                      | Network              | N                                   | Nil                                                                                       |
| Net Use \* \ SERVER /user               | Network              | N                                   | Nil                                                                                       |
| MMC snap-ins to remote computer         | Network              | N                                   | Nil                                                                                       |
| PowerShell WinRM                        | Network              | N                                   | e.g. Enter-PSSession SERVER                                                               |
| PowerShell WinRM with CredSSP           | NetworkClearText     | Y                                   | e.g. New-PSSession SERVER -Authentication Credssp -Credential PWD                         |
| PsExec without explicit creds           | Network              | N                                   | e.g. PsExec \SERVER cmd                                                                   |
| PsExec with explicit creds              | Network\&Interactive | Y                                   | PsExec \SERVER -u USER -p PWD cmd                                                         |
| Remote Registry                         | Network              | N                                   | Nil                                                                                       |
| Remote Desktop Gateway                  | Network              | N                                   | Authenticating to Remote Desktop Gateway                                                  |
| Scheduled Task                          | Batch                | Y                                   | Also saved as LSA secret on disk                                                          |
| Tools as Service                        | Service              | Y                                   | Also saved as LSA secret on disk                                                          |
| Vuln Scanners                           | Network              | N                                   | Most use Network logons; however, those that don’t have the risk of creds on destination. |
| IIS “Basic Authentication”              | NetworkCleartext     | Y                                   | Nil                                                                                       |
| IIS “Integrated Windows Authentication” | Network              | N                                   | NTLM/Kerberos Providers                                                                   |

### Kerberos Tickets and Exposure <a href="#kerberos-tickets-and-exposure" id="kerberos-tickets-and-exposure"></a>

Special thanks to [Cert EU](https://cert.europa.eu/static/WhitePapers/CERT-EU\_SWP\_17-002\_Lateral\_Movements.pdf) for this. When comparing Pass-the-Hash to Pass-the-Ticket attacks, the following key differences apply:

* Administrative privileges are required to steal credentials, but NOT to use an obtained Kerberos ticket.
* A password change does NOT make Kerberos tickets invalid. By default Kerberos has a max lifetime of 10hrs before the ticket must be renewed, and a max renewal time of 7 days after being granted.

Due to this disabling accounts may not be enough to prevent ongoing compromise, and you may have to purge the users kerberos ticket. Locate the user in question using ‘sessions’ and purge by specifying the user session prior to logging them off.

```
klist.exe sessions
klist purge –li 0x2e079217 
query user
logoff <session id>
```
