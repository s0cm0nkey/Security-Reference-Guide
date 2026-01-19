# Interact with Remote Machine

## PowerShell Remoting (WinRM)

PowerShell Remoting is the preferred method for interacting with Windows systems. It relies on the Windows Remote Management (WinRM) service.

### Enable PowerShell Remoting

To enable remoting on a target machine if it isn't already (requires local access or another remote method like PsExec or WMI).

**Using PsExec (Sysinternals):**
```powershell
psexec.exe \\TARGET -s powershell Enable-PSRemoting -Force
```

**Using WMIC (Legacy/Deprecated):**
```cmd
wmic /node:[IP] process call create "powershell enable-psremoting -force"
```

### Establish Remote Session

**Interactive Session (One-off):**
[Enter-PSSession Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession)

```powershell
Enter-PSSession -ComputerName [IP]
```

**Persistent Session Variable:**
Useful for running multiple commands or scripts against the same host.

```powershell
$s1 = New-PSSession -ComputerName remotehost -SessionOption (New-PSSessionOption -NoMachineProfile) -ErrorAction Stop
```

**Enter or Exit Remote Session:**

```powershell
Enter-PSSession -Session $s1
# Do work...
Exit-PSSession
```

### Issuing Remote Commands

Execute a script block or file without entering an interactive shell.

```powershell
Invoke-Command -ScriptBlock {whoami} -Session $s1
Invoke-Command -FilePath ./file.ps1 -Session $s1
```

### Retrieving/Downloading Files

```powershell
Copy-Item -Path "C:\Remote\Path\file.ext" -Destination "C:\Local\Path\" -FromSession $s1
```

### Setup Logging for IR

When participating in a remote session, it is critical to log your actions.
**Note:** If you run `Start-Transcript` inside a PSSession, the log file is generated **on the remote host**. You must retrieve this file (using `Copy-Item`) before closing the session or after finishing your investigation.

```powershell
Start-Transcript -Path "C:\Temp\investigation-1.log" -NoClobber
# Run commands...
Stop-Transcript
```

*Reference:* [Barnaby Skeggs - Windows PowerShell Remoting Host Based](https://b2dfir.blogspot.com/2018/11/windows-powershell-remoting-host-based.html)

## SSH (Secure Shell)

The standard for Linux and macOS remote management, and increasingly available on Windows (OpenSSH Server).

```bash
ssh user@hostname
```

## Legacy & Alternative Tools

### PsExec (Sysinternals)

PsExec allows you to execute processes on other systems. It typically uses SMB (port 445) and leaves artifacts (PSEXESVC service) on the target.

```cmd
PsExec.exe \\IP -c cmd.exe
```

## Credentials and Exposure

When investigating a compromised asset, it’s important to know which remote triage methods expose your credentials to the infected endpoint.
*Reference:* [Microsoft Securing Privileged Access](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#administrative-tools-and-logon-types)

| Connection Method                       | Logon Type           | Reusable credentials on destination | Notes                                                                                     |
| --------------------------------------- | -------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------- |
| Logon via console                       | Interactive          | Y                                   | Includes hardware remote access/network KVM/lights-out cards                              |
| RUNAS                                   | Interactive          | Y                                   | Nil                                                                                       |
| RUNAS/NETWORK                           | NewCredentials       | Y                                   | Clones LSA session, but uses new creds when connecting to network resources.              |
| Remote Desktop                          | RemoteInteractive    | Y                                   | Nil                                                                                       |
| Remote Desktop Failure                  | RemoteInteractive    | N                                   | Only stored briefly                                                                       |
| Net Use * \\SERVER                      | Network              | N                                   | Nil                                                                                       |
| Net Use * \\SERVER /user                | Network              | N                                   | Nil                                                                                       |
| MMC snap-ins to remote computer         | Network              | N                                   | Nil                                                                                       |
| PowerShell WinRM                        | Network              | N                                   | e.g. Enter-PSSession SERVER                                                               |
| PowerShell WinRM with CredSSP           | NetworkClearText     | Y                                   | e.g. New-PSSession SERVER -Authentication Credssp -Credential PWD                         |
| PsExec without explicit creds           | Network              | N                                   | e.g. PsExec \\SERVER cmd                                                                   |
| PsExec with explicit creds              | Network&Interactive  | Y                                   | PsExec \\SERVER -u USER -p PWD cmd                                                         |
| Remote Registry                         | Network              | N                                   | Nil                                                                                       |
| Remote Desktop Gateway                  | Network              | N                                   | Authenticating to Remote Desktop Gateway                                                  |
| Scheduled Task                          | Batch                | Y                                   | Also saved as LSA secret on disk                                                          |
| Tools as Service                        | Service              | Y                                   | Also saved as LSA secret on disk                                                          |
| Vuln Scanners                           | Network              | N                                   | Most use Network logons; however, those that don’t have the risk of creds on destination. |
| IIS “Basic Authentication”              | NetworkCleartext     | Y                                   | Nil                                                                                       |
| IIS “Integrated Windows Authentication” | Network              | N                                   | NTLM/Kerberos Providers                                                                   |

## Kerberos Tickets and Exposure

Special thanks to [Cert EU](https://cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf) for this. When comparing Pass-the-Hash to Pass-the-Ticket attacks, the following key differences apply:

*   Administrative privileges are required to steal credentials, but **NOT** to use an obtained Kerberos ticket.
*   A password change does **NOT** make Kerberos tickets invalid instantly. By default, Kerberos has a max lifetime of 10 hours before the ticket must be renewed, and a max renewal time of 7 days after being granted.

Due to this, simply disabling accounts may not be enough to prevent ongoing compromise. You may have to purge the user's Kerberos tickets. Locate the user in question using `sessions` and purge by specifying the user session prior to logging them off.

```cmd
klist.exe sessions
klist purge -li 0x2e079217 
query user
logoff <session id>
```
