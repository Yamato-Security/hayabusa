# အတိုကောက်များ

နေရာချွေတာရန်အတွက် levels, MITRE ATT&CK tactics, channels, providers, field names စသည်တို့ကို ကျွန်ုပ်တို့ အတိုကောက်သုံးပါသည်...

ဤအတိုကောက်အချို့ကို `-b, --disable-abbreviations` option ဖြင့် ပိတ်ပြီး မူရင်း channel name, provider name စသည်တို့ကို ကြည့်ရှုနိုင်ပါသည်...

## Level အတိုကောက်များ

နေရာချွေတာရန်အတွက် alert `level` ကို ပြသသည့်အခါ အောက်ပါအတိုကောက်များကို သုံးပါသည်။

* `emer`: `emergency`
* `crit`: `critical`
* `high`: `high`
* `med `: `medium`
* `low `: `low`
* `info`: `informational`
* `undef`: `undefined`

## MITRE ATT&CK Tactics အတိုကောက်များ

နေရာချွေတာရန်အတွက် MITRE ATT&CK tactic tags ကို ပြသသည့်အခါ အောက်ပါအတိုကောက်များကို သုံးပါသည်။
ဤအတိုကောက်များကို `./config/mitre_tactics.txt` configuration file တွင် လွတ်လပ်စွာ ပြင်ဆင်နိုင်ပါသည်။

* `Recon` : Reconnaissance
* `ResDev` : Resource Development
* `InitAccess` : Initial Access
* `Exec` : Execution
* `Persis` : Persistence
* `PrivEsc` : Privilege Escalation
* `Stealth` : Stealth (formerly Defense Evasion)
* `DefImpair` : Defense Impairment
* `CredAccess` : Credential Access
* `Disc` : Discovery
* `LatMov` : Lateral Movement
* `Collect` : Collection
* `C2` : Command and Control
* `Exfil` : Exfiltration
* `Impact` : Impact

## Channel အတိုကောက်များ

နေရာချွေတာရန်အတွက် Channel ကို ပြသသည့်အခါ အောက်ပါအတိုကောက်များကို သုံးပါသည်။
ဤအတိုကောက်များကို `./rules/config/channel_abbreviations.txt` configuration file တွင် လွတ်လပ်စွာ ပြင်ဆင်နိုင်ပါသည်။

* `App` : `Application`
* `AppLocker` : `Microsoft-Windows-AppLocker/*`
* `BitsCli` : `Microsoft-Windows-Bits-Client/Operational`
* `CodeInteg` : `Microsoft-Windows-CodeIntegrity/Operational`
* `Defender` : `Microsoft-Windows-Windows Defender/Operational`
* `DHCP-Svr` : `Microsoft-Windows-DHCP-Server/Operational`
* `DNS-Svr` : `DNS Server`
* `DvrFmwk` : `Microsoft-Windows-DriverFrameworks-UserMode/Operational`
* `Exchange` : `MSExchange Management`
* `Firewall` : `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`
* `KeyMgtSvc` : `Key Management Service`
* `LDAP-Cli` : `Microsoft-Windows-LDAP-Client/Debug`
* `NTLM` `Microsoft-Windows-NTLM/Operational`
* `OpenSSH` : `OpenSSH/Operational`
* `PrintAdm` : `Microsoft-Windows-PrintService/Admin`
* `PrintOp` : `Microsoft-Windows-PrintService/Operational`
* `PwSh` : `Microsoft-Windows-PowerShell/Operational`
* `PwShClassic` : `Windows PowerShell`
* `RDP-Client` : `Microsoft-Windows-TerminalServices-RDPClient/Operational`
* `Sec` : `Security`
* `SecMitig` : `Microsoft-Windows-Security-Mitigations/*`
* `SmbCliSec` : `Microsoft-Windows-SmbClient/Security`
* `SvcBusCli` : `Microsoft-ServiceBus-Client`
* `Sys` : `System`
* `Sysmon` : `Microsoft-Windows-Sysmon/Operational`
* `TaskSch` : `Microsoft-Windows-TaskScheduler/Operational`
* `WinRM` : `Microsoft-Windows-WinRM/Operational`
* `WMI` : `Microsoft-Windows-WMI-Activity/Operational`

## အခြားအတိုကောက်များ

output ကို တတ်နိုင်သမျှ တိုတောင်းစေရန်အတွက် rules များတွင် အောက်ပါအတိုကောက်များကို သုံးပါသည်-

* `Acct` -> Account
* `Addr` -> Address
* `Auth` -> Authentication
* `Cli` -> Client
* `Chan` -> Channel
* `Cmd` -> Command
* `Cnt` -> Count
* `Comp` -> Computer
* `Conn` -> Connection/Connected
* `Creds` -> Credentials
* `Crit` -> Critical
* `Disconn` -> Disconnection/Disconnected
* `Dir` -> Directory
* `Drv` -> Driver
* `Dst` -> Destination
* `EID` -> Event ID
* `Err` -> Error
* `Exec` -> Execution
* `FW` -> Firewall
* `Grp` -> Group
* `Img` -> Image
* `Inj` -> Injection
* `Krb` -> Kerberos
* `LID` -> Logon ID
* `Med` -> Medium
* `Net` -> Network
* `Obj` -> Object
* `Op` -> Operational/Operation
* `Proto` -> Protocol
* `PW` -> Password
* `Reconn` -> Reconnection
* `Req` -> Request
* `Rsp` -> Response
* `Sess` -> Session
* `Sig` -> Signature
* `Susp` -> Suspicious
* `Src` -> Source
* `Svc` -> Service
* `Svr` -> Server
* `Temp` -> Temporary
* `Term` -> Termination/Terminated
* `Tkt` -> Ticket
* `Tgt` -> Target
* `Unkwn` -> Unknown
* `Usr` -> User
* `Perm` -> Permament
* `Pkg` -> Package
* `Priv` -> Privilege
* `Proc` -> Process
* `PID` -> Process ID
* `PGUID` -> Process GUID (Global Unique ID)
* `Ver` -> Version
