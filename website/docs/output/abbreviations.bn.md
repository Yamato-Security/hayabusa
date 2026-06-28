# সংক্ষিপ্ত রূপ

জায়গা বাঁচানোর জন্য, আমরা লেভেল, MITRE ATT&CK কৌশল, চ্যানেল, প্রোভাইডার, ফিল্ড নাম, ইত্যাদি সংক্ষিপ্ত করি...

আপনি `-b, --disable-abbreviations` অপশন দিয়ে এই সংক্ষিপ্ত রূপগুলোর কিছু বন্ধ করে মূল চ্যানেল নাম, প্রোভাইডার নাম, ইত্যাদি দেখতে পারেন...

## লেভেল সংক্ষিপ্ত রূপ

জায়গা বাঁচানোর জন্য, অ্যালার্ট `level` প্রদর্শন করার সময় আমরা নিম্নলিখিত সংক্ষিপ্ত রূপগুলো ব্যবহার করি।

* `emer`: `emergency`
* `crit`: `critical`
* `high`: `high`
* `med `: `medium`
* `low `: `low`
* `info`: `informational`
* `undef`: `undefined`

## MITRE ATT&CK কৌশল সংক্ষিপ্ত রূপ

জায়গা বাঁচানোর জন্য, MITRE ATT&CK কৌশল ট্যাগ প্রদর্শন করার সময় আমরা নিম্নলিখিত সংক্ষিপ্ত রূপগুলো ব্যবহার করি।
আপনি `./config/mitre_tactics.txt` কনফিগারেশন ফাইলে এই সংক্ষিপ্ত রূপগুলো স্বাধীনভাবে সম্পাদনা করতে পারেন।

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

## চ্যানেল সংক্ষিপ্ত রূপ

জায়গা বাঁচানোর জন্য, চ্যানেল প্রদর্শন করার সময় আমরা নিম্নলিখিত সংক্ষিপ্ত রূপগুলো ব্যবহার করি।
আপনি `./rules/config/channel_abbreviations.txt` কনফিগারেশন ফাইলে এই সংক্ষিপ্ত রূপগুলো স্বাধীনভাবে সম্পাদনা করতে পারেন।

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

## অন্যান্য সংক্ষিপ্ত রূপ

আউটপুট যতটা সম্ভব সংক্ষিপ্ত করার জন্য রুলগুলোতে নিম্নলিখিত সংক্ষিপ্ত রূপগুলো ব্যবহার করা হয়:

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
