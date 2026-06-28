# संक्षिप्ताक्षर

स्थान बचाने के लिए, हम स्तरों, MITRE ATT&CK रणनीतियों, चैनलों, प्रदाताओं, फ़ील्ड नामों आदि को संक्षिप्त करते हैं...

आप `-b, --disable-abbreviations` विकल्प के साथ इनमें से कुछ संक्षिप्ताक्षरों को बंद कर सकते हैं ताकि मूल चैनल नाम, प्रदाता नाम आदि देख सकें...

## स्तर संक्षिप्ताक्षर

स्थान बचाने के लिए, हम अलर्ट `level` प्रदर्शित करते समय निम्नलिखित संक्षिप्ताक्षरों का उपयोग करते हैं।

* `emer`: `emergency`
* `crit`: `critical`
* `high`: `high`
* `med `: `medium`
* `low `: `low`
* `info`: `informational`
* `undef`: `undefined`

## MITRE ATT&CK रणनीति संक्षिप्ताक्षर

स्थान बचाने के लिए, हम MITRE ATT&CK रणनीति टैग प्रदर्शित करते समय निम्नलिखित संक्षिप्ताक्षरों का उपयोग करते हैं।
आप `./config/mitre_tactics.txt` कॉन्फ़िगरेशन फ़ाइल में इन संक्षिप्ताक्षरों को स्वतंत्र रूप से संपादित कर सकते हैं।

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

## चैनल संक्षिप्ताक्षर

स्थान बचाने के लिए, हम चैनल प्रदर्शित करते समय निम्नलिखित संक्षिप्ताक्षरों का उपयोग करते हैं।
आप `./rules/config/channel_abbreviations.txt` कॉन्फ़िगरेशन फ़ाइल में इन संक्षिप्ताक्षरों को स्वतंत्र रूप से संपादित कर सकते हैं।

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

## अन्य संक्षिप्ताक्षर

आउटपुट को यथासंभव संक्षिप्त बनाने के लिए नियमों में निम्नलिखित संक्षिप्ताक्षरों का उपयोग किया जाता है:

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
