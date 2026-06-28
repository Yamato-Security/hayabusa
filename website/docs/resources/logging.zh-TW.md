# Windows 記錄與 Sysmon

## Windows 記錄建議

為了正確偵測 Windows 機器上的惡意活動，您需要改善預設的記錄設定。
我們建立了一個獨立的專案，記錄哪些記錄設定需要啟用，並提供可自動啟用適當設定的指令碼，位於 [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings)。

我們也推薦以下網站作為指引：

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Sysmon 相關專案

為了產生最多的鑑識證據並以最高的準確度進行偵測，您需要安裝 sysmon。我們推薦以下網站與設定檔：

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
