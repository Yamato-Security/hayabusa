# Windows-Protokollierung & Sysmon

## Empfehlungen zur Windows-Protokollierung

Um bösartige Aktivitäten auf Windows-Rechnern ordnungsgemäß zu erkennen, müssen Sie die Standardeinstellungen für die Protokollierung verbessern.
Wir haben ein separates Projekt erstellt, um zu dokumentieren, welche Protokolleinstellungen aktiviert werden müssen, sowie Skripte zur automatischen Aktivierung der richtigen Einstellungen unter [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

Wir empfehlen außerdem die folgenden Seiten als Orientierungshilfe:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Sysmon-bezogene Projekte

Um die meisten forensischen Beweise zu erzeugen und mit höchster Genauigkeit zu erkennen, müssen Sie Sysmon installieren. Wir empfehlen die folgenden Seiten und Konfigurationsdateien:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
