# Журналювання Windows та Sysmon

## Рекомендації щодо журналювання Windows

Щоб належно виявляти зловмисну активність на машинах Windows, вам потрібно покращити стандартні налаштування журналювання.
Ми створили окремий проєкт, щоб задокументувати, які налаштування журналювання потрібно увімкнути, а також скрипти для автоматичного увімкнення належних налаштувань за адресою [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

Ми також рекомендуємо наступні сайти для отримання вказівок:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Проєкти, пов'язані з Sysmon

Щоб створити якнайбільше криміналістичних доказів і виявляти з найвищою точністю, вам потрібно встановити sysmon. Ми рекомендуємо наступні сайти та конфігураційні файли:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
