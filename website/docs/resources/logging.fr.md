# Journalisation Windows et Sysmon

## Recommandations pour la journalisation Windows

Afin de détecter correctement les activités malveillantes sur les machines Windows, vous devrez améliorer les paramètres de journalisation par défaut.
Nous avons créé un projet distinct pour documenter quels paramètres de journalisation doivent être activés, ainsi que des scripts permettant d'activer automatiquement les paramètres appropriés à l'adresse [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

Nous recommandons également les sites suivants pour vous guider :

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Projets liés à Sysmon

Pour générer le maximum de preuves forensiques et détecter avec la plus grande précision, vous devez installer sysmon. Nous recommandons les sites et fichiers de configuration suivants :

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
