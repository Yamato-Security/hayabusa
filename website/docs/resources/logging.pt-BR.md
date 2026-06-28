# Logging do Windows e Sysmon

## Recomendações de Logging do Windows

Para detectar adequadamente atividades maliciosas em máquinas Windows, você precisará aprimorar as configurações padrão de logs.
Criamos um projeto separado para documentar quais configurações de log precisam ser habilitadas, bem como scripts para habilitar automaticamente as configurações adequadas em [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

Também recomendamos os seguintes sites para orientação:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Projetos Relacionados ao Sysmon

Para criar a maior quantidade de evidências forenses e detectar com a maior precisão, você precisa instalar o sysmon. Recomendamos os seguintes sites e arquivos de configuração:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
