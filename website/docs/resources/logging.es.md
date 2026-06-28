# Registro de Windows y Sysmon

## Recomendaciones para el registro de Windows

Para detectar adecuadamente la actividad maliciosa en máquinas Windows, necesitará mejorar la configuración de registro predeterminada.
Hemos creado un proyecto aparte para documentar qué configuraciones de registro deben habilitarse, así como scripts para habilitar automáticamente la configuración adecuada en [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

También recomendamos los siguientes sitios como guía:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Proyectos relacionados con Sysmon

Para generar la mayor cantidad de evidencia forense y detectar con la mayor precisión, necesita instalar sysmon. Recomendamos los siguientes sitios y archivos de configuración:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
