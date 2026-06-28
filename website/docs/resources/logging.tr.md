# Windows Loglama ve Sysmon

## Windows Loglama Önerileri

Windows makinelerindeki kötü amaçlı etkinlikleri düzgün şekilde tespit edebilmek için varsayılan log ayarlarını iyileştirmeniz gerekecektir.
Hangi log ayarlarının etkinleştirilmesi gerektiğini belgelemek ve doğru ayarları otomatik olarak etkinleştiren betikler sağlamak amacıyla [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) adresinde ayrı bir proje oluşturduk.

Ayrıca rehberlik için aşağıdaki siteleri öneriyoruz:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Loglama Esasları](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Loglama ve Yönlendirme Kılavuzu](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Hile Sayfaları](https://www.malwarearchaeology.com/cheat-sheets)

## Sysmon ile İlgili Projeler

En fazla adli kanıtı oluşturmak ve en yüksek doğrulukla tespit yapmak için sysmon kurmanız gerekir. Aşağıdaki siteleri ve yapılandırma dosyalarını öneriyoruz:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [Neo23x0 tarafından SwiftOnSecurity Sysmon Config çatallaması](https://github.com/Neo23x0/sysmon-config)
* [ion-storm tarafından SwiftOnSecurity Sysmon Config çatallaması](https://github.com/ion-storm/sysmon-config)
