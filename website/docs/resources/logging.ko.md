# Windows 로깅 & Sysmon

## Windows 로깅 권장 사항

Windows 시스템에서 악성 활동을 제대로 탐지하려면 기본 로그 설정을 개선해야 합니다.
어떤 로그 설정을 활성화해야 하는지를 문서화하고 적절한 설정을 자동으로 활성화하는 스크립트를 제공하기 위해 [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings)에 별도의 프로젝트를 만들었습니다.

또한 다음 사이트들을 참고 자료로 권장합니다:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Sysmon 관련 프로젝트

가장 많은 포렌식 증거를 생성하고 가장 높은 정확도로 탐지하려면 sysmon을 설치해야 합니다. 다음 사이트와 설정 파일들을 권장합니다:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
