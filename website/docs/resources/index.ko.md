# 프로젝트 및 생태계

## 관련 프로젝트

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Windows 이벤트 로그를 올바르게 활성화하기 위한 문서 및 스크립트.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Hayabusa Rules 저장소와 동일하지만 규칙과 설정 파일이 하나의 파일에 저장되고 XOR 처리되어 안티바이러스로 인한 오탐을 방지합니다.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa에서 사용하는 Hayabusa 및 선별된 Sigma 탐지 규칙.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - 더 잘 유지 관리되는 `evtx` 크레이트의 포크.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - hayabusa/sigma 탐지 규칙을 테스트하는 데 사용할 샘플 evtx 파일.
* [Presentations](https://github.com/Yamato-Security/Presentations) - 우리의 도구 및 자료에 대해 발표한 강연 자료.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - 업스트림의 Windows 이벤트 로그 기반 Sigma 규칙을 더 사용하기 쉬운 형태로 선별합니다.
* [Takajo](https://github.com/Yamato-Security/takajo) - hayabusa 결과를 위한 분석기.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - PowerShell로 작성된 Windows 이벤트 로그 분석기. (더 이상 사용되지 않으며 Takajo로 대체됨.)

## Hayabusa를 사용하는 서드파티 프로젝트

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Plaso 및 Hayabusa 결과를 Timesketch로 가져오는 NodeRED 워크플로.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - 필요에 맞는 클라우드 기반 보안 도구 및 인프라를 제공합니다. 
* [OpenRelik](https://openrelik.org/) - 협업 디지털 포렌식 조사를 간소화하도록 설계된 오픈소스(Apache-2.0) 플랫폼.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - 조사 중에 로그 및 도구 출력을 살펴보기 위해 Docker로 splunk 인스턴스를 빠르게 구동합니다.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - The Velociraptor Query Language (VQL) 쿼리를 사용하여 호스트 기반 상태 정보를 수집하는 도구.

## 기타 Windows 이벤트 로그 분석기 및 관련 자료

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Python으로 작성된 공격 탐지 도구.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  디지털 포렌식 및 사고 대응에 유용한 Event ID 자료 모음
* [Chainsaw](https://github.com/countercept/chainsaw) - Rust로 작성된 또 다른 sigma 기반 공격 탐지 도구.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - [Eric Conrad](https://twitter.com/eric_conrad)이 Powershell로 작성한 공격 탐지 도구.
* [Epagneul](https://github.com/jurelou/epagneul) - Windows 이벤트 로그를 위한 그래프 시각화.
* [EventList](https://github.com/miriamxyra/EventList/) - [Miriam Wiesner](https://github.com/miriamxyra)가 보안 기준선 이벤트 ID를 MITRE ATT&CK에 매핑.
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) 작성
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - [Eric Zimmerman](https://twitter.com/ericrzimmerman)의 Evtx 파서.
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - 할당되지 않은 공간 및 메모리 이미지에서 EVTX 로그 파일을 복구합니다.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Evtx 데이터를 Elastic Stack으로 전송하는 Python 도구.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - [SBousseaden](https://twitter.com/SBousseaden)의 EVTX 공격 샘플 이벤트 로그 파일.
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)가 ATT&CK에 매핑한 EVTX 공격 샘플 이벤트 로그 파일
* [EVTX parser](https://github.com/omerbenamram/evtx) - [@OBenamram](https://twitter.com/obenamram)이 작성한, 우리가 사용하는 Rust evtx 라이브러리.
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Sysmon 및 PowerShell 로그 시각화 도구.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - [JPCERTCC](https://twitter.com/jpcert_en)가 측면 이동을 탐지하기 위해 로그온을 시각화하는 그래픽 인터페이스.
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - 무엇을 모니터링해야 하는지에 대한 NSA의 가이드.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Yamato Security의 DeepBlueCLI Rust 포팅.
* [Sigma](https://github.com/SigmaHQ/sigma) - 커뮤니티 기반의 일반적인 SIEM 규칙.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - [Phil Hagen](https://twitter.com/philhagen)이 만든, DFIR 분석을 위해 데이터를 가져오는 Elastic Stack이 사전 패키징된 VM
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtx 파일을 Security Onion으로 가져옵니다.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Sysmon을 위한 설정 및 오프라인 로그 시각화 도구.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - [Eric Zimmerman](https://twitter.com/ericrzimmerman)의 최고의 CSV 타임라인 분석기.
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - Forward Defense의 Steve Anson 작성.
* [Zircolite](https://github.com/wagga40/Zircolite) - Python으로 작성된 Sigma 기반 공격 탐지 도구.
