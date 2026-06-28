# 룰 파일 생성

## Hayabusa-Rules 소개

이 저장소는 Windows 이벤트 로그에서 공격을 탐지하는 선별된 sigma 룰을 포함하고 있습니다.
주로 [Hayabusa](https://github.com/Yamato-Security/hayabusa)의 탐지 룰 및 설정 파일과 [Velociraptor](https://github.com/Velocidex/velociraptor)의 내장 sigma 탐지에 사용됩니다.
[업스트림 sigma 저장소](https://github.com/SigmaHQ/sigma) 대신 이 저장소를 사용하는 장점은 대부분의 sigma 네이티브 도구가 파싱할 수 있는 룰만 포함한다는 점입니다.
또한 `logsource` 필드에 필요한 `Channel`, `EventID` 등의 필드를 추가하여 추상화를 해제함으로써, 룰이 무엇을 필터링하는지 이해하기 쉽게 하고 더 중요하게는 오탐을 줄입니다.
또한 `process_creation` 룰과 `registry` 기반 룰에 대해 변환된 필드 이름과 값으로 새로운 룰을 생성하여, sigma 룰이 Sysmon 로그뿐만 아니라 내장 Windows 로그에서도 탐지할 수 있도록 합니다.

## 룰 파일 생성에 대하여

Hayabusa 탐지 룰은 [YAML](https://en.wikipedia.org/wiki/YAML) 형식으로 작성되며 파일 확장자는 `.yml`입니다. (`.yaml` 파일은 무시됩니다.)
이들은 sigma 룰의 하위 집합이지만 일부 추가 기능도 포함합니다.
우리는 커뮤니티에 환원하기 위해 Hayabusa 룰을 sigma로 다시 쉽게 변환할 수 있도록 가능한 한 sigma 룰에 가깝게 만들려고 노력하고 있습니다.
Hayabusa 룰은 단순한 문자열 매칭뿐만 아니라 정규 표현식, `AND`, `OR` 및 기타 조건을 조합하여 복잡한 탐지 룰을 표현할 수 있습니다.
이 섹션에서는 Hayabusa 탐지 룰을 작성하는 방법을 설명합니다.

### 룰 파일 형식

예시:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## Author 섹션

- **author [필수]**: 작성자 이름.
- **date [필수]**: 룰이 만들어진 날짜.
- **modified** [선택]: 룰이 업데이트된 날짜.

> ## Alert 섹션

- **title [필수]**: 룰 파일 제목. 이는 표시되는 알림의 이름이기도 하므로 간결할수록 좋습니다. (85자를 넘지 않아야 합니다.)
- **details** [선택]: 표시되는 알림의 세부 정보. 분석에 유용한 Windows 이벤트 로그의 필드를 출력하십시오. 필드는 `" ¦ "`로 구분됩니다. 필드 자리 표시자는 `%`로 둘러싸이며 (예시: `%MemberName%`) `rules/config/eventkey_alias.txt`에 정의되어야 합니다. (아래에서 설명합니다.)
- **description** [선택]: 룰에 대한 설명. 이것은 표시되지 않으므로 길고 상세하게 작성할 수 있습니다.

> ## Rule 섹션

- **id [필수]**: 룰을 고유하게 식별하는 데 사용되는 무작위로 생성된 버전 4 UUID. [여기](https://www.uuidgenerator.net/version4)에서 생성할 수 있습니다.
- **level [필수]**: [sigma의 정의](https://github.com/SigmaHQ/sigma/wiki/Specification)에 기반한 심각도 수준. 다음 중 하나를 작성하십시오: `informational`,`low`,`medium`,`high`,`critical`
- **status[필수]**: [sigma의 정의](https://github.com/SigmaHQ/sigma/wiki/Specification)에 기반한 상태. 다음 중 하나를 작성하십시오: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [필수]**: 현재 Hayabusa에서 실제로 사용되지는 않지만, sigma 룰과의 호환성을 위해 sigma와 동일한 방식으로 logsource를 정의합니다.
- **detection  [필수]**: 탐지 로직이 여기에 들어갑니다. (아래에서 설명합니다.)
- **falsepositives [필수]**: 오탐의 가능성. 예를 들어: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. 알 수 없는 경우 `unknown`이라고 작성하십시오.
- **tags** [선택]: 해당 기법이 [LOLBINS/LOLBAS](https://lolbas-project.github.io/) 기법인 경우 `lolbas` 태그를 추가하십시오. 알림이 [MITRE ATT&CK](https://attack.mitre.org/) 프레임워크의 기법에 매핑될 수 있는 경우, 전술 ID(예시: `attack.t1098`)와 아래의 해당 전술을 추가하십시오:
  - `attack.reconnaissance` -> 정찰 (Recon)
  - `attack.resource-development` -> 자원 개발 (ResDev)
  - `attack.initial-access` -> 초기 접근 (InitAccess)
  - `attack.execution` -> 실행 (Exec)
  - `attack.persistence` -> 지속성 (Persis)
  - `attack.privilege-escalation` -> 권한 상승 (PrivEsc)
  - `attack.stealth` -> 은닉 (Stealth)
  - `attack.defense-impairment` -> 방어 무력화 (DefImpair)
  - `attack.credential-access` -> 자격 증명 접근 (CredAccess)
  - `attack.discovery` -> 탐색 (Disc)
  - `attack.lateral-movement` -> 측면 이동 (LatMov)
  - `attack.collection` -> 수집 (Collect)
  - `attack.command-and-control` -> 명령 및 제어 (C2)
  - `attack.exfiltration` -> 유출 (Exfil)
  - `attack.impact` -> 영향 (Impact)
- **references** [선택]: 참조 링크.
- **ruletype [필수]**: hayabusa 룰의 경우 `Hayabusa`. sigma Windows 룰에서 자동으로 변환된 룰은 `Sigma`가 됩니다.

> ## Sample XML Event 섹션

- **sample-message [필수]**: 앞으로 룰 작성자는 룰에 대한 샘플 메시지를 포함하도록 요청받습니다. 이것은 Windows의 이벤트 뷰어가 표시하는 렌더링된 메시지입니다.
- **sample-evtx [필수]**: 앞으로 룰 작성자는 룰에 대한 샘플 XML 이벤트를 포함하도록 요청받습니다.
