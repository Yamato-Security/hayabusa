# 탐지 필드

## Selection 기초

먼저 selection 규칙을 작성하는 방법의 기초를 설명합니다.

### AND 및 OR 로직 작성 방법

AND 로직을 작성하려면 중첩된 딕셔너리를 사용합니다.
아래 탐지 규칙은 규칙이 일치하기 위해 **두 조건 모두**가 참이어야 한다고 정의합니다.
- EventID가 정확히 `7040`이어야 합니다.
- **AND**
- Channel이 정확히 `System`이어야 합니다.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

OR 로직을 작성하려면 리스트(`-`로 시작하는 딕셔너리)를 사용합니다.
아래 탐지 규칙에서는 조건 중 **어느 하나**라도 충족되면 규칙이 트리거됩니다.
- EventID가 정확히 `7040`이어야 합니다.
- **OR**
- Channel이 정확히 `System`이어야 합니다.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

아래와 같이 `AND`와 `OR` 로직을 결합할 수도 있습니다.
이 경우, 규칙은 다음 두 조건이 모두 참일 때 일치합니다.
- EventID가 정확히 `7040` **OR** `7041`입니다.
- **AND**
- Channel이 정확히 `System`입니다.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

다음은 Windows 이벤트 로그를 원본 XML 형식으로 나타낸 일부입니다.
위의 규칙 파일 예시에 있는 `Event.System.Channel` 필드는 원본 XML 태그인 `<Event><System><Channel>System<Channel><System></Event>`를 가리킵니다.
중첩된 XML 태그는 점(`.`)으로 구분된 태그 이름으로 대체됩니다.
hayabusa 규칙에서는 이렇게 점으로 연결된 필드 문자열을 `eventkeys`라고 부릅니다.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Eventkey 별칭

`.`으로 여러 번 구분된 긴 eventkey는 흔하기 때문에, hayabusa는 이를 더 다루기 쉽게 하기 위해 별칭을 사용합니다. 별칭은 `rules/config/eventkey_alias.txt` 파일에 정의되어 있습니다. 이 파일은 `alias`와 `event_key` 매핑으로 구성된 CSV 파일입니다. 위의 규칙을 아래와 같이 별칭을 사용하여 다시 작성하면 규칙을 더 읽기 쉽게 만들 수 있습니다.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### 주의: 정의되지 않은 Eventkey 별칭

모든 eventkey 별칭이 `rules/config/eventkey_alias.txt`에 정의되어 있는 것은 아닙니다. `details`(`Alert details`) 메시지에서 올바른 데이터를 얻지 못하고 대신 `n/a`(사용 불가)가 표시되거나, 탐지 로직의 selection이 제대로 작동하지 않는 경우, `rules/config/eventkey_alias.txt`에 새 별칭을 추가하여 업데이트해야 할 수 있습니다.

### 조건에서 XML 속성을 사용하는 방법

XML 요소는 요소에 공백을 추가하여 속성을 설정할 수 있습니다. 예를 들어, 아래 `Provider Name`의 `Name`은 `Provider` 요소의 XML 속성입니다.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

eventkey에서 XML 속성을 지정하려면 `{eventkey}_attributes.{attribute_name}` 형식을 사용합니다. 예를 들어, 규칙 파일에서 `Provider` 요소의 `Name` 속성을 지정하면 다음과 같습니다.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep 검색

Hayabusa는 eventkey를 지정하지 않음으로써 Windows 이벤트 로그 파일에서 grep 검색을 수행할 수 있습니다.

grep 검색을 수행하려면 아래와 같이 탐지를 지정합니다. 이 경우, Windows 이벤트 로그에 `mimikatz` 또는 `metasploit` 문자열이 포함되어 있으면 일치합니다. 와일드카드를 지정하는 것도 가능합니다.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> 참고: Hayabusa는 데이터를 처리하기 전에 내부적으로 Windows 이벤트 로그 데이터를 JSON 형식으로 변환하므로 XML 태그를 일치시키는 것은 불가능합니다.

### EventData

Windows 이벤트 로그는 두 부분으로 나뉩니다. 기본 데이터(Event ID, Timestamp, Record ID, 로그 이름(Channel))가 기록되는 `System` 부분과, Event ID에 따라 임의의 데이터가 기록되는 `EventData` 또는 `UserData` 부분입니다.
자주 발생하는 한 가지 문제는 `EventData`에 중첩된 필드의 이름이 모두 `Data`라고 불린다는 점이며, 지금까지 설명한 eventkey로는 `SubjectUserSid`와 `SubjectUserName`을 구별할 수 없습니다.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

이 문제를 해결하려면 `Data Name`에 할당된 값을 지정할 수 있습니다. 예를 들어, EventData의 `SubjectUserName`과 `SubjectDomainName`을 규칙의 조건으로 사용하려면 다음과 같이 작성할 수 있습니다.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventData의 비정상 패턴

`EventData`에 중첩된 일부 태그에는 `Name` 속성이 없습니다.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

위와 같은 이벤트 로그를 탐지하려면 `Data`라는 이름의 eventkey를 지정할 수 있습니다.
이 경우, 중첩된 `Data` 태그 중 어느 하나라도 `None`과 같으면 조건이 일치합니다.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### 같은 이름을 가진 여러 필드명에서 필드 데이터 출력하기

일부 이벤트는 이전 예시처럼 데이터를 모두 `Data`라는 필드명에 저장합니다.
`details:`에 `%Data%`를 지정하면 모든 데이터가 배열로 출력됩니다.

예를 들면:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

첫 번째 `Data` 필드 데이터만 출력하려면 `details:` 알림 문자열에 `%Data[1]%`를 지정하면 `rundll32.exe`만 출력됩니다.

## 필드 수정자

아래와 같이 파이프 문자를 eventkey와 함께 사용하여 문자열을 일치시킬 수 있습니다.
지금까지 설명한 모든 조건은 정확한 일치를 사용하지만, 필드 수정자를 사용하면 더 유연한 탐지 규칙을 작성할 수 있습니다.
다음 예시에서는 `Data`의 값에 `EngineVersion=2` 문자열이 포함되어 있으면 조건이 일치합니다.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

문자열 일치는 대소문자를 구분하지 않습니다. 그러나 `|re` 또는 `|equalsfield`를 사용할 때는 대소문자를 구분하게 됩니다.

### 지원되는 Sigma 필드 수정자

Hayabusa는 현재 Sigma 사양 전체를 완전히 지원하는 유일한 오픈소스 도구입니다.

지원되는 모든 필드 수정자의 현재 상태와 이 수정자들이 Sigma 및 Hayabusa 규칙에서 몇 번 사용되는지를 https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md 에서 확인할 수 있습니다.
이 문서는 Sigma 또는 Hayabusa 규칙이 업데이트될 때마다 동적으로 갱신됩니다.

- `'|all':`: 이 필드 수정자는 특정 필드에 적용되는 것이 아니라 모든 필드에 적용되기 때문에 위의 수정자들과 다릅니다.

    이 예시에서는 `Keyword-1`과 `Keyword-2` 두 문자열이 모두 존재해야 하지만 어느 필드에서든 어디에나 존재할 수 있습니다:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: 데이터는 인코딩된 문자열 내 위치에 따라 세 가지 다른 방식으로 base64로 인코딩됩니다. 이 수정자는 문자열을 세 가지 변형으로 모두 인코딩하고 그 문자열이 base64 문자열 어딘가에 인코딩되어 있는지 확인합니다.
- `|cased`: 검색을 대소문자 구분으로 만듭니다.
- `|cidr`: 필드 값이 IPv4 또는 IPv6 CIDR 표기법과 일치하는지 확인합니다. (예: `192.0.2.0/24`)
- `|contains`: 필드 값이 특정 문자열을 포함하는지 확인합니다.
- `|contains|all`: 여러 단어가 데이터에 포함되어 있는지 확인합니다.
- `|contains|all|windash`: `|contains|windash`와 동일하지만 모든 키워드가 존재해야 합니다.
- `|contains|cased`: 필드 값이 특정 대소문자 구분 문자열을 포함하는지 확인합니다.
- `|contains|expand`: 필드 값이 `/config/expand/` 내부의 `expand` 설정 파일에 있는 문자열을 포함하는지 확인합니다.
- `|contains|windash`: 문자열을 그대로 확인하고, 첫 번째 `-` 문자를 `/`, `–`(en dash), `—`(em dash), `―`(horizontal bar) 문자 조합으로 변환하여 확인합니다.
- `|endswith`: 필드 값이 특정 문자열로 끝나는지 확인합니다.
- `|endswith|cased`: 필드 값이 특정 대소문자 구분 문자열로 끝나는지 확인합니다.
- `|endswith|windash`: 문자열의 끝을 확인하고 대시에 대한 변형을 수행합니다.
- `|exists`: 필드가 존재하는지 확인합니다.
- `|expand`: 필드 값이 `/config/expand/` 내부의 `expand` 설정 파일에 있는 문자열과 같은지 확인합니다.
- `|fieldref`: 두 필드의 값이 같은지 확인합니다. 두 필드가 다른지 확인하려면 `condition`에서 `not`을 사용할 수 있습니다.
- `|fieldref|contains`: 한 필드의 값이 다른 필드에 포함되어 있는지 확인합니다.
- `|fieldref|endswith`: 왼쪽 필드가 오른쪽 필드의 문자열로 끝나는지 확인합니다. 두 필드가 다른지 확인하려면 `condition`에서 `not`을 사용할 수 있습니다.
- `|fieldref|startswith`: 왼쪽 필드가 오른쪽 필드의 문자열로 시작하는지 확인합니다. 두 필드가 다른지 확인하려면 `condition`에서 `not`을 사용할 수 있습니다.
- `|gt`: 필드 값이 특정 숫자보다 큰지 확인합니다.
- `|gte`: 필드 값이 특정 숫자보다 크거나 같은지 확인합니다.
- `|lt`: 필드 값이 특정 숫자보다 작은지 확인합니다.
- `|lte`: 필드 값이 특정 숫자보다 작거나 같은지 확인합니다.
- `|re`: 대소문자 구분 정규 표현식을 사용합니다. (regex crate를 사용하고 있으므로 지원되는 정규 표현식을 작성하는 방법을 배우려면 <https://docs.rs/regex/latest/regex/#syntax>의 문서를 참조하세요.)
    > 주의: [Sigma 규칙의 정규 표현식 구문](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression)은 PCRE를 사용하며 문자 클래스, lookbehind, atomic grouping 등을 위한 특정 메타문자는 지원되지 않습니다. Rust regex crate는 Sigma 규칙의 모든 정규 표현식을 사용할 수 있어야 하지만 비호환 가능성이 있습니다. 
- `|re|i`: (Insensitive) 대소문자를 구분하지 않는 정규 표현식을 사용합니다.
- `|re|m`: (Multi-line) 여러 줄에 걸쳐 일치시킵니다. `^` / `$`는 줄의 시작/끝과 일치합니다.
- `|re|s`: (Single-line) 점(`.`)이 줄바꿈 문자를 포함한 모든 문자와 일치합니다.
- `|startswith`: 필드 값이 특정 문자열로 시작하는지 확인합니다.
- `|startswith|cased`: 필드 값이 특정 대소문자 구분 문자열로 시작하는지 확인합니다.
- `|utf16|base64offset|contains`: 특정 UTF-16 문자열이 base64 문자열 내부에 인코딩되어 있는지 확인합니다.
- `|utf16be|base64offset|contains`: 특정 UTF-16 빅엔디안 문자열이 base64 문자열 내부에 인코딩되어 있는지 확인합니다.
- `|utf16le|base64offset|contains`: 특정 UTF-16 리틀엔디안 문자열이 base64 문자열 내부에 인코딩되어 있는지 확인합니다.
- `|wide|base64offset|contains`: `utf16le|base64offset|contains`의 별칭으로, UTF-16 리틀엔디안 문자열을 확인합니다.

### 더 이상 사용되지 않는 필드 수정자

다음 수정자들은 이제 더 이상 사용되지 않으며 Sigma 사양을 더 잘 준수하는 수정자로 대체되었습니다.

- `|equalsfield`: 이제 `|fieldref`로 대체되었습니다.
- `|endswithfield`: 이제 `|fieldref|endswith`로 대체되었습니다.

### Expand 필드 수정자

`expand` 필드 수정자는 사용하기 전에 설정이 필요한 유일한 필드 수정자라는 점에서 독특합니다.
예를 들어, `%DC-MACHINE-NAME%`와 같은 자리표시자를 사용하며 가능한 모든 DC 머신 이름을 포함하는 `/config/expand/DC-MACHINE-NAME.txt`라는 설정 파일이 필요합니다.

이를 설정하는 방법은 [여기](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command)에서 더 자세히 설명되어 있습니다.

## 와일드카드

eventkey에서 와일드카드를 사용할 수 있습니다. 아래 예시에서는 `ProcessCommandLine`이 "malware" 문자열로 시작하면 규칙이 일치합니다.
사양은 기본적으로 sigma 규칙 와일드카드와 동일하므로 대소문자를 구분하지 않습니다.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

다음 두 가지 와일드카드를 사용할 수 있습니다.
- `*`: 0개 이상의 문자로 이루어진 모든 문자열과 일치합니다. (내부적으로 정규 표현식 `.*`로 변환됩니다)
- `?`: 임의의 단일 문자와 일치합니다. (내부적으로 정규 표현식 `.`로 변환됩니다)

와일드카드 이스케이프에 대하여:
- 와일드카드(`*` 및 `?`)는 백슬래시를 사용하여 이스케이프할 수 있습니다: `\*`, `\?`.
- 와일드카드 바로 앞에 백슬래시를 사용하려면 `\\*` 또는 `\\?`로 작성합니다.
- 백슬래시를 단독으로 사용하는 경우에는 이스케이프가 필요하지 않습니다.

## null 키워드

`null` 키워드를 사용하여 필드가 존재하지 않는지 확인할 수 있습니다.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

참고: 이는 필드 값이 비어 있는지 확인하는 `ProcessCommandLine: ''`와는 다릅니다.

## condition

위에서 설명한 표기법으로 `AND`와 `OR` 로직을 표현할 수 있지만, 복잡한 로직을 정의하려고 하면 혼란스러울 수 있습니다.
더 복잡한 규칙을 만들고자 할 때는 아래와 같이 `condition` 키워드를 사용해야 합니다.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

`condition`에는 다음 표현식을 사용할 수 있습니다.
- `{expression1} and {expression2}`: {expression1}과 {expression2} 모두 필요
- `{expression1} or {expression2}`: {expression1} 또는 {expression2} 중 하나 필요
- `not {expression}`: {expression}의 로직을 반전
- `( {expression} )`: {expression}의 우선순위를 설정. 수학에서와 동일한 우선순위 로직을 따릅니다.

위 예시에서는 `SELECTION_1`, `SELECTION_2` 등의 selection 이름이 사용되지만, 다음 문자만 포함한다면 어떤 이름이든 지을 수 있습니다: `a-z A-Z 0-9 _`
> 그러나 가능하면 읽기 쉽도록 `selection_1`, `selection_2`, `filter_1`, `filter_2` 등의 표준 규칙을 사용하세요.

## not 로직

많은 규칙이 오탐을 발생시키므로, 검색할 시그니처를 위한 selection과 함께 오탐에 대해 알림을 발생시키지 않기 위한 filter selection을 두는 것이 매우 일반적입니다.
예를 들면:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma 상관관계

[여기](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md)에 정의된 Sigma 버전 2.0.0 상관관계를 모두 구현했습니다.

지원되는 상관관계:
- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

2025년 9월 12일 Sigma 버전 2.1.0에서 출시된 새로운 "metrics" 상관관계 규칙(`value_sum`, `value_avg`, `value_percentile`)은 현재 지원되지 않습니다.
