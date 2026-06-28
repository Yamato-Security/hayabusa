## 이벤트 개수(Event Count) 규칙

이 규칙들은 특정 이벤트의 개수를 세어 일정 시간 범위 내에 해당 이벤트가 너무 많이 또는 너무 적게 발생하면 경고를 발생시키는 규칙입니다.
특정 시간 범위 내에 많은 이벤트를 탐지하는 일반적인 예로는 패스워드 추측 공격, 패스워드 스프레이 공격, 서비스 거부(DoS) 공격 탐지가 있습니다.
또한 특정 이벤트가 일정 임계값 아래로 떨어지는 경우와 같이 로그 소스 신뢰성 문제를 탐지하는 데에도 이 규칙들을 사용할 수 있습니다.

### 이벤트 개수 규칙 예시:

다음 예시는 두 개의 규칙을 사용하여 패스워드 추측 공격을 탐지합니다.
참조된 규칙이 5분 이내에 5회 이상 매칭되고 해당 이벤트들의 `IpAddress` 필드가 동일한 경우 경고가 발생합니다.

> 개념을 이해하는 데 필요한 필드만 포함했다는 점에 유의하세요.
> 이 예시의 기반이 되는 전체 규칙은 참고용으로 [여기](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml)에 있습니다.

### 이벤트 개수 상관관계 규칙:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### 로그온 실패 - 잘못된 패스워드 규칙:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### 더 이상 사용되지 않는 `count` 규칙 예시:

위의 상관관계 규칙과 참조된 규칙들은 이전의 `count` 수정자를 사용하는 다음 규칙과 동일한 결과를 제공합니다:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### 이벤트 개수 규칙 출력:

위 규칙들은 다음과 같은 출력을 생성합니다:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## 값 개수(Value Count) 규칙

이 규칙들은 시간 범위 내에서 특정 필드의 **서로 다른** 값을 가진 동일한 이벤트의 개수를 셉니다.

예시:

- 단일 소스 IP 주소가 다수의 서로 다른 대상 IP 주소 및/또는 포트에 연결을 시도하는 네트워크 스캔.
- 단일 소스가 다수의 서로 다른 사용자에 대한 인증에 실패하는 패스워드 스프레이 공격.
- 짧은 시간 범위 내에 다수의 고권한 AD 그룹을 열거하는 BloodHound 같은 도구 탐지.

### 값 개수 규칙 예시:

다음 규칙은 공격자가 사용자 이름을 추측하려고 시도하는 경우를 탐지합니다.
즉, **동일한** 소스 IP 주소(`IpAddress`)가 5분 이내에 3개 초과의 **서로 다른** 사용자 이름(`TargetUserName`)으로 로그온에 실패하는 경우입니다.

> 개념을 이해하는 데 필요한 필드만 포함했다는 점에 유의하세요.
> 이 예시의 기반이 되는 전체 규칙은 참고용으로 [여기](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml)에 있습니다.

### 값 개수 상관관계 규칙:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### 값 개수 로그온 실패 (존재하지 않는 사용자) 규칙:

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### 더 이상 사용되지 않는 `count` 수정자 규칙:

위의 상관관계 규칙과 참조된 규칙들은 이전의 `count` 수정자를 사용하는 다음 규칙과 동일한 결과를 제공합니다:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### 값 개수 규칙 출력:

위 규칙들은 다음과 같은 출력을 생성합니다:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## 시간 근접성(Temporal Proximity) 규칙

rule 필드가 참조하는 규칙들로 정의된 모든 이벤트는 timespan으로 정의된 시간 범위 내에 발생해야 합니다.
`group-by`에 정의된 필드들의 값은 모두 동일한 값이어야 합니다(예: 동일한 호스트, 사용자 등).

### 시간 근접성 규칙 예시:

예시: 세 개의 Sigma 규칙에 정의된 정찰 명령들이 동일한 사용자에 의해 시스템에서 5분 이내에 임의의 순서로 실행됩니다.

### 시간 근접성 상관관계 규칙:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## 순서가 있는 시간 근접성(Ordered Temporal Proximity) 규칙

`temporal_ordered` 상관관계 유형은 `temporal`처럼 동작하며, 추가로 이벤트들이 `rules` 속성에 제공된 순서대로 나타날 것을 요구합니다.

### 순서가 있는 시간 근접성 규칙 예시:

예시: 위에서 정의한 다수의 로그인 실패 이후 1시간 이내에 동일한 사용자 계정의 로그인 성공이 뒤따릅니다:

### 순서가 있는 시간 근접성 상관관계 규칙:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## 상관관계 규칙에 대한 참고 사항

1. 모든 상관관계 규칙과 참조된 규칙을 하나의 파일에 포함시키고 YAML 구분자 `---`로 구분해야 합니다.

2. 기본적으로 참조된 상관관계 규칙은 출력되지 않습니다. 참조된 규칙의 출력을 보고 싶다면 `correlation` 아래에 `generate: true`를 추가해야 합니다. 이는 상관관계 규칙을 만들 때 켜서 확인하기에 매우 유용합니다.

    예시:
    ```
    correlation:
        generate: true
    ```
3. 이해를 더 쉽게 하기 위해 규칙을 참조할 때 규칙 ID 대신 별칭 이름을 사용할 수 있습니다.

4. 여러 규칙을 참조할 수 있습니다.

5. `group-by`에 여러 필드를 사용할 수 있습니다. 그렇게 하면 해당 필드들의 모든 값이 동일해야 하며, 그렇지 않으면 경고가 발생하지 않습니다. 대부분의 경우 오탐을 줄이기 위해 `group-by`로 특정 필드를 필터링하는 규칙을 작성하지만, `group-by`를 생략하여 보다 일반적인 규칙을 만드는 것도 가능합니다.

6. 상관관계 규칙의 타임스탬프는 공격의 맨 처음 시점이 되므로, 오탐 여부를 확인하려면 그 이후의 이벤트들을 확인해야 합니다.
