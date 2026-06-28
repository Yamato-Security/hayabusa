# 더 이상 사용되지 않는 기능

더 이상 사용되지 않는 특수 키워드와 `count` 집계는 Hayabusa에서 여전히 지원되지만 앞으로는 룰 내부에서 사용되지 않을 예정입니다.

## 더 이상 사용되지 않는 특수 키워드

현재 다음 특수 키워드를 지정할 수 있습니다:

- `value`: 문자열로 매칭합니다(와일드카드와 파이프도 지정할 수 있습니다).
- `min_length`: 문자 수가 지정한 숫자 이상일 때 매칭합니다.
- `regexes`: 이 필드에 지정한 파일 안의 정규 표현식 중 하나가 매칭되면 매칭됩니다.
- `allowlist`: 이 필드에 지정한 파일 안의 정규 표현식 목록에서 매칭이 발견되면 룰을 건너뜁니다.

아래 예시에서, 다음이 모두 참이면 룰이 매칭됩니다:

- `ServiceName`이 `malicious-service`라고 불리거나 `./rules/config/regex/detectlist_suspicous_services.txt`의 정규 표현식을 포함하는 경우.
- `ImagePath`가 최소 1000자인 경우.
- `ImagePath`가 `allowlist`에서 매칭되지 않는 경우.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### regexes 및 allowlist 키워드 샘플 파일

Hayabusa에는 `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml` 파일에 사용되는 두 개의 내장 정규 표현식 파일이 있었습니다:

- `./rules/config/regex/detectlist_suspicous_services.txt`: 의심스러운 서비스 이름을 탐지합니다
- `./rules/config/regex/allowlist_legitimate_services.txt`: 정상적인 서비스를 허용합니다

`regexes` 및 `allowlist`에 정의된 파일은 룰 파일 자체를 변경하지 않고도 편집하여 이를 참조하는 모든 룰의 동작을 변경할 수 있습니다.

직접 만든 다른 detectlist 및 allowlist 텍스트 파일을 사용할 수도 있습니다.

## 더 이상 사용되지 않는 집계 조건 (`count` 룰)

이는 Hayabusa에서 여전히 지원되지만 앞으로 Sigma 상관관계 룰로 대체될 예정입니다.

### 기본 사항

위에서 설명한 `condition` 키워드는 `AND` 및 `OR` 로직을 구현할 뿐만 아니라 이벤트를 카운트하거나 "집계"할 수도 있습니다.
이 기능은 "집계 조건"이라고 하며 조건을 파이프로 연결하여 지정합니다.
아래의 패스워드 스프레이 탐지 예시에서는, 5분의 시간 범위 내에 하나의 소스 `IpAddress`로부터 5개 이상의 `TargetUserName` 값이 있는지 판단하기 위해 조건식이 사용됩니다.

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

집계 조건은 다음 형식으로 정의할 수 있습니다:

- `count() {operator} {number}`: 파이프 앞의 첫 번째 조건과 매칭되는 로그 이벤트에 대해, 매칭된 로그 수가 `{operator}`와 `{number}`로 지정된 조건식을 충족하면 조건이 매칭됩니다.

`{operator}`는 다음 중 하나가 될 수 있습니다:

- `==`: 값이 지정된 값과 같으면 조건에 매칭되는 것으로 처리됩니다.
- `>=`: 값이 지정된 값 이상이면 조건이 충족된 것으로 간주됩니다.
- `>`: 값이 지정된 값보다 크면 조건이 충족된 것으로 간주됩니다.
- `<=`: 값이 지정된 값 이하이면 조건이 충족된 것으로 간주됩니다.
- `<`: 값이 지정된 값보다 작으면 조건이 충족된 것으로 처리됩니다.

`{number}`는 숫자여야 합니다.

`timeframe`은 다음과 같이 정의할 수 있습니다:

- `15s`: 15초
- `30m`: 30분
- `12h`: 12시간
- `7d`: 7일
- `3M`: 3개월

### 집계 조건의 네 가지 패턴

1. count 인수나 `by` 키워드가 없음. 예시: `selection | count() > 10`
   > `selection`이 시간 범위 내에 10회를 초과하여 매칭되면 조건이 매칭됩니다.
   > 이는 `group-by` 필드를 사용하지 않는 Event Count 상관관계 룰로 대체됩니다.
2. count 인수는 없지만 `by` 키워드가 있음. 예시: `selection | count() by IpAddress > 10`
   > **동일한** `IpAddress`에 대해 `selection`이 10회를 초과하여 참이어야 합니다.
   > 이 #2 룰은 #1 룰보다 더 일반적입니다.
   > 그룹화할 여러 필드를 지정할 수도 있습니다. 예: `by IpAddress, Computer`
   > 이는 `group-by` 필드를 사용하는 Event Count 상관관계 룰로 대체됩니다.
3. count 인수는 있지만 `by` 키워드가 없음. 예시: `selection | count(TargetUserName) > 10`
   > `selection`이 매칭되고 `TargetUserName`이 시간 범위 내에 10회를 초과하여 **다른** 경우, 조건이 매칭됩니다.
   > 이는 `group-by` 필드를 사용하지 않는 Value Count 상관관계 룰로 대체됩니다.
4. count 인수와 `by` 키워드가 모두 있음. 예시: `selection | count(Users) by IpAddress > 10`
   > **동일한** `IpAddress`에 대해, 조건이 매칭되려면 10개를 초과하는 **다른** `TargetUserName`이 있어야 합니다.
   > 이 #4 룰은 #3 룰보다 더 일반적입니다.
   > 이는 `group-by` 필드를 사용하는 Value Count 상관관계 룰로 대체됩니다.

### 패턴 1 예시

이는 가장 기본적인 패턴입니다: `count() {operator} {number}`. 아래 룰은 `selection`이 3회 이상 발생하면 매칭됩니다.

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### 패턴 2 예시

`count() by {eventkey} {operator} {number}`: 파이프 앞의 `condition`과 매칭되는 로그 이벤트는 **동일한** `{eventkey}`로 그룹화됩니다. 각 그룹화에 대해 매칭된 이벤트 수가 `{operator}`와 `{number}`로 지정된 조건을 충족하면 조건이 매칭됩니다.

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### 패턴 3 예시

`count({eventkey}) {operator} {number}`: 조건 파이프 앞의 조건과 매칭되는 로그 이벤트에 `{eventkey}`의 **다른** 값이 몇 개 존재하는지 카운트합니다. 그 수가 `{operator}`와 `{number}`로 지정된 조건식을 충족하면 조건이 충족된 것으로 간주됩니다.

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### 패턴 4 예시

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: 조건 파이프 앞의 조건과 매칭되는 로그는 **동일한** `{eventkey_2}`로 그룹화되고, 각 그룹에서 `{eventkey_1}`의 **다른** 값의 수가 카운트됩니다. 각 그룹화에 대해 카운트된 값이 `{operator}`와 `{number}`로 지정된 조건식을 충족하면 조건이 매칭됩니다.

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Count 룰 출력

count 룰의 세부 출력은 고정되어 있으며 `[condition]`에 원본 count 조건을 출력한 다음 `[result]`에 기록된 eventkey를 출력합니다.

아래 예시에서는, 무차별 대입 공격을 받던 `TargetUserName` 사용자 이름 목록과 그에 이어 소스 `IpAddress`가 출력됩니다:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

알림의 타임스탬프는 탐지된 첫 번째 이벤트의 시간이 됩니다.
