# jq로 Hayabusa 결과 분석하기

# 작성자

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# 개요

로그에서 중요한 필드를 식별하고, 추출하며, 이를 기반으로 지표를 생성하는 능력은 DFIR 및 위협 헌팅 분석가에게 필수적인 기술입니다.
Hayabusa 결과는 보통 Excel이나 Timeline Explorer 같은 프로그램으로 가져와 타임라인 분석을 하기 위해 `.csv` 파일로 저장됩니다.
그러나 동일한 이벤트가 수백 개 이상 존재할 경우, 이를 수동으로 확인하는 것은 비현실적이거나 불가능해집니다.
이러한 상황에서 분석가들은 보통 유사한 유형의 데이터를 정렬하고 집계하여 이상치를 찾습니다.
이는 롱테일 분석, 스택 랭킹, 빈도 분석 등으로도 알려져 있습니다.
이는 Hayabusa에서 결과를 `.json` 또는 `.jsonl` 파일로 출력한 다음 `jq`로 분석함으로써 수행할 수 있습니다.

예를 들어, 분석가는 조직 내 모든 워크스테이션에 설치된 서비스를 비교할 수 있습니다.
특정 악성코드가 모든 워크스테이션에 설치되었을 가능성도 있지만, 대개는 소수의 시스템에만 존재할 가능성이 더 높습니다.
이 경우 모든 시스템에 설치된 서비스는 양성일 가능성이 더 높은 반면, 드문 서비스는 더 의심스러운 경향이 있으므로 주기적으로 확인해야 합니다.

또 다른 사용 사례는 어떤 것이 얼마나 의심스러운지 판단하는 데 도움을 주는 것입니다.
예를 들어, 분석가는 `4625` 로그온 실패 로그를 분석하여 특정 IP 주소가 몇 번이나 로그온에 실패했는지 판단할 수 있습니다.
로그온 실패가 몇 번에 불과하다면 관리자가 비밀번호를 잘못 입력했을 가능성이 높습니다.
그러나 특정 IP 주소에 의해 짧은 시간 내에 수백 번 이상의 로그온 실패가 발생했다면, 그 IP 주소는 악의적일 가능성이 높습니다.

`jq` 사용법을 익히면 Windows 이벤트 로그뿐만 아니라 모든 JSON 형식 로그를 분석하는 데 능숙해질 수 있습니다.
이제 JSON이 매우 인기 있는 로그 형식이 되었고 대부분의 클라우드 제공업체가 로그에 이를 사용하므로, `jq`로 이를 파싱할 수 있는 능력은 현대 보안 분석가에게 필수적인 기술이 되었습니다.

이 가이드에서는 먼저 `jq`를 한 번도 사용해 본 적이 없는 분들을 위해 사용법을 설명한 다음, 실제 사례와 함께 더 복잡한 사용법을 설명하겠습니다.
`sort`, `uniq`, `grep`, `sed` 등과 같은 다른 유용한 명령어와 `jq`를 결합할 수 있도록 linux, macOS 또는 Windows에서의 linux 사용을 권장합니다.

# jq 설치

[https://stedolan.github.io/jq/](https://stedolan.github.io/jq/)를 참조하여 `jq` 명령어를 설치하십시오.

# JSON 형식 소개

JSON 로그는 중괄호 `{` `}` 안에 담긴 객체들의 목록입니다.
이 객체들 안에는 콜론으로 구분된 키-값 쌍이 들어 있습니다.
키는 반드시 문자열이어야 하지만, 값은 다음 중 하나일 수 있습니다:
  * 문자열 (예: `"string"`)
  * 숫자 (예: `10`)
  * 다른 객체 (예: `{ xxxx }`)
  * 배열 (예: `["string", 10]`)
  * 불리언 (예: `true`, `false`)
  * `null`

객체 안에 원하는 만큼 많은 객체를 중첩할 수 있습니다.

이 예시에서 `Details`는 루트 객체 안에 중첩된 객체입니다:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Hayabusa의 JSON 및 JSONL 형식 소개

이전 버전에서 Hayabusa는 모든 `{ xxx }` 로그 객체를 하나의 거대한 배열에 담는 전통적인 JSON 형식을 사용했습니다.

예시:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

이에는 두 가지 문제가 있습니다.
첫 번째 문제는 모든 것이 해당 배열을 들여다보도록 지시하는 추가적인 `.[]`로 시작해야 하기 때문에 `jq` 쿼리가 더 번거로워진다는 것입니다.
훨씬 더 큰 문제는 이러한 로그를 파싱하려면 먼저 배열의 모든 데이터를 읽어 들여야 한다는 것입니다.
이는 매우 큰 JSON 파일이 있고 메모리가 충분하지 않은 경우 문제가 됩니다.
필요한 CPU와 메모리 사용량을 줄이기 위해, 모든 것을 거대한 배열에 담지 않는 JSONL(JSON Lines) 형식이 더 인기를 얻게 되었습니다.
Hayabusa는 JSON 및 JSONL 형식으로 출력하지만, JSON 형식은 더 이상 배열 안에 저장되지 않습니다.
유일한 차이점은 JSON 형식은 텍스트 편집기나 콘솔에서 읽기 더 쉬운 반면, JSONL 형식은 모든 JSON 객체를 한 줄에 저장한다는 것입니다.
JSONL 형식은 약간 더 빠르고 크기가 더 작으므로 로그를 SIEM 등으로 가져오기만 하고 들여다보지 않을 경우 이상적입니다.
JSON 형식은 일부 수동 확인도 수행할 경우 이상적입니다.

# JSON 결과 파일 생성

현재 2.x 버전의 Hayabusa에서는 `hayabusa json-timeline -d <directory> -o results.json`으로 결과를 JSON으로 저장하거나, JSONL 형식의 경우 `hayabusa json-timeline -d <directory> -J -o results.jsonl`로 저장할 수 있습니다.

Hayabusa는 기본 `standard` 프로파일을 사용하며 `Details` 객체에 분석을 위한 최소한의 데이터만 저장합니다.
.evtx 로그의 모든 원본 필드 정보를 저장하고 싶다면, `--profile all-field-info` 옵션과 함께 `all-field-info` 프로파일을 사용할 수 있습니다.
이렇게 하면 모든 필드 정보가 `AllFieldInfo` 객체에 저장됩니다.
만일을 대비해 `Details`와 `AllFieldInfo` 객체를 모두 저장하고 싶다면 `super-verbose` 프로파일을 사용할 수 있습니다.

## AllFieldInfo 대신 Details를 사용하는 이점

`AllFieldInfo` 대신 `Details`를 사용하는 첫 번째 이점은 중요한 필드만 저장되고, 파일 공간을 절약하기 위해 필드 이름이 단축되었다는 점입니다.
단점은 실제로 관심 있었던 데이터가 누락될 가능성이 있다는 것입니다.
두 번째 이점은 Hayabusa가 필드 이름을 정규화하여 필드를 보다 일관된 방식으로 저장한다는 것입니다.
예를 들어, 원본 Windows 로그에서 사용자 이름은 보통 `SubjectUserName` 또는 `TargetUserName` 필드에 있습니다.
그러나 때로는 사용자 이름이 `AccountName` 필드에 있거나, 때로는 대상 사용자가 실제로 `SubjectUserName` 필드에 있는 경우 등이 있습니다.
안타깝게도 Windows 이벤트 로그에는 일관성 없는 필드 이름이 많습니다.
Hayabusa는 이러한 필드를 정규화하려고 시도하므로, 분석가는 Windows의 이벤트 ID 간의 무수히 많은 특이점과 불일치를 이해할 필요 없이 공통 이름만 파싱하면 됩니다.

다음은 사용자 필드의 예시입니다.
Hayabusa는 `SubjectUserName`, `TargetUserName`, `AccountName` 등을 다음과 같은 방식으로 정규화합니다:
  * `SrcUser` (소스 사용자): 어떤 동작이 사용자**로부터** 발생할 때. (보통 원격 사용자.)
  * `TgtUser` (대상 사용자): 어떤 동작이 사용자**에게** 발생할 때. (예를 들어, 사용자**에게** 로그온.)
  * `User`: 현재 로그인한 사용자에 의해 동작이 발생할 때. (동작에 특정한 방향이 없음.)

또 다른 예시는 프로세스입니다.
원본 Windows 이벤트 로그에서 프로세스 필드는 `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName` 등 여러 명명 규칙으로 참조됩니다.
필드 정규화가 없다면 분석가는 먼저 모든 다양한 필드 이름에 대해 잘 알고 있어야 하고, 그런 다음 이러한 필드 이름을 가진 모든 로그를 추출한 후 함께 결합해야 합니다.

분석가는 Hayabusa가 `Details` 객체에서 제공하는 정규화된 단일 `Proc` 필드를 사용하기만 하면 많은 시간과 수고를 절약할 수 있습니다.

# jq 레슨/레시피

이제 작업에 도움이 될 수 있는 실용적인 예시의 여러 레슨/레시피를 나열하겠습니다.

## 1. jq와 컬러 Less로 수동 확인하기

이것은 로그에 어떤 필드가 있는지 이해하기 위해 가장 먼저 해야 할 일 중 하나입니다.
단순히 `less results.json`을 할 수도 있지만, 더 나은 방법은 다음과 같습니다:
`cat results.json | jq -C | less -R`

`jq`로 전달하면, 처음부터 깔끔하게 정리되어 있지 않았던 모든 필드를 깔끔하게 포맷해 줍니다.
`jq`의 `-C`(컬러) 옵션과 `less`의 `-R`(원시 출력) 옵션을 사용하면 컬러로 위아래로 스크롤할 수 있습니다.

## 2. 지표

Hayabusa에는 이미 이벤트 ID를 기반으로 이벤트의 수와 비율을 출력하는 기능이 있지만, 이를 `jq`로 수행하는 방법을 아는 것도 좋습니다.
이렇게 하면 지표를 생성하려는 데이터를 사용자 정의할 수 있습니다.

먼저 다음 명령어로 이벤트 ID 목록을 추출해 봅시다:

`cat results.json | jq '.EventID'`

이렇게 하면 각 로그에서 이벤트 ID 번호만 추출됩니다.
`jq` 뒤에 작은따옴표 안에 `.`과 추출하려는 필드 이름을 입력하기만 하면 됩니다.
다음과 같은 긴 목록이 표시될 것입니다:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

이제 결과를 `sort`와 `uniq -c` 명령어로 파이프하여 이벤트 ID가 몇 번이나 발생했는지 집계합니다:

`cat results.json | jq '.EventID' | sort | uniq -c`

`uniq`의 `-c` 옵션은 고유한 이벤트 ID가 몇 번이나 발생했는지 집계합니다.

다음과 같은 결과가 표시될 것입니다:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 왼쪽은 횟수이고, 오른쪽은 이벤트 ID입니다.
 보시다시피 정렬되어 있지 않아서 어떤 이벤트 ID가 가장 많이 발생했는지 알기 어렵습니다.

 끝에 `sort -n`을 추가하여 이를 해결할 수 있습니다:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

`-n` 옵션은 `sort`에게 숫자로 정렬하라고 지시합니다.

다음과 같은 결과가 표시될 것입니다:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

`4688`(프로세스 생성) 이벤트가 가장 많이 기록된 것을 볼 수 있습니다.
두 번째로 많이 기록된 이벤트는 `4625`(로그온 실패)였습니다.

가장 많이 기록된 이벤트를 맨 위에 출력하고 싶다면, `sort -n -r` 또는 `sort -nr`로 정렬을 역순으로 할 수 있습니다.
또한 결과를 `head -n 10`으로 파이프하여 가장 많이 기록된 상위 10개 이벤트만 출력할 수도 있습니다.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

이렇게 하면 다음과 같은 결과가 나옵니다:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

EID(이벤트 ID)는 고유하지 않으므로 동일한 이벤트 ID를 가진 완전히 다른 이벤트가 있을 수 있다는 점을 고려하는 것이 중요합니다.
따라서 `Channel`도 함께 확인하는 것이 중요합니다.

다음과 같이 이 필드 정보를 추가할 수 있습니다:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

`jq`에 `-j`(join) 옵션을 추가하여 모든 필드를 쉼표로 구분하고 `\n` 줄바꿈 문자로 끝나도록 함께 결합합니다.

이렇게 하면 다음과 같은 결과가 나옵니다:
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 참고: `Security`는 `Sec`로, `System`은 `Sys`로, `PowerShell`은 `PwSh`로 축약됩니다.

다음과 같이 규칙 제목을 추가할 수 있습니다:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

이렇게 하면 다음과 같은 결과가 나옵니다:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

이제 로그에서 원하는 데이터를 자유롭게 추출하고 발생 횟수를 집계할 수 있습니다.

## 3. 특정 데이터에 대한 필터링

특정 이벤트 ID, 사용자, 프로세스, LID(로그온 ID) 등에 대해 필터링하고 싶은 경우가 많을 것입니다.
이는 `jq` 쿼리 내부의 `select`로 수행할 수 있습니다.

예를 들어, 모든 `4624` 로그온 성공 이벤트를 추출해 봅시다:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

이렇게 하면 EID `4624`에 대한 모든 JSON 객체가 반환됩니다:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

여러 조건에 대해 필터링하고 싶다면 `and`, `or`, `not` 같은 키워드를 사용할 수 있습니다.

예를 들어, 유형이 `3`(네트워크 로그온)인 `4624` 이벤트를 검색해 봅시다.

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

이렇게 하면 `EventID`가 `4624`이고 중첩된 `"Details": { "Type" }` 필드가 `3`인 모든 객체가 반환됩니다.

그런데 문제가 있습니다.
`jq: error (at <stdin>:10636): Cannot index string with string "Type"`라는 오류가 나타날 수 있습니다.
`Cannot index string with string` 오류가 나타날 때마다, 이는 존재하지 않거나 유형이 잘못된 필드를 출력하도록 `jq`에 지시하고 있다는 의미입니다.
필드 끝에 `?`를 추가하여 이러한 오류를 제거할 수 있습니다.
이는 `jq`에게 오류를 무시하라고 지시합니다.

예시: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

이제 특정 기준으로 필터링한 후, `jq` 쿼리 내부에서 `|`를 사용하여 관심 있는 특정 필드를 선택할 수 있습니다.

예를 들어, 대상 사용자 이름 `TgtUser`와 소스 IP 주소 `SrcIP`를 추출해 봅시다:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

다시 한 번, 출력할 여러 필드를 선택하기 위해 `jq`에 `-j`(join) 옵션을 추가합니다.
그런 다음 이전 예시처럼 `sort`, `uniq -c` 등을 실행하여 특정 IP 주소가 유형 3 네트워크 로그온을 통해 사용자에 몇 번이나 로그인했는지 알아낼 수 있습니다.

## 4. 출력을 CSV 형식으로 저장하기

안타깝게도 Windows 이벤트 로그의 필드는 이벤트 유형에 따라 완전히 다르므로, 수백 개의 열 없이 필드별로 쉼표로 구분된 타임라인을 만드는 것은 쉽지 않습니다.
그러나 단일 유형의 이벤트에 대해서는 필드로 구분된 타임라인을 만드는 것이 가능합니다.
두 가지 일반적인 예시는 측면 이동 및 비밀번호 추측/스프레이를 확인하기 위한 보안 `4624`(로그온 성공)와 `4625`(로그온 실패)입니다.

이 예시에서는 보안 4624 로그만 추출하여 타임스탬프, 컴퓨터 이름 및 모든 `Details` 정보를 출력합니다.
`| @csv`를 사용하여 CSV 파일로 저장하지만, 데이터를 배열로 전달해야 합니다.
이는 이전에 했던 것처럼 출력하려는 필드를 선택하고 `[ ]` 대괄호로 감싸 배열로 변환함으로써 수행할 수 있습니다.

예시: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

참고:
  * `Details` 객체의 모든 필드를 선택하기 위해 `[]`를 추가합니다.
  * `Details`가 배열이 아니라 문자열인 경우가 있어 `Cannot iterate over string` 오류가 발생하므로 `?`를 추가해야 합니다.
  * 큰따옴표를 백슬래시로 이스케이프하지 않기 위해 `jq`에 `-r`(원시 출력) 옵션을 추가합니다.

결과:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

단지 누가 로그온에 성공했는지 확인하는 경우라면, 마지막 `LID`(로그온 ID) 필드는 필요하지 않을 수 있습니다.
`del` 함수로 불필요한 열을 삭제할 수 있습니다.

예시: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

배열은 `0`부터 세므로 7번째 필드를 제거하려면 `6`을 사용합니다.

이제 `> 4624-logs.csv`를 추가하여 CSV 파일을 저장한 다음, 추가 분석을 위해 Excel이나 Timeline Explorer로 가져올 수 있습니다.

필터링을 하려면 헤더를 추가해야 한다는 점에 유의하십시오.
`jq` 쿼리 내부에서 헤더를 추가하는 것도 가능하지만, 보통은 파일을 저장한 후 맨 위 행을 수동으로 추가하는 것이 가장 쉽습니다.

## 5. 알림이 가장 많은 날짜 찾기

Hayabusa는 기본적으로 심각도 수준에 따라 알림이 가장 많았던 날짜를 알려줍니다.
그러나 두 번째, 세 번째 등 알림이 많은 날짜도 찾고 싶을 수 있습니다.
필요에 따라 연, 월 또는 일로 그룹화하기 위해 타임스탬프를 문자열 슬라이싱하여 이를 수행할 수 있습니다.

예시: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]`은 `jq`에게 `Timestamp`에서 처음 10바이트만 추출하라고 지시합니다.

이렇게 하면 이벤트가 가장 많은 날짜가 표시됩니다:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

이벤트가 가장 많은 월을 알고 싶다면, 처음 7바이트를 추출하도록 `.[:10]`을 `.[:7]`로 변경하기만 하면 됩니다.

`high` 알림이 가장 많은 날짜를 나열하고 싶다면 다음과 같이 할 수 있습니다:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

필요에 따라 컴퓨터 이름, 이벤트 ID 등에 따라 `select` 함수에 필터 조건을 계속 추가할 수 있습니다.

## 6. PowerShell 로그 재구성

PowerShell 로그의 안타까운 점은 로그가 종종 여러 로그로 나뉘어 읽기 어렵다는 것입니다.
공격자가 실행한 명령어만 추출하면 로그를 훨씬 더 읽기 쉽게 만들 수 있습니다.

예를 들어, EID `4104` ScriptBlock 로그가 있다면, 해당 필드만 추출하여 읽기 쉬운 타임라인을 만들 수 있습니다.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

이렇게 하면 다음과 같은 타임라인이 생성됩니다:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. 의심스러운 네트워크 연결 찾기

먼저 다음 명령어로 모든 대상 IP 주소 목록을 얻을 수 있습니다:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

위협 인텔리전스가 있다면, IP 주소 중 악의적인 것으로 알려진 것이 있는지 확인할 수 있습니다.

다음 명령어로 특정 대상 IP 주소에 연결된 횟수를 집계할 수 있습니다:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

`TgtIP`를 `SrcIP`로 변경하면 소스 IP 주소를 기반으로 악의적인 IP 주소에 대해 동일한 위협 인텔리전스 확인을 수행할 수 있습니다.

환경에서 악의적인 IP 주소 `93.184.220.29`에 연결되었다는 것을 발견했다고 가정해 봅시다.
다음 쿼리로 해당 이벤트에 대한 세부 정보를 얻을 수 있습니다:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

이렇게 하면 다음과 같은 JSON 결과가 나옵니다:
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

연결된 도메인을 나열하고 싶다면 다음 명령어를 사용할 수 있습니다:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> 참고: NETBIOS 호스트 이름을 제거하기 위해 `.`에 대한 grep 필터를 추가했습니다.

## 8. 실행 가능한 바이너리 해시 추출

Sysmon EID `1` 프로세스 생성 로그에서 sysmon은 바이너리의 해시를 계산하도록 구성할 수 있습니다.
보안 분석가는 위협 인텔리전스를 통해 이러한 해시를 알려진 악성 해시와 비교할 수 있습니다.
다음 명령어로 `Hashes` 필드를 추출할 수 있습니다:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

이렇게 하면 다음과 같은 해시 목록이 나옵니다:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon은 보통 `MD5`, `SHA1`, `IMPHASH` 같은 여러 해시를 계산합니다.
`jq`에서 정규 표현식으로 이러한 해시를 추출하거나, 더 나은 성능을 위해 문자열 슬라이싱을 사용할 수 있습니다.

예를 들어, 다음 명령어로 MD5 해시를 추출하고 중복을 제거할 수 있습니다:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. PowerShell 로그 추출

PowerShell Scriptblock 로그(EID: 4104)는 보통 여러 로그로 나뉘며, CSV 형식으로 출력할 때 Hayabusa는 출력을 더 간결하게 만들기 위해 탭과 캐리지 리턴 문자를 삭제합니다.
그러나 powershell 로그는 원본 탭 및 캐리지 리턴 문자 포맷을 유지하고 로그를 함께 결합하여 분석하는 것이 가장 쉽습니다.
다음은 `COMPUTER-A`에서 PowerShell EID 4104 로그를 추출하여 VSCode 등에서 열고 분석하기 위해 `.ps1` 파일로 저장하는 예시입니다.
ScriptBlock 필드를 추출한 후, `awk`를 사용하여 `\r\n`과 `\n`을 캐리지 리턴 문자로, `\t`를 탭으로 대체합니다.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

분석가가 악성 PowerShell 명령어에 대해 로그를 분석한 후에는, 보통 해당 명령어가 언제 실행되었는지 조회해야 합니다.
다음은 명령어가 실행된 시간을 조회하기 위해 타임스탬프와 PowerShell 로그를 CSV 파일로 출력하는 예시입니다:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

참고: 사용된 문자열 구분 기호는 `¦`인데, 작은따옴표와 큰따옴표가 PowerShell 로그에서 자주 발견되어 CSV 출력을 손상시키기 때문입니다.
CSV 파일을 가져올 때, 애플리케이션에 문자열 구분 기호 `¦`를 지정해야 합니다.
