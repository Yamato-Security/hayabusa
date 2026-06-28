# 룰 작성 조언

## 룰 작성 조언

1. **가능한 경우 항상 `Channel` 또는 `ProviderName` 이름과 `EventID` 번호를 지정하십시오.** 기본적으로 `./rules/config/target_event_IDs.txt`에 나열된 이벤트 ID만 스캔되므로, 해당 EID가 이 파일에 아직 없다면 새 `EventID` 번호를 이 파일에 추가해야 할 수 있습니다.

2. **필요하지 않을 때 여러 개의 `selection` 또는 `filter` 필드와 과도한 그룹화를 사용하지 마십시오.** 예를 들어:

#### 다음과 같이 하는 대신

```yaml
detection:
    SELECTION_1:
        Channnel: Security
    SELECTION_2:
        EventID: 4625
    SELECTION_3:
        LogonType: 3
    FILTER_1:
        SubStatus: "0xc0000064"   #Non-existent user
    FILTER_2:
        SubStatus: "0xc000006a"   #Wrong password
    condition: SELECTION_1 and SELECTION_2 and SELECTION_3 and not (FILTER_1 or FILTER_2)
```

#### 다음과 같이 하십시오

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        - SubStatus: "0xc0000064"   #Non-existent user
        - SubStatus: "0xc000006a"   #Wrong password
    condition: selection and not filter
```

3. **여러 섹션이 필요한 경우, 첫 번째 섹션은 채널과 이벤트 ID 정보를 담아 `section_basic` 섹션으로 이름 짓고, 다른 선택은 `section_` 및 `filter_` 뒤에 의미 있는 이름을 붙이십시오. 또한 이해하기 어려운 부분은 주석으로 설명해 주십시오.** 예를 들어:

#### 다음과 같이 하는 대신

```yaml
detection:
    Takoyaki:
        Channel: Security
        EventID: 4648
    Naruto:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    Sushi:
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    Godzilla:
        SubjectUserName|endswith: "$"
    Ninja:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$"
        IpAddress: "-"
    Daisuki:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: Takoyaki and Daisuki and not (Naruto and not Godzilla) and not Ninja and not Sushi
```

#### 다음과 같이 하십시오

```yaml
detection:
    selection_basic:
        Channel: Security
        EventID: 4648
    selection_TargetUserIsComputerAccount:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    filter_UsersAndTargetServerAreComputerAccounts:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_SubjectUserIsComputerAccount:
        SubjectUserName|endswith: "$"
    filter_SystemAccounts:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_SuspiciousProcess:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_basic and selection_SuspiciousProcess and not (selection_TargetUserIsComputerAccount
               and not filter_SubjectUserIsComputerAccount) and not filter_SystemAccounts and not filter_UsersAndTargetServerAreComputerAccounts
```

## Sigma 룰을 Hayabusa 형식으로 변환하기

Sigma 룰을 Hayabusa 호환 형식으로 변환하는 백엔드를 [여기](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)에 만들었습니다.
