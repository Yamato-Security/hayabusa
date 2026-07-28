# 타임라인 출력

## 출력 프로파일

Hayabusa에는 `config/profiles.yaml`에서 사용할 수 있는 사전 정의된 5개의 출력 프로파일이 있습니다:

1. `minimal`
2. `standard` (기본값)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

이 파일을 편집하여 자신만의 프로파일을 쉽게 사용자 정의하거나 추가할 수 있습니다.
또한 `set-default-profile --profile <profile>`로 기본 프로파일을 쉽게 변경할 수 있습니다.
사용 가능한 프로파일과 그 필드 정보를 표시하려면 `list-profiles` 명령을 사용하세요.

### 1. `minimal` 프로파일 출력

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard` 프로파일 출력

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose` 프로파일 출력

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info` 프로파일 출력

최소한의 `details` 정보를 출력하는 대신, `EventData`와 `UserData` 섹션의 모든 필드 정보가 원래 필드 이름과 함께 출력됩니다.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose` 프로파일 출력

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose` 프로파일 출력

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal` 프로파일 출력

[Timesketch](https://timesketch.org/)로 가져오기에 호환되는 형식으로 출력합니다.

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose` 프로파일 출력

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 프로파일 비교

다음 벤치마크는 3GB의 evtx 데이터와 3891개의 규칙을 활성화한 상태로 2018 Lenovo P51(Xeon 4 Core CPU / 64GB RAM)에서 수행되었습니다. (2023/06/01)

| 프로파일 | 처리 시간 | 출력 파일 크기 | 파일 크기 증가 |
| :---: | :---: | :---: | :---: |
| minimal | 8분 50초 | 770 MB | -30% |
| standard (기본값) | 9분 00초 | 1.1 GB | 없음 |
| verbose | 9분 10초 | 1.3 GB | +20% |
| all-field-info | 9분 3초 | 1.2 GB | +10% |
| all-field-info-verbose | 9분 10초 | 1.3 GB | +20% |
| super-verbose | 9분 12초 | 1.5 GB | +35% |

### 프로파일 필드 별칭

다음 정보는 내장 출력 프로파일로 출력할 수 있습니다:

| 별칭 이름 | Hayabusa 출력 정보|
| :--- | :--- |
|%AllFieldInfo% | 모든 필드 정보. |
|%Channel% | 로그의 이름. `<Event><System><Channel>` 필드. |
|%Computer% | `<Event><System><Computer>` 필드. |
|%Details% | YML 탐지 규칙의 `details` 필드이지만, hayabusa 규칙만 이 필드를 가집니다. 이 필드는 경고나 이벤트에 대한 추가 정보를 제공하며 이벤트 로그의 필드에서 유용한 데이터를 추출할 수 있습니다. 예를 들어 사용자 이름, 명령줄 정보, 프로세스 정보 등이 있습니다. 플레이스홀더가 존재하지 않는 필드를 가리키거나 잘못된 별칭 매핑이 있는 경우 `n/a`(not available)로 출력됩니다. `details` 필드가 지정되지 않은 경우(즉, sigma 규칙) `./rules/config/default_details.txt`에 정의된 필드를 추출하기 위한 기본 `details` 메시지가 출력됩니다. `default_details.txt`에 출력하려는 `Provider Name`, `EventID` 및 `details` 메시지를 추가하여 기본 `details` 메시지를 더 추가할 수 있습니다. 규칙이나 `default_details.txt`에 `details` 필드가 정의되지 않은 경우, 모든 필드가 `details` 열에 출력됩니다. |
|%ExtraFieldInfo% | %Details%에 출력되지 않은 필드 정보를 인쇄합니다. |
|%EventID% | `<Event><System><EventID>` 필드. |
|%EvtxFile% | 경고나 이벤트를 발생시킨 evtx 파일 이름. |
|%Level% | YML 탐지 규칙의 `level` 필드. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [전술](https://attack.mitre.org/tactics/enterprise/) (예: Initial Access, Lateral Movement 등). |
|%MitreTags% | MITRE ATT&CK 그룹 ID, 기술 ID 및 소프트웨어 ID. |
|%OtherTags% | YML 탐지 규칙의 `tags` 필드에서 `MitreTactics`나 `MitreTags`에 포함되지 않은 모든 키워드. |
|%Provider% | `<Event><System><Provider>` 필드의 `Name` 속성. |
|%RecordID% | `<Event><System><EventRecordID>` 필드의 이벤트 레코드 ID. |
|%RuleAuthor% | YML 탐지 규칙의 `author` 필드. |
|%RuleCreationDate% | YML 탐지 규칙의 `date` 필드. |
|%RuleFile% | 경고나 이벤트를 생성한 탐지 규칙의 파일 이름. |
|%RuleID% | YML 탐지 규칙의 `id` 필드. |
|%RuleModifiedDate% | YML 탐지 규칙의 `modified` 필드. |
|%RuleTitle% | YML 탐지 규칙의 `title` 필드. |
|%Status% | YML 탐지 규칙의 `status` 필드. |
|%Timestamp% | 기본값은 `YYYY-MM-DD HH:mm:ss.sss +hh:mm` 형식입니다. 이벤트 로그의 `<Event><System><TimeCreated SystemTime>` 필드. 기본 시간대는 로컬 시간대이지만 `--utc` 옵션으로 시간대를 UTC로 변경할 수 있습니다. |

#### 추가 프로파일 필드 별칭

필요한 경우 출력 프로파일에 이 추가 별칭을 추가할 수도 있습니다:

| 별칭 이름 | Hayabusa 출력 정보|
| :--- | :--- |
|%RenderedMessage% | WEC 전달 로그의 `<Event><RenderingInfo><Message>` 필드. |

참고: 이것은 어떤 내장 프로파일에도 포함되어 **있지 않으므로** `config/default_profile.yaml` 파일을 수동으로 편집하여 다음 줄을 추가해야 합니다:

```
Message: "%RenderedMessage%"
```

다른 필드를 출력하려면 [이벤트 키 별칭](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases)을 정의할 수도 있습니다.
