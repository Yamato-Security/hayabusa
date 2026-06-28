# DFIR 타임라인 명령어

## 스캔 마법사 (Scan Wizard)

`csv-timeline` 및 `json-timeline` 명령어는 이제 기본적으로 스캔 마법사가 활성화되어 있습니다.
이는 사용자가 자신의 필요와 선호에 따라 활성화할 탐지 룰을 쉽게 선택할 수 있도록 돕기 위한 것입니다.
로드할 탐지 룰 세트는 Sigma 프로젝트의 공식 목록을 기반으로 합니다.
자세한 내용은 [이 블로그 게시물](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81)에서 설명합니다.
`-w, --no-wizard` 옵션을 추가하면 마법사를 쉽게 끄고 Hayabusa를 기존 방식대로 사용할 수 있습니다.

### Core 룰

`core` 룰 세트는 상태가 `test` 또는 `stable`이고 레벨이 `high` 또는 `critical`인 룰을 활성화합니다.
이들은 높은 신뢰도와 관련성을 가진 고품질 룰로, 오탐(false positive)을 많이 발생시키지 않습니다.
룰 상태가 `test` 또는 `stable`이라는 것은 6개월 이상 오탐이 보고되지 않았다는 의미입니다.
룰은 공격자 기법, 일반적인 의심스러운 활동 또는 악의적인 행위에 매칭됩니다.
이는 `--exclude-status deprecated,unsupported,experimental --min-level high` 옵션을 사용하는 것과 동일합니다.

### Core+ 룰

`core+` 룰 세트는 상태가 `test` 또는 `stable`이고 레벨이 `medium` 이상인 룰을 활성화합니다.
`medium` 룰은 특정 애플리케이션, 합법적인 사용자 행위 또는 조직의 스크립트에 매칭될 수 있기 때문에 대부분 추가적인 튜닝이 필요합니다.
이는 `--exclude-status deprecated,unsupported,experimental --min-level medium` 옵션을 사용하는 것과 동일합니다.

### Core++ 룰

`core++` 룰 세트는 상태가 `experimental`, `test` 또는 `stable`이고 레벨이 `medium` 이상인 룰을 활성화합니다.
이들은 최첨단(bleeding edge) 룰입니다.
이들은 SigmaHQ 프로젝트에서 제공하는 기준 evtx 파일에 대해 검증되었으며 여러 탐지 엔지니어에 의해 검토되었습니다.
그 외에는 처음에는 사실상 거의 테스트되지 않은 상태입니다.
오탐을 더 높은 임계치로 관리하는 비용을 감수하더라도 위협을 가능한 한 조기에 탐지하고 싶다면 이들을 사용하십시오.
이는 `--exclude-status deprecated,unsupported --min-level medium` 옵션을 사용하는 것과 동일합니다.

### Emerging Threats (ET) 추가 룰

`Emerging Threats (ET)` 룰 세트는 `detection.emerging_threats` 태그를 가진 룰을 활성화합니다.
이 룰들은 특정 위협을 대상으로 하며, 아직 많은 정보가 알려지지 않은 현재 진행 중인 위협에 특히 유용합니다.
이 룰들은 오탐이 많지 않아야 하지만 시간이 지남에 따라 관련성이 감소합니다.
이 룰들이 활성화되지 않은 경우, `--exclude-tag detection.emerging_threats` 옵션을 사용하는 것과 동일합니다.
마법사 없이 Hayabusa를 기존 방식으로 실행하면 이 룰들은 기본적으로 포함됩니다.

### Threat Hunting (TH) 추가 룰

`Threat Hunting (TH)` 룰 세트는 `detection.threat_hunting` 태그를 가진 룰을 활성화합니다.
이 룰들은 알려지지 않은 악의적인 활동을 탐지할 수 있지만, 일반적으로 오탐이 더 많습니다.
이 룰들이 활성화되지 않은 경우, `--exclude-tag detection.threat_hunting` 옵션을 사용하는 것과 동일합니다.
마법사 없이 Hayabusa를 기존 방식으로 실행하면 이 룰들은 기본적으로 포함됩니다.

## Channel 기반 이벤트 로그 및 룰 필터링

Hayabusa v2.16.0부터, `.evtx` 파일과 `.yml` 룰을 로드할 때 Channel 기반 필터를 활성화합니다.
그 목적은 필요한 것만 로드하여 스캔을 가능한 한 효율적으로 만드는 것입니다.
단일 이벤트 로그에 여러 프로바이더가 존재할 수는 있지만, 단일 evtx 파일 안에 여러 채널이 있는 경우는 흔하지 않습니다.
(우리가 이를 본 유일한 경우는 누군가가 [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) 프로젝트를 위해 서로 다른 두 evtx 파일을 인위적으로 병합했을 때였습니다.)
우리는 스캔하도록 지정된 모든 `.evtx` 파일의 첫 번째 레코드에서 `Channel` 필드를 먼저 확인함으로써 이를 활용할 수 있습니다.
또한 어떤 `.yml` 룰이 룰의 `Channel` 필드에 지정된 어떤 채널을 사용하는지도 확인합니다.
이 두 목록을 사용하여, `.evtx` 파일 안에 실제로 존재하는 채널을 사용하는 룰만 로드합니다.

예를 들어, 사용자가 `Security.evtx`를 스캔하려는 경우, `Channel: Security`를 지정한 룰만 사용됩니다.
다른 탐지 룰, 예를 들어 `Application` 로그의 이벤트만 찾는 룰 등을 로드하는 것은 의미가 없습니다.
채널 필드(예: `Channel: Security`)는 원본 Sigma 룰 안에 **명시적으로** 정의되어 있지 않다는 점에 유의하십시오.
Sigma 룰에서 채널 및 이벤트 ID 필드는 `logsource` 아래의 `service`와 `category` 필드로 **암시적으로** 정의됩니다. (예: `service: security`)
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 저장소에서 Sigma 룰을 큐레이션할 때, 우리는 `logsource` 필드를 비추상화(de-abstract)하여 채널 및 이벤트 ID 필드를 명시적으로 정의합니다.
우리가 이를 어떻게, 왜 하는지에 대해서는 [여기](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)에서 심도 있게 설명합니다.

현재 `Channel`이 정의되어 있지 않아 모든 `.evtx` 파일을 스캔하도록 의도된 탐지 룰은 다음 두 가지뿐입니다:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

이 두 룰을 사용하여 로드된 `.evtx` 파일에 대해 모든 룰을 스캔하려면, `csv-timeline` 및 `json-timeline` 명령어에서 `-A, --enable-all-rules` 옵션을 추가해야 합니다.
우리의 벤치마크에서, 룰 필터링은 어떤 파일을 스캔하느냐에 따라 일반적으로 20%에서 10배의 속도 향상을 제공하며 물론 메모리도 덜 사용합니다.

채널 필터링은 `.evtx` 파일을 로드할 때도 사용됩니다.
예를 들어, `Security` 채널의 이벤트를 찾는 룰을 지정하면, `Security` 로그가 아닌 `.evtx` 파일을 로드하는 것은 의미가 없습니다.
우리의 벤치마크에서, 이는 일반 스캔에서 약 10%, 단일 룰로 스캔할 때 최대 60% 이상의 성능 향상을 제공합니다.
단일 `.evtx` 파일 안에 여러 채널이 사용되고 있다고 확신하는 경우, 예를 들어 누군가가 여러 `.evtx` 파일을 함께 병합하는 도구를 사용한 경우, `csv-timeline` 및 `json-timeline` 명령어에서 `-a, --scan-all-evtx-files` 옵션으로 이 필터링을 비활성화할 수 있습니다.

> 참고: 채널 필터링은 `.evtx` 파일에서만 작동하며, `-J, --json-input`으로 JSON 파일에서 이벤트 로그를 로드하면서 `-A` 또는 `-a`를 함께 지정하려고 하면 오류가 발생합니다.

## `csv-timeline` 명령어

`csv-timeline` 명령어는 CSV 형식으로 이벤트의 포렌식 타임라인을 생성합니다.

```
Usage: csv-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -M, --multiline                    Output event field information in multiple rows
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in CSV format (ex: results.csv)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)
  -S, --tab-separator                Separate event field information by tabs

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `csv-timeline` 명령어 예시

* 기본 `standard` 프로필로 하나의 Windows 이벤트 로그 파일에 대해 hayabusa 실행:

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* verbose 프로필로 여러 Windows 이벤트 로그 파일이 있는 sample-evtx 디렉터리에 대해 hayabusa 실행:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* LibreOffice, Timeline Explorer, Elastic Stack 등으로 추가 분석하기 위해 단일 CSV 파일로 내보내고 모든 필드 정보 포함(경고: `super-verbose` 프로필을 사용하면 파일 출력 크기가 훨씬 커집니다!):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* EID(Event ID) 필터 활성화:

> 참고: EID 필터를 활성화하면 우리의 테스트에서 분석 속도가 약 10-15% 빨라지지만 알림을 놓칠 가능성이 있습니다.

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* hayabusa 룰만 실행(기본값은 `-r .\rules`의 모든 룰을 실행):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Windows에서 기본적으로 활성화된 로그에 대해 hayabusa 룰만 실행:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* sysmon 로그에 대해 hayabusa 룰만 실행:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* sigma 룰만 실행:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* deprecated 룰(`status`가 `deprecated`로 표시된 룰)과 noisy 룰(룰 ID가 `.\rules\config\noisy_rules.txt`에 나열된 룰) 활성화:

> 참고: 최근에 deprecated 룰은 sigma 저장소의 별도 디렉터리에 위치하므로 더 이상 Hayabusa에 기본적으로 포함되지 않습니다.
> 따라서 deprecated 룰을 활성화할 필요가 없을 것입니다.

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* 로그온을 분석하는 룰만 실행하고 UTC 시간대로 출력:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* 실행 중인 Windows 머신에서 실행(관리자 권한 필요)하고 알림(잠재적으로 악의적인 행위)만 탐지:

```
hayabusa.exe csv-timeline -l -m low
```

* verbose 정보 출력(처리하는 데 오래 걸리는 파일, 파싱 오류 등을 파악하는 데 유용):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* verbose 출력 예시:

룰 로딩:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

스캔 중 오류:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* [Timesketch](https://timesketch.org/)로 가져오기에 호환되는 CSV 형식으로 출력:

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Quiet error 모드:
기본적으로 hayabusa는 오류 메시지를 오류 로그 파일에 저장합니다.
오류 메시지를 저장하고 싶지 않다면 `-Q`를 추가하십시오.

### 고급 - GeoIP 로그 보강(Enrichment)

무료 GeoLite2 위치 정보 데이터를 사용하여 SrcIP(출발지 IP) 필드와 TgtIP(목적지 IP) 필드에 GeoIP(ASN 조직, 도시 및 국가) 정보를 추가할 수 있습니다.

단계:

1. 먼저 [여기](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)에서 MaxMind 계정에 가입하십시오.
2. [다운로드 페이지](https://www.maxmind.com/en/accounts/current/geoip/downloads)에서 세 개의 `.mmdb` 파일을 다운로드하여 디렉터리에 저장하십시오. 파일 이름은 `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`여야 합니다.
3. `csv-timeline` 또는 `json-timeline` 명령어를 실행할 때, MaxMind 데이터베이스가 있는 디렉터리를 뒤에 붙여 `-G` 옵션을 추가하십시오.

* `csv-timeline`을 사용하면 다음 6개의 열이 추가로 출력됩니다: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* `json-timeline`을 사용하면 동일한 `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` 필드가 `Details` 객체에 추가되지만, 정보가 포함된 경우에만 추가됩니다.

* `SrcIP` 또는 `TgtIP`가 localhost(`127.0.0.1`, `::1` 등)인 경우, `SrcASN` 또는 `TgtASN`은 `Local`로 출력됩니다.
* `SrcIP` 또는 `TgtIP`가 사설 IP 주소(`10.0.0.0/8`, `fe80::/10` 등)인 경우, `SrcASN` 또는 `TgtASN`은 `Private`로 출력됩니다.

#### GeoIP 설정 파일

GeoIP 데이터베이스에서 조회되는 출발지 및 목적지 IP 주소를 포함하는 필드 이름은 `rules/config/geoip_field_mapping.yaml`에 정의되어 있습니다.
필요한 경우 이 목록에 추가할 수 있습니다.
이 파일에는 어떤 이벤트에서 IP 주소 정보를 추출할지 결정하는 필터 섹션도 있습니다.

#### GeoIP 데이터베이스의 자동 업데이트

MaxMind GeoIP 데이터베이스는 2주마다 업데이트됩니다.
이러한 데이터베이스를 자동으로 업데이트하기 위해 [여기](https://github.com/maxmind/geoipupdate)에서 MaxMind `geoipupdate` 도구를 설치할 수 있습니다.

macOS에서의 단계:

1. `brew install geoipupdate`
2. `/usr/local/etc/GeoIP.conf` 또는 `/opt/homebrew/etc/GeoIP.conf` 편집: MaxMind 웹사이트에 로그인한 후 생성한 `AccountID`와 `LicenseKey`를 입력하십시오. `EditionIDs` 줄이 `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`로 되어 있는지 확인하십시오.
3. `geoipupdate` 실행.
4. GeoIP 정보를 추가하려면 `-G /usr/local/var/GeoIP` 또는 `-G /opt/homebrew/var/GeoIP`를 추가하십시오.

Windows에서의 단계:

1. [Releases](https://github.com/maxmind/geoipupdate/releases) 페이지에서 최신 Windows 바이너리(예: `geoipupdate_4.10.0_windows_amd64.zip`)를 다운로드하십시오.
2. `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf` 편집: MaxMind 웹사이트에 로그인한 후 생성한 `AccountID`와 `LicenseKey`를 입력하십시오. `EditionIDs` 줄이 `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`로 되어 있는지 확인하십시오.
3. `geoipupdate` 실행 파일을 실행하십시오.

### `csv-timeline` 명령어 설정 파일

`./rules/config/channel_abbreviations.txt`: 채널 이름과 그 약어의 매핑.

`./rules/config/default_details.txt`: 룰에 `details:` 줄이 지정되지 않은 경우 출력할 기본 필드 정보(`%Details%` 필드)에 대한 설정 파일입니다.
이는 프로바이더 이름과 이벤트 ID를 기반으로 합니다.

`./rules/config/eventkey_alias.txt`: 이 파일은 필드의 짧은 이름 별칭과 원래의 더 긴 필드 이름의 매핑을 가지고 있습니다.

예시:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

여기에 필드가 정의되어 있지 않으면, Hayabusa는 자동으로 `Event.EventData` 아래에서 해당 필드를 확인합니다.

`./rules/config/exclude_rules.txt`: 이 파일은 사용에서 제외될 룰 ID 목록을 가지고 있습니다.
일반적으로 이는 한 룰이 다른 룰을 대체했거나 애초에 룰을 사용할 수 없기 때문입니다.
방화벽 및 IDS와 마찬가지로, 모든 시그니처 기반 도구는 사용자 환경에 맞추기 위해 약간의 튜닝이 필요하므로 특정 룰을 영구적으로 또는 일시적으로 제외해야 할 수 있습니다.
필요하지 않거나 사용할 수 없는 룰을 무시하기 위해 `./rules/config/exclude_rules.txt`에 룰 ID(예: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`)를 추가할 수 있습니다.

`./rules/config/noisy_rules.txt`: 이 파일은 기본적으로 비활성화되어 있지만 `-n, --enable-noisy-rules` 옵션으로 noisy 룰을 활성화하여 사용할 수 있는 룰 ID 목록입니다.
이 룰들은 일반적으로 본질적으로 또는 오탐으로 인해 noisy합니다.

`./rules/config/target_event_IDs.txt`: EID 필터가 활성화된 경우 이 파일에 지정된 이벤트 ID만 스캔됩니다.
기본적으로 Hayabusa는 모든 이벤트를 스캔하지만, 성능을 개선하고 싶다면 `-E, --EID-filter` 옵션을 사용하십시오.
이는 일반적으로 10~25%의 속도 향상을 가져옵니다.

## `json-timeline` 명령어

`json-timeline` 명령어는 JSON 또는 JSONL 형식으로 이벤트의 포렌식 타임라인을 생성합니다.
JSONL로 출력하면 JSON보다 더 빠르고 파일 크기가 작으므로 결과를 Elastic Stack과 같은 다른 도구로 가져오기만 할 경우에 좋습니다.
JSON은 텍스트 편집기로 결과를 수동으로 분석할 경우에 더 좋습니다.
CSV 출력은 더 작은 타임라인(일반적으로 2GB 미만)을 LibreOffice 또는 Timeline Explorer와 같은 도구로 가져올 때 좋습니다.
JSON은 `Details` 필드가 분리되어 더 쉽게 분석할 수 있으므로 `jq`와 같은 도구로 데이터(대용량 결과 파일 포함)를 더 자세히 분석하는 데 가장 좋습니다.
(CSV 출력에서는 모든 이벤트 로그 필드가 하나의 큰 `Details` 열에 들어 있어 데이터 정렬 등이 더 어렵습니다.)

```
Usage: json-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -L, --JSONL-output                 Save the timeline in JSONL format (ex: -L -o results.jsonl)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in JSON format (ex: results.json)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `json-timeline` 명령어 예시 및 설정 파일

`json-timeline`의 옵션과 설정 파일은 `csv-timeline`과 동일하지만 JSONL 형식으로 출력하기 위한 추가 옵션 `-L, --JSONL-output` 하나가 있습니다.

## `level-tuning` 명령어

`level-tuning` 명령어를 사용하면 룰의 알림 레벨을 원하는 대로 위험 레벨을 높이거나 낮추어 튜닝할 수 있습니다.
이 명령어는 설정 파일을 사용하여 `rules` 폴더에 있는 룰의 위험 레벨(`level` 필드)을 덮어씁니다.

> 경고: `update-rules` 명령어를 실행할 때마다 위험 레벨이 원래 값으로 되돌아가므로, 그 후에 `level-tuning` 명령어를 다시 실행해야 합니다.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` 명령어 예시

* 일반 사용법: `hayabusa.exe level-tuning`
* 사용자 정의 설정 파일을 기반으로 룰 알림 레벨 튜닝: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` 설정 파일

Hayabusa 및 Sigma 룰 작성자는 룰을 작성할 때 알림의 적절한 위험 레벨을 추정합니다.
그러나 때로는 위험 레벨이 일관되지 않고 또한 실제 위험 레벨이 사용자 환경에 따라 다를 수 있습니다.
Yamato Security는 룰을 튜닝하는 데 사용할 수 있는 설정 파일을 `./rules/config/level_tuning.txt`에서 제공하고 유지 관리합니다.

`./rules/config/level_tuning.txt` 샘플:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

이 경우, rules 디렉터리에서 `id`가 `570ae5ec-33dc-427c-b815-db86228ad43e`인 룰의 위험 레벨은 `level`이 `informational`로 다시 작성됩니다.
설정 가능한 레벨은 `critical`, `high`, `medium`, `low`, `informational`입니다.

> 경고: `./rules/config/level_tuning.txt` 설정 파일도 `update-rules`를 실행할 때마다 hayabusa-rules 저장소의 최신 버전으로 업데이트됩니다.
> 따라서 이 파일을 변경하면 그 변경 사항을 잃게 됩니다!
> 자신만의 설정 파일을 유지하고 싶다면, `./config/level_tuning.txt`에 설정 파일을 생성하고 `hayabusa.exe level-tuning -f ./config/level_tuning.txt`를 실행하십시오.
> 먼저 Yamato Security가 제공하는 설정 파일로 레벨 튜닝을 수행한 다음 자신만의 설정 파일로 추가 튜닝을 할 수도 있습니다.

## `list-profiles` 명령어

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` 명령어

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` 명령어 예시

* 기본 프로필을 `minimal`로 설정: `hayabusa.exe set-default-profile minimal`
* 기본 프로필을 `super-verbose`로 설정: `hayabusa.exe set-default-profile super-verbose`

## `update-rules` 명령어

`update-rules` 명령어는 `rules` 폴더를 [Hayabusa rules github 저장소](https://github.com/Yamato-Security/hayabusa-rules)와 동기화하여 룰 및 설정 파일을 업데이트합니다.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` 명령어 예시

일반적으로 이것만 실행하면 됩니다: `hayabusa.exe update-rules`
