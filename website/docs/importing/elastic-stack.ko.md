- [SOF-ELK(Elastic Stack)로 결과 가져오기](#importing-results-into-sof-elk-elastic-stack)
  - [SOF-ELK 설치 및 시작](#install-and-start-sof-elk)
    - [Mac에서의 네트워크 연결 문제](#network-connectivity-trouble-on-macs)
  - [SOF-ELK 업데이트!](#update-sof-elk)
  - [Hayabusa 실행](#run-hayabusa)
  - [선택 사항: 이전에 가져온 데이터 삭제](#optional-deleting-old-imported-data)
  - [SOF-ELK에서 Hayabusa logstash 설정 파일 구성](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Hayabusa 결과를 SOF-ELK로 가져오기](#import-hayabusa-results-into-sof-elk)
  - [Kibana에서 가져오기가 제대로 되었는지 확인](#check-that-the-import-worked-in-kibana)
  - [Discover에서 결과 보기](#view-results-in-discover)
  - [결과 분석](#analyzing-results)
    - [열 추가](#adding-columns)
    - [필터링](#filtering)
    - [세부 정보 토글](#toggling-details)
    - [주변 문서 보기](#view-surrounding-documents)
    - [필드에 대한 빠른 메트릭 얻기](#get-quick-metrics-on-fields)
  - [향후 계획](#future-plans)

# SOF-ELK(Elastic Stack)로 결과 가져오기

## SOF-ELK 설치 및 시작

Hayabusa 결과는 Elastic Stack으로 쉽게 가져올 수 있습니다.
DFIR 조사에 중점을 둔 무료 Elastic Stack Linux 배포판인 [SOF-ELK](https://github.com/philhagen/sof-elk)를 사용하는 것을 권장합니다.

먼저 [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README)에서 SOF-ELK 7-zip으로 압축된 VMware 이미지를 다운로드하고 압축을 해제하세요.

두 가지 버전이 있는데, Intel CPU용 x86 버전과 Apple M 시리즈 컴퓨터용 ARM 버전입니다.

VM을 부팅하면 다음과 유사한 화면이 나타납니다:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Kibana URL과 SSH 서버의 IP 주소를 기록해 두세요.

다음 자격 증명으로 로그인할 수 있습니다:

* 사용자 이름: `elk_user`
* 비밀번호: `forensics`

표시된 URL에 따라 웹 브라우저에서 Kibana를 엽니다.
예: http://172.16.23.128:5601/

> 참고: Kibana가 로드되는 데 시간이 걸릴 수 있습니다.

다음과 같은 웹페이지가 나타날 것입니다:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

VM 내부에서 명령을 입력하는 대신 `ssh elk_user@172.16.23.128`로 VM에 SSH 접속하는 것을 권장합니다.

> 참고: 기본 키보드 레이아웃은 US 키보드입니다.

### Mac에서의 네트워크 연결 문제

macOS를 사용 중이고 터미널에서 `no route to host` 오류가 발생하거나 브라우저에서 Kibana에 접근할 수 없는 경우, 이는 아마도 macOS의 로컬 네트워크 개인정보 보호 제어 때문일 것입니다.

`System Settings`에서 `Privacy & Security` -> `Local Network`를 열고, 브라우저와 터미널 프로그램이 로컬 네트워크의 장치와 통신할 수 있도록 활성화되어 있는지 확인하세요.

## SOF-ELK 업데이트!

데이터를 가져오기 전에 `sudo sof-elk_update.sh` 명령으로 SOF-ELK를 업데이트해야 합니다.

## Hayabusa 실행

Hayabusa를 실행하고 결과를 JSONL로 저장합니다.

예: `./hayabusa dfir-timeline -t jsonl -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## 선택 사항: 이전에 가져온 데이터 삭제

Hayabusa 결과를 가져오는 것이 처음이 아니고 모든 것을 정리하고 싶다면, 다음과 같이 할 수 있습니다:

1. 현재 SOF-ELK에 있는 레코드를 확인합니다: `sof-elk_clear.py -i list`
2. 현재 데이터를 삭제합니다: `sof-elk_clear.py -a`
3. logstash 디렉터리의 파일을 삭제합니다: `rm /logstash/hayabusa/*`

## SOF-ELK에서 Hayabusa logstash 설정 파일 구성

SOF-ELK에는 필드 이름을 Elastic Common Schema 형식으로 변환하는 Hayabusa logstash 설정 파일이 이미 포함되어 있습니다.
Hayabusa 필드 이름에 더 익숙하다면, 저희가 제공하는 것을 사용하는 것을 권장합니다.

1. 먼저 SOF-ELK에 SSH 접속합니다: `ssh elk_user@172.16.23.128`
2. 현재 logstash 설정 파일을 삭제하거나 이동합니다: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. 새 [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) 파일을 `/etc/logstash/conf.d/`에 업로드합니다: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. logstash를 재부팅합니다: `sudo systemctl restart logstash`

이 설정 파일은 통합된 `DetailsText` 및 `ExtraFieldInfoText` 필드를 생성하여, 각 레코드를 하나씩 열어 모든 필드를 살펴보는 데 시간을 들이는 대신 가장 중요한 필드를 한눈에 빠르게 볼 수 있게 해줍니다.

## Hayabusa 결과를 SOF-ELK로 가져오기

로그는 `/logstash` 디렉터리 내의 적절한 디렉터리로 로그를 복사함으로써 SOF-ELK에 수집됩니다.

먼저 SSH에서 `exit`로 나간 다음, 생성한 Hayabusa 결과 파일을 복사합니다:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Kibana에서 가져오기가 제대로 되었는지 확인

먼저 Hayabusa 스캔의 `Results Summary`에서 `Total detections`, `First Timestamp`, `Last Timestamp`를 기록해 두세요.

이 정보를 얻을 수 없다면, *nix에서 `wc -l results.jsonl`을 실행하여 `Total detections`에 해당하는 전체 줄 수를 얻을 수 있습니다.

기본적으로 Hayabusa는 성능 향상을 위해 결과를 정렬하지 않으므로, 첫 번째와 마지막 줄을 보고 첫 번째와 마지막 타임스탬프를 얻을 수 없습니다.
정확한 첫 번째 및 마지막 타임스탬프를 모른다면, Kibana에서 첫 번째 날짜를 2007년으로, 마지막 날짜를 `now`로 설정하면 모든 결과를 얻을 수 있습니다.

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

이제 가져온 이벤트의 `Total Records`와 첫 번째 및 마지막 타임스탬프가 표시될 것입니다.

모든 이벤트를 가져오는 데 때때로 시간이 걸리므로, `Total Records`가 예상하는 개수가 될 때까지 페이지를 계속 새로 고치세요.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

터미널에서 `sof-elk_clear.py -i list`를 실행하여 가져오기가 성공했는지 확인할 수도 있습니다.
`evtxlogs` 인덱스에 더 많은 레코드가 있는 것을 볼 수 있을 것입니다:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

가져오는 동안 파싱 오류가 발생하면 GitHub에 이슈를 생성해 주세요.
`/var/log/logstash/logstash-plain.log` 로그 파일의 끝부분을 확인하여 이를 점검할 수 있습니다.

## Discover에서 결과 보기

왼쪽 상단의 사이드바 아이콘을 클릭하고 `Discover`를 클릭하세요:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

아마도 `No results match your search criteria`가 표시될 것입니다.

왼쪽 상단 모서리의 `logstash-*` 인덱스라고 표시된 부분을 클릭하여 `evtxlogs-*`로 변경하세요.
이제 Discover 타임라인이 표시될 것입니다.

## 결과 분석

기본 Discover 보기는 다음과 유사하게 나타날 것입니다:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

상단의 히스토그램을 보면 이벤트가 언제 발생했는지와 이벤트의 빈도에 대한 개요를 얻을 수 있습니다.

### 열 추가

왼쪽 사이드바에서, 필드 위에 마우스를 올린 후 더하기 기호를 클릭하여 열에 표시할 필드를 추가할 수 있습니다.
필드가 많으므로, 찾고 있는 필드 이름을 검색 상자에 입력하는 것이 좋습니다.

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

우선, 다음 열을 권장합니다:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

모니터가 충분히 넓다면, 모든 필드 정보를 볼 수 있도록 `ExtraFieldInfoText`도 추가하는 것이 좋습니다.

이제 Discover 보기는 다음과 같이 나타날 것입니다:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### 필터링

KQL(Kibana Query Language)로 필터링하여 특정 이벤트와 경고를 검색할 수 있습니다. 예를 들어:
  * `Level: "crit"`: 심각(critical) 경고만 표시합니다.
  * `Level: "crit" OR Level: "high"`: 높음(high) 및 심각(critical) 경고를 표시합니다.
  * `NOT Level: info`: 정보성 이벤트는 표시하지 않고 경고만 표시합니다.
  * `MitreTactics: *LatMov*`: 측면 이동(lateral movement)과 관련된 이벤트와 경고를 표시합니다.
  * `"PW Spray"`: "Password Spray"와 같은 특정 공격만 표시합니다.
  * `"LID: 0x8724ead"`: 로그온 ID 0x8724ead와 관련된 모든 활동을 표시합니다.
  * `Details_TgtUser: admmig`: 대상 사용자가 `admmig`인 모든 이벤트를 검색합니다.

### 세부 정보 토글

레코드의 모든 필드를 확인하려면, 타임스탬프 옆의 아이콘(세부 정보가 있는 대화상자 토글)을 클릭하기만 하면 됩니다:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### 주변 문서 보기

특정 경고의 직전과 직후 이벤트를 보고 싶다면, 먼저 해당 경고의 세부 정보를 연 다음 오른쪽 상단의 `View surrounding documents`를 클릭하세요:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

이 예에서는 Pass the Hash 공격 경고 전후의 이벤트를 보고 있습니다:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> 참고: 더 많은 이벤트를 가져오려면 상단의 `Load x newer documents` 또는 하단의 `Load x older documents`의 숫자를 변경하세요.

### 필드에 대한 빠른 메트릭 얻기

왼쪽 열에서 필드 이름을 클릭하면 해당 필드의 사용에 대한 빠른 메트릭을 제공합니다:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> 데이터는 속도를 위해 샘플링되므로 100% 정확하지는 않다는 점에 유의하세요.

## 향후 계획

* CSV용 Logstash 파서
* 사전 구축된 대시보드
