# Timesketch로 Hayabusa 결과 분석하기

## 개요

"[Timesketch](https://timesketch.org/)는 협업 포렌식 타임라인 분석을 위한 오픈소스 도구입니다. 스케치를 사용하면 여러분과 협업자들이 타임라인을 쉽게 정리하고 동시에 함께 분석할 수 있습니다. 풍부한 주석, 댓글, 태그, 별표로 원시 데이터에 의미를 부여하세요."

수백 MB 정도 크기의 CSV 파일만 분석하고 혼자 작업하는 소규모 조사의 경우 Timeline Explorer가 적합하지만, 더 큰 데이터를 다루거나 팀으로 작업할 때는 Timesketch와 같은 도구가 훨씬 좋습니다.

Timesketch는 다음과 같은 이점을 제공합니다:

1. 매우 빠르며 대용량 데이터를 처리할 수 있습니다
2. 여러 사용자가 동시에 사용할 수 있는 협업 도구입니다
3. 고급 데이터 분석, 히스토그램 및 시각화를 제공합니다
4. Windows에 국한되지 않습니다
5. 고급 쿼리를 지원합니다

CTI 지원, 다양한 분석기, 대화형 노트북 등 그 외에도 많은 이점이 있습니다...
자세한 내용은 [사용자 가이드](https://timesketch.org/guides/user/upload-data/)와 [YouTube 채널](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ)을 확인해 주세요.

유일한 단점은 실험 환경에 Timesketch 서버를 구축해야 한다는 것이지만, 다행히도 이는 매우 간단하게 할 수 있습니다.

## 설치
### Docker
[여기](https://docs.docker.com/compose/install)의 공식 안내를 따르세요.

### Ubuntu
**참고:** 진행하기 전에 Docker가 설치되어 있어야 합니다. 아직 Docker를 설치하지 않았다면 [위의 Docker 설치 안내](#docker)를 따라 주세요.
최소 8GB 메모리를 갖춘 최신 Ubuntu LTS Server 에디션 사용을 권장합니다.
[여기](https://ubuntu.com/download/server)에서 다운로드할 수 있습니다.
설정할 때 최소 설치를 선택하세요.
OS를 설정할 때 docker는 설치하지 마세요.
`ifconfig`를 사용할 수 없으므로 `sudo apt install net-tools`로 설치하세요.

그 후 `ifconfig`를 실행하여 VM의 IP 주소를 찾고 선택적으로 ssh로 접속합니다.

다음 명령을 실행하세요:
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**참고:** 진행하기 전에 시스템에 [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/)이 설치되어 실행 중인지 확인하세요.
Timesketch 저장소를 클론하고 디렉터리로 이동합니다.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
아래 단계를 따라 Docker 컨테이너를 시작하세요.

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## 로그인

`ifconfig`로 Timesketch 서버의 IP 주소를 찾아 웹 브라우저로 엽니다.
로그인 페이지로 리디렉션됩니다.
사용자를 추가할 때 사용한 사용자 자격 증명으로 로그인하세요.

## 새 스케치 만들기

`Start a new investigation` 아래에서 `BLANK SKETCH`를 클릭합니다.
조사와 관련된 이름으로 스케치 이름을 지정하세요.

## 타임라인 업로드하기

`+ ADD TIMELINE`을 클릭하면 Plaso, JSONL 또는 CSV 파일을 업로드하라는 대화 상자가 표시됩니다.
안타깝게도 Timesketch는 현재 Hayabusa의 `JSONL` 형식을 가져올 수 없으므로 다음 명령으로 CSV 타임라인을 생성하여 업로드하세요:

```shell
hayabusa-x.x.x-win-x64.exe dfir-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --ISO-8601
```

> 참고: `timesketch*` 프로필을 선택하고 타임스탬프를 UTC의 경우 `--ISO-8601`로, 현지 시간의 경우 `--RFC-3339`로 지정해야 합니다. 원한다면 다른 Hayabusa 옵션을 추가할 수 있지만, 줄바꿈 문자가 가져오기를 손상시키므로 `-M, --multiline` 옵션은 추가하지 마세요.

"Select file to upload" 대화 상자에서 타임라인 이름을 `hayabusa`와 같이 지정하고 `Comma (,)` CSV 구분자를 선택한 다음 `SUBMIT`을 클릭합니다.

> CSV 파일이 너무 커서 업로드할 수 없는 경우 Takajo의 [split-dfir-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-dfir-timeline-command) 명령으로 파일을 여러 CSV 파일로 분할할 수 있습니다.

파일을 가져오는 동안 회전하는 원이 표시되므로 완료되어 `hayabusa`가 나타날 때까지 기다려 주세요.

## 분석 팁

### 타임라인 표시하기

**참고: 가져오기가 성공적으로 완료된 후에도 `Your search did not match any events`가 표시되고 `hayabusa` 타임라인에 `0`개의 이벤트가 표시됩니다.**

`*`를 검색하면 아래와 같이 이벤트가 표시됩니다:

![Timesketch results](../assets/doc/TimesketchImport/TimesketchResults.png)

### 알림 세부 정보

`message` 열 아래에서 알림 규칙 제목을 클릭하면 알림에 대한 자세한 정보를 얻을 수 있습니다:

![Alert details](../assets/doc/TimesketchImport/AlertDetails.png)

sigma 규칙 로직을 이해하고 싶거나 설명, 참조 등을 찾아보려면 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 저장소에서 해당 규칙을 찾아보세요.

#### 필드 필터링

규칙 제목을 클릭하여 이벤트의 세부 정보를 연 후 어떤 필드 위에든 마우스를 올려 값을 쉽게 필터링하여 포함하거나 제외할 수 있습니다:

![Filter In Out](../assets/doc/TimesketchImport/FilterInOut.png)

#### 집계 분석

마우스를 올렸을 때 맨 왼쪽의 `Aggregation dialog` 아이콘을 클릭하면 해당 필드에 관한 정말 훌륭한 이벤트 데이터 분석을 얻을 수 있습니다:

![Event Data Analytics](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### 사용자 댓글

자세한 정보를 얻기 위해 알림을 클릭하면 아래와 같이 오른쪽에 새 댓글 대화 상자 아이콘이 표시됩니다:

![Comment Icon](../assets/doc/TimesketchImport/CommentIcon.png)

여기서 사용자는 채팅을 시작하고 조사에 대한 댓글을 작성할 수 있습니다.

> 팀으로 작업하는 경우 누가 무엇을 작성했는지 알 수 있도록 각 구성원마다 다른 사용자 계정을 생성하는 것이 좋습니다.

![Comment chat](../assets/doc/TimesketchImport/CommentChat.png)

> 댓글 위에 마우스를 올리면 메시지를 쉽게 편집하고 삭제할 수 있습니다.

### 열 수정하기

기본적으로 타임스탬프와 알림 규칙 제목만 표시되므로 `Modify columns` 아이콘을 클릭하여 필드를 사용자 지정하세요:

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

그러면 다음 대화 상자가 열립니다:

![Select columns](../assets/doc/TimesketchImport/SelectColumns.png)

최소한 다음 열을 **순서대로** 추가하는 것을 권장합니다:

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

열의 순서는 추가하는 순서에 따라 달라지므로 더 중요한 필드를 먼저 추가하세요.

화면에 아직 공간이 남아 있다면 여기에 표시된 것처럼 `Details`도 추가하는 것을 권장합니다:

![Details](../assets/doc/TimesketchImport/Details.png)

화면에 아직 공간이 남아 있다면 `ExtraFieldInfo`도 추가하는 것을 권장하지만, 여기서 볼 수 있듯이 너무 많은 열을 추가하면 `message` 필드가 너무 좁아져서 더 이상 알림 제목을 읽을 수 없게 됩니다:

![Too much details](../assets/doc/TimesketchImport/TooMuchDetails.png)

### 상단 아이콘

#### 줄임표 아이콘

`···` 아이콘을 클릭하면 행을 더 압축하고 `Timeline name`을 제거하여 결과를 위한 공간을 더 확보할 수 있습니다:

![More room](../assets/doc/TimesketchImport/MoreRoom.png)

#### 이벤트 히스토그램

이벤트 히스토그램을 켜서 타임라인을 시각화할 수 있습니다:

![Event Histogram](../assets/doc/TimesketchImport/EventHistogram.png)

막대 중 하나를 클릭하면 해당 기간 동안의 결과만 표시하는 시간 필터가 생성됩니다.

#### 현재 검색 저장하기

타임스탬프 바로 위, `Toggle Event Histogram` 아이콘 왼쪽에 있는 `Save current search` 아이콘을 클릭하면 현재 검색 쿼리와 열 구성을 `Saved Searches`에 저장할 수 있습니다.
나중에 왼쪽 사이드바에서 즐겨찾는 검색에 쉽게 접근할 수 있습니다.

### 검색 바

특정 심각도 수준의 알림만 표시하는 것으로 시작할 수 있는 몇 가지 유용한 쿼리는 다음과 같습니다:

1. `Level:crit`은 중요 알림만 표시합니다.
2. `Level:crit OR Level:high`는 높음 및 중요 알림을 표시합니다
3. `NOT Level:info`는 정보성 알림을 숨깁니다

필드 이름에 `:`와 값을 입력하여 쉽게 필터링할 수 있습니다.
`AND`, `OR`, `NOT`으로 필터를 조합할 수 있습니다.
와일드카드와 정규 표현식이 지원됩니다.

더 고급 쿼리는 [여기](https://timesketch.org/guides/user/search-query-guide/)의 사용자 가이드를 참조하세요.

#### 검색 기록

검색 바 왼쪽의 시계 아이콘을 클릭하면 이전에 입력한 쿼리를 표시할 수 있습니다.
또한 왼쪽 및 오른쪽 화살표 아이콘을 클릭하여 이전 및 다음 쿼리를 실행할 수 있습니다.

![Search History](../assets/doc/TimesketchImport/SearchHistory.png)

### 세로 줄임표

타임스탬프 왼쪽의 세로 줄임표를 클릭하고 `Context search`를 클릭하면 특정 이벤트 전후에 발생한 알림을 볼 수 있습니다:

![Vertical elipsis](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

그러면 다음이 표시됩니다:

![Context Search](../assets/doc/TimesketchImport/ContextSearch.png)

위 예에서는 60초(`60S`) 전후의 이벤트가 표시되고 있지만, +- 1초(`1S`)에서 +- 60분(`60M`)까지 조정할 수 있습니다.

표시된 이벤트를 더 자세히 살펴보려면 `Replace Search`를 클릭하여 표준 타임라인에 이벤트를 표시하세요.

### 별표와 태그

타임스탬프 왼쪽의 별표 아이콘을 클릭하여 별표를 표시하고 중요한 이벤트로 기록할 수 있습니다.

이벤트에 태그를 추가할 수도 있습니다.
이는 이벤트가 의심스럽거나, 악성이거나, 오탐 등임을 확인했음을 다른 사람에게 알리는 데 유용합니다...
팀으로 작업하는 경우 `under investigation by xxx`와 같은 태그를 생성하여 누군가 현재 해당 알림을 조사하고 있음을 나타낼 수 있습니다.

![Stars and tags](../assets/doc/TimesketchImport/StarsAndTags.png)
