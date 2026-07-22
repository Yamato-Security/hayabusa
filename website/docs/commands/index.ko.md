# 명령어 목록

## 분석 명령어:
* `computer-metrics`: 컴퓨터 이름을 기준으로 이벤트 수를 출력합니다.
* `eid-metrics`: Event ID를 기준으로 이벤트 수와 비율을 출력합니다.
* `expand-list`: `rules` 폴더에서 `expand` 자리표시자를 추출합니다.
* `extract-base64`: 이벤트에서 base64 문자열을 추출하고 디코딩합니다.
* `log-metrics`: 로그 파일 메트릭을 출력합니다.
* `logon-summary`: 로그온 이벤트 요약을 출력합니다.
* `pivot-keywords-list`: 피벗에 사용할 의심스러운 키워드 목록을 출력합니다.
* `search`: 키워드 또는 정규 표현식으로 모든 이벤트를 검색합니다

## 구성 명령어:
* `config-critical-systems`: 도메인 컨트롤러 및 파일 서버와 같은 중요 시스템을 찾습니다.

## DFIR 타임라인 명령어:
* `dfir-timeline`: 타임라인을 CSV 형식으로 저장합니다.
* `dfir-timeline`: 타임라인을 JSON/JSONL 형식으로 저장합니다.
* `level-tuning`: 경고의 `level`을 사용자 지정으로 조정합니다.
* `list-profiles`: 사용 가능한 출력 프로필을 나열합니다.
* `set-default-profile`: 기본 프로필을 변경합니다.
* `update-rules`: [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) GitHub 저장소의 최신 규칙으로 규칙을 동기화합니다.

## 일반 명령어:
* `help`: 이 메시지 또는 지정된 하위 명령어의 도움말을 출력합니다
* `list-contributors`: 기여자 목록을 출력합니다
