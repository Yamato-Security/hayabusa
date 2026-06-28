# Config 명령어

## `config-critical-systems` 명령어

이 명령어는 도메인 컨트롤러 및 파일 서버와 같은 중요 시스템을 자동으로 찾아 `./config/critical_systems.txt` 설정 파일에 추가하여 모든 경고 수준이 한 단계씩 높아지도록 합니다.
도메인 컨트롤러인지 확인하기 위해 Security 4768 (Kerberos TGT requested) 이벤트를 검색합니다.
파일 서버인지 확인하기 위해 Security 5145 (Network Share File Access) 이벤트를 검색합니다.
`critical_systems.txt` 파일에 추가된 모든 호스트명은 low 이상의 모든 경고가 한 단계씩 높아지며 최대 `emergency` 수준까지 올라갑니다.

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### `config-critical-systems` 명령어 예시

* `../hayabusa-sample-evtx` 디렉터리에서 도메인 컨트롤러 및 파일 서버를 검색:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
