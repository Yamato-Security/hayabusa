# Git 클로닝

다음 명령어로 저장소를 `git clone`하고 소스 코드에서 바이너리를 컴파일할 수 있습니다:

**경고:** 저장소의 main 브랜치는 개발 목적이므로 아직 공식적으로 릴리스되지 않은 새로운 기능에 접근할 수 있지만, 버그가 있을 수 있으므로 불안정한 것으로 간주하십시오.

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **참고:** --recursive 옵션을 사용하는 것을 잊으면, git 서브모듈로 관리되는 `rules` 폴더가 클론되지 않습니다.

`git pull --recurse-submodules`로 `rules` 폴더를 동기화하여 최신 Hayabusa 규칙을 받거나 다음 명령어를 사용할 수 있습니다:

```bash
hayabusa.exe update-rules
```

업데이트에 실패하면, `rules` 폴더의 이름을 변경한 후 다시 시도해야 할 수 있습니다.

>> 주의: 업데이트 시, `rules` 폴더의 규칙 및 설정 파일은 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 저장소의 최신 규칙 및 설정 파일로 교체됩니다.
>> 기존 파일에 대한 변경 사항은 덮어쓰여지므로, 업데이트 전에 편집한 파일은 백업해 두는 것을 권장합니다.
>> `level-tuning`으로 레벨 튜닝을 수행하는 경우, 각 업데이트 후에 규칙 파일을 다시 튜닝하십시오.
>> `rules` 폴더 안에 **새로운** 규칙을 추가하면, 업데이트 시 덮어쓰여지거나 삭제되지 **않습니다**.
