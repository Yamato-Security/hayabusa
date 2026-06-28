# Hayabusa 규칙

Hayabusa 탐지 규칙은 sigma와 유사한 YML 형식으로 작성되며 `rules` 폴더에 위치합니다.
규칙은 [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)에서 호스팅되므로, 규칙에 관한 이슈와 풀 리퀘스트는 메인 Hayabusa 저장소가 아닌 그곳으로 보내주시기 바랍니다.

규칙 형식과 규칙 작성 방법을 이해하려면 이 섹션의 [규칙 파일 작성하기](creating-rules.md), [탐지 필드](detection-fields.md) 및 [Sigma 상관관계](correlations.md)를 참고하세요. (출처: [hayabusa-rules 저장소](https://github.com/Yamato-Security/hayabusa-rules).)

hayabusa-rules 저장소의 모든 규칙은 `rules` 폴더에 배치해야 합니다.
`informational` 수준의 규칙은 `events`로 간주되며, `level`이 `low` 이상인 것은 모두 `alerts`로 간주됩니다.

hayabusa 규칙 디렉터리 구조는 2개의 디렉터리로 분리되어 있습니다:

* `builtin`: Windows 내장 기능으로 생성될 수 있는 로그.
* `sysmon`: [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)으로 생성되는 로그.

규칙은 로그 유형(예: Security, System 등)별로 디렉터리에 추가로 분리되며 다음 형식으로 이름이 지정됩니다:

새 규칙을 작성하기 위한 템플릿으로 사용하거나 탐지 로직을 확인하기 위해 현재 규칙들을 확인해 보세요.

## Sigma 대 Hayabusa (내장 Sigma 호환) 규칙

Hayabusa는 `logsource` 필드를 내부적으로 처리하는 단 하나의 예외를 제외하고 Sigma 규칙을 기본적으로 지원합니다.
오탐을 줄이기 위해, Sigma 규칙은 [여기](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md)에서 설명하는 우리의 변환기를 통해 실행해야 합니다.
이는 적절한 `Channel`과 `EventID`를 추가하고, `process_creation`과 같은 특정 카테고리에 대해 필드 매핑을 수행합니다.

거의 모든 Hayabusa 규칙은 Sigma 형식과 호환되므로 Sigma 규칙처럼 사용하여 다른 SIEM 형식으로 변환할 수 있습니다.
Hayabusa 규칙은 오직 Windows 이벤트 로그 분석을 위해 설계되었으며 다음과 같은 이점이 있습니다:

1. 로그에서 유용한 필드만 가져온 추가 정보를 표시하는 별도의 `details` 필드.
2. 모두 샘플 로그에 대해 테스트되어 작동하는 것으로 확인되었습니다.
3. `|equalsfield` 및 `|endswithfield`와 같이 sigma에는 없는 추가 집계자(aggregator).

저희가 아는 한, hayabusa는 어떤 오픈 소스 Windows 이벤트 로그 분석 도구보다도 sigma 규칙에 대한 가장 뛰어난 기본 지원을 제공합니다.
