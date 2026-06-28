# Hayabusa 소개

Hayabusa는 일본의 [Yamato Security](https://yamatosecurity.connpass.com/) 그룹이 만든 **Windows 이벤트 로그 고속 포렌식 타임라인 생성기**이자 **위협 헌팅 도구**입니다.
Hayabusa는 일본어로 ["송골매"](https://en.wikipedia.org/wiki/Peregrine_falcon)를 의미하며, 송골매는 세계에서 가장 빠른 동물이고 사냥에 뛰어나며 매우 잘 훈련되기 때문에 선택되었습니다.
Hayabusa는 메모리 안전성을 갖춘 [Rust](https://www.rust-lang.org/)로 작성되었으며, 최대한 빠르게 동작하도록 멀티스레딩을 지원하고, v2 상관관계 규칙을 포함한 Sigma 사양을 완전히 지원하는 유일한 오픈소스 도구입니다.
Hayabusa는 [업스트림 Sigma](https://github.com/SigmaHQ/sigma) 규칙의 파싱을 처리할 수 있지만, 우리가 사용하고 [hayabusa-rules 저장소](https://github.com/Yamato-Security/hayabusa-rules)에서 호스팅하는 Sigma 규칙은 규칙 로딩을 더 유연하게 하고 오탐을 줄이기 위해 일부 변환이 적용되어 있습니다.
이에 대한 자세한 내용은 [sigma-to-hayabusa-converter 저장소](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) README 파일에서 확인할 수 있습니다.
Hayabusa는 라이브 분석을 위해 단일 실행 시스템에서 실행하거나, 오프라인 분석을 위해 단일 또는 여러 시스템에서 로그를 수집하여 실행하거나, 기업 전반의 위협 헌팅 및 사고 대응을 위해 [Velociraptor](https://docs.velociraptor.app/)와 함께 [Hayabusa 아티팩트](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/)를 실행할 수 있습니다.
출력은 [LibreOffice](https://www.libreoffice.org/), [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) [Elastic Stack](../importing/elastic-stack.md), [Timesketch](https://timesketch.org/) 등에서 손쉽게 분석할 수 있도록 단일 CSV/JSON/JSONL 타임라인으로 통합됩니다...
