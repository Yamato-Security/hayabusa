# 주요 목표

## 위협 헌팅 및 전사적 DFIR

Hayabusa는 현재 4000개가 넘는 Sigma 규칙과 170개가 넘는 Hayabusa 내장 탐지 규칙을 보유하고 있으며, 규칙은 정기적으로 추가되고 있습니다.
[Velociraptor](https://docs.velociraptor.app/)의 [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/)를 사용하면 전사적인 능동적 위협 헌팅뿐만 아니라 DFIR(디지털 포렌식 및 사고 대응)에도 무료로 사용할 수 있습니다.
이 두 가지 오픈 소스 도구를 결합하면, 환경에 SIEM이 구축되어 있지 않은 경우에도 본질적으로 SIEM을 소급하여 재현할 수 있습니다.
이를 수행하는 방법은 [Eric Capuano](https://twitter.com/eric_capuano)의 Velociraptor 안내 영상을 [여기](https://www.youtube.com/watch?v=Q1IoGX--814)에서 시청하여 배울 수 있습니다.

## 빠른 포렌식 타임라인 생성

Windows 이벤트 로그 분석은 전통적으로 매우 길고 지루한 과정이었는데, 이는 Windows 이벤트 로그가 1) 분석하기 어려운 데이터 형식으로 되어 있고 2) 데이터의 대부분이 노이즈이며 조사에 유용하지 않기 때문입니다.
Hayabusa의 목표는 유용한 데이터만을 추출하여, 전문적으로 훈련된 분석가뿐만 아니라 모든 Windows 시스템 관리자가 사용할 수 있도록 가능한 한 간결하고 읽기 쉬운 형식으로 제시하는 것입니다.
Hayabusa는 분석가가 전통적인 Windows 이벤트 로그 분석과 비교했을 때 20%의 시간으로 작업의 80%를 완료할 수 있도록 하는 것을 목표로 합니다.

![DFIR Timeline](../assets/doc/DFIR-TimelineCreation-EN.png)
