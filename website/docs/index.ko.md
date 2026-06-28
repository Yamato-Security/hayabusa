---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong>는 <a href="https://yamatosecurity.connpass.com/">Yamato Security</a>가 만든
Windows 이벤트 로그 <strong>빠른 포렌식 타임라인 생성기</strong>이자
<strong>위협 헌팅 도구</strong>입니다.
메모리 안전성을 갖춘 Rust로 작성되었고 속도를 위해 멀티 스레드로 동작하며,
Sigma 명세를 완전히 지원하는 유일한 오픈 소스 도구입니다 — v2 상관관계 규칙까지 포함합니다.
</p>

<div class="hb-cta" markdown>
[시작하기 :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[명령어 참조 :material-console:](commands/index.md){ .md-button }
[GitHub에서 보기 :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
<a href="https://www.blackhat.com/asia-22/arsenal/schedule/#hayabusa-26211"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20Asia-2022-blue"></a>
<a href="https://codeblue.jp/2022/en/talks/?content=talks_24"><img src="https://img.shields.io/badge/CODE%20BLUE%20Bluebox-2022-blue"></a>
<a href="https://www.seccon.jp/2022/seccon_workshop/windows.html"><img src="https://img.shields.io/badge/SECCON-2023-blue"></a>
<a href="https://www.security-camp.or.jp/minicamp/tokyo2023.html"><img src="https://img.shields.io/badge/Security%20MiniCamp%20Tokyo-2023-blue"></a>
<a href="https://www.sans.org/cyber-security-training-events/digital-forensics-summit-2023/"><img src="https://img.shields.io/badge/SANS%20DFIR%20Summit-2023-blue"></a>
<a href="https://bsides.tokyo/2024/"><img src="https://img.shields.io/badge/BSides%20Tokyo-2024-blue"></a>
<a href="https://www.hacker.or.jp/hack-fes-2024/"><img src="https://img.shields.io/badge/Hack%20Fes.-2024-blue"></a>
<a href="https://hitcon.org/2024/CMT/"><img src="https://img.shields.io/badge/HITCON-2024-blue"></a>
<a href="https://www.blackhat.com/sector/2024/briefings/schedule/index.html#performing-dfir-and-threat-hunting-with-yamato-security-oss-tools-and-community-driven-knowledge-41347"><img src="https://img.shields.io/badge/SecTor-2024-blue"></a>
<a href="https://www.infosec-city.com/schedule/sin25-con"><img src="https://img.shields.io/badge/SINCON%20Kampung%20Workshop-2025-blue"></a>
<a href="https://www.blackhat.com/us-25/arsenal/schedule/index.html#windows-fast-forensics-with-yamato-securitys-hayabusa-45629"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2025-blue"></a>
<a href="https://codeblue.jp/en/program/time-table/day2-t3-02/"><img src="https://img.shields.io/badge/CODE%20BLUE%20-2025-blue"></a>
<a href="https://blackhat.com/us-26/arsenal/schedule/index.html#mecha-hayabusa-by-yamato-security-52897"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2026-blue"></a>
<a href="https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d"><img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg" /></a>
<a href="https://github.com/Yamato-Security/hayabusa/commits/main/"><img src="https://img.shields.io/github/commit-activity/t/Yamato-Security/hayabusa/main" /></a>
<a href="https://rust-reportcard.xuri.me/report/github.com/Yamato-Security/hayabusa"><img src="https://rust-reportcard.xuri.me/badge/github.com/Yamato-Security/hayabusa" /></a>
<a href="https://codecov.io/gh/Yamato-Security/hayabusa" ><img src="https://codecov.io/gh/Yamato-Security/hayabusa/branch/main/graph/badge.svg?token=WFN5XO9W8C"/></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## Hayabusa를 사용하는 이유

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __매우 빠른 속도__

    ---

    메모리 안전성을 갖춘 **Rust**로 작성되었으며 완전한 멀티 스레드를 활용해 산더미 같은
    `.evtx` 파일을 파싱하고 단일 타임라인을 최대한 빠르게 생성합니다.

-   :material-shield-search:{ .lg .middle } __완전한 Sigma 지원__

    ---

    **v2 상관관계 규칙**을 포함해 Sigma 명세를 완전히 지원하는 유일한 오픈 소스 도구로,
    4,000개 이상의 엄선된 탐지 규칙을 기반으로 합니다.

-   :material-timeline-clock:{ .lg .middle } __DFIR 타임라인__

    ---

    한 대의 호스트부터 수천 대에 이르는 이벤트를 분석 준비가 된 단일 **CSV / JSON / JSONL**
    포렌식 타임라인으로 통합합니다.

-   :material-server-network:{ .lg .middle } __전사적 헌팅__

    ---

    단일 시스템에서 실시간으로 실행하거나, 오프라인 분석을 위해 로그를 수집하거나,
    **Velociraptor** Hayabusa 아티팩트로 전사적으로 헌팅할 수 있습니다.

-   :material-chart-box:{ .lg .middle } __풍부한 분석 출력__

    ---

    지표, 로그온 요약, 키워드 피벗, HTML 보고서, 그리고 중요한 것을 빠르게 드러내는
    탐지 빈도 타임라인을 제공합니다.

-   :material-import:{ .lg .middle } __다른 도구와의 뛰어난 호환성__

    ---

    결과를 **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**로 바로 가져오거나 **jq**로 JSON을 분석할 수 있습니다.

</div>

## 실제 동작 보기

![Hayabusa DFIR 타임라인 생성](assets/doc/DFIR-TimelineCreation-EN.png)

터미널 출력, HTML 결과 요약, 그리고 LibreOffice, Timeline Explorer 및 Timesketch에서의
분석을 보려면 [스크린샷](overview/screenshots.md) 갤러리를 둘러보세요.

## 빠른 링크

<div class="grid cards" markdown>

-   __:material-book-open-variant: 처음이신가요?__

    [개요](overview/index.md)에서 시작한 다음, Hayabusa를 다운로드하고 실행하려면
    [시작하기](getting-started/index.md)로 이동하세요.

-   __:material-console-line: CLI로 작업하시나요?__

    [명령어 목록](commands/index.md)과 [분석](commands/analysis.md), [구성](commands/config.md),
    [DFIR 타임라인](commands/dfir-timeline.md) 명령어에 대한 명령어별 참조로
    이동하세요.

-   __:material-tune: 출력을 조정하시나요?__

    [출력 프로필](output/index.md), [약어](output/abbreviations.md),
    [표시 및 요약](output/display.md) 옵션을 참조하세요.

-   __:material-puzzle: 더 깊이 살펴보시나요?__

    [규칙](rules/index.md), [프로젝트 생태계](resources/index.md),
    그리고 [기여](resources/contributing.md) 방법을 살펴보세요.

</div>
