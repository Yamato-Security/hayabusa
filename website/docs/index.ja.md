---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong>（隼）は、日本の<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>
グループによって開発された、<strong>Windows イベントログの高速フォレンジックタイムライン生成ツール</strong>
兼<strong>スレットハンティングツール</strong>です。メモリセーフな Rust で記述され、可能な限り高速に動作するよう
マルチスレッドに対応しており、v2 相関ルールを含む Sigma 仕様を完全にサポートする唯一のオープンソースツールです。
</p>

<div class="hb-cta" markdown>
[はじめる :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[コマンド一覧 :material-console:](commands/index.md){ .md-button }
[GitHub で見る :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
<a href="https://www.blackhat.com/asia-22/arsenal/schedule/#hayabusa-26211"><img src="https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/asia/2022.svg"></a>
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
<a href="https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d"><img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg" /></a>
<a href="https://github.com/Yamato-Security/hayabusa/commits/main/"><img src="https://img.shields.io/github/commit-activity/t/Yamato-Security/hayabusa/main" /></a>
<a href="https://rust-reportcard.xuri.me/report/github.com/Yamato-Security/hayabusa"><img src="https://rust-reportcard.xuri.me/badge/github.com/Yamato-Security/hayabusa" /></a>
<a href="https://codecov.io/gh/Yamato-Security/hayabusa" ><img src="https://codecov.io/gh/Yamato-Security/hayabusa/branch/main/graph/badge.svg?token=WFN5XO9W8C"/></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## なぜ Hayabusa なのか？

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __圧倒的な速さ__

    ---

    メモリセーフな **Rust** で記述され、フルマルチスレッドに対応。大量の `.evtx`
    ファイルを解析し、単一のタイムラインを可能な限り高速に生成します。

-   :material-shield-search:{ .lg .middle } __Sigma を完全サポート__

    ---

    **v2 相関ルール**を含む Sigma 仕様を完全にサポートする唯一のオープンソースツール。
    4,000 件以上のキュレーションされた検知ルールが利用できます。

-   :material-timeline-clock:{ .lg .middle } __DFIR タイムライン__

    ---

    1 台から数千台までのイベントを、解析しやすい単一の **CSV / JSON / JSONL**
    フォレンジックタイムラインに集約します。

-   :material-server-network:{ .lg .middle } __組織全体のハンティング__

    ---

    単一システムでのライブ解析、ログ収集によるオフライン解析、**Velociraptor**
    の Hayabusa アーティファクトを用いた組織全体のハンティングに対応。

-   :material-chart-box:{ .lg .middle } __豊富な解析出力__

    ---

    メトリクス、ログオンサマリ、キーワードのピボット、HTML レポート、検知頻度
    タイムラインで、重要な事象を素早く可視化します。

-   :material-import:{ .lg .middle } __他ツールとの連携__

    ---

    結果を **Elastic Stack**・**Timesketch**・**Timeline Explorer** に直接インポート
    したり、**jq** で JSON を加工したりできます。

</div>

## 実際の動作

![Hayabusa DFIR タイムライン生成](assets/doc/DFIR-TimelineCreation-JP.png)

ターミナル出力、HTML 結果サマリ、LibreOffice・Timeline Explorer・Timesketch での解析例は
[スクリーンショット](overview/screenshots.md)のページをご覧ください。

## クイックリンク

<div class="grid cards" markdown>

-   __:material-book-open-variant: はじめての方へ__

    まずは[概要](overview/index.md)を読み、[はじめる](getting-started/index.md)で
    Hayabusa のダウンロードと実行を行いましょう。

-   __:material-console-line: CLI を使う__

    [コマンド一覧](commands/index.md)や、[分析](commands/analysis.md)・
    [Config](commands/config.md)・[DFIR タイムライン](commands/dfir-timeline.md)
    の各コマンドリファレンスへ。

-   __:material-tune: 出力の調整__

    [出力プロファイル](output/index.md)、[省略形](output/abbreviations.md)、
    [表示とサマリ](output/display.md)のオプションを確認できます。

-   __:material-puzzle: さらに活用する__

    [ルール](rules/index.md)、[プロジェクトエコシステム](resources/index.md)、
    [貢献方法](resources/contributing.md)を見てみましょう。

</div>
