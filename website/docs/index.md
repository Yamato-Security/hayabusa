---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> is a Windows event log <strong>fast forensics timeline generator</strong>
and <strong>threat hunting tool</strong> created by
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Written in memory-safe Rust, multi-threaded for speed, and the only open-source tool
with full support for the Sigma specification — including v2 correlation rules.
</p>

<div class="hb-cta" markdown>
[Get Started :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Command Reference :material-console:](commands/index.md){ .md-button }
[View on GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## Why Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Blazing fast__

    ---

    Written in memory-safe **Rust** with full multi-threading to parse mountains
    of `.evtx` files and produce a single timeline as quickly as possible.

-   :material-shield-search:{ .lg .middle } __Full Sigma support__

    ---

    The only open-source tool with complete support for the Sigma spec, including
    **v2 correlation rules**, backed by 4,000+ curated detection rules.

-   :material-timeline-clock:{ .lg .middle } __DFIR timelines__

    ---

    Consolidates events from one host or thousands into a single **CSV / JSON / JSONL**
    forensics timeline ready for analysis.

-   :material-server-network:{ .lg .middle } __Enterprise-wide hunting__

    ---

    Run live on a single system, collect logs for offline analysis, or hunt across
    the enterprise with the **Velociraptor** Hayabusa artifact.

-   :material-chart-box:{ .lg .middle } __Rich analysis output__

    ---

    Metrics, logon summaries, keyword pivoting, HTML reports, and a detection
    frequency timeline to surface what matters fast.

-   :material-import:{ .lg .middle } __Plays well with others__

    ---

    Import results straight into **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**, or slice JSON with **jq**.

</div>

## See it in action

![Hayabusa DFIR timeline creation](assets/doc/DFIR-TimelineCreation-EN.png)

Browse the [Screenshots](overview/screenshots.md) gallery for terminal output, the
HTML results summary, and analysis in LibreOffice, Timeline Explorer and Timesketch.

## Quick links

<div class="grid cards" markdown>

-   __:material-book-open-variant: New here?__

    Start with the [Overview](overview/index.md), then head to
    [Getting Started](getting-started/index.md) to download and run Hayabusa.

-   __:material-console-line: Working with the CLI?__

    Jump to the [Command List](commands/index.md) and the per-command reference for
    [Analysis](commands/analysis.md), [Config](commands/config.md) and
    [DFIR Timeline](commands/dfir-timeline.md) commands.

-   __:material-tune: Tuning output?__

    See [Output Profiles](output/index.md), [Abbreviations](output/abbreviations.md)
    and [Display & Summary](output/display.md) options.

-   __:material-puzzle: Going further?__

    Explore the [Rules](rules/index.md), the [project ecosystem](resources/index.md)
    and how to [contribute](resources/contributing.md).

</div>
