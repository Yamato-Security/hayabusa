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
