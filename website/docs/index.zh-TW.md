---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> 是一款 Windows 事件記錄檔的<strong>快速鑑識時間軸產生器</strong>
與<strong>威脅獵捕工具</strong>，由
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a> 開發。
以記憶體安全的 Rust 撰寫，採用多執行緒以追求速度，並且是唯一完整支援 Sigma 規格
（包括 v2 關聯規則）的開源工具。
</p>

<div class="hb-cta" markdown>
[開始使用 :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[指令參考 :material-console:](commands/index.md){ .md-button }
[在 GitHub 上檢視 :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
</p>

</div>

---

## 為什麼選擇 Hayabusa？

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __極致快速__

    ---

    以記憶體安全的 **Rust** 撰寫，並採用完整多執行緒，以盡可能快速地解析大量
    `.evtx` 檔案並產生單一時間軸。

-   :material-shield-search:{ .lg .middle } __完整 Sigma 支援__

    ---

    唯一完整支援 Sigma 規格的開源工具，包括
    **v2 關聯規則**，並由 4,000 多條精選偵測規則支援。

-   :material-timeline-clock:{ .lg .middle } __DFIR 時間軸__

    ---

    將來自單一主機或數千台主機的事件整合為單一 **CSV / JSON / JSONL**
    鑑識時間軸，可供分析使用。

-   :material-server-network:{ .lg .middle } __全企業範圍獵捕__

    ---

    可在單一系統上即時執行、收集記錄供離線分析，或使用 **Velociraptor**
    Hayabusa artifact 在整個企業範圍內進行獵捕。

-   :material-chart-box:{ .lg .middle } __豐富的分析輸出__

    ---

    提供指標、登入摘要、關鍵字樞紐分析、HTML 報告，以及偵測
    頻率時間軸，能快速凸顯重要事項。

-   :material-import:{ .lg .middle } __與其他工具良好搭配__

    ---

    可將結果直接匯入 **Elastic Stack**、**Timesketch**、**Timeline
    Explorer**，或使用 **jq** 切分 JSON。

</div>

## 實際運作展示

![Hayabusa DFIR 時間軸建立](assets/doc/DFIR-TimelineCreation-EN.png)

瀏覽[螢幕截圖](overview/screenshots.md)圖庫，查看終端機輸出、
HTML 結果摘要，以及在 LibreOffice、Timeline Explorer 與 Timesketch 中的分析。

## 快速連結

<div class="grid cards" markdown>

-   __:material-book-open-variant: 第一次接觸？__

    從[概覽](overview/index.md)開始，接著前往
    [開始使用](getting-started/index.md)以下載並執行 Hayabusa。

-   __:material-console-line: 使用 CLI 嗎？__

    跳至[指令清單](commands/index.md)以及各指令的參考，包括
    [分析](commands/analysis.md)、[設定](commands/config.md)與
    [DFIR 時間軸](commands/dfir-timeline.md)指令。

-   __:material-tune: 調整輸出？__

    請參閱[輸出設定檔](output/index.md)、[縮寫](output/abbreviations.md)
    與[顯示與摘要](output/display.md)選項。

-   __:material-puzzle: 想更進一步？__

    探索[規則](rules/index.md)、[專案生態系](resources/index.md)
    以及如何[貢獻](resources/contributing.md)。

</div>
