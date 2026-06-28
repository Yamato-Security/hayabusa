---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> adalah <strong>generator linimasa forensik cepat</strong> untuk log peristiwa Windows
dan <strong>alat perburuan ancaman</strong> yang dibuat oleh
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Ditulis dalam Rust yang aman secara memori, multi-threaded untuk kecepatan, dan satu-satunya alat open-source
dengan dukungan penuh untuk spesifikasi Sigma — termasuk aturan korelasi v2.
</p>

<div class="hb-cta" markdown>
[Mulai :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Referensi Perintah :material-console:](commands/index.md){ .md-button }
[Lihat di GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## Mengapa Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Sangat cepat__

    ---

    Ditulis dalam **Rust** yang aman secara memori dengan multi-threading penuh untuk mengurai tumpukan
    file `.evtx` dan menghasilkan satu linimasa secepat mungkin.

-   :material-shield-search:{ .lg .middle } __Dukungan Sigma penuh__

    ---

    Satu-satunya alat open-source dengan dukungan lengkap untuk spesifikasi Sigma, termasuk
    **aturan korelasi v2**, didukung oleh 4.000+ aturan deteksi terkurasi.

-   :material-timeline-clock:{ .lg .middle } __Linimasa DFIR__

    ---

    Mengonsolidasikan peristiwa dari satu host atau ribuan host menjadi satu linimasa forensik
    **CSV / JSON / JSONL** yang siap untuk dianalisis.

-   :material-server-network:{ .lg .middle } __Perburuan di seluruh perusahaan__

    ---

    Jalankan secara langsung pada satu sistem, kumpulkan log untuk analisis offline, atau berburu di seluruh
    perusahaan dengan artefak Hayabusa untuk **Velociraptor**.

-   :material-chart-box:{ .lg .middle } __Keluaran analisis yang kaya__

    ---

    Metrik, ringkasan logon, pivoting kata kunci, laporan HTML, dan linimasa frekuensi
    deteksi untuk menampilkan hal yang penting dengan cepat.

-   :material-import:{ .lg .middle } __Cocok dengan alat lain__

    ---

    Impor hasil langsung ke **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**, atau iris JSON dengan **jq**.

</div>

## Lihat dalam aksi

![Pembuatan linimasa DFIR Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

Jelajahi galeri [Tangkapan Layar](overview/screenshots.md) untuk keluaran terminal, ringkasan
hasil HTML, dan analisis di LibreOffice, Timeline Explorer dan Timesketch.

## Tautan cepat

<div class="grid cards" markdown>

-   __:material-book-open-variant: Baru di sini?__

    Mulai dengan [Ikhtisar](overview/index.md), lalu menuju ke
    [Memulai](getting-started/index.md) untuk mengunduh dan menjalankan Hayabusa.

-   __:material-console-line: Bekerja dengan CLI?__

    Lompat ke [Daftar Perintah](commands/index.md) dan referensi per perintah untuk
    perintah [Analisis](commands/analysis.md), [Konfigurasi](commands/config.md) dan
    [Linimasa DFIR](commands/dfir-timeline.md).

-   __:material-tune: Menyetel keluaran?__

    Lihat opsi [Profil Keluaran](output/index.md), [Singkatan](output/abbreviations.md)
    dan [Tampilan & Ringkasan](output/display.md).

-   __:material-puzzle: Ingin lebih jauh?__

    Jelajahi [Aturan](rules/index.md), [ekosistem proyek](resources/index.md)
    dan cara [berkontribusi](resources/contributing.md).

</div>
