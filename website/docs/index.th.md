---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Hayabusa](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Hayabusa</strong> เป็น <strong>เครื่องมือสร้างไทม์ไลน์นิติวิทยาศาสตร์อย่างรวดเร็ว</strong>
และ <strong>เครื่องมือล่าภัยคุกคาม</strong> สำหรับ Windows event log ที่สร้างโดย
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>。
เขียนด้วย Rust ที่ปลอดภัยต่อหน่วยความจำ ทำงานแบบมัลติเธรดเพื่อความเร็ว และเป็นเครื่องมือโอเพนซอร์สเพียงหนึ่งเดียว
ที่รองรับข้อกำหนด Sigma อย่างเต็มรูปแบบ รวมถึง correlation rules แบบ v2 ด้วย
</p>

<div class="hb-cta" markdown>
[เริ่มต้นใช้งาน :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[คู่มืออ้างอิงคำสั่ง :material-console:](commands/index.md){ .md-button }
[ดูบน GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## ทำไมต้อง Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __รวดเร็วสุดขีด__

    ---

    เขียนด้วย **Rust** ที่ปลอดภัยต่อหน่วยความจำพร้อมการทำงานแบบมัลติเธรดเต็มรูปแบบ เพื่อแยกวิเคราะห์ไฟล์
    `.evtx` จำนวนมหาศาลและสร้างไทม์ไลน์เดียวให้เร็วที่สุดเท่าที่จะเป็นไปได้

-   :material-shield-search:{ .lg .middle } __รองรับ Sigma อย่างเต็มรูปแบบ__

    ---

    เครื่องมือโอเพนซอร์สเพียงหนึ่งเดียวที่รองรับข้อกำหนด Sigma อย่างสมบูรณ์ รวมถึง
    **correlation rules แบบ v2** สนับสนุนด้วยกฎตรวจจับที่คัดสรรกว่า 4,000+ ข้อ

-   :material-timeline-clock:{ .lg .middle } __ไทม์ไลน์ DFIR__

    ---

    รวมเหตุการณ์จากโฮสต์เดียวหรือนับพันเครื่องเข้าเป็นไทม์ไลน์นิติวิทยาศาสตร์ **CSV / JSON / JSONL**
    เดียวที่พร้อมสำหรับการวิเคราะห์

-   :material-server-network:{ .lg .middle } __การล่าภัยคุกคามทั่วทั้งองค์กร__

    ---

    รันแบบสดบนระบบเดียว เก็บล็อกสำหรับการวิเคราะห์แบบออฟไลน์ หรือล่าภัยคุกคามทั่วทั้ง
    องค์กรด้วย artifact ของ Hayabusa บน **Velociraptor**

-   :material-chart-box:{ .lg .middle } __ผลลัพธ์การวิเคราะห์ที่ครบครัน__

    ---

    เมตริก สรุปการล็อกออน การหมุนตามคีย์เวิร์ด รายงาน HTML และไทม์ไลน์ความถี่ของการตรวจจับ
    เพื่อเผยสิ่งที่สำคัญได้อย่างรวดเร็ว

-   :material-import:{ .lg .middle } __ทำงานร่วมกับเครื่องมืออื่นได้ดี__

    ---

    นำเข้าผลลัพธ์ตรงเข้าสู่ **Elastic Stack**, **Timesketch**, **Timeline
    Explorer** หรือแบ่งย่อย JSON ด้วย **jq**

</div>

## ดูการทำงานจริง

![การสร้างไทม์ไลน์ DFIR ของ Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

เรียกดูแกลเลอรี [ภาพหน้าจอ](overview/screenshots.md) สำหรับเอาต์พุตบนเทอร์มินัล สรุป
ผลลัพธ์ HTML และการวิเคราะห์ใน LibreOffice, Timeline Explorer และ Timesketch

## ลิงก์ด่วน

<div class="grid cards" markdown>

-   __:material-book-open-variant: เพิ่งเริ่มต้นที่นี่?__

    เริ่มจาก [ภาพรวม](overview/index.md) แล้วไปที่
    [เริ่มต้นใช้งาน](getting-started/index.md) เพื่อดาวน์โหลดและรัน Hayabusa

-   __:material-console-line: กำลังทำงานกับ CLI?__

    ข้ามไปที่ [รายการคำสั่ง](commands/index.md) และคู่มืออ้างอิงรายคำสั่งสำหรับคำสั่ง
    [Analysis](commands/analysis.md), [Config](commands/config.md) และ
    [DFIR Timeline](commands/dfir-timeline.md)

-   __:material-tune: กำลังปรับแต่งเอาต์พุต?__

    ดูตัวเลือก [Output Profiles](output/index.md), [Abbreviations](output/abbreviations.md)
    และ [Display & Summary](output/display.md)

-   __:material-puzzle: ต้องการก้าวไปไกลกว่านี้?__

    สำรวจ [Rules](rules/index.md), [ระบบนิเวศของโปรเจกต์](resources/index.md)
    และวิธี [มีส่วนร่วม](resources/contributing.md)

</div>
