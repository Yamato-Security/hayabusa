---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> သည် <a href="https://yamatosecurity.connpass.com/">Yamato Security</a> မှ ဖန်တီးထားသော Windows event log
<strong>လျင်မြန်သော forensics timeline ထုတ်လုပ်ပေးသည့်ကိရိယာ</strong>
နှင့် <strong>threat hunting ကိရိယာ</strong> ဖြစ်သည်။
memory-safe Rust ဖြင့်ရေးသားထားပြီး အမြန်နှုန်းအတွက် multi-threaded ဖြစ်ကာ
Sigma သတ်မှတ်ချက်ကို အပြည့်အဝ ပံ့ပိုးပေးသည့် တစ်ခုတည်းသော open-source ကိရိယာဖြစ်သည် — v2 correlation rules အပါအဝင်ဖြစ်သည်။
</p>

<div class="hb-cta" markdown>
[စတင်အသုံးပြုရန် :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Command Reference :material-console:](commands/index.md){ .md-button }
[GitHub တွင် ကြည့်ရှုရန် :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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
<a href="https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d"><img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg" /></a>
<a href="https://github.com/Yamato-Security/hayabusa/commits/main/"><img src="https://img.shields.io/github/commit-activity/t/Yamato-Security/hayabusa/main" /></a>
<a href="https://rust-reportcard.xuri.me/report/github.com/Yamato-Security/hayabusa"><img src="https://rust-reportcard.xuri.me/badge/github.com/Yamato-Security/hayabusa" /></a>
<a href="https://codecov.io/gh/Yamato-Security/hayabusa" ><img src="https://codecov.io/gh/Yamato-Security/hayabusa/branch/main/graph/badge.svg?token=WFN5XO9W8C"/></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## Hayabusa ကို ဘာကြောင့်ရွေးချယ်သင့်သနည်း။

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __အလွန်လျင်မြန်သည်__

    ---

    memory-safe **Rust** ဖြင့်ရေးသားထားပြီး multi-threading အပြည့်အဝပါဝင်ကာ
    `.evtx` ဖိုင်အမြောက်အမြားကို parse လုပ်ပြီး timeline တစ်ခုတည်းကို တတ်နိုင်သမျှ အမြန်ဆုံးထုတ်လုပ်ပေးသည်။

-   :material-shield-search:{ .lg .middle } __Sigma အပြည့်အဝ ပံ့ပိုးမှု__

    ---

    Sigma သတ်မှတ်ချက်ကို အပြည့်အဝ ပံ့ပိုးပေးသည့် တစ်ခုတည်းသော open-source ကိရိယာဖြစ်ပြီး၊
    **v2 correlation rules** အပါအဝင်၊ စိစစ်ရွေးချယ်ထားသော detection rules ၄,၀၀၀+ ဖြင့် အားဖြည့်ထားသည်။

-   :material-timeline-clock:{ .lg .middle } __DFIR timelines__

    ---

    host တစ်ခု သို့မဟုတ် ထောင်ပေါင်းများစွာမှ events များကို စိစစ်ရန် အသင့်ဖြစ်သော
    **CSV / JSON / JSONL** forensics timeline တစ်ခုတည်းအဖြစ် စုစည်းပေးသည်။

-   :material-server-network:{ .lg .middle } __လုပ်ငန်းတစ်ခုလုံးအတွက် hunting__

    ---

    စနစ်တစ်ခုတည်းတွင် live ဖြင့်လည်ပတ်နိုင်ပြီး၊ offline စိစစ်မှုအတွက် logs များကိုစုဆောင်းနိုင်သည်၊ သို့မဟုတ်
    **Velociraptor** Hayabusa artifact ဖြင့် လုပ်ငန်းတစ်ခုလုံးတွင် hunting ပြုလုပ်နိုင်သည်။

-   :material-chart-box:{ .lg .middle } __ကြွယ်ဝသော စိစစ်မှု output__

    ---

    Metrics, logon summaries, keyword pivoting, HTML reports နှင့် အရေးကြီးသည်များကို လျင်မြန်စွာ
    ဖော်ထုတ်ပေးသည့် detection frequency timeline တို့ဖြစ်သည်။

-   :material-import:{ .lg .middle } __အခြားကိရိယာများနှင့် ကောင်းစွာအလုပ်လုပ်သည်__

    ---

    ရလဒ်များကို **Elastic Stack**, **Timesketch**, **Timeline
    Explorer** သို့ တိုက်ရိုက် import လုပ်နိုင်ပြီး၊ သို့မဟုတ် **jq** ဖြင့် JSON ကို ပိုင်းခြားနိုင်သည်။

</div>

## လက်တွေ့လုပ်ဆောင်ပုံကို ကြည့်ရှုပါ

![Hayabusa DFIR timeline ဖန်တီးခြင်း](assets/doc/DFIR-TimelineCreation-EN.png)

terminal output, HTML ရလဒ်အကျဉ်းချုပ်နှင့် LibreOffice, Timeline Explorer နှင့် Timesketch တို့တွင် စိစစ်မှုများကိုကြည့်ရှုရန်
[Screenshots](overview/screenshots.md) gallery ကို ကြည့်ရှုပါ။

## အမြန်လင့်ခ်များ

<div class="grid cards" markdown>

-   __:material-book-open-variant: ဒီကိုအသစ်လာသူလား။__

    [Overview](overview/index.md) ဖြင့်စတင်ပြီး၊ Hayabusa ကို download လုပ်ကာ လည်ပတ်ရန်
    [Getting Started](getting-started/index.md) သို့ ဆက်သွားပါ။

-   __:material-console-line: CLI ဖြင့် အလုပ်လုပ်နေသလား။__

    [Command List](commands/index.md) နှင့် command တစ်ခုချင်းစီအတွက် reference ဖြစ်သော
    [Analysis](commands/analysis.md), [Config](commands/config.md) နှင့်
    [DFIR Timeline](commands/dfir-timeline.md) commands များသို့ သွားပါ။

-   __:material-tune: Output ကို ချိန်ညှိနေသလား။__

    [Output Profiles](output/index.md), [Abbreviations](output/abbreviations.md)
    နှင့် [Display & Summary](output/display.md) ရွေးချယ်စရာများကို ကြည့်ပါ။

-   __:material-puzzle: ပိုမိုလေ့လာချင်သလား။__

    [Rules](rules/index.md), [project ecosystem](resources/index.md)
    နှင့် [contribute](resources/contributing.md) ပြုလုပ်ပုံတို့ကို လေ့လာပါ။

</div>
