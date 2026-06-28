---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> হলো একটি Windows ইভেন্ট লগ <strong>ফাস্ট ফরেনসিকস টাইমলাইন জেনারেটর</strong>
এবং <strong>থ্রেট হান্টিং টুল</strong> যা তৈরি করেছে
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>।
মেমরি-নিরাপদ Rust-এ লেখা, গতির জন্য মাল্টি-থ্রেডেড, এবং একমাত্র ওপেন-সোর্স টুল
যা Sigma স্পেসিফিকেশনের সম্পূর্ণ সমর্থন দেয় — v2 কোরিলেশন রুল সহ।
</p>

<div class="hb-cta" markdown>
[শুরু করুন :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[কমান্ড রেফারেন্স :material-console:](commands/index.md){ .md-button }
[GitHub-এ দেখুন :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## Hayabusa কেন?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __অত্যন্ত দ্রুত__

    ---

    মেমরি-নিরাপদ **Rust**-এ লেখা সম্পূর্ণ মাল্টি-থ্রেডিং সহ, যা পাহাড়সম
    `.evtx` ফাইল পার্স করে এবং যত দ্রুত সম্ভব একটি একক টাইমলাইন তৈরি করে।

-   :material-shield-search:{ .lg .middle } __সম্পূর্ণ Sigma সমর্থন__

    ---

    একমাত্র ওপেন-সোর্স টুল যা Sigma স্পেসের সম্পূর্ণ সমর্থন দেয়, যার মধ্যে রয়েছে
    **v2 কোরিলেশন রুল**, ৪,০০০+ যত্নসহকারে নির্বাচিত ডিটেকশন রুল দ্বারা সমর্থিত।

-   :material-timeline-clock:{ .lg .middle } __DFIR টাইমলাইন__

    ---

    এক হোস্ট বা হাজার হোস্টের ইভেন্ট একত্রিত করে একটি একক **CSV / JSON / JSONL**
    ফরেনসিকস টাইমলাইনে পরিণত করে যা বিশ্লেষণের জন্য প্রস্তুত।

-   :material-server-network:{ .lg .middle } __এন্টারপ্রাইজ-ব্যাপী হান্টিং__

    ---

    একটি একক সিস্টেমে লাইভ চালান, অফলাইন বিশ্লেষণের জন্য লগ সংগ্রহ করুন, অথবা **Velociraptor**
    Hayabusa আর্টিফ্যাক্ট দিয়ে পুরো এন্টারপ্রাইজ জুড়ে হান্ট করুন।

-   :material-chart-box:{ .lg .middle } __সমৃদ্ধ বিশ্লেষণ আউটপুট__

    ---

    মেট্রিক্স, লগন সারাংশ, কীওয়ার্ড পিভটিং, HTML রিপোর্ট, এবং একটি ডিটেকশন
    ফ্রিকোয়েন্সি টাইমলাইন যা গুরুত্বপূর্ণ বিষয় দ্রুত সামনে আনে।

-   :material-import:{ .lg .middle } __অন্যদের সাথে ভালোভাবে কাজ করে__

    ---

    ফলাফল সরাসরি **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**-এ ইম্পোর্ট করুন, অথবা **jq** দিয়ে JSON কাটুন।

</div>

## এটি কাজ করতে দেখুন

![Hayabusa DFIR টাইমলাইন তৈরি](assets/doc/DFIR-TimelineCreation-EN.png)

টার্মিনাল আউটপুট, HTML ফলাফল সারাংশ, এবং LibreOffice, Timeline Explorer ও Timesketch-এ
বিশ্লেষণের জন্য [স্ক্রিনশট](overview/screenshots.md) গ্যালারি ব্রাউজ করুন।

## দ্রুত লিঙ্ক

<div class="grid cards" markdown>

-   __:material-book-open-variant: এখানে নতুন?__

    [ওভারভিউ](overview/index.md) দিয়ে শুরু করুন, তারপর Hayabusa ডাউনলোড ও চালানোর জন্য
    [শুরু করা](getting-started/index.md)-এ যান।

-   __:material-console-line: CLI নিয়ে কাজ করছেন?__

    [কমান্ড তালিকা](commands/index.md) এবং প্রতি-কমান্ড রেফারেন্সে যান:
    [বিশ্লেষণ](commands/analysis.md), [কনফিগ](commands/config.md) এবং
    [DFIR টাইমলাইন](commands/dfir-timeline.md) কমান্ড।

-   __:material-tune: আউটপুট টিউন করছেন?__

    [আউটপুট প্রোফাইল](output/index.md), [সংক্ষিপ্ত রূপ](output/abbreviations.md)
    এবং [ডিসপ্লে ও সারাংশ](output/display.md) অপশন দেখুন।

-   __:material-puzzle: আরও এগিয়ে যাচ্ছেন?__

    [রুল](rules/index.md), [প্রজেক্ট ইকোসিস্টেম](resources/index.md)
    এবং কীভাবে [অবদান রাখবেন](resources/contributing.md) তা অন্বেষণ করুন।

</div>
