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
