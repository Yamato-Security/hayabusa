---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> एक Windows इवेंट लॉग <strong>fast forensics timeline generator</strong>
और <strong>threat hunting tool</strong> है, जिसे
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a> द्वारा बनाया गया है।
मेमोरी-सुरक्षित Rust में लिखा गया, गति के लिए मल्टी-थ्रेडेड, और Sigma विनिर्देश के पूर्ण समर्थन वाला एकमात्र ओपन-सोर्स टूल — जिसमें v2 correlation rules भी शामिल हैं।
</p>

<div class="hb-cta" markdown>
[शुरू करें :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[कमांड संदर्भ :material-console:](commands/index.md){ .md-button }
[GitHub पर देखें :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## Hayabusa क्यों?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __बेहद तेज़__

    ---

    मेमोरी-सुरक्षित **Rust** में पूर्ण मल्टी-थ्रेडिंग के साथ लिखा गया, ताकि ढेरों
    `.evtx` फ़ाइलों को पार्स किया जा सके और एक ही टाइमलाइन यथासंभव शीघ्रता से तैयार की जा सके।

-   :material-shield-search:{ .lg .middle } __पूर्ण Sigma समर्थन__

    ---

    Sigma विनिर्देश के पूर्ण समर्थन वाला एकमात्र ओपन-सोर्स टूल, जिसमें
    **v2 correlation rules** शामिल हैं, और जो 4,000+ क्यूरेटेड डिटेक्शन रूल्स द्वारा समर्थित है।

-   :material-timeline-clock:{ .lg .middle } __DFIR टाइमलाइन__

    ---

    एक होस्ट या हज़ारों होस्ट से इवेंट्स को एक ही **CSV / JSON / JSONL**
    फॉरेंसिक टाइमलाइन में समेकित करता है, जो विश्लेषण के लिए तैयार होती है।

-   :material-server-network:{ .lg .middle } __उद्यम-व्यापी हंटिंग__

    ---

    किसी एक सिस्टम पर लाइव चलाएँ, ऑफ़लाइन विश्लेषण के लिए लॉग एकत्र करें, या
    **Velociraptor** Hayabusa artifact के साथ पूरे उद्यम में हंट करें।

-   :material-chart-box:{ .lg .middle } __समृद्ध विश्लेषण आउटपुट__

    ---

    मेट्रिक्स, लॉगऑन सारांश, कीवर्ड पिवटिंग, HTML रिपोर्ट, और एक डिटेक्शन
    फ़्रीक्वेंसी टाइमलाइन, ताकि जो महत्वपूर्ण हो उसे तेज़ी से सामने लाया जा सके।

-   :material-import:{ .lg .middle } __दूसरों के साथ अच्छा तालमेल__

    ---

    परिणामों को सीधे **Elastic Stack**, **Timesketch**, **Timeline
    Explorer** में इम्पोर्ट करें, या **jq** से JSON को स्लाइस करें।

</div>

## इसे क्रिया में देखें

![Hayabusa DFIR टाइमलाइन निर्माण](assets/doc/DFIR-TimelineCreation-EN.png)

टर्मिनल आउटपुट, HTML परिणाम सारांश, और LibreOffice, Timeline Explorer तथा Timesketch में
विश्लेषण के लिए [Screenshots](overview/screenshots.md) गैलरी ब्राउज़ करें।

## त्वरित लिंक

<div class="grid cards" markdown>

-   __:material-book-open-variant: यहाँ नए हैं?__

    [Overview](overview/index.md) से शुरुआत करें, फिर Hayabusa डाउनलोड करने और चलाने के लिए
    [Getting Started](getting-started/index.md) पर जाएँ।

-   __:material-console-line: CLI के साथ काम कर रहे हैं?__

    [Command List](commands/index.md) और प्रति-कमांड संदर्भ पर जाएँ —
    [Analysis](commands/analysis.md), [Config](commands/config.md) और
    [DFIR Timeline](commands/dfir-timeline.md) कमांड्स के लिए।

-   __:material-tune: आउटपुट ट्यून कर रहे हैं?__

    [Output Profiles](output/index.md), [Abbreviations](output/abbreviations.md)
    और [Display & Summary](output/display.md) विकल्प देखें।

-   __:material-puzzle: और आगे जाना है?__

    [Rules](rules/index.md), [project ecosystem](resources/index.md)
    और [contribute](resources/contributing.md) कैसे करें — इन्हें एक्सप्लोर करें।

</div>
