---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Hayabusa](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Hayabusa</strong> هي أداة <strong>توليد سريع للخط الزمني للتحليل الجنائي</strong> لسجلات أحداث Windows
و<strong>أداة لصيد التهديدات</strong> أنشأتها
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
مكتوبة بلغة Rust الآمنة للذاكرة، ومتعددة الخيوط للسرعة، وهي الأداة مفتوحة المصدر الوحيدة
التي تدعم مواصفات Sigma بالكامل — بما في ذلك قواعد الارتباط الإصدار v2.
</p>

<div class="hb-cta" markdown>
[ابدأ الآن :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[مرجع الأوامر :material-console:](commands/index.md){ .md-button }
[عرض على GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## لماذا Hayabusa؟

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __سريعة كالبرق__

    ---

    مكتوبة بلغة **Rust** الآمنة للذاكرة مع دعم كامل لتعدد الخيوط لتحليل جبال
    من ملفات `.evtx` وإنتاج خط زمني واحد بأسرع ما يمكن.

-   :material-shield-search:{ .lg .middle } __دعم كامل لـ Sigma__

    ---

    الأداة مفتوحة المصدر الوحيدة التي تدعم مواصفات Sigma بالكامل، بما في ذلك
    **قواعد الارتباط الإصدار v2**، مدعومة بأكثر من 4000 قاعدة كشف منتقاة.

-   :material-timeline-clock:{ .lg .middle } __خطوط زمنية للتحليل الجنائي DFIR__

    ---

    تدمج الأحداث من مضيف واحد أو من الآلاف في خط زمني جنائي واحد بصيغة **CSV / JSON / JSONL**
    جاهز للتحليل.

-   :material-server-network:{ .lg .middle } __صيد على مستوى المؤسسة__

    ---

    شغّلها مباشرة على نظام واحد، أو اجمع السجلات للتحليل دون اتصال، أو اصطد عبر
    المؤسسة باستخدام مصنف Hayabusa الخاص بـ **Velociraptor**.

-   :material-chart-box:{ .lg .middle } __مخرجات تحليل ثرية__

    ---

    مقاييس، وملخصات تسجيل الدخول، والتمحور حول الكلمات المفتاحية، وتقارير HTML، وخط زمني
    لتكرار الكشف لإبراز ما يهم بسرعة.

-   :material-import:{ .lg .middle } __تتكامل بسلاسة مع غيرها__

    ---

    استورد النتائج مباشرة إلى **Elastic Stack** أو **Timesketch** أو **Timeline
    Explorer**، أو قطّع JSON باستخدام **jq**.

</div>

## شاهدها وهي تعمل

![إنشاء خط زمني للتحليل الجنائي DFIR باستخدام Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

تصفح معرض [لقطات الشاشة](overview/screenshots.md) لرؤية مخرجات الطرفية، وملخص
نتائج HTML، والتحليل في LibreOffice وTimeline Explorer وTimesketch.

## روابط سريعة

<div class="grid cards" markdown>

-   __:material-book-open-variant: جديد هنا؟__

    ابدأ بـ [نظرة عامة](overview/index.md)، ثم انتقل إلى
    [البدء](getting-started/index.md) لتنزيل Hayabusa وتشغيلها.

-   __:material-console-line: تعمل مع واجهة سطر الأوامر؟__

    انتقل إلى [قائمة الأوامر](commands/index.md) والمرجع الخاص بكل أمر لأوامر
    [التحليل](commands/analysis.md) و[الإعدادات](commands/config.md) و
    [الخط الزمني للتحليل الجنائي DFIR](commands/dfir-timeline.md).

-   __:material-tune: تضبط المخرجات؟__

    اطّلع على خيارات [ملفات تعريف المخرجات](output/index.md) و[الاختصارات](output/abbreviations.md)
    و[العرض والملخص](output/display.md).

-   __:material-puzzle: تريد المزيد؟__

    استكشف [القواعد](rules/index.md)، و[منظومة المشروع](resources/index.md)
    وكيفية [المساهمة](resources/contributing.md).

</div>
