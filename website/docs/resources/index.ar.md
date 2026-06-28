# المشاريع والنظام البيئي

## المشاريع المرافقة

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - وثائق وبرامج نصية لتفعيل سجلات أحداث Windows بشكل صحيح.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - نفس مستودع Hayabusa Rules ولكن يتم تخزين القواعد وملفات التهيئة في ملف واحد مع تطبيق XOR لمنع النتائج الإيجابية الخاطئة من برامج مكافحة الفيروسات.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - قواعد كشف Hayabusa وقواعد Sigma المنتقاة المستخدمة في Hayabusa.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - نسخة متفرعة (fork) أكثر صيانة من حزمة `evtx`.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - ملفات evtx نموذجية لاستخدامها في اختبار قواعد كشف hayabusa/sigma.
* [Presentations](https://github.com/Yamato-Security/Presentations) - عروض تقديمية من المحاضرات التي قدمناها حول أدواتنا ومواردنا.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - ينظّم قواعد Sigma المعتمدة على سجلات أحداث Windows من المصدر إلى شكل أسهل للاستخدام.
* [Takajo](https://github.com/Yamato-Security/takajo) - محلل لنتائج hayabusa.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - محلل لسجلات أحداث Windows مكتوب بلغة PowerShell. (مهمل وتم استبداله بـ Takajo.)

## مشاريع الطرف الثالث التي تستخدم Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - سير عمل NodeRED يستورد نتائج Plaso وHayabusa إلى Timesketch.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - يوفر أدوات وبنية تحتية أمنية قائمة على السحابة لتلبية احتياجاتك. 
* [OpenRelik](https://openrelik.org/) - منصة مفتوحة المصدر (Apache-2.0) مصممة لتبسيط تحقيقات الطب الشرعي الرقمي التعاونية.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - أنشئ بسرعة نسخة من splunk باستخدام Docker لتصفح السجلات ومخرجات الأدوات أثناء تحقيقاتك.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - أداة لجمع معلومات حالة المضيف باستخدام استعلامات The Velociraptor Query Language (VQL).

## محللات سجلات أحداث Windows الأخرى والموارد ذات الصلة

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - أداة كشف هجمات مكتوبة بلغة Python.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  مجموعة من موارد Event ID المفيدة للطب الشرعي الرقمي والاستجابة للحوادث
* [Chainsaw](https://github.com/countercept/chainsaw) - أداة كشف هجمات أخرى معتمدة على sigma ومكتوبة بلغة Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - أداة كشف هجمات مكتوبة بلغة Powershell بواسطة [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - تصور بياني لسجلات أحداث Windows.
* [EventList](https://github.com/miriamxyra/EventList/) - ربط معرّفات أحداث الأساس الأمني بـ MITRE ATT&CK بواسطة [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - بواسطة [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - محلل Evtx بواسطة [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - استعادة ملفات سجل EVTX من المساحة غير المخصصة وصور الذاكرة.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - أداة Python لإرسال بيانات Evtx إلى Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - ملفات سجل أحداث نموذجية لهجمات EVTX بواسطة [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - ملفات سجل أحداث نموذجية لهجمات EVTX مرتبطة بـ ATT&CK بواسطة [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - مكتبة evtx الخاصة بـ Rust التي نستخدمها مكتوبة بواسطة [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - أداة تصور سجلات Sysmon وPowerShell.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - واجهة رسومية لتصور عمليات تسجيل الدخول لكشف الحركة الجانبية بواسطة [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - دليل وكالة الأمن القومي حول ما يجب مراقبته.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - نسخة Rust من DeepBlueCLI بواسطة Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - قواعد SIEM عامة قائمة على المجتمع.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - جهاز افتراضي معبأ مسبقاً مع Elastic Stack لاستيراد البيانات لتحليل DFIR بواسطة [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - استيراد ملفات evtx إلى Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - أداة تهيئة وتصور السجلات دون اتصال لـ Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - أفضل محلل للجداول الزمنية بصيغة CSV بواسطة [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - بواسطة Steve Anson من Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - أداة كشف هجمات معتمدة على Sigma ومكتوبة بلغة Python.
