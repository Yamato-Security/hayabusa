- [استيراد النتائج إلى SOF-ELK (Elastic Stack)](#importing-results-into-sof-elk-elastic-stack)
  - [تثبيت وتشغيل SOF-ELK](#install-and-start-sof-elk)
    - [مشكلة الاتصال بالشبكة على أجهزة Mac](#network-connectivity-trouble-on-macs)
  - [تحديث SOF-ELK!](#update-sof-elk)
  - [تشغيل Hayabusa](#run-hayabusa)
  - [اختياري: حذف البيانات المستوردة القديمة](#optional-deleting-old-imported-data)
  - [تكوين ملف إعدادات logstash الخاص بـ Hayabusa في SOF-ELK](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [استيراد نتائج Hayabusa إلى SOF-ELK](#import-hayabusa-results-into-sof-elk)
  - [التحقق من نجاح الاستيراد في Kibana](#check-that-the-import-worked-in-kibana)
  - [عرض النتائج في Discover](#view-results-in-discover)
  - [تحليل النتائج](#analyzing-results)
    - [إضافة الأعمدة](#adding-columns)
    - [التصفية](#filtering)
    - [تبديل عرض التفاصيل](#toggling-details)
    - [عرض المستندات المحيطة](#view-surrounding-documents)
    - [الحصول على مقاييس سريعة عن الحقول](#get-quick-metrics-on-fields)
  - [الخطط المستقبلية](#future-plans)

# استيراد النتائج إلى SOF-ELK (Elastic Stack)

## تثبيت وتشغيل SOF-ELK

يمكن استيراد نتائج Hayabusa بسهولة إلى Elastic Stack.
نوصي باستخدام [SOF-ELK](https://github.com/philhagen/sof-elk)، وهو توزيعة Linux مجانية لـ elastic stack تركز على تحقيقات DFIR.

أولاً قم بتنزيل وفك ضغط صورة SOF-ELK المضغوطة بصيغة 7-zip لـ VMware من [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README).

يوجد إصداران، x86 لمعالجات Intel وإصدار ARM لأجهزة Apple من سلسلة M.

عند تشغيل الجهاز الافتراضي (VM)، ستظهر لك شاشة مشابهة لهذه:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

لاحظ عنوان URL الخاص بـ Kibana وعنوان IP لخادم SSH.

يمكنك تسجيل الدخول باستخدام بيانات الاعتماد التالية:

* اسم المستخدم: `elk_user`
* كلمة المرور: `forensics`

افتح Kibana في متصفح ويب وفقًا لعنوان URL المعروض.
على سبيل المثال: http://172.16.23.128:5601/

> ملاحظة: قد يستغرق تحميل Kibana بعض الوقت.

يجب أن ترى صفحة ويب كما يلي:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

نوصي بالاتصال عبر SSH بالجهاز الافتراضي بدلاً من كتابة الأوامر داخل الجهاز الافتراضي باستخدام `ssh elk_user@172.16.23.128`.

> ملاحظة: تخطيط لوحة المفاتيح الافتراضي هو لوحة المفاتيح الأمريكية.

### مشكلة الاتصال بالشبكة على أجهزة Mac

إذا كنت تستخدم macOS وحصلت على خطأ `no route to host` في الطرفية أو لم تتمكن من الوصول إلى Kibana في متصفحك، فمن المحتمل أن يكون ذلك بسبب ضوابط خصوصية الشبكة المحلية في macOS.

في `System Settings`، افتح `Privacy & Security` -> `Local Network` وتأكد من تمكين متصفحك وبرنامج الطرفية للتمكن من التواصل مع الأجهزة على شبكتك المحلية.

## تحديث SOF-ELK!

قبل استيراد البيانات، تأكد من تحديث SOF-ELK باستخدام الأمر `sudo sof-elk_update.sh`.

## تشغيل Hayabusa

شغّل Hayabusa واحفظ النتائج بصيغة JSONL.

مثال: `./hayabusa dfir-timeline -t jsonl -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## اختياري: حذف البيانات المستوردة القديمة

إذا لم تكن هذه المرة الأولى لاستيراد نتائج Hayabusa وأردت مسح كل شيء، يمكنك القيام بذلك بالطريقة التالية:

1. تحقق من السجلات الموجودة حاليًا في SOF-ELK: `sof-elk_clear.py -i list`
2. احذف البيانات الحالية: `sof-elk_clear.py -a`
3. احذف الملفات في دليل logstash: `rm /logstash/hayabusa/*`

## تكوين ملف إعدادات logstash الخاص بـ Hayabusa في SOF-ELK

يوجد بالفعل ملف إعدادات logstash لـ Hayabusa مضمّن في SOF-ELK يحوّل أسماء الحقول إلى صيغة Elastic Common Schema.
إذا كنت أكثر ارتياحًا مع أسماء حقول Hayabusa، نوصي باستخدام الملف الذي نوفره.

1. أولاً اتصل عبر SSH بـ SOF-ELK: `ssh elk_user@172.16.23.128`
2. احذف أو انقل ملف إعدادات logstash الحالي: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. ارفع ملف [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) الجديد إلى `/etc/logstash/conf.d/`: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. أعد تشغيل logstash: `sudo systemctl restart logstash`

سيُنشئ ملف الإعدادات هذا حقلَي `DetailsText` و`ExtraFieldInfoText` الموحّدين اللذين يتيحان لك رؤية أهم الحقول بنظرة سريعة بدلاً من الاضطرار إلى قضاء الوقت في فتح كل سجل واحدًا تلو الآخر للاطلاع على جميع الحقول.

## استيراد نتائج Hayabusa إلى SOF-ELK

يتم استيعاب السجلات في SOF-ELK عن طريق نسخ السجلات إلى الدليل المناسب داخل دليل `/logstash`.

أولاً اخرج من SSH باستخدام `exit` ثم انسخ ملف نتائج Hayabusa الذي أنشأته:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## التحقق من نجاح الاستيراد في Kibana

أولاً لاحظ قيم `Total detections` و`First Timestamp` و`Last Timestamp` في `Results Summary` الخاص بفحص Hayabusa.

إذا لم تتمكن من الحصول على هذه المعلومات، يمكنك تشغيل `wc -l results.jsonl` على أنظمة *nix للحصول على إجمالي عدد الأسطر لـ `Total detections`.

افتراضيًا، لا يقوم Hayabusa بفرز النتائج لتحسين الأداء، لذا لا يمكنك النظر إلى السطر الأول والأخير للحصول على الطابع الزمني الأول والأخير.
إذا كنت لا تعرف الطابعين الزمنيين الأول والأخير بدقة، فما عليك سوى تعيين التاريخ الأول في Kibana إلى عام 2007 واليوم الأخير إلى `now` بحيث تحصل على جميع النتائج.

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

يجب أن ترى الآن `Total Records` بالإضافة إلى الطابعين الزمنيين الأول والأخير للأحداث التي تم استيرادها.

يستغرق استيراد جميع الأحداث بعض الوقت أحيانًا، لذا استمر في تحديث الصفحة حتى يصبح `Total Records` هو العدد الذي تتوقعه.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

يمكنك أيضًا التحقق من الطرفية عن طريق تشغيل `sof-elk_clear.py -i list` لمعرفة ما إذا كان الاستيراد ناجحًا.
يجب أن ترى أن فهرس `evtxlogs` الخاص بك يحتوي على المزيد من السجلات:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

يرجى إنشاء issue على GitHub إذا واجهت أي أخطاء في التحليل عند الاستيراد.
يمكنك التحقق من ذلك بالنظر إلى نهاية ملف السجل `/var/log/logstash/logstash-plain.log`.

## عرض النتائج في Discover

انقر على أيقونة الشريط الجانبي في أعلى اليسار وانقر على `Discover`:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

من المحتمل أن ترى `No results match your search criteria`.

في الزاوية العلوية اليسرى حيث يظهر فهرس `logstash-*`، انقر عليه وغيّره إلى `evtxlogs-*`.
يجب أن ترى الآن المخطط الزمني لـ Discover.

## تحليل النتائج

يجب أن يبدو عرض Discover الافتراضي مشابهًا لهذا:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

يمكنك الحصول على نظرة عامة على وقت وقوع الأحداث وتكرارها من خلال النظر إلى الرسم البياني في الأعلى. 

### إضافة الأعمدة

في الشريط الجانبي الأيسر، يمكنك إضافة الحقول التي تريد عرضها في الأعمدة بالنقر على علامة الزائد بعد تمرير المؤشر فوق حقل.
نظرًا لوجود العديد من الحقول، قد ترغب في كتابة اسم الحقل الذي تبحث عنه في مربع البحث.

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

للبداية، نوصي بالأعمدة التالية:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

إذا كانت شاشتك عريضة بما يكفي، فقد ترغب أيضًا في إضافة `ExtraFieldInfoText` بحيث ترى جميع معلومات الحقول.

يجب أن يبدو عرض Discover الآن كما يلي:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### التصفية

يمكنك التصفية باستخدام KQL(Kibana Query Language) للبحث عن أحداث وتنبيهات معينة. على سبيل المثال:
  * `Level: "crit"`: عرض التنبيهات الحرجة فقط.
  * `Level: "crit" OR Level: "high"`: عرض التنبيهات العالية والحرجة.
  * `NOT Level: info`: عدم عرض الأحداث المعلوماتية، فقط التنبيهات.
  * `MitreTactics: *LatMov*`: عرض الأحداث والتنبيهات المتعلقة بالحركة الجانبية.
  * `"PW Spray"`: عرض هجمات محددة فقط مثل "Password Spray".
  * `"LID: 0x8724ead"`: عرض جميع الأنشطة المرتبطة بمعرّف تسجيل الدخول 0x8724ead.
  * `Details_TgtUser: admmig`: البحث عن جميع الأحداث التي يكون فيها المستخدم المستهدف `admmig`.

### تبديل عرض التفاصيل

للتحقق من جميع الحقول في سجل، ما عليك سوى النقر على الأيقونة (Toggle dialog with details) بجوار الطابع الزمني:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### عرض المستندات المحيطة

إذا أردت عرض الأحداث مباشرة قبل وبعد تنبيه معين، فافتح أولاً تفاصيل ذلك التنبيه ثم انقر على `View surrounding documents` في أعلى اليمين:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

في هذا المثال، نشاهد الأحداث قبل وبعد تنبيه هجوم Pass the Hash:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> ملاحظة: غيّر الأرقام في الأعلى `Load x newer documents` أو في الأسفل `Load x older documents` لاسترداد المزيد من الأحداث.

### الحصول على مقاييس سريعة عن الحقول

في العمود الأيسر، إذا نقرت على اسم حقل فسيعطيك مقاييس سريعة عن استخدامه:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> لاحظ أن البيانات تؤخذ كعينة من أجل السرعة لذا فهي ليست دقيقة بنسبة 100%.

## الخطط المستقبلية

* محللات Logstash لصيغة CSV
* لوحة معلومات جاهزة مسبقًا
