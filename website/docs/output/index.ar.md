# إخراج المخطط الزمني

## ملفات تعريف الإخراج

يحتوي Hayabusa على 5 ملفات تعريف إخراج معرّفة مسبقًا لاستخدامها في `config/profiles.yaml`:

1. `minimal`
2. `standard` (الافتراضي)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

يمكنك بسهولة تخصيص ملفات التعريف الخاصة بك أو إضافتها عن طريق تحرير هذا الملف.
يمكنك أيضًا تغيير ملف التعريف الافتراضي بسهولة باستخدام `set-default-profile --profile <profile>`.
استخدم الأمر `list-profiles` لعرض ملفات التعريف المتاحة ومعلومات حقولها.

### 1. إخراج ملف التعريف `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. إخراج ملف التعريف `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. إخراج ملف التعريف `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. إخراج ملف التعريف `all-field-info`

بدلاً من إخراج المعلومات الأدنى في `details`، سيتم إخراج جميع معلومات الحقول في قسمي `EventData` و`UserData` مع أسماء حقولها الأصلية.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. إخراج ملف التعريف `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. إخراج ملف التعريف `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. إخراج ملف التعريف `timesketch-minimal`

الإخراج بتنسيق متوافق مع الاستيراد إلى [Timesketch](https://timesketch.org/).

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. إخراج ملف التعريف `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### مقارنة ملفات التعريف

أُجريت المقاييس التالية على جهاز Lenovo P51 موديل 2018 (معالج Xeon رباعي النواة / ذاكرة وصول عشوائي 64 جيجابايت) مع 3 جيجابايت من بيانات evtx و3891 قاعدة مُفعّلة. (2023/06/01)

| ملف التعريف | وقت المعالجة | حجم ملف الإخراج | زيادة حجم الملف |
| :---: | :---: | :---: | :---: |
| minimal | 8 دقائق و50 ثانية | 770 ميجابايت | -30% |
| standard (الافتراضي) | 9 دقائق و00 ثانية | 1.1 جيجابايت | لا شيء |
| verbose | 9 دقائق و10 ثوانٍ | 1.3 جيجابايت | +20% |
| all-field-info | 9 دقائق و3 ثوانٍ | 1.2 جيجابايت | +10% |
| all-field-info-verbose | 9 دقائق و10 ثوانٍ | 1.3 جيجابايت | +20% |
| super-verbose | 9 دقائق و12 ثانية | 1.5 جيجابايت | +35% |

### الأسماء المستعارة لحقول ملف التعريف

يمكن إخراج المعلومات التالية باستخدام ملفات تعريف الإخراج المدمجة:

| الاسم المستعار | معلومات إخراج Hayabusa |
| :--- | :--- |
|%AllFieldInfo% | جميع معلومات الحقول. |
|%Channel% | اسم السجل. حقل `<Event><System><Channel>`. |
|%Computer% | حقل `<Event><System><Computer>`. |
|%Details% | حقل `details` في قاعدة الكشف بصيغة YML، إلا أن قواعد hayabusa وحدها هي التي تمتلك هذا الحقل. يوفر هذا الحقل معلومات إضافية حول التنبيه أو الحدث ويمكنه استخراج بيانات مفيدة من الحقول في سجلات الأحداث. على سبيل المثال، أسماء المستخدمين، ومعلومات سطر الأوامر، ومعلومات العمليات، وما إلى ذلك... عندما يشير عنصر نائب إلى حقل غير موجود أو يوجد تعيين اسم مستعار غير صحيح، فسيتم إخراجه على أنه `n/a` (غير متاح). إذا لم يُحدَّد حقل `details` (أي قواعد sigma)، فسيتم إخراج رسائل `details` الافتراضية لاستخراج الحقول المعرّفة في `./rules/config/default_details.txt`. يمكنك إضافة المزيد من رسائل `details` الافتراضية بإضافة `Provider Name` و`EventID` ورسالة `details` التي تريد إخراجها في `default_details.txt`. عندما لا يُعرَّف أي حقل `details` في قاعدة ما ولا في `default_details.txt`، سيتم إخراج جميع الحقول إلى عمود `details`. |
|%ExtraFieldInfo% | طباعة معلومات الحقول التي لم تُخرَج في %Details%. |
|%EventID% | حقل `<Event><System><EventID>`. |
|%EvtxFile% | اسم ملف evtx الذي تسبب في التنبيه أو الحدث. |
|%Level% | حقل `level` في قاعدة الكشف بصيغة YML. (`informational`، `low`، `medium`، `high`، `critical`) |
|%MitreTactics% | [أساليب](https://attack.mitre.org/tactics/enterprise/) MITRE ATT&CK (مثال: Initial Access، Lateral Movement، وما إلى ذلك...). |
|%MitreTags% | معرّف مجموعة MITRE ATT&CK، ومعرّف التقنية، ومعرّف البرنامج. |
|%OtherTags% | أي كلمة مفتاحية في حقل `tags` في قاعدة الكشف بصيغة YML غير مُضمّنة في `MitreTactics` أو `MitreTags`. |
|%Provider% | السمة `Name` في حقل `<Event><System><Provider>`. |
|%RecordID% | معرّف سجل الحدث من حقل `<Event><System><EventRecordID>`. |
|%RuleAuthor% | حقل `author` في قاعدة الكشف بصيغة YML. |
|%RuleCreationDate% | حقل `date` في قاعدة الكشف بصيغة YML. |
|%RuleFile% | اسم ملف قاعدة الكشف التي ولّدت التنبيه أو الحدث. |
|%RuleID% | حقل `id` في قاعدة الكشف بصيغة YML. |
|%RuleModifiedDate% | حقل `modified` في قاعدة الكشف بصيغة YML. |
|%RuleTitle% | حقل `title` في قاعدة الكشف بصيغة YML. |
|%Status% | حقل `status` في قاعدة الكشف بصيغة YML. |
|%Timestamp% | الافتراضي هو تنسيق `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. حقل `<Event><System><TimeCreated SystemTime>` في سجل الأحداث. ستكون المنطقة الزمنية الافتراضية هي المنطقة الزمنية المحلية، ولكن يمكنك تغيير المنطقة الزمنية إلى UTC باستخدام الخيار `--UTC`. |

#### اسم مستعار إضافي لحقل ملف التعريف

يمكنك أيضًا إضافة هذا الاسم المستعار الإضافي إلى ملف تعريف الإخراج الخاص بك إذا احتجت إليه:

| الاسم المستعار | معلومات إخراج Hayabusa |
| :--- | :--- |
|%RenderedMessage% | حقل `<Event><RenderingInfo><Message>` في سجلات WEC المُعاد توجيهها. |

ملاحظة: هذا **غير** مُضمّن في أي ملف تعريف مدمج، لذا ستحتاج إلى تحرير ملف `config/default_profile.yaml` يدويًا وإضافة السطر التالي:

```
Message: "%RenderedMessage%"
```

يمكنك أيضًا تعريف [أسماء مستعارة لمفاتيح الأحداث](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) لإخراج حقول أخرى.
