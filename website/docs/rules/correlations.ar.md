## قواعد عدّ الأحداث (Event Count)

هذه قواعد تَعُدّ أحداثًا معيّنة وتُطلق تنبيهًا إذا وقع عدد كبير جدًا أو غير كافٍ من هذه الأحداث ضمن إطار زمني.
من الأمثلة الشائعة لاكتشاف عدد كبير من الأحداث ضمن فترة زمنية معيّنة اكتشاف هجمات تخمين كلمات المرور، وهجمات رشّ كلمات المرور، وهجمات حجب الخدمة.
يمكنك أيضًا استخدام هذه القواعد لاكتشاف مشكلات موثوقية مصدر السجلات، مثل عندما تنخفض أحداث معيّنة دون حدّ معيّن.

### مثال على قاعدة عدّ الأحداث:

يستخدم المثال التالي قاعدتين لاكتشاف هجمات تخمين كلمات المرور.
سيكون هناك تنبيه عندما تتطابق القاعدة المُشار إليها 5 مرات أو أكثر خلال 5 دقائق ويكون حقل `IpAddress` نفسه لتلك الأحداث.

> لاحظ أننا أدرجنا فقط الحقول الضرورية من أجل فهم المفهوم.
> القاعدة الكاملة التي يستند إليها هذا المثال موجودة [هنا](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) كمرجع لك.

### قاعدة الارتباط لعدّ الأحداث:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### قاعدة فشل تسجيل الدخول - كلمة مرور غير صحيحة:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### مثال على قاعدة `count` المهجورة:

توفّر قاعدة الارتباط والقواعد المُشار إليها أعلاه النتائج نفسها التي توفّرها القاعدة التالية التي تستخدم مُعدِّل `count` الأقدم:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### مخرجات قاعدة عدّ الأحداث:

ستُنشئ القواعد أعلاه المخرجات التالية:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## قواعد عدّ القيم (Value Count)

تَعُدّ هذه القواعد الأحداث نفسها ضمن إطار زمني بقيم **مختلفة** لحقل معيّن.

أمثلة:
- مسح الشبكة حيث يحاول عنوان IP مصدر واحد الاتصال بالعديد من عناوين IP و/أو المنافذ الوجهة المختلفة.
- هجمات رشّ كلمات المرور حيث يفشل مصدر واحد في المصادقة مع العديد من المستخدمين المختلفين.
- اكتشاف أدوات مثل BloodHound التي تُعدّد العديد من مجموعات AD ذات الامتيازات العالية ضمن إطار زمني قصير.

### مثال على قاعدة عدّ القيم:

تكتشف القاعدة التالية عندما يحاول مهاجم تخمين أسماء المستخدمين.
أي عندما يفشل عنوان IP المصدر **نفسه** (`IpAddress`) في تسجيل الدخول بأكثر من 3 أسماء مستخدمين **مختلفة** (`TargetUserName`) خلال 5 دقائق.

> لاحظ أننا أدرجنا فقط الحقول الضرورية من أجل فهم المفهوم.
> القاعدة الكاملة التي يستند إليها هذا المثال موجودة [هنا](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) كمرجع لك.

### قاعدة الارتباط لعدّ القيم:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### قاعدة فشل تسجيل الدخول لعدّ القيم (مستخدم غير موجود):

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### قاعدة مُعدِّل `count` المهجورة:

توفّر قاعدة الارتباط والقواعد المُشار إليها أعلاه النتائج نفسها التي توفّرها القاعدة التالية التي تستخدم مُعدِّل `count` الأقدم:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### مخرجات قاعدة عدّ القيم:

ستُنشئ القواعد أعلاه المخرجات التالية:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## قواعد التقارب الزمني (Temporal Proximity)

يجب أن تقع جميع الأحداث المُعرَّفة بواسطة القواعد المُشار إليها في حقل rule ضمن الإطار الزمني المُعرَّف بواسطة timespan.
يجب أن تكون قيم الحقول المُعرَّفة في `group-by` جميعها بالقيمة نفسها (مثال: المضيف نفسه، المستخدم نفسه، إلخ...).

### مثال على قاعدة التقارب الزمني:

مثال: أوامر الاستطلاع المُعرَّفة في ثلاث قواعد Sigma تُستدعى بترتيب عشوائي خلال 5 دقائق على نظام بواسطة المستخدم نفسه.

### قاعدة الارتباط للتقارب الزمني:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## قواعد التقارب الزمني المُرتَّب (Ordered Temporal Proximity)

يتصرّف نوع الارتباط `temporal_ordered` مثل `temporal` ويتطلّب بالإضافة إلى ذلك أن تظهر الأحداث بالترتيب المُقدَّم في خاصية `rules`.

### مثال على قاعدة التقارب الزمني المُرتَّب:

مثال: العديد من عمليات تسجيل الدخول الفاشلة كما هو مُعرَّف أعلاه يتبعها تسجيل دخول ناجح من حساب المستخدم نفسه خلال ساعة واحدة:

### قاعدة الارتباط للتقارب الزمني المُرتَّب:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## ملاحظات حول قواعد الارتباط

1. يجب أن تُدرج جميع قواعد الارتباط والقواعد المُشار إليها في ملف واحد وتفصل بينها بفاصل YAML وهو `---`.

2. بشكل افتراضي، لن تُخرَج قواعد الارتباط المُشار إليها. إذا أردت رؤية مخرجات القواعد المُشار إليها، فأنت بحاجة إلى إضافة `generate: true` تحت `correlation`. هذا مفيد جدًا لتفعيله والتحقق منه عند إنشاء قواعد الارتباط.

    مثال:
    ```
    correlation:
        generate: true
    ```
3. يمكنك استخدام أسماء مستعارة بدلًا من معرّفات القواعد عند الإشارة إلى القواعد لجعل الأمور أسهل للفهم.

4. يمكنك الإشارة إلى قواعد متعددة.

5. يمكنك استخدام حقول متعددة في `group-by`. إذا فعلت ذلك، فيجب أن تكون جميع القيم في تلك الحقول متطابقة وإلا فلن تحصل على تنبيه. في معظم الأوقات، ستكتب قواعد تُرشِّح حقولًا معيّنة باستخدام `group-by` من أجل تقليل النتائج الإيجابية الكاذبة، ومع ذلك، من الممكن حذف `group-by` لإنشاء قاعدة أكثر عمومية.

6. ستكون الطابع الزمني لقاعدة الارتباط هو البداية الأولى للهجوم لذا يجب أن تتحقق من الأحداث التي تليها للتأكّد مما إذا كانت نتيجة إيجابية كاذبة أم لا.
