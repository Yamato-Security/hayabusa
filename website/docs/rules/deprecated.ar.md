# الميزات المهملة

لا تزال الكلمات المفتاحية الخاصة المهملة وتجميع `count` مدعومة في Hayabusa ولكن لن تُستخدم داخل القواعد في المستقبل.

## الكلمات المفتاحية الخاصة المهملة

حاليًا، يمكن تحديد الكلمات المفتاحية الخاصة التالية:

- `value`: يطابق حسب السلسلة النصية (يمكن أيضًا تحديد أحرف البدل والأنابيب).
- `min_length`: يطابق عندما يكون عدد الأحرف أكبر من أو يساوي العدد المحدد.
- `regexes`: يطابق إذا تطابق أحد التعبيرات النمطية في الملف الذي تحدده في هذا الحقل.
- `allowlist`: سيتم تخطي القاعدة إذا تم العثور على أي تطابق في قائمة التعبيرات النمطية في الملف الذي تحدده في هذا الحقل.

في المثال أدناه، ستتطابق القاعدة إذا كانت الشروط التالية صحيحة:

- `ServiceName` يُسمى `malicious-service` أو يحتوي على تعبير نمطي في `./rules/config/regex/detectlist_suspicous_services.txt`.
- `ImagePath` يحتوي على 1000 حرف كحد أدنى.
- `ImagePath` ليس لديه أي تطابقات في `allowlist`.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### ملفات نموذجية للكلمتين المفتاحيتين regexes و allowlist

كان لدى Hayabusa ملفان مدمجان للتعبيرات النمطية يُستخدمان لملف `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml`:

- `./rules/config/regex/detectlist_suspicous_services.txt`: لاكتشاف أسماء الخدمات المشبوهة
- `./rules/config/regex/allowlist_legitimate_services.txt`: للسماح بالخدمات المشروعة

يمكن تحرير الملفات المُعرَّفة في `regexes` و `allowlist` لتغيير سلوك جميع القواعد التي تشير إليها دون الحاجة إلى تغيير أي ملف قاعدة بنفسه.

يمكنك أيضًا استخدام ملفات نصية مختلفة لـ detectlist و allowlist تقوم بإنشائها.

## شروط التجميع المهملة (قواعد `count`)

لا يزال هذا مدعومًا في Hayabusa ولكن سيتم استبداله بقواعد ارتباط Sigma في المستقبل.

### الأساسيات

الكلمة المفتاحية `condition` الموصوفة أعلاه لا تنفّذ منطق `AND` و `OR` فحسب، بل قادرة أيضًا على عدّ الأحداث أو "تجميعها".
تُسمى هذه الوظيفة "شرط التجميع" ويتم تحديدها عن طريق ربط شرط بأنبوب.
في مثال اكتشاف رش كلمات المرور أدناه، يُستخدم تعبير شرطي لتحديد ما إذا كان هناك 5 قيم أو أكثر من `TargetUserName` من مصدر `IpAddress` واحد خلال إطار زمني مدته 5 دقائق.

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

يمكن تعريف شروط التجميع بالتنسيق التالي:

- `count() {operator} {number}`: بالنسبة لأحداث السجل التي تطابق الشرط الأول قبل الأنبوب، سيتطابق الشرط إذا كان عدد السجلات المطابقة يفي بالتعبير الشرطي المحدد بواسطة `{operator}` و `{number}`.

يمكن أن يكون `{operator}` أحد التالي:

- `==`: إذا كانت القيمة مساوية للقيمة المحددة، يُعامَل على أنه مطابق للشرط.
- `>=`: إذا كانت القيمة أكبر من أو تساوي القيمة المحددة، يُعتبر الشرط مستوفىً.
- `>`: إذا كانت القيمة أكبر من القيمة المحددة، يُعتبر الشرط مستوفىً.
- `<=`: إذا كانت القيمة أقل من أو تساوي القيمة المحددة، يُعتبر الشرط مستوفىً.
- `<`: إذا كانت القيمة أقل من القيمة المحددة، يُعامَل على أن الشرط مستوفىً.

يجب أن يكون `{number}` رقمًا.

يمكن تعريف `timeframe` بما يلي:

- `15s`: 15 ثانية
- `30m`: 30 دقيقة
- `12h`: 12 ساعة
- `7d`: 7 أيام
- `3M`: 3 أشهر

### أربعة أنماط لشروط التجميع

1. لا يوجد وسيط count أو كلمة مفتاحية `by`. مثال: `selection | count() > 10`
   > إذا تطابق `selection` أكثر من 10 مرات خلال الإطار الزمني، فسيتطابق الشرط.
   > يتم استبدال هذه بقواعد ارتباط عدّ الأحداث التي لا تستخدم الحقل `group-by`.
2. لا يوجد وسيط count ولكن توجد كلمة مفتاحية `by`. مثال: `selection | count() by IpAddress > 10`
   > يجب أن يكون `selection` صحيحًا أكثر من 10 مرات لنفس `IpAddress`.
   > قواعد رقم 2 هذه أكثر شيوعًا من قواعد رقم 1.
   > يمكنك أيضًا تحديد حقول متعددة للتجميع حسبها. على سبيل المثال: `by IpAddress, Computer`
   > يتم استبدال هذه بقواعد ارتباط عدّ الأحداث التي تستخدم الحقل `group-by`.
3. يوجد وسيط count ولكن لا توجد كلمة مفتاحية `by`. مثال: `selection | count(TargetUserName) > 10`
   > إذا تطابق `selection` وكان `TargetUserName` **مختلفًا** أكثر من 10 مرات خلال الإطار الزمني، فسيتطابق الشرط.
   > يتم استبدال هذه بقواعد ارتباط عدّ القيم التي لا تستخدم الحقل `group-by`.
4. يوجد كل من وسيط count وكلمة مفتاحية `by`. مثال: `selection | count(Users) by IpAddress > 10`
   > بالنسبة لنفس `IpAddress`، يجب أن يكون هناك أكثر من 10 قيم **مختلفة** من `TargetUserName` لكي يتطابق الشرط.
   > قواعد رقم 4 هذه أكثر شيوعًا من قواعد رقم 3.
   > يتم استبدال هذه بقواعد ارتباط عدّ القيم التي تستخدم الحقل `group-by`.

### مثال النمط 1

هذا هو النمط الأساسي: `count() {operator} {number}`. ستتطابق القاعدة أدناه إذا حدث `selection` 3 مرات أو أكثر.

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### مثال النمط 2

`count() by {eventkey} {operator} {number}`: يتم تجميع أحداث السجل التي تطابق `condition` قبل الأنبوب حسب نفس `{eventkey}`. إذا كان عدد الأحداث المطابقة لكل تجميع يفي بالشرط المحدد بواسطة `{operator}` و `{number}`، فسيتطابق الشرط.

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### مثال النمط 3

`count({eventkey}) {operator} {number}`: يحسب عدد القيم **المختلفة** لـ `{eventkey}` الموجودة في حدث السجل الذي يطابق الشرط قبل أنبوب الشرط. إذا كان العدد يفي بالتعبير الشرطي المحدد في `{operator}` و `{number}`، يُعتبر الشرط مستوفىً.

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### مثال النمط 4

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: يتم تجميع السجلات التي تطابق الشرط قبل أنبوب الشرط حسب نفس `{eventkey_2}`، ويتم عدّ عدد القيم **المختلفة** لـ `{eventkey_1}` في كل مجموعة. إذا كانت القيم المعدودة لكل تجميع تفي بالتعبير الشرطي المحدد بواسطة `{operator}` و `{number}`، فسيتطابق الشرط.

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### مخرجات قاعدة count

مخرجات التفاصيل لقواعد count ثابتة وستطبع شرط count الأصلي في `[condition]` متبوعًا بمفاتيح الأحداث المسجلة في `[result]`.

في المثال أدناه، قائمة بأسماء مستخدمي `TargetUserName` التي كانت تتعرض للهجوم بالقوة الغاشمة متبوعةً بمصدر `IpAddress`:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

سيكون طابع الوقت للتنبيه هو الوقت من أول حدث تم اكتشافه.
