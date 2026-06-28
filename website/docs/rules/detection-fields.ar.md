# حقل الكشف

## أساسيات التحديد (Selection)

أولاً، سيتم شرح أساسيات كيفية إنشاء قاعدة تحديد (selection).

### كيفية كتابة منطق AND و OR

لكتابة منطق AND، نستخدم قواميس متداخلة.
تحدد قاعدة الكشف أدناه أن **كلا الشرطين** يجب أن يكونا صحيحين لكي تتطابق القاعدة.

- يجب أن يكون EventID مساوياً تماماً للقيمة `7040`.
- **AND**
- يجب أن يكون Channel مساوياً تماماً للقيمة `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

لكتابة منطق OR، نستخدم القوائم (القواميس التي تبدأ بـ `-`).
في قاعدة الكشف أدناه، **أي واحد** من الشرطين سيؤدي إلى تفعيل القاعدة.

- يجب أن يكون EventID مساوياً تماماً للقيمة `7040`.
- **OR**
- يجب أن يكون Channel مساوياً تماماً للقيمة `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

يمكننا أيضاً دمج منطق `AND` و `OR` كما هو موضح أدناه.
في هذه الحالة، تتطابق القاعدة عندما يكون الشرطان التاليان صحيحين معاً.

- EventID إما أن يكون مساوياً تماماً للقيمة `7040` **OR** `7041`.
- **AND**
- Channel مساوٍ تماماً للقيمة `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### مفاتيح الأحداث (Eventkeys)

ما يلي هو مقتطف من سجل أحداث Windows، منسَّق بصيغة XML الأصلية.
يشير الحقل `Event.System.Channel` في مثال ملف القاعدة أعلاه إلى وسم XML الأصلي: `<Event><System><Channel>System<Channel><System></Event>`
يتم استبدال وسوم XML المتداخلة بأسماء الوسوم المفصولة بنقاط (`.`).
في قواعد hayabusa، يُشار إلى سلاسل الحقول هذه المتصلة معاً بالنقاط باسم `eventkeys`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### الأسماء المستعارة لمفاتيح الأحداث (Eventkey Aliases)

تعدّ مفاتيح الأحداث الطويلة ذات الفواصل `.` المتعددة شائعة، لذلك سيستخدم hayabusa أسماءً مستعارة لجعلها أسهل في التعامل. تُعرَّف الأسماء المستعارة في الملف `rules/config/eventkey_alias.txt`. هذا الملف هو ملف CSV يتألف من تعيينات `alias` و `event_key`. يمكنك إعادة كتابة القاعدة أعلاه كما هو موضح أدناه باستخدام الأسماء المستعارة مما يجعل القاعدة أسهل في القراءة.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### تنبيه: الأسماء المستعارة لمفاتيح الأحداث غير المعرَّفة

ليست كل الأسماء المستعارة لمفاتيح الأحداث معرَّفة في `rules/config/eventkey_alias.txt`. إذا لم تكن تحصل على البيانات الصحيحة في رسالة `details` (`Alert details`)، وبدلاً من ذلك تحصل على `n/a` (غير متاح) أو إذا كان التحديد (selection) في منطق الكشف لديك لا يعمل بشكل صحيح، فقد تحتاج إلى تحديث `rules/config/eventkey_alias.txt` باسم مستعار جديد.

### كيفية استخدام سمات XML في الشروط

قد تحتوي عناصر XML على سمات تُضبط بإضافة مسافة إلى العنصر. على سبيل المثال، `Name` في `Provider Name` أدناه هي سمة XML للعنصر `Provider`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

لتحديد سمات XML في مفتاح حدث، استخدم الصيغة `{eventkey}_attributes.{attribute_name}`. على سبيل المثال، لتحديد السمة `Name` للعنصر `Provider` في ملف قاعدة، سيبدو الأمر كالتالي:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### بحث grep

يمكن لـ Hayabusa إجراء عمليات بحث grep في ملفات سجل أحداث Windows من خلال عدم تحديد أي مفاتيح أحداث.

لإجراء بحث grep، حدد الكشف كما هو موضح أدناه. في هذه الحالة، إذا كانت السلاسل `mimikatz` أو `metasploit` مضمَّنة في سجل أحداث Windows، فسوف تتطابق. من الممكن أيضاً تحديد أحرف البدل (wildcards).

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> ملاحظة: يقوم Hayabusa داخلياً بتحويل بيانات سجل أحداث Windows إلى صيغة JSON قبل معالجة البيانات لذلك لا يمكن المطابقة على وسوم XML.

### EventData

تنقسم سجلات أحداث Windows إلى جزأين: جزء `System` حيث تُكتب البيانات الأساسية (Event ID، الطابع الزمني، Record ID، اسم السجل (Channel))، وجزء `EventData` أو `UserData` حيث تُكتب بيانات اعتباطية اعتماداً على Event ID.
إحدى المشكلات التي تظهر غالباً هي أن أسماء الحقول المتداخلة في `EventData` تُسمى جميعها `Data` لذلك لا يمكن لمفاتيح الأحداث الموصوفة حتى الآن التمييز بين `SubjectUserSid` و `SubjectUserName`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

للتعامل مع هذه المشكلة، يمكنك تحديد القيمة المعيَّنة في `Data Name`. على سبيل المثال، إذا كنت تريد استخدام `SubjectUserName` و `SubjectDomainName` في EventData كشرط لقاعدة، يمكنك وصفها على النحو التالي:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### الأنماط غير الطبيعية في EventData

بعض الوسوم المتداخلة في `EventData` لا تحتوي على سمة `Name`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

للكشف عن سجل حدث مثل المذكور أعلاه، يمكنك تحديد مفتاح حدث باسم `Data`.
في هذه الحالة، سيتطابق الشرط طالما أن أي واحد من وسوم `Data` المتداخلة يساوي `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### إخراج بيانات الحقل من أسماء حقول متعددة بنفس الاسم

ستحفظ بعض الأحداث بياناتها في أسماء حقول تُسمى جميعها `Data` كما في المثال السابق.
إذا حددت `%Data%` في `details:`، فسيتم إخراج جميع البيانات في مصفوفة.

على سبيل المثال:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

إذا كنت تريد طباعة بيانات حقل `Data` الأول فقط، يمكنك تحديد `%Data[1]%` في سلسلة التنبيه `details:` الخاصة بك وسيتم إخراج `rundll32.exe` فقط.

## معدِّلات الحقول (Field Modifiers)

يمكن استخدام حرف الأنبوب (pipe) مع مفاتيح الأحداث كما هو موضح أدناه لمطابقة السلاسل.
تستخدم جميع الشروط التي وصفناها حتى الآن مطابقات تامة، ولكن باستخدام معدِّلات الحقول، يمكنك وصف قواعد كشف أكثر مرونة.
في المثال التالي، إذا كانت قيمة `Data` تحتوي على السلسلة `EngineVersion=2`، فسوف تتطابق مع الشرط.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

مطابقات السلاسل لا تميز بين الأحرف الكبيرة والصغيرة. ومع ذلك، تصبح حساسة لحالة الأحرف كلما استُخدم `|re` أو `|equalsfield`.

### معدِّلات حقول Sigma المدعومة

Hayabusa حالياً هو الأداة مفتوحة المصدر الوحيدة التي تدعم بالكامل مواصفات Sigma بأكملها.

يمكنك التحقق من الحالة الحالية لجميع معدِّلات الحقول المدعومة وكذلك عدد المرات التي تُستخدم فيها هذه المعدِّلات في قواعد Sigma و Hayabusa على https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
يتم تحديث هذا المستند ديناميكياً في كل مرة يحدث فيها تحديث لقواعد Sigma أو Hayabusa.

- `'|all':`: يختلف معدِّل الحقل هذا عن المعدِّلات أعلاه لأنه لا يُطبَّق على حقل معين بل على جميع الحقول.

    في هذا المثال، يجب أن توجد كلتا السلسلتين `Keyword-1` و `Keyword-2` ولكن يمكن أن توجدا في أي مكان في أي حقل:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: سيتم ترميز البيانات إلى base64 بثلاث طرق مختلفة اعتماداً على موضعها في السلسلة المرمَّزة. سيرمِّز هذا المعدِّل سلسلة إلى جميع الاختلافات الثلاثة ويتحقق مما إذا كانت السلسلة مرمَّزة في مكان ما في سلسلة base64.
- `|cased`: يجعل البحث حساساً لحالة الأحرف.
- `|cidr`: يتحقق مما إذا كانت قيمة الحقل تتطابق مع صيغة CIDR لـ IPv4 أو IPv6. (مثال: `192.0.2.0/24`)
- `|contains`: يتحقق مما إذا كانت قيمة الحقل تحتوي على سلسلة معينة.
- `|contains|all`: يتحقق مما إذا كانت كلمات متعددة مضمَّنة في البيانات.
- `|contains|all|windash`: مثل `|contains|windash` ولكن يجب أن تكون جميع الكلمات المفتاحية موجودة.
- `|contains|cased`: يتحقق مما إذا كانت قيمة الحقل تحتوي على سلسلة معينة حساسة لحالة الأحرف.
- `|contains|expand`: يتحقق مما إذا كانت قيمة الحقل تحتوي على سلسلة في ملف الإعداد `expand` داخل `/config/expand/`.
- `|contains|windash`: سيتحقق من السلسلة كما هي، وكذلك يحوِّل حرف `-` الأول إلى تباديل أحرف `/`، `–` (شرطة قصيرة)، `—` (شرطة طويلة)، و `―` (شريط أفقي).
- `|endswith`: يتحقق مما إذا كانت قيمة الحقل تنتهي بسلسلة معينة.
- `|endswith|cased`: يتحقق مما إذا كانت قيمة الحقل تنتهي بسلسلة معينة حساسة لحالة الأحرف.
- `|endswith|windash`: يتحقق من نهاية السلسلة ويُجري اختلافات للشرطات.
- `|exists`: يتحقق مما إذا كان الحقل موجوداً.
- `|expand`: يتحقق مما إذا كانت قيمة الحقل تساوي سلسلة في ملف الإعداد `expand` داخل `/config/expand/`.
- `|fieldref`: يتحقق مما إذا كانت القيم في حقلين متماثلة. يمكنك استخدام `not` في `condition` إذا كنت تريد التحقق مما إذا كان الحقلان مختلفين.
- `|fieldref|contains`: يتحقق مما إذا كانت قيمة حقل واحد مضمَّنة في حقل آخر.
- `|fieldref|endswith`: يتحقق مما إذا كان الحقل على اليسار ينتهي بسلسلة الحقل على اليمين. يمكنك استخدام `not` في `condition` للتحقق مما إذا كانا مختلفين.
- `|fieldref|startswith`: يتحقق مما إذا كان الحقل على اليسار يبدأ بسلسلة الحقل على اليمين. يمكنك استخدام `not` في `condition` للتحقق مما إذا كانا مختلفين.
- `|gt`: يتحقق مما إذا كانت قيمة الحقل أكبر من رقم معين.
- `|gte`: يتحقق مما إذا كانت قيمة الحقل أكبر من أو تساوي رقماً معيناً.
- `|lt`: يتحقق مما إذا كانت قيمة الحقل أقل من رقم معين.
- `|lte`: يتحقق مما إذا كانت قيمة الحقل أقل من أو تساوي رقماً معيناً.
- `|re`: استخدام تعبيرات نمطية حساسة لحالة الأحرف. (نحن نستخدم regex crate لذا يرجى مراجعة الوثائق على <https://docs.rs/regex/latest/regex/#syntax> لمعرفة كيفية كتابة التعبيرات النمطية المدعومة.)
    > تنبيه: [بناء جملة التعبيرات النمطية في قواعد Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) يستخدم PCRE مع كون بعض الأحرف الوصفية لفئات الأحرف، والنظر للخلف (lookbehind)، والتجميع الذري (atomic grouping)، وما إلى ذلك... غير مدعومة. يجب أن يكون Rust regex crate قادراً على استخدام جميع التعبيرات النمطية في قواعد Sigma ولكن هناك احتمال لعدم التوافق. 
- `|re|i`: (غير حساس) استخدام تعبيرات نمطية غير حساسة لحالة الأحرف.
- `|re|m`: (متعدد الأسطر) المطابقة عبر أسطر متعددة. `^` / `$` تطابق بداية/نهاية السطر.
- `|re|s`: (سطر واحد) النقطة (`.`) تطابق جميع الأحرف، بما في ذلك حرف السطر الجديد.
- `|startswith`: يتحقق مما إذا كانت قيمة الحقل تبدأ بسلسلة معينة.
- `|startswith|cased`: يتحقق مما إذا كانت قيمة الحقل تبدأ بسلسلة معينة حساسة لحالة الأحرف.
- `|utf16|base64offset|contains`: يتحقق مما إذا كانت سلسلة UTF-16 معينة مرمَّزة داخل سلسلة base64.
- `|utf16be|base64offset|contains`: يتحقق مما إذا كانت سلسلة UTF-16 big-endian معينة مرمَّزة داخل سلسلة base64.
- `|utf16le|base64offset|contains`: يتحقق مما إذا كانت سلسلة UTF-16 little-endian معينة مرمَّزة داخل سلسلة base64.
- `|wide|base64offset|contains`: اسم مستعار لـ `utf16le|base64offset|contains`، يتحقق من سلاسل UTF-16 little-endian.

### معدِّلات الحقول المهملة (Deprecated)

المعدِّلات التالية مهملة الآن واستُبدلت بمعدِّلات تلتزم أكثر بمواصفات sigma.

- `|equalsfield`: استُبدل الآن بـ `|fieldref`.
- `|endswithfield`: استُبدل الآن بـ `|fieldref|endswith`.

### معدِّلات حقول Expand

تتميز معدِّلات الحقول `expand` بأنها معدِّل الحقل الوحيد الذي يتطلب إعداداً مسبقاً للاستخدام.
على سبيل المثال، تستخدم عناصر نائبة (placeholders) مثل `%DC-MACHINE-NAME%` وتتطلب ملف إعداد باسم `/config/expand/DC-MACHINE-NAME.txt` يحتوي على جميع أسماء أجهزة DC المحتملة.

يتم شرح كيفية إعداد هذا بمزيد من التفصيل [هنا](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## أحرف البدل (Wildcards)

يمكن استخدام أحرف البدل في مفاتيح الأحداث. في المثال أدناه، إذا بدأ `ProcessCommandLine` بالسلسلة "malware"، فستتطابق القاعدة.
المواصفات هي في الأساس نفسها مثل أحرف بدل قاعدة sigma لذلك ستكون غير حساسة لحالة الأحرف.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

يمكن استخدام حرفي البدل التاليين.

- `*`: يطابق أي سلسلة من صفر أحرف أو أكثر. (داخلياً يتم تحويله إلى التعبير النمطي `.*`)
- `?`: يطابق أي حرف واحد. (داخلياً يتم تحويله إلى التعبير النمطي `.`)

حول الهروب من أحرف البدل:

- يمكن الهروب من أحرف البدل (`*` و `?`) باستخدام خط مائل عكسي: `\*`، `\?`.
- إذا كنت تريد استخدام خط مائل عكسي مباشرة قبل حرف بدل فاكتب `\\*` أو `\\?`.
- الهروب غير مطلوب إذا كنت تستخدم خطوطاً مائلة عكسية بمفردها.

## الكلمة المفتاحية null

يمكن استخدام الكلمة المفتاحية `null` للتحقق مما إذا كان الحقل غير موجود.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

ملاحظة: هذا يختلف عن `ProcessCommandLine: ''` الذي يتحقق مما إذا كانت قيمة الحقل فارغة.

## condition

باستخدام التدوين الذي شرحناه أعلاه، يمكنك التعبير عن منطق `AND` و `OR` ولكنه سيكون مربكاً إذا كنت تحاول تعريف منطق معقد.
عندما تريد إنشاء قواعد أكثر تعقيداً، يجب عليك استخدام الكلمة المفتاحية `condition` كما هو موضح أدناه.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

يمكن استخدام التعبيرات التالية لـ `condition`.

- `{expression1} and {expression2}`: يتطلب كلاً من {expression1} AND {expression2}
- `{expression1} or {expression2}`: يتطلب إما {expression1} OR {expression2}
- `not {expression}`: يعكس منطق {expression}
- `( {expression} )`: يضبط أسبقية {expression}. يتبع نفس منطق الأسبقية كما في الرياضيات.

في المثال أعلاه، تُستخدم أسماء تحديد مثل `SELECTION_1`، `SELECTION_2`، إلخ... ولكن يمكن تسميتها بأي شيء طالما أنها تحتوي فقط على الأحرف التالية: `a-z A-Z 0-9 _`
> ومع ذلك، يرجى استخدام العرف القياسي `selection_1`، `selection_2`، `filter_1`، `filter_2`، إلخ... لجعل الأمور سهلة القراءة كلما أمكن ذلك.

## منطق not

ستؤدي العديد من القواعد إلى إيجابيات كاذبة لذلك من الشائع جداً أن يكون هناك تحديد (selection) للبحث عن التواقيع ولكن أيضاً تحديد فلتر (filter) لعدم التنبيه على الإيجابيات الكاذبة.
على سبيل المثال:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# ارتباطات Sigma (Sigma correlations)

لقد نفَّذنا جميع ارتباطات Sigma الإصدار 2.0.0 كما هي معرَّفة [هنا](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

الارتباطات المدعومة:

- عدّ الأحداث (`event_count`)
- عدّ القيم (`value_count`)
- التقارب الزمني (`temporal`)
- التقارب الزمني المرتَّب (`temporal_ordered`)

قواعد الارتباط "metrics" الجديدة (`value_sum`، `value_avg`، `value_percentile`) التي صدرت في 12 سبتمبر 2025 في Sigma الإصدار 2.1.0 غير مدعومة حالياً.
