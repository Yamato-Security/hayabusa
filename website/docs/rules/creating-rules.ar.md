# إنشاء ملفات القواعد

## حول Hayabusa-Rules

هذا مستودع يحتوي على قواعد sigma منتقاة تكتشف الهجمات في سجلات أحداث Windows.
يُستخدم بشكل رئيسي لقواعد كشف وملفات إعدادات [Hayabusa](https://github.com/Yamato-Security/hayabusa)، بالإضافة إلى الكشف المدمج المعتمد على sigma في [Velociraptor](https://github.com/Velocidex/velociraptor).
ميزة استخدام هذا المستودع بدلاً من [مستودع sigma الأصلي](https://github.com/SigmaHQ/sigma) هي أننا نضمّن فقط القواعد التي ينبغي أن تكون معظم أدوات sigma الأصلية قادرة على تحليلها.
كما نقوم بإلغاء تجريد حقل `logsource` عبر إضافة الحقول اللازمة مثل `Channel` و`EventID` وغيرها إلى القواعد لتسهيل فهم ما تقوم القاعدة بترشيحه، والأهم من ذلك لتقليل النتائج الإيجابية الكاذبة.
كما ننشئ قواعد جديدة بأسماء وقيم حقول محوّلة لقواعد `process_creation` والقواعد المعتمدة على `registry` بحيث لا تكتشف قواعد sigma سجلات Sysmon فحسب، بل تكتشف أيضاً سجلات Windows المدمجة.

## حول إنشاء ملفات القواعد

تُكتب قواعد كشف Hayabusa بصيغة [YAML](https://en.wikipedia.org/wiki/YAML) بامتداد ملف `.yml`. (سيتم تجاهل ملفات `.yaml`.)
وهي مجموعة فرعية من قواعد sigma لكنها تحتوي أيضاً على بعض الميزات المضافة.
نحاول جعلها أقرب ما يمكن إلى قواعد sigma بحيث يسهل تحويل قواعد Hayabusa مرة أخرى إلى sigma للمساهمة بها للمجتمع.
يمكن لقواعد Hayabusa التعبير عن قواعد كشف معقدة عبر الدمج ليس فقط بين مطابقة النصوص البسيطة، بل أيضاً التعبيرات النمطية وشروط `AND` و`OR` وغيرها.
في هذا القسم، سنشرح كيفية كتابة قواعد كشف Hayabusa.

### صيغة ملف القاعدة

مثال:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## قسم المؤلف

- **author [required]**: اسم المؤلف (المؤلفين).
- **date [required]**: التاريخ الذي أُنشئت فيه القاعدة.
- **modified** [optional]: التاريخ الذي حُدِّثت فيه القاعدة.

> ## قسم التنبيه

- **title [required]**: عنوان ملف القاعدة. سيكون هذا أيضاً اسم التنبيه الذي يُعرض، لذا كلما كان أوجز كان أفضل. (يجب ألا يتجاوز 85 حرفاً.)
- **details** [optional]: تفاصيل التنبيه الذي يُعرض. يُرجى إخراج أي حقول في سجل أحداث Windows تكون مفيدة للتحليل. تُفصل الحقول بـ `" ¦ "`. تُحاط العناصر النائبة للحقول بـ `%` (مثال: `%MemberName%`) ويجب تعريفها في `rules/config/eventkey_alias.txt`. (موضّح أدناه.)
- **description** [optional]: وصف للقاعدة. لا يُعرض هذا، لذا يمكنك جعله طويلاً ومفصّلاً.

> ## قسم القاعدة

- **id [required]**: معرّف UUID من الإصدار الرابع مُولَّد عشوائياً يُستخدم لتمييز القاعدة بشكل فريد. يمكنك توليد واحد [هنا](https://www.uuidgenerator.net/version4).
- **level [required]**: مستوى الخطورة بناءً على [تعريف sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). يُرجى كتابة واحد مما يلي: `informational`،`low`،`medium`،`high`،`critical`
- **status[required]**: الحالة بناءً على [تعريف sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). يُرجى كتابة واحد مما يلي: `deprecated`، `experimental`، `test`، `stable`.
- **logsource [required]**: على الرغم من أن هذا غير مُستخدم فعلياً من قبل Hayabusa في الوقت الحالي، فإننا نُعرّف logsource بنفس طريقة sigma لكي يكون متوافقاً مع قواعد sigma.
- **detection  [required]**: منطق الكشف يوضع هنا. (موضّح أدناه.)
- **falsepositives [required]**: احتمالات النتائج الإيجابية الكاذبة. على سبيل المثال: `system administrator`، `normal user usage`، `normal system usage`، `legacy application`، `security team`، `none`. إذا كانت غير معروفة، يُرجى كتابة `unknown`.
- **tags** [optional]: إذا كانت التقنية تقنية [LOLBINS/LOLBAS](https://lolbas-project.github.io/)، يُرجى إضافة الوسم `lolbas`. إذا كان التنبيه قابلاً للربط بتقنية في إطار [MITRE ATT&CK](https://attack.mitre.org/)، يُرجى إضافة معرّف التكتيك (مثال: `attack.t1098`) وأي تكتيكات قابلة للتطبيق أدناه:
  - `attack.reconnaissance` -> الاستطلاع (Recon)
  - `attack.resource-development` -> تطوير الموارد  (ResDev)
  - `attack.initial-access` -> الوصول الأولي (InitAccess)
  - `attack.execution` -> التنفيذ (Exec)
  - `attack.persistence` -> الاستمرارية (Persis)
  - `attack.privilege-escalation` -> تصعيد الامتيازات (PrivEsc)
  - `attack.stealth` -> التخفي (Stealth)
  - `attack.defense-impairment` -> إضعاف الدفاعات (DefImpair)
  - `attack.credential-access` -> الوصول إلى بيانات الاعتماد (CredAccess)
  - `attack.discovery` -> الاكتشاف (Disc)
  - `attack.lateral-movement` -> الحركة الجانبية (LatMov)
  - `attack.collection` -> التجميع (Collect)
  - `attack.command-and-control` -> القيادة والتحكم (C2)
  - `attack.exfiltration` -> الاستخراج (Exfil)
  - `attack.impact` -> التأثير (Impact)
- **references** [optional]: أي روابط للمراجع.
- **ruletype [required]**: `Hayabusa` لقواعد hayabusa. القواعد المُحوَّلة تلقائياً من قواعد sigma الخاصة بـ Windows ستكون `Sigma`.

> ## نموذج حدث XML

- **sample-message [required]**: من الآن فصاعداً، نطلب من مؤلفي القواعد تضمين رسائل نموذجية لقواعدهم. هذه هي الرسالة المعروضة التي يعرضها عارض الأحداث Event Viewer في Windows.
- **sample-evtx [required]**: من الآن فصاعداً، نطلب من مؤلفي القواعد تضمين أحداث XML نموذجية لقواعدهم.
