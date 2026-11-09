# تشغيل Hayabusa

## تحذير: تنبيهات برامج مكافحة الفيروسات/EDR وبطء أوقات التشغيل

قد تتلقى تنبيهًا من منتجات مكافحة الفيروسات أو EDR عند محاولة تشغيل hayabusa أو حتى عند تنزيل قواعد `.yml` فقط، وذلك لوجود كلمات مفتاحية مثل `mimikatz` وأوامر PowerShell المشبوهة في توقيع الاكتشاف.
هذه إنذارات كاذبة، لذا ستحتاج إلى تكوين استثناءات في منتجات الأمان لديك للسماح بتشغيل hayabusa.
إذا كنت قلقًا بشأن البرمجيات الخبيثة أو هجمات سلسلة التوريد، فيرجى التحقق من الكود المصدري لـ hayabusa وتجميع الملفات الثنائية بنفسك.

قد تواجه بطئًا في وقت التشغيل خاصة عند التشغيل الأول بعد إعادة التشغيل بسبب الحماية في الوقت الفعلي من Windows Defender.
يمكنك تجنب ذلك عن طريق إيقاف الحماية في الوقت الفعلي مؤقتًا أو إضافة استثناء لدليل تشغيل hayabusa.
(يرجى مراعاة المخاطر الأمنية قبل القيام بذلك.)

## Windows

في موجّه الأوامر/PowerShell أو Windows Terminal، ما عليك سوى تشغيل الملف الثنائي المناسب لنظام Windows ذي 32 بت أو 64 بت.

### خطأ عند محاولة فحص ملف أو دليل يحتوي مساره على مسافة

عند استخدام موجّه الأوامر أو PowerShell المدمج في Windows، قد تتلقى خطأً بأن Hayabusa لم يتمكن من تحميل أي ملفات .evtx إذا كان هناك مسافة في مسار ملفك أو دليلك.
لتحميل ملفات .evtx بشكل صحيح، تأكد من القيام بما يلي:

1. ضع مسار الملف أو الدليل بين علامتي اقتباس مزدوجتين.
2. إذا كان مسار دليل، فتأكد من عدم تضمين شرطة مائلة عكسية كآخر حرف.

### الأحرف لا تُعرض بشكل صحيح

مع الخط الافتراضي `Lucida Console` على Windows، لن تُعرض العديد من الأحرف المستخدمة في الشعار والجداول بشكل صحيح.
يجب أن تغيّر الخط إلى `Consalas` لإصلاح ذلك.

سيؤدي هذا إلى إصلاح معظم عرض النصوص باستثناء عرض الأحرف اليابانية في الرسائل الختامية:

![تشويش الأحرف](../assets/screenshots/Mojibake.png)

لديك أربعة خيارات لإصلاح ذلك:

1. استخدم [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) بدلًا من موجّه الأوامر أو PowerShell. (موصى به)
2. استخدم الخط `MS Gothic`. لاحظ أن الشرطات المائلة العكسية ستتحول إلى رموز الين.
   ![إصلاح تشويش الأحرف](../assets/screenshots/MojibakeFix.png)
3. ثبّت خطوط [HackGen](https://github.com/yuru7/HackGen/releases) واستخدم `HackGen Console NF`.
4. استخدم `-q, --quiet` لعدم عرض الرسائل الختامية التي تحتوي على أحرف يابانية.

## Linux

تحتاج أولًا إلى جعل الملف الثنائي قابلًا للتنفيذ.

```bash
chmod +x ./hayabusa
```

ثم شغّله من الدليل الجذري لـ Hayabusa:

```bash
./hayabusa
```

## macOS

من Terminal أو iTerm2، تحتاج أولًا إلى جعل الملف الثنائي قابلًا للتنفيذ.

```bash
chmod +x ./hayabusa
```

ثم حاول تشغيله من الدليل الجذري لـ Hayabusa:

```bash
./hayabusa
```

في أحدث إصدار من macOS، قد تتلقى خطأ الأمان التالي عند محاولة تشغيله:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

انقر على "Cancel" ثم من System Preferences، افتح "Security & Privacy" ومن علامة التبويب General، انقر على "Allow Anyway".

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

بعد ذلك، حاول تشغيله مرة أخرى.

```bash
./hayabusa
```

سيظهر التحذير التالي، لذا يرجى النقر على "Open".

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

يجب أن تكون الآن قادرًا على تشغيل hayabusa.

## إدخال VHDX


تدعم جميع أوامر فحص سجلات الأحداث الخيار `--vhdx` مع `-f <IMAGE.vhdx>` أو `-d <DIR>`. يبحث الخيار `-d` في المجلد المحدد وثلاثة مستويات من المجلدات الفرعية. داخل الصور، تُفحص جميع وحدات NTFS القابلة للقراءة دون حد العمق هذا.

```bash
./hayabusa dfir-timeline --vhdx -f host.vhdx -w -U -p verbose -o timeline.csv
./hayabusa dfir-timeline --vhdx -d images/ -w -U -p verbose -o timeline.csv
```


تعمل القراءة الأصلية على **Linux وmacOS وWindows** باستخدام واجهة NTFS المحمولة المشتركة مع Juntei. تُقرأ الملفات مباشرة كتدفقات قابلة للبحث وللقراءة فقط، دون FUSE أو برامج تشغيل للتركيب أو صلاحيات مدير أو استخراج مؤقت. تبقى الصور المصدر دون تغيير. تُحفظ مسارات الأدلة بصيغة `host.vhdx!/path/log.evtx`. لا يُدعم BitLocker أو الصور التي تتطلب صورة أصل خارجية.

[English: VHDX input details and limitations](https://yamato-security.github.io/hayabusa/getting-started/running/#vhdx-inputs).
