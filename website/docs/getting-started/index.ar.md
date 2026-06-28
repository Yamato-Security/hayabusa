# التنزيلات

يرجى تنزيل أحدث إصدار مستقر من Hayabusa مع الملفات الثنائية المُجمَّعة أو ترجمة الكود المصدري من صفحة [Releases](https://github.com/Yamato-Security/hayabusa/releases).

نوفّر ملفات ثنائية للمعماريات التالية:
- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [لسبب ما لا يعمل الملف الثنائي Linux ARM MUSL بشكل صحيح](https://github.com/Yamato-Security/hayabusa/issues/1332) لذلك لا نوفّر ذلك الملف الثنائي. الأمر خارج عن سيطرتنا، لذا نخطط لتوفيره في المستقبل عندما يتم إصلاحه.

## حزم الاستجابة المباشرة لـ Windows

اعتبارًا من v2.18.0، نوفّر حزم Windows خاصة تستخدم قواعد مُرمَّزة بطريقة XOR مُقدَّمة في ملف واحد بالإضافة إلى جميع ملفات الإعدادات مدمجة في ملف واحد (مُستضافة في [مستودع hayabusa-encoded-rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
ما عليك سوى تنزيل حزم zip التي تحتوي على `live-response` في اسمها.
تتضمّن ملفات zip ثلاثة ملفات فقط: الملف الثنائي لـ Hayabusa، وملف القواعد المُرمَّز بطريقة XOR، وملف الإعدادات.
الغرض من حزم الاستجابة المباشرة هذه هو أنه عند تشغيل Hayabusa على نقاط نهاية العملاء، نريد التأكد من أن برامج فحص مكافحة الفيروسات مثل Windows Defender لا تُصدر نتائج إيجابية خاطئة على ملفات قواعد `.yml`.
كما نريد تقليل عدد الملفات التي تُكتب إلى النظام إلى الحد الأدنى حتى لا يتم استبدال آثار التحليل الجنائي مثل USN Journal.
