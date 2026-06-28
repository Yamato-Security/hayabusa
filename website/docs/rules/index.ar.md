# قواعد Hayabusa

تُكتب قواعد كشف Hayabusa بتنسيق YML شبيه بتنسيق sigma وتوجد في مجلد `rules`.
تُستضاف القواعد على [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) لذا يُرجى إرسال أي مشكلات وطلبات سحب خاصة بالقواعد هناك بدلاً من مستودع Hayabusa الرئيسي.

راجع [إنشاء ملفات القواعد](creating-rules.md) و[حقول الكشف](detection-fields.md) و[ارتباطات Sigma](correlations.md) في هذا القسم لفهم تنسيق القواعد وكيفية إنشاء القواعد. (المصدر: [مستودع hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).)

يجب وضع جميع القواعد من مستودع hayabusa-rules في مجلد `rules`.
تُعتبر قواعد المستوى `informational` بمثابة `events`، بينما يُعتبر أي شيء بمستوى `level` يساوي `low` أو أعلى بمثابة `alerts`.

ينقسم هيكل دليل قواعد hayabusa إلى دليلين:

* `builtin`: السجلات التي يمكن إنشاؤها بواسطة وظائف Windows المدمجة.
* `sysmon`: السجلات التي يتم إنشاؤها بواسطة [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

تُقسَّم القواعد كذلك إلى أدلة حسب نوع السجل (مثال: Security وSystem وغيرها...) وتُسمى بالتنسيق التالي:

يُرجى مراجعة القواعد الحالية لاستخدامها كقالب في إنشاء قواعد جديدة أو للتحقق من منطق الكشف.

## قواعد Sigma مقابل Hayabusa (المتوافقة مع Sigma المدمجة)

يدعم Hayabusa قواعد Sigma بشكل أصلي مع استثناء وحيد وهو التعامل مع حقول `logsource` داخلياً.
من أجل تقليل النتائج الإيجابية الخاطئة، يجب تمرير قواعد Sigma عبر المحوّل الخاص بنا الموضح [هنا](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md).
سيؤدي هذا إلى إضافة `Channel` و`EventID` الصحيحين، وإجراء تعيين الحقول لفئات معينة مثل `process_creation`.

تتوافق جميع قواعد Hayabusa تقريباً مع تنسيق Sigma لذا يمكنك استخدامها تماماً مثل قواعد Sigma للتحويل إلى تنسيقات SIEM أخرى.
صُممت قواعد Hayabusa حصرياً لتحليل سجل أحداث Windows ولها الفوائد التالية:

1. حقل `details` إضافي لعرض معلومات إضافية مأخوذة من الحقول المفيدة فقط في السجل.
2. تم اختبارها جميعاً مقابل سجلات عينة ومن المعروف أنها تعمل.
3. مُجمِّعات إضافية غير موجودة في sigma، مثل `|equalsfield` و`|endswithfield`.

على حد علمنا، يوفر hayabusa أكبر دعم أصلي لقواعد sigma من بين أي أداة مفتوحة المصدر لتحليل سجل أحداث Windows.
