# أوامر التهيئة

## أمر `config-critical-systems`

سيحاول هذا الأمر تلقائيًا العثور على الأنظمة الحرجة مثل وحدات التحكم بالنطاق وخوادم الملفات وإضافتها إلى ملف التهيئة `./config/critical_systems.txt` بحيث تزداد جميع التنبيهات بمستوى واحد.
سيبحث عن أحداث Security 4768 (طلب Kerberos TGT) لتحديد ما إذا كان وحدة تحكم بالنطاق.
سيبحث عن أحداث Security 5145 (الوصول إلى ملف مشاركة الشبكة) لتحديد ما إذا كان خادم ملفات.
أي أسماء مضيفين تُضاف إلى ملف `critical_systems.txt` سيتم زيادة جميع تنبيهاتها التي تتجاوز المستوى المنخفض بمستوى واحد بحد أقصى مستوى `emergency`.

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  دليل يحتوي على ملفات .evtx متعددة
  -f, --file <FILE>      مسار ملف .evtx واحد

Display Settings:
  -K, --no-color  تعطيل إخراج الألوان
  -q, --quiet     الوضع الصامت: عدم عرض شعار البدء

General Options:
  -h, --help  عرض قائمة المساعدة
```

### أمثلة على أمر `config-critical-systems`

* ابحث في الدليل `../hayabusa-sample-evtx` عن وحدات التحكم بالنطاق وخوادم الملفات:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
