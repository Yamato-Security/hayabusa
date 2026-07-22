# أوامر التسلسل الزمني لـ DFIR

## معالج المسح

يحتوي الأمر `dfir-timeline` الآن على معالج مسح مُفعَّل افتراضيًا.
الغرض من ذلك هو مساعدة المستخدمين على الاختيار بسهولة لقواعد الكشف التي يرغبون في تفعيلها وفقًا لاحتياجاتهم وتفضيلاتهم.
تستند مجموعات قواعد الكشف التي يتم تحميلها إلى القوائم الرسمية في مشروع Sigma.
التفاصيل موضَّحة في [هذه التدوينة](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
يمكنك بسهولة إيقاف المعالج واستخدام Hayabusa بطريقته التقليدية عن طريق إضافة الخيار `-w, --no-wizard`.

### قواعد Core

تُفعِّل مجموعة قواعد `core` القواعد التي لها حالة `test` أو `stable` ومستوى `high` أو `critical`.
هذه قواعد عالية الجودة وذات ثقة وأهمية عالية ولا ينبغي أن تنتج العديد من النتائج الإيجابية الخاطئة.
حالة القاعدة هي `test` أو `stable` مما يعني أنه لم يتم الإبلاغ عن أي نتائج إيجابية خاطئة لأكثر من 6 أشهر.
ستتطابق القواعد مع تقنيات المهاجمين، أو النشاط المشبوه العام، أو السلوك الخبيث.
وهذا مماثل لاستخدام الخيارات `--exclude-status deprecated,unsupported,experimental --min-level high`.

### قواعد Core+

تُفعِّل مجموعة قواعد `core+` القواعد التي لها حالة `test` أو `stable` ومستوى `medium` أو أعلى.
غالبًا ما تحتاج قواعد `medium` إلى ضبط إضافي حيث قد تتطابق مع تطبيقات معينة، أو سلوك مستخدم مشروع، أو نصوص برمجية خاصة بمؤسسة ما.
وهذا مماثل لاستخدام الخيارات `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### قواعد Core++

تُفعِّل مجموعة قواعد `core++` القواعد التي لها حالة `experimental` أو `test` أو `stable` ومستوى `medium` أو أعلى.
هذه القواعد متطورة للغاية.
يتم التحقق منها مقابل ملفات evtx الأساسية المتاحة في مشروع SigmaHQ ومراجعتها من قبل عدة مهندسي كشف.
بخلاف ذلك فهي غير مختبرة إلى حد كبير في البداية.
استخدم هذه القواعد إذا كنت ترغب في القدرة على اكتشاف التهديدات في أقرب وقت ممكن مقابل التعامل مع عتبة أعلى من النتائج الإيجابية الخاطئة.
وهذا مماثل لاستخدام الخيارات `--exclude-status deprecated,unsupported --min-level medium`.

### قواعد إضافية للتهديدات الناشئة (ET)

تُفعِّل مجموعة قواعد `Emerging Threats (ET)` القواعد التي لها وسم `detection.emerging_threats`.
تستهدف هذه القواعد تهديدات محددة وهي مفيدة بشكل خاص للتهديدات الحالية التي لا تتوفر عنها معلومات كثيرة بعد.
لا ينبغي أن تحتوي هذه القواعد على العديد من النتائج الإيجابية الخاطئة ولكن ستقل أهميتها بمرور الوقت.
عندما لا تكون هذه القواعد مُفعَّلة، فإن ذلك مماثل لاستخدام الخيار `--exclude-tag detection.emerging_threats`.
عند تشغيل Hayabusa بالطريقة التقليدية بدون المعالج، ستُضمَّن هذه القواعد افتراضيًا.

### قواعد إضافية لصيد التهديدات (TH)

تُفعِّل مجموعة قواعد `Threat Hunting (TH)` القواعد التي لها وسم `detection.threat_hunting`.
قد تكتشف هذه القواعد نشاطًا خبيثًا غير معروف، ومع ذلك، سيكون لديها عادةً المزيد من النتائج الإيجابية الخاطئة.
عندما لا تكون هذه القواعد مُفعَّلة، فإن ذلك مماثل لاستخدام الخيار `--exclude-tag detection.threat_hunting`.
عند تشغيل Hayabusa بالطريقة التقليدية بدون المعالج، ستُضمَّن هذه القواعد افتراضيًا.

## تصفية سجلات الأحداث والقواعد المبنية على القناة

اعتبارًا من Hayabusa v2.16.0، نقوم بتفعيل تصفية مبنية على القناة عند تحميل ملفات `.evtx` وقواعد `.yml`.
الغرض هو جعل المسح فعالًا قدر الإمكان عن طريق تحميل ما هو ضروري فقط.
بينما من الممكن وجود عدة مزودين في سجل أحداث واحد، فمن غير الشائع وجود قنوات متعددة داخل ملف evtx واحد.
(المرة الوحيدة التي رأينا فيها ذلك هي عندما قام شخص ما بدمج ملفي evtx مختلفين بشكل مصطنع لمشروع [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).)
يمكننا استخدام ذلك لصالحنا عن طريق التحقق أولًا من حقل `Channel` في السجل الأول لكل ملف `.evtx` محدد للمسح.
كما نتحقق من القنوات التي تستخدمها قواعد `.yml` المحددة في حقل `Channel` للقاعدة.
باستخدام هاتين القائمتين، نقوم فقط بتحميل القواعد التي تستخدم قنوات موجودة فعليًا داخل ملفات `.evtx`.

فعلى سبيل المثال، إذا أراد المستخدم مسح `Security.evtx`، فلن تُستخدم سوى القواعد التي تحدد `Channel: Security`.
لا فائدة من تحميل قواعد كشف أخرى، على سبيل المثال القواعد التي تبحث فقط عن أحداث في سجل `Application`، وما إلى ذلك...
لاحظ أن حقول القناة (مثال: `Channel: Security`) ليست معرَّفة **صراحةً** داخل قواعد Sigma الأصلية.
بالنسبة لقواعد Sigma، يتم تعريف حقول القناة ومعرفات الأحداث **ضمنيًا** باستخدام حقلي `service` و `category` تحت `logsource`. (مثال: `service: security`)
عند تنسيق قواعد Sigma في مستودع [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)، نقوم بإزالة تجريد حقل `logsource` وتعريف حقول القناة ومعرف الحدث صراحةً.
نشرح كيف ولماذا نقوم بذلك بالتفصيل [هنا](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

حاليًا، هناك قاعدتا كشف فقط لا تحتويان على `Channel` معرَّف ومخصصتان لمسح جميع ملفات `.evtx` وهما التاليتان:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

إذا كنت ترغب في استخدام هاتين القاعدتين ومسح جميع القواعد مقابل ملفات `.evtx` المحمَّلة فستحتاج إلى إضافة الخيار `-A, --enable-all-rules` في الأمر `dfir-timeline`.
في اختباراتنا المرجعية، تعطي تصفية القواعد عادةً تحسينًا في السرعة بنسبة 20% إلى 10 أضعاف اعتمادًا على الملفات التي يتم مسحها وبالطبع تستخدم ذاكرة أقل.

تُستخدم تصفية القناة أيضًا عند تحميل ملفات `.evtx`.
على سبيل المثال، إذا حددت قاعدة تبحث عن أحداث بقناة `Security`، فلا فائدة من تحميل ملفات `.evtx` التي ليست من سجل `Security`.
في اختباراتنا المرجعية، يعطي هذا فائدة في السرعة بحوالي 10% مع عمليات المسح العادية وزيادة في الأداء تصل إلى أكثر من 60%+ عند المسح بقاعدة واحدة.
إذا كنت متأكدًا من استخدام قنوات متعددة داخل ملف `.evtx` واحد، على سبيل المثال استخدم شخص ما أداة لدمج عدة ملفات `.evtx` معًا، فيمكنك تعطيل هذه التصفية باستخدام الخيار `-a, --scan-all-evtx-files` في الأمر `dfir-timeline`.

> ملاحظة: تعمل تصفية القناة فقط مع ملفات `.evtx` وستتلقى خطأ إذا حاولت تحميل سجلات الأحداث من ملف JSON باستخدام `-J, --json-input` وحددت أيضًا `-A` أو `-a`.

## الأمر `dfir-timeline`

ينشئ الأمر `dfir-timeline` تسلسلًا زمنيًا جنائيًا للأحداث. اختر تنسيق الإخراج باستخدام `-t, --output-type`: `csv` (الافتراضي)، أو `json`، أو `jsonl`. القيمة غير حساسة لحالة الأحرف (مثال: `-t JSONL`).

- **CSV** جيد لاستيراد التسلسلات الزمنية الأصغر (عادةً أقل من 2 جيجابايت) إلى أدوات مثل LibreOffice أو Timeline Explorer (توضع جميع حقول الحدث في عمود `Details` واحد كبير).
- **JSON** هو الأفضل للتحليل الأكثر تفصيلًا للنتائج الكبيرة باستخدام أدوات مثل `jq`، حيث تكون حقول `Details` منفصلة.
- **JSONL** أسرع وينتج ملفًا أصغر من JSON، وهو مثالي للاستيراد إلى أدوات مثل Elastic Stack.

تنطبق خيارات **CSV Output** وهي `-M, --multiline` و `-S, --tab-separator` و `-R, --remove-duplicate-data` على إخراج CSV فقط وستنتج خطأ إذا تم دمجها مع `-t` غير CSV.

```
  hayabusa.exe dfir-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort results before saving the file (warning: this uses much more memory!)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)
      --threads <NUMBER>               Number of threads (default: optimal number for performance)
  -V, --validate-checksums             Enable checksum validation

Filtering:
  -E, --eid-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --geo-ip <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --html-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline to a file (ex: results.csv)
  -t, --output-type <OUTPUT_FORMAT>  Output format: csv (default), json, or jsonl (case-insensitive, e.g. -t JSONL) [default: csv] [possible values: csv, json, jsonl]
  -p, --profile <PROFILE>            Specify output profile
  -X, --remove-duplicate-detections  Remove duplicate detections (sort required)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode, sort required)

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --utc               Output time in UTC format (default: local time)

CSV Output:
  -M, --multiline              Separate event field information by newline characters (CSV output only)
  -R, --remove-duplicate-data  Duplicate field data will be replaced with "DUP" (CSV output only, sort required)
  -S, --tab-separator          Separate event field information by tabs (CSV output only)
```

### أمثلة على الأمر `dfir-timeline`

* تشغيل hayabusa على ملف سجل أحداث Windows واحد باستخدام الملف الشخصي `standard` الافتراضي:

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* تشغيل hayabusa على دليل sample-evtx الذي يحتوي على عدة ملفات سجلات أحداث Windows باستخدام الملف الشخصي verbose:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* التصدير إلى ملف CSV واحد لمزيد من التحليل باستخدام LibreOffice أو Timeline Explorer أو Elastic Stack وما إلى ذلك... وتضمين جميع معلومات الحقول (تحذير: سيصبح حجم ملف الإخراج أكبر بكثير مع الملف الشخصي `super-verbose`!):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* الإخراج بتنسيق JSON بدلًا من CSV (للتحليل باستخدام `jq`، وما إلى ذلك...):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* الإخراج بتنسيق JSONL (للاستيراد إلى Elastic Stack، وما إلى ذلك...؛ `-t` غير حساس لحالة الأحرف):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* تفعيل تصفية EID (معرف الحدث):

> ملاحظة: سيؤدي تفعيل تصفية EID إلى تسريع التحليل بنحو 10-15% في اختباراتنا ولكن هناك احتمال لتفويت بعض التنبيهات.

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* تشغيل قواعد hayabusa فقط (الافتراضي هو تشغيل جميع القواعد في `-r .\rules`):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* تشغيل قواعد hayabusa فقط للسجلات المُفعَّلة افتراضيًا على Windows:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* تشغيل قواعد hayabusa فقط لسجلات sysmon:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* تشغيل قواعد sigma فقط:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* تفعيل القواعد المهملة (تلك التي لها `status` معلَّمة بـ `deprecated`) والقواعد المزعجة (تلك التي يكون معرف القاعدة فيها مدرجًا في `.\rules\config\noisy_rules.txt`):

> ملاحظة: مؤخرًا، أصبحت القواعد المهملة موجودة في دليل منفصل في مستودع sigma لذا لم تعد مُضمَّنة افتراضيًا في Hayabusa.
> لذلك، من المحتمل أنه ليس لديك حاجة لتفعيل القواعد المهملة.

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* تشغيل القواعد فقط لتحليل عمليات تسجيل الدخول والإخراج بالمنطقة الزمنية UTC:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* التشغيل على جهاز Windows مباشر (يتطلب صلاحيات المسؤول) واكتشاف التنبيهات فقط (السلوك الخبيث المحتمل):

```
hayabusa.exe dfir-timeline -l -m low
```

* طباعة المعلومات المُفصَّلة (مفيد لتحديد الملفات التي تستغرق وقتًا طويلًا للمعالجة، وأخطاء التحليل، وما إلى ذلك...):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* مثال على الإخراج المُفصَّل:

تحميل القواعد:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

الأخطاء أثناء المسح:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* الإخراج بتنسيق CSV متوافق للاستيراد إلى [Timesketch](https://timesketch.org/):

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* وضع كتم الأخطاء:
افتراضيًا، سيحفظ hayabusa رسائل الخطأ في ملفات سجل الأخطاء.
إذا كنت لا تريد حفظ رسائل الخطأ، فيرجى إضافة `-Q`.

### متقدم - إثراء السجلات بـ GeoIP

يمكنك إضافة معلومات GeoIP (منظمة ASN والمدينة والبلد) إلى حقول SrcIP (عنوان IP المصدر) وحقول TgtIP (عنوان IP الهدف) باستخدام بيانات تحديد الموقع الجغرافي المجانية GeoLite2.

الخطوات:

1. أولًا قم بالتسجيل للحصول على حساب MaxMind [هنا](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. قم بتنزيل ملفات `.mmdb` الثلاثة من [صفحة التنزيل](https://www.maxmind.com/en/accounts/current/geoip/downloads) واحفظها في دليل. يجب أن تكون أسماء الملفات `GeoLite2-ASN.mmdb`	و `GeoLite2-City.mmdb` و `GeoLite2-Country.mmdb`.
3. عند تشغيل الأمر `dfir-timeline`، أضف الخيار `-G` متبوعًا بالدليل الذي يحتوي على قواعد بيانات MaxMind.

* عند استخدام إخراج CSV، سيتم إخراج الأعمدة الستة التالية بشكل إضافي: `SrcASN` و `SrcCity` و `SrcCountry` و `TgtASN` و `TgtCity` و `TgtCountry`.
* عند استخدام إخراج JSON/JSONL، ستتم إضافة نفس الحقول `SrcASN` و `SrcCity` و `SrcCountry` و `TgtASN` و `TgtCity` و `TgtCountry` إلى كائن `Details`، ولكن فقط إذا كانت تحتوي على معلومات.

* عندما يكون `SrcIP` أو `TgtIP` هو localhost (`127.0.0.1`، `::1`، وما إلى ذلك...)، سيتم إخراج `SrcASN` أو `TgtASN` كـ `Local`.
* عندما يكون `SrcIP` أو `TgtIP` عنوان IP خاصًا (`10.0.0.0/8`، `fe80::/10`، وما إلى ذلك...)، سيتم إخراج `SrcASN` أو `TgtASN` كـ `Private`.

#### ملف تكوين GeoIP

أسماء الحقول التي تحتوي على عناوين IP المصدر والهدف التي يتم البحث عنها في قواعد بيانات GeoIP معرَّفة في `rules/config/geoip_field_mapping.yaml`.
يمكنك الإضافة إلى هذه القائمة إذا لزم الأمر.
يوجد أيضًا قسم تصفية في هذا الملف يحدد الأحداث التي يتم استخراج معلومات عنوان IP منها.

#### التحديثات التلقائية لقواعد بيانات GeoIP

يتم تحديث قواعد بيانات MaxMind GeoIP كل أسبوعين.
يمكنك تثبيت أداة `geoipupdate` من MaxMind [هنا](https://github.com/maxmind/geoipupdate) من أجل تحديث قواعد البيانات هذه تلقائيًا.

الخطوات على macOS:

1. `brew install geoipupdate`
2. عدِّل `/usr/local/etc/GeoIP.conf` أو `/opt/homebrew/etc/GeoIP.conf`: أدخل `AccountID` و `LicenseKey` اللذين تنشئهما بعد تسجيل الدخول إلى موقع MaxMind. تأكد من أن سطر `EditionIDs` يقول `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. شغِّل `geoipupdate`.
4. أضف `-G /usr/local/var/GeoIP` أو `-G /opt/homebrew/var/GeoIP` عندما تريد إضافة معلومات GeoIP.

الخطوات على Windows:

1. قم بتنزيل أحدث ملف Windows الثنائي (مثال: `geoipupdate_4.10.0_windows_amd64.zip`) من صفحة [الإصدارات](https://github.com/maxmind/geoipupdate/releases).
2. عدِّل `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: أدخل `AccountID` و `LicenseKey` اللذين تنشئهما بعد تسجيل الدخول إلى موقع MaxMind. تأكد من أن سطر `EditionIDs` يقول `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. شغِّل الملف التنفيذي `geoipupdate`.

الخطوات على Linux:

1. ثبِّت باستخدام `sudo apt install geoip-update`.
2. عدِّل ملف الإعداد باستخدام `sudo nano /etc/GeoIP.conf`.
3. حدِّث ملفات قاعدة البيانات باستخدام `sudo geoipupdate`.
4. أضف `-G /var/lib/GeoIP/` عندما تريد إضافة معلومات GeoIP.

### ملفات تكوين الأمر `dfir-timeline`

`./rules/config/channel_abbreviations.txt`: تعيينات أسماء القنوات واختصاراتها.

`./rules/config/default_details.txt`: ملف التكوين لمعلومات الحقل الافتراضية (حقل `%Details%`) التي يجب إخراجها إذا لم يتم تحديد سطر `details:` في القاعدة.
يستند هذا إلى اسم المزود ومعرفات الأحداث.

`./rules/config/eventkey_alias.txt`: يحتوي هذا الملف على تعيينات الأسماء المستعارة المختصرة للحقول وأسماء الحقول الأصلية الأطول الخاصة بها.

مثال:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

إذا لم يكن الحقل معرَّفًا هنا، فسيتحقق Hayabusa تلقائيًا من الحقل تحت `Event.EventData`.

`./rules/config/exclude_rules.txt`: يحتوي هذا الملف على قائمة بمعرفات القواعد التي سيتم استبعادها من الاستخدام.
عادةً ما يكون هذا بسبب أن قاعدة قد حلَّت محل أخرى أو أن القاعدة لا يمكن استخدامها في المقام الأول.
مثل جدران الحماية وأنظمة كشف التسلل، ستتطلب أي أداة مبنية على التواقيع بعض الضبط لتناسب بيئتك لذا قد تحتاج إلى استبعاد قواعد معينة بشكل دائم أو مؤقت.
يمكنك إضافة معرف قاعدة (مثال: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) إلى `./rules/config/exclude_rules.txt` من أجل تجاهل أي قاعدة لا تحتاجها أو لا يمكن استخدامها.

`./rules/config/noisy_rules.txt`: يحتوي هذا الملف على قائمة بمعرفات القواعد المُعطَّلة افتراضيًا ولكن يمكن تفعيلها عن طريق تفعيل القواعد المزعجة بالخيار `-n, --enable-noisy-rules`.
عادةً ما تكون هذه القواعد مزعجة بطبيعتها أو بسبب النتائج الإيجابية الخاطئة.

`./rules/config/target_event_IDs.txt`: سيتم مسح معرفات الأحداث المحددة في هذا الملف فقط إذا كانت تصفية EID مُفعَّلة.
افتراضيًا، سيمسح Hayabusa جميع الأحداث، ولكن إذا كنت تريد تحسين الأداء، فيرجى استخدام الخيار `-E, --eid-filter`.
عادةً ما يؤدي هذا إلى تحسين السرعة بنسبة 10~25%.

## الأمر `level-tuning`

سيتيح لك الأمر `level-tuning` ضبط مستويات التنبيه للقواعد، إما برفع مستوى المخاطر أو خفضه كما ترغب.
يستخدم هذا الأمر ملف تكوين للكتابة فوق مستويات المخاطر (حقل `level`) للقواعد في مجلد `rules`.

> تحذير: في كل مرة تشغِّل فيها الأمر `update-rules`، سيعود مستوى المخاطر إلى القيمة الأصلية لذا ستحتاج إلى تشغيل الأمر `level-tuning` مرة أخرى بعد ذلك.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### أمثلة على الأمر `level-tuning`

* الاستخدام العادي: `hayabusa.exe level-tuning`
* ضبط مستويات تنبيه القواعد بناءً على ملف التكوين المخصص الخاص بك: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### ملف تكوين `level-tuning`

سيقدِّر مؤلفو قواعد Hayabusa و Sigma مستوى المخاطر المناسب للتنبيه عند كتابة قواعدهم.
ومع ذلك، تكون مستويات المخاطر أحيانًا غير متسقة وقد يختلف مستوى المخاطر الفعلي أيضًا وفقًا لبيئتك.
توفر Yamato Security وتصون ملف تكوين في `./rules/config/level_tuning.txt` يمكنك استخدامه لضبط قواعدك أيضًا.

عينة من `./rules/config/level_tuning.txt`:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

في هذه الحالة، سيتم إعادة كتابة `level` للقاعدة التي لها `id` يساوي `570ae5ec-33dc-427c-b815-db86228ad43e` في دليل القواعد إلى `informational`.
المستويات المحتملة للتعيين هي `critical` و `high` و `medium` و `low` و `informational`.

> تحذير: سيتم أيضًا تحديث ملف التكوين `./rules/config/level_tuning.txt` إلى أحدث إصدار في مستودع hayabusa-rules في كل مرة تشغِّل فيها `update-rules`.
> لذلك، إذا أجريت تغييرات على هذا الملف، فستفقد تلك التغييرات!
> إذا كنت تريد الاحتفاظ بملف تكوين لنفسك، فأنشئ ملف تكوين في `./config/level_tuning.txt` وشغِّل `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> يمكنك أيضًا أولًا إجراء ضبط المستوى باستخدام ملف التكوين المقدَّم من Yamato Security ثم إجراء مزيد من الضبط باستخدام ملف التكوين الخاص بك.

## الأمر `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## الأمر `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### أمثلة على الأمر `set-default-profile`

* تعيين الملف الشخصي الافتراضي إلى `minimal`: `hayabusa.exe set-default-profile minimal`
* تعيين الملف الشخصي الافتراضي إلى `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## الأمر `update-rules`

سيقوم الأمر `update-rules` بمزامنة مجلد `rules` مع [مستودع github لقواعد Hayabusa](https://github.com/Yamato-Security/hayabusa-rules)، وتحديث القواعد وملفات التكوين.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### مثال على الأمر `update-rules`

ستنفِّذ هذا عادةً ببساطة: `hayabusa.exe update-rules`
