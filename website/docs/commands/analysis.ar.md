# أوامر التحليل

## أمر `computer-metrics`

يمكنك استخدام أمر `computer-metrics` للتحقق من عدد الأحداث وفقًا لكل جهاز كمبيوتر مُعرّف في حقل `<System><Computer>`.
انتبه إلى أنه لا يمكنك الاعتماد كليًا على حقل `Computer` للفصل بين الأحداث حسب جهاز الكمبيوتر الأصلي الخاص بها.
سيستخدم Windows 11 أحيانًا أسماء `Computer` مختلفة تمامًا عند الحفظ في سجلات الأحداث.
كما أن Windows 10 سيسجّل أحيانًا اسم `Computer` بأحرف صغيرة بالكامل.
لا يستخدم هذا الأمر أي قواعد كشف لذا سيحلّل جميع الأحداث.
هذا أمر جيد لتشغيله لمعرفة أي أجهزة الكمبيوتر تحتوي على أكبر عدد من السجلات بسرعة.
بهذه المعلومات، يمكنك بعد ذلك استخدام خياري `--include-computer` أو `--exclude-computer` عند إنشاء جداولك الزمنية لجعل إنشاء الجدول الزمني أكثر كفاءة من خلال إنشاء جداول زمنية متعددة وفقًا لجهاز الكمبيوتر أو استبعاد الأحداث من أجهزة كمبيوتر معينة.

```
Usage: computer-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)

Filtering:
      --time-offset <OFFSET>  Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)

Output:
  -o, --output <FILE>  Save the results in CSV format (ex: computer-metrics.csv)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information
```

### أمثلة على أمر `computer-metrics`

* طباعة مقاييس اسم الكمبيوتر من دليل: `hayabusa.exe computer-metrics -d ../logs`
* حفظ النتائج في ملف CSV: `hayabusa.exe computer-metrics -d ../logs -o computer-metrics.csv`

### لقطة شاشة لـ `computer-metrics`

![computer-metrics screenshot](../assets/screenshots/ComputerMetrics.png)

## أمر `eid-metrics`

يمكنك استخدام أمر `eid-metrics` لطباعة العدد الإجمالي والنسبة المئوية لمعرّفات الأحداث (حقل `<System><EventID>`) مفصولة حسب القنوات.
لا يستخدم هذا الأمر أي قواعد كشف لذا سيفحص جميع الأحداث.

```
Usage: eid-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)

Output:
  -b, --disable-abbreviations  Disable abbreviations
  -o, --output <FILE>          Save the Metrics in CSV format (ex: metrics.csv)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --utc               Output time in UTC format (default: local time)
```

### أمثلة على أمر `eid-metrics`

* طباعة مقاييس معرّف الحدث من ملف واحد: `hayabusa.exe eid-metrics -f Security.evtx`
* طباعة مقاييس معرّف الحدث من دليل: `hayabusa.exe eid-metrics -d ../logs`
* حفظ النتائج في ملف CSV: `hayabusa.exe eid-metrics -f Security.evtx -o eid-metrics.csv`

### ملف إعداد أمر `eid-metrics`

يتم تعريف القناة ومعرّفات الأحداث وعناوين الأحداث في `rules/config/channel_eid_info.txt`.

مثال:
```
Channel,EventID,EventTitle
Microsoft-Windows-Sysmon/Operational,1,Process Creation.
Microsoft-Windows-Sysmon/Operational,2,File Creation Timestamp Changed. (Possible Timestomping)
Microsoft-Windows-Sysmon/Operational,3,Network Connection.
Microsoft-Windows-Sysmon/Operational,4,Sysmon Service State Changed.
```

### لقطة شاشة لـ `eid-metrics`

![eid-metrics screenshot](../assets/screenshots/EID-Metrics.png)

## أمر `expand-list`

استخراج العناصر النائبة `expand` من مجلد القواعد.
هذا مفيد عند إنشاء ملفات الإعداد لاستخدام أي قاعدة تستخدم معدّل الحقل `expand`.
لاستخدام قواعد `expand`، تحتاج فقط إلى إنشاء ملف `.txt` باسم معدّل الحقل `expand` ضمن دليل `./config/expand/`، ووضع جميع القيم التي تريد التحقق منها داخل الملف.

على سبيل المثال، إذا كان منطق `detection` للقاعدة هو:
```yaml
detection:
    selection:
        EventID: 5145
        RelativeTargetName|contains: '\winreg'
    filter_main:
        IpAddress|expand: '%Admins_Workstations%'
    condition: selection and not filter_main
```

فسوف تنشئ الملف النصي `./config/expand/Admins_Workstations.txt` وتضع فيه قيمًا مثل:
```
AdminWorkstation1
AdminWorkstation2
AdminWorkstation3
```

سيؤدي هذا أساسًا إلى التحقق من نفس المنطق مثل:
```
- IpAddress: 'AdminWorkstation1'
- IpAddress: 'AdminWorkstation2'
- IpAddress: 'AdminWorkstation3'
```

إذا لم يكن ملف الإعداد موجودًا، فسيظل Hayabusa يحمّل قاعدة `expand` لكن سيتجاهلها.

```
Usage:  expand-list <INPUT> [OPTIONS]

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify rule directory (default: ./rules)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

### أمثلة على أمر `expand-list`

* استخراج معدّلات الحقل `expand` من دليل `rules` الافتراضي: `hayabusa.exe expand-list`
* استخراج معدّلات الحقل `expand` من دليل `sigma`: `hayabusa.exe eid-metrics -r ../sigma`

### نتائج `expand-list`

```
5 unique expand placeholders found:
Admins_Workstations
DC-MACHINE-NAME
Workstations
internal_domains
domain_controller_hostnames
```

## أمر `extract-base64`

سيستخرج هذا الأمر سلاسل base64 من الأحداث التالية، ويفك تشفيرها ويخبرك بنوع الترميز المستخدم.
  * Security 4688 CommandLine
  * Sysmon 1 CommandLine, ParentCommandLine
  * System 7045 ImagePath
  * PowerShell Operational 4104
  * PowerShell Operational 4103

```
Usage:  extract-base64 <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)

Output:
  -o, --output <FILE>  Extract Base64 strings

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --utc               Output time in UTC format (default: local time)
```

### أمثلة على أمر `extract-base64`

* فحص دليل وإخراج النتائج إلى الطرفية: `hayabusa.exe  extract-base64 -d ../hayabusa-sample-evtx`
* فحص دليل وإخراج النتائج إلى ملف CSV: `hayabusa.exe eid-metrics -r ../sigma -o base64-extracted.csv`

### نتائج `extract-base64`

عند الإخراج إلى الطرفية، نظرًا لأن المساحة محدودة، يتم عرض الحقول التالية فقط:
  * Timestamp
  * Computer
  * Base64 String
  * Decoded String (if not binary)

عند الحفظ في ملف CSV، يتم حفظ الحقول التالية:
  * Timestamp
  * Computer
  * Base64 String
  * Decoded String (if not binary)
  * Original Field
  * Length
  * Binary (`Y/N`)
  * Double Encoding (when `Y`, it usually is malicious)
  * Encoding Type
  * File Type
  * Event
  * Record ID
  * File Name

## أمر `log-metrics`

يمكنك استخدام أمر `log-metrics` لطباعة البيانات الوصفية التالية داخل سجلات الأحداث:
  * Filename
  * Computer names
  * Number of events
  * First timestamp
  * Last timestamp
  * Channels
  * Providers

لا يستخدم هذا الأمر أي قواعد كشف لذا سيفحص جميع الأحداث.

```
Usage: log-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)

Output:
  -b, --disable-abbreviations  Disable abbreviations
  -M, --multiline              Output event field information in multiple rows for CSV output
  -o, --output <FILE>          Save the Metrics in CSV format (ex: metrics.csv)
  -S, --tab-separator          Separate event field information by tabs

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --utc               Output time in UTC format (default: local time)
```

### أمثلة على أمر `log-metrics`

* طباعة مقاييس معرّف الحدث من ملف واحد: `hayabusa.exe log-metrics -f Security.evtx`
* طباعة مقاييس معرّف الحدث من دليل: `hayabusa.exe log-metrics -d ../logs`
* حفظ النتائج في ملف CSV: `hayabusa.exe log-metrics -d ../logs -o eid-metrics.csv`

### لقطة شاشة لـ `log-metrics`

![log-metrics screenshot](../assets/screenshots/LogMetrics.png)

## أمر `logon-summary`

يمكنك استخدام أمر `logon-summary` لإخراج ملخص معلومات تسجيل الدخول (أسماء مستخدمي تسجيل الدخول وعدد عمليات تسجيل الدخول الناجحة والفاشلة).
يمكنك عرض معلومات تسجيل الدخول لملف evtx واحد باستخدام `-f` أو ملفات evtx متعددة باستخدام خيار `-d`.

تؤخذ عمليات تسجيل الدخول الناجحة من الأحداث التالية:
  * `Security 4624` (Successful Logon)
  * `RDS-LSM 21` (Remote Desktop Service Local Session Manager Logon)
  * `RDS-GTW 302` (Remote Desktop Service Gateway Logon)
  
تؤخذ عمليات تسجيل الدخول الفاشلة من أحداث `Security 4625`.

```
Usage: logon-summary <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -o, --output <FILENAME-PREFIX>  Save the logon summary to two CSV files (ex: -o logon-summary)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --utc               Output time in UTC format (default: local time)
```

### أمثلة على أمر `logon-summary`

* طباعة ملخص تسجيل الدخول: `hayabusa.exe logon-summary -f Security.evtx`
* حفظ نتائج ملخص تسجيل الدخول: `hayabusa.exe logon-summary -d ../logs -o logon-summary.csv`

### لقطات شاشة لـ `logon-summary`

![logon-summary successful logons screenshot](../assets/screenshots/LogonSummarySuccessfulLogons.png)

![logon-summary failed logons screenshot](../assets/screenshots/LogonSummaryFailedLogons.png)

## أمر `pivot-keywords-list`

يمكنك استخدام أمر `pivot-keywords-list` لإنشاء قائمة بالكلمات المفتاحية المحورية الفريدة لتحديد المستخدمين وأسماء المضيفين والعمليات وما إلى ذلك غير الطبيعية بسرعة، بالإضافة إلى ربط الأحداث.

مهم: بشكل افتراضي، سيعيد hayabusa النتائج من جميع الأحداث (المعلوماتية والأعلى) لذا نوصي بشدة بدمج أمر `pivot-keywords-list` مع خيار `-m, --min-level`.
على سبيل المثال، ابدأ بإنشاء كلمات مفتاحية من التنبيهات `critical` فقط باستخدام `-m critical` ثم استمر مع `-m high` و `-m medium` وما إلى ذلك.
على الأرجح ستكون هناك كلمات مفتاحية شائعة في نتائجك تطابق العديد من الأحداث الطبيعية، لذا بعد التحقق يدويًا من النتائج وإنشاء قائمة بالكلمات المفتاحية الفريدة في ملف واحد، يمكنك بعد ذلك إنشاء جدول زمني مُضيّق للنشاط المشبوه باستخدام أمر مثل `grep -f keywords.txt timeline.csv`.

```
Usage: pivot-keywords-list <INPUT> [OPTIONS]

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
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --eid-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -o, --output <FILENAME-PREFIX>  Save pivot words to separate files (ex: PivotKeywords)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information
```

### أمثلة على أمر `pivot-keywords-list`

* إخراج الكلمات المفتاحية المحورية إلى الشاشة: `hayabusa.exe pivot-keywords-list -d ../logs -m critical`
* إنشاء قائمة بالكلمات المفتاحية المحورية من التنبيهات الحرجة وحفظ النتائج. (سيتم حفظ النتائج في `keywords-Ip Addresses.txt` و `keywords-Users.txt` وما إلى ذلك):

```
hayabusa.exe pivot-keywords-list -d ../logs -m critical -o keywords`
```

### ملف إعداد `pivot-keywords-list`

يمكنك تخصيص الكلمات المفتاحية التي تريد البحث عنها عن طريق تحرير `./rules/config/pivot_keywords.txt`.
[هذه الصفحة](https://github.com/Yamato-Security/hayabusa-rules/blob/main/config/pivot_keywords.txt) هي الإعداد الافتراضي.

التنسيق هو `KeywordName.FieldName`. على سبيل المثال، عند إنشاء قائمة `Users`، سيُدرج hayabusa جميع القيم في حقول `SubjectUserName` و `TargetUserName` و `User`.

## أمر `search`

سيتيح لك أمر `search` البحث بالكلمات المفتاحية في جميع الأحداث.
(ليس فقط نتائج كشف Hayabusa.)
هذا مفيد لتحديد ما إذا كان هناك أي دليل في الأحداث التي لا يكتشفها Hayabusa.

```
Usage: hayabusa.exe search <INPUT> <--keywords "<KEYWORDS>" OR --regex "<REGEX>"> [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
  -v, --verbose   Output verbose information

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)
  -s, --sort                           Sort results before saving the file (warning: this uses much more memory!)

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

Filtering:
  -a, --and-logic              Search keywords with AND logic (default: OR)
  -F, --filter <FILTER...>     Filter by specific field(s)
  -i, --ignore-case            Case-insensitive keyword search
  -k, --keyword <KEYWORD...>   Search by keyword(s)
  -r, --regex <REGEX>          Search by regular expression
      --time-offset <OFFSET>   Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>    End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>  Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations  Disable abbreviations
  -J, --json-output            Save the search results in JSON format (ex: -J -o results.json)
  -L, --jsonl-output           Save the search results in JSONL format (ex: -L -o results.jsonl)
  -M, --multiline              Output event field information in multiple rows for CSV output
  -o, --output <FILE>          Save the search results in CSV format (ex: search.csv)
  -S, --tab-separator          Separate event field information by tabs

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --utc               Output time in UTC format (default: local time)
```

### أمثلة على أمر `search`

* البحث في دليل `../hayabusa-sample-evtx` عن الكلمة المفتاحية `mimikatz`:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz"
```

> ملاحظة: ستطابق الكلمة المفتاحية إذا تم العثور على `mimikatz` في أي مكان في البيانات. إنها ليست مطابقة تامة.

* البحث في دليل `../hayabusa-sample-evtx` عن الكلمات المفتاحية `mimikatz` أو `kali`:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -k "kali"
```

* البحث في دليل `../hayabusa-sample-evtx` عن الكلمة المفتاحية `mimikatz` مع تجاهل حالة الأحرف:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -i
```

* البحث في دليل `../hayabusa-sample-evtx` عن عناوين IP باستخدام التعبيرات النمطية:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
```

* البحث في دليل `../hayabusa-sample-evtx` وعرض جميع الأحداث حيث يكون حقل `WorkstationName` هو `kali`:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r ".*" -F WorkstationName:"kali"
```

> ملاحظة: `.*` هو التعبير النمطي للمطابقة على كل حدث.

### ملفات إعداد أمر `search`

`./rules/config/channel_abbreviations.txt`: تعيينات أسماء القنوات واختصاراتها.
