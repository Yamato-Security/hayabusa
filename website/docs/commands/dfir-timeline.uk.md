# Команди DFIR-таймлайну

## Майстер сканування

Команди `csv-timeline` та `json-timeline` тепер мають майстер сканування, увімкнений за замовчуванням.
Він призначений для того, щоб допомогти користувачам легко обирати, які правила виявлення вони хочуть увімкнути відповідно до своїх потреб і вподобань.
Набори правил виявлення для завантаження базуються на офіційних списках у проєкті Sigma.
Подробиці пояснено в [цьому дописі блогу](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
Ви можете легко вимкнути майстер і використовувати Hayabusa традиційним способом, додавши опцію `-w, --no-wizard`.

### Правила Core

Набір правил `core` вмикає правила, які мають статус `test` або `stable` і рівень `high` чи `critical`.
Це високоякісні правила з високою достовірністю та релевантністю, які не повинні створювати багато хибних спрацювань.
Статус правил `test` або `stable` означає, що про хибні спрацювання не повідомлялося понад 6 місяців.
Правила спрацьовуватимуть на техніки зловмисників, загальну підозрілу активність або шкідливу поведінку.
Це те саме, що використання опцій `--exclude-status deprecated,unsupported,experimental --min-level high`.

### Правила Core+

Набір правил `core+` вмикає правила, які мають статус `test` або `stable` і рівень `medium` чи вище.
Правила рівня `medium` найчастіше потребують додаткового налаштування, оскільки можуть спрацьовувати на певні застосунки, легітимну поведінку користувачів або скрипти організації.
Це те саме, що використання опцій `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### Правила Core++

Набір правил `core++` вмикає правила, які мають статус `experimental`, `test` або `stable` і рівень `medium` чи вище.
Ці правила перебувають на передньому краї.
Вони перевіряються відносно базових файлів evtx, доступних у проєкті SigmaHQ, і переглядаються кількома інженерами з виявлення.
Окрім цього, спочатку вони майже не протестовані.
Використовуйте їх, якщо хочете мати змогу виявляти загрози якомога раніше ціною керування вищим порогом хибних спрацювань.
Це те саме, що використання опцій `--exclude-status deprecated,unsupported --min-level medium`.

### Додаткові правила нових загроз (ET)

Набір правил `Emerging Threats (ET)` вмикає правила, які мають тег `detection.emerging_threats`.
Ці правила націлені на конкретні загрози й особливо корисні для поточних загроз, про які ще не доступно багато інформації.
Ці правила не повинні мати багато хибних спрацювань, але з часом їхня релевантність зменшуватиметься.
Коли ці правила не ввімкнено, це те саме, що використання опції `--exclude-tag detection.emerging_threats`.
Під час традиційного запуску Hayabusa без майстра ці правила буде включено за замовчуванням.

### Додаткові правила полювання на загрози (TH)

Набір правил `Threat Hunting (TH)` вмикає правила, які мають тег `detection.threat_hunting`.
Ці правила можуть виявляти невідому шкідливу активність, проте зазвичай матимуть більше хибних спрацювань.
Коли ці правила не ввімкнено, це те саме, що використання опції `--exclude-tag detection.threat_hunting`.
Під час традиційного запуску Hayabusa без майстра ці правила буде включено за замовчуванням.

## Фільтрація журналів подій та правил на основі каналу

Починаючи з Hayabusa v2.16.0, ми вмикаємо фільтр на основі каналу під час завантаження файлів `.evtx` та правил `.yml`.
Мета полягає в тому, щоб зробити сканування максимально ефективним, завантажуючи лише необхідне.
Хоча в одному журналі подій може бути кілька провайдерів, наявність кількох каналів усередині одного файлу evtx не є поширеною.
(Єдиний випадок, коли ми це бачили, був, коли хтось штучно об'єднав два різні файли evtx разом для проєкту [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).)
Ми можемо використати це на свою користь, спочатку перевіривши поле `Channel` у першому записі кожного файлу `.evtx`, вказаного для сканування.
Ми також перевіряємо, які правила `.yml` використовують які канали, вказані в полі `Channel` правила.
За допомогою цих двох списків ми завантажуємо лише ті правила, які використовують канали, фактично присутні у файлах `.evtx`.

Тож, наприклад, якщо користувач хоче просканувати `Security.evtx`, будуть використані лише правила, які вказують `Channel: Security`.
Немає сенсу завантажувати інші правила виявлення, наприклад правила, які шукають події лише в журналі `Application` тощо...
Зверніть увагу, що поля каналу (наприклад: `Channel: Security`) не визначені **явно** всередині оригінальних правил Sigma.
Для правил Sigma поля каналу та ідентифікаторів подій визначаються **неявно** за допомогою полів `service` та `category` під `logsource`. (Наприклад: `service: security`)
Під час курування правил Sigma у репозиторії [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) ми деабстрагуємо поле `logsource` і явно визначаємо поля каналу та ідентифікатора події.
Ми детально пояснюємо, як і чому ми це робимо, [тут](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Наразі існує лише два правила виявлення, які не мають визначеного `Channel` і призначені для сканування всіх файлів `.evtx`, а саме:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Якщо ви хочете використовувати ці два правила і сканувати всі правила відносно завантажених файлів `.evtx`, то вам потрібно буде додати опцію `-A, --enable-all-rules` у командах `csv-timeline` та `json-timeline`.
У наших тестах фільтрація правил зазвичай дає прискорення від 20% до 10 разів залежно від того, які файли скануються, і, звісно, використовує менше пам'яті.

Фільтрація за каналом також використовується під час завантаження файлів `.evtx`.
Наприклад, якщо ви вкажете правило, яке шукає події з каналом `Security`, то немає сенсу завантажувати файли `.evtx`, які не походять із журналу `Security`.
У наших тестах це дає перевагу у швидкості близько 10% при звичайних скануваннях і до 60%+ приросту продуктивності під час сканування з одним правилом.
Якщо ви впевнені, що всередині одного файлу `.evtx` використовується кілька каналів, наприклад, хтось використав інструмент для об'єднання кількох файлів `.evtx` разом, то ви можете вимкнути цю фільтрацію опцією `-a, --scan-all-evtx-files` у командах `csv-timeline` та `json-timeline`.

> Примітка: Фільтрація за каналом працює лише з файлами `.evtx`, і ви отримаєте помилку, якщо спробуєте завантажити журнали подій із файлу JSON за допомогою `-J, --json-input` і також вкажете `-A` або `-a`.

## Команда `csv-timeline`

Команда `csv-timeline` створить криміналістичний таймлайн подій у форматі CSV.

```
Usage: csv-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
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
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -M, --multiline                    Output event field information in multiple rows
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in CSV format (ex: results.csv)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)
  -S, --tab-separator                Separate event field information by tabs

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### Приклади команди `csv-timeline`

* Запустити hayabusa проти одного файлу журналу подій Windows із профілем `standard` за замовчуванням:

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* Запустити hayabusa проти каталогу sample-evtx із кількома файлами журналів подій Windows із профілем verbose:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* Експортувати в єдиний файл CSV для подальшого аналізу за допомогою LibreOffice, Timeline Explorer, Elastic Stack тощо... і включити всю інформацію полів (Попередження: розмір вашого вихідного файлу стане значно більшим із профілем `super-verbose`!):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Увімкнути фільтр EID (Event ID):

> Примітка: Увімкнення фільтра EID прискорить аналіз приблизно на 10-15% у наших тестах, але є ймовірність пропуску сповіщень.

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Запустити лише правила hayabusa (за замовчуванням запускаються всі правила в `-r .\rules`):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Запустити лише правила hayabusa для журналів, які ввімкнені за замовчуванням у Windows:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Запустити лише правила hayabusa для журналів sysmon:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Запустити лише правила sigma:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Увімкнути застарілі правила (ті, у яких `status` позначено як `deprecated`) та шумні правила (ті, чий ідентифікатор правила перелічено в `.\rules\config\noisy_rules.txt`):

> Примітка: Останнім часом застарілі правила тепер розташовані в окремому каталозі в репозиторії sigma, тому більше не включаються за замовчуванням у Hayabusa.
> Тому вам, ймовірно, немає потреби вмикати застарілі правила.

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Запустити лише правила для аналізу входів у систему та вивести в часовому поясі UTC:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Запустити на живій машині Windows (потребує прав адміністратора) і виявляти лише сповіщення (потенційно шкідливу поведінку):

```
hayabusa.exe csv-timeline -l -m low
```

* Вивести докладну інформацію (корисно для визначення того, які файли довго обробляються, помилки розбору тощо...):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* Приклад докладного виводу:

Завантаження правил:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Помилки під час сканування:
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

* Вивести у формат CSV, сумісний для імпорту в [Timesketch](https://timesketch.org/):

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Тихий режим помилок:
За замовчуванням hayabusa зберігатиме повідомлення про помилки у файли журналів помилок.
Якщо ви не хочете зберігати повідомлення про помилки, додайте `-Q`.

### Розширене - Збагачення журналів GeoIP

Ви можете додати інформацію GeoIP (організація ASN, місто та країна) до полів SrcIP (вихідний IP) та полів TgtIP (цільовий IP) за допомогою безкоштовних геолокаційних даних GeoLite2.

Кроки:

1. Спочатку зареєструйте обліковий запис MaxMind [тут](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Завантажте три файли `.mmdb` зі [сторінки завантаження](https://www.maxmind.com/en/accounts/current/geoip/downloads) і збережіть їх у каталозі. Імена файлів повинні називатися `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` та `GeoLite2-Country.mmdb`.
3. Під час запуску команд `csv-timeline` або `json-timeline` додайте опцію `-G`, після якої вкажіть каталог із базами даних MaxMind.

* Коли використовується `csv-timeline`, додатково виводитимуться наступні 6 стовпців: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* Коли використовується `json-timeline`, ті самі поля `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` будуть додані до об'єкта `Details`, але лише якщо вони містять інформацію.

* Коли `SrcIP` або `TgtIP` є localhost (`127.0.0.1`, `::1` тощо...), `SrcASN` або `TgtASN` виводитиметься як `Local`.
* Коли `SrcIP` або `TgtIP` є приватною IP-адресою (`10.0.0.0/8`, `fe80::/10` тощо...), `SrcASN` або `TgtASN` виводитиметься як `Private`.

#### Конфігураційний файл GeoIP

Імена полів, що містять вихідні та цільові IP-адреси, які шукаються в базах даних GeoIP, визначаються в `rules/config/geoip_field_mapping.yaml`.
Ви можете додавати до цього списку за потреби.
У цьому файлі також є секція фільтрів, яка визначає, з яких подій витягувати інформацію про IP-адресу.

#### Автоматичні оновлення баз даних GeoIP

Бази даних MaxMind GeoIP оновлюються кожні 2 тижні.
Ви можете встановити інструмент MaxMind `geoipupdate` [тут](https://github.com/maxmind/geoipupdate), щоб автоматично оновлювати ці бази даних.

Кроки в macOS:

1. `brew install geoipupdate`
2. Відредагуйте `/usr/local/etc/GeoIP.conf` або `/opt/homebrew/etc/GeoIP.conf`: Вкажіть свої `AccountID` та `LicenseKey`, які ви створюєте після входу на вебсайт MaxMind. Переконайтеся, що рядок `EditionIDs` містить `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Запустіть `geoipupdate`.
4. Додайте `-G /usr/local/var/GeoIP` або `-G /opt/homebrew/var/GeoIP`, коли хочете додати інформацію GeoIP.

Кроки в Windows:

1. Завантажте останній двійковий файл для Windows (наприклад: `geoipupdate_4.10.0_windows_amd64.zip`) зі сторінки [Releases](https://github.com/maxmind/geoipupdate/releases).
2. Відредагуйте `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: Вкажіть свої `AccountID` та `LicenseKey`, які ви створюєте після входу на вебсайт MaxMind. Переконайтеся, що рядок `EditionIDs` містить `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Запустіть виконуваний файл `geoipupdate`.

Кроки в Linux:

1. Встановіть за допомогою `sudo apt install geoip-update`.
2. Відредагуйте файл конфігурації за допомогою `sudo nano /etc/GeoIP.conf`.
3. Оновіть файли бази даних за допомогою `sudo geoipupdate`.
4. Додайте `-G /var/lib/GeoIP/`, коли хочете додати інформацію GeoIP.

### Конфігураційні файли команди `csv-timeline`

`./rules/config/channel_abbreviations.txt`: Зіставлення імен каналів та їхніх скорочень.

`./rules/config/default_details.txt`: Конфігураційний файл для того, яку інформацію полів за замовчуванням (поле `%Details%`) слід виводити, якщо в правилі не вказано рядок `details:`.
Це базується на імені провайдера та ідентифікаторах подій.

`./rules/config/eventkey_alias.txt`: Цей файл містить зіставлення коротких псевдонімів імен для полів та їхніх оригінальних довших імен полів.

Приклад:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Якщо поле тут не визначено, Hayabusa автоматично перевірятиме поле під `Event.EventData`.

`./rules/config/exclude_rules.txt`: Цей файл містить список ідентифікаторів правил, які будуть виключені з використання.
Зазвичай це тому, що одне правило замінило інше або правило взагалі не може бути використане.
Як і брандмауери та IDS, будь-який інструмент на основі сигнатур потребуватиме певного налаштування, щоб відповідати вашому середовищу, тому вам може знадобитися постійно або тимчасово виключати певні правила.
Ви можете додати ідентифікатор правила (Приклад: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) до `./rules/config/exclude_rules.txt`, щоб ігнорувати будь-яке правило, яке вам не потрібне або не може бути використане.

`./rules/config/noisy_rules.txt`: Цей файл містить список ідентифікаторів правил, які вимкнені за замовчуванням, але можуть бути ввімкнені шляхом увімкнення шумних правил за допомогою опції `-n, --enable-noisy-rules`.
Ці правила зазвичай шумні за своєю природою або через хибні спрацювання.

`./rules/config/target_event_IDs.txt`: Якщо фільтр EID увімкнено, скануватимуться лише ідентифікатори подій, вказані в цьому файлі.
За замовчуванням Hayabusa скануватиме всі події, але якщо ви хочете покращити продуктивність, використовуйте опцію `-E, --EID-filter`.
Це зазвичай дає прискорення на 10~25%.

## Команда `json-timeline`

Команда `json-timeline` створить криміналістичний таймлайн подій у форматі JSON або JSONL.
Вивід у JSONL буде швидшим і меншим за розміром файлу, ніж JSON, тому це добре, якщо ви збираєтеся просто імпортувати результати в інший інструмент, як-от Elastic Stack.
JSON краще, якщо ви збираєтеся вручну аналізувати результати за допомогою текстового редактора.
Вивід CSV добре підходить для імпорту менших таймлайнів (зазвичай менше 2 ГБ) в інструменти, як-от LibreOffice чи Timeline Explorer.
JSON найкраще підходить для детальнішого аналізу даних (включно з великими файлами результатів) за допомогою інструментів, як-от `jq`, оскільки поля `Details` розділені для зручнішого аналізу.
(У виводі CSV усі поля журналу подій знаходяться в одному великому стовпці `Details`, що ускладнює сортування даних тощо...)

```
Usage: json-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
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
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -L, --JSONL-output                 Save the timeline in JSONL format (ex: -L -o results.jsonl)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in JSON format (ex: results.json)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### Приклади та конфігураційні файли команди `json-timeline`

Опції та конфігураційні файли для `json-timeline` такі самі, як і для `csv-timeline`, але з однією додатковою опцією `-L, --JSONL-output` для виводу у формат JSONL.

## Команда `level-tuning`

Команда `level-tuning` дозволить вам налаштувати рівні сповіщень для правил, підвищуючи або знижуючи рівень ризику так, як вам потрібно.
Ця команда використовує конфігураційний файл для перезапису рівнів ризику (поле `level`) правил у папці `rules`.

> Попередження: щоразу, коли ви запускаєте команду `update-rules`, рівень ризику повертатиметься до оригінального значення, тому вам потрібно буде знову запустити команду `level-tuning` після цього.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### Приклади команди `level-tuning`

* Звичайне використання: `hayabusa.exe level-tuning`
* Налаштувати рівні сповіщень правил на основі вашого власного конфігураційного файлу: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### Конфігураційний файл `level-tuning`

Автори правил Hayabusa та Sigma оцінюватимуть відповідний рівень ризику сповіщення під час написання своїх правил.
Однак іноді рівні ризику не є узгодженими, а також фактичний рівень ризику може відрізнятися залежно від вашого середовища.
Yamato Security надає та підтримує конфігураційний файл за адресою `./rules/config/level_tuning.txt`, який ви також можете використовувати для налаштування своїх правил.

Зразок `./rules/config/level_tuning.txt`:

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

У цьому випадку рівень ризику правила з `id`, рівним `570ae5ec-33dc-427c-b815-db86228ad43e`, у каталозі правил буде переписано на `informational`.
Можливі рівні для встановлення: `critical`, `high`, `medium`, `low` та `informational`.

> Попередження: Конфігураційний файл `./rules/config/level_tuning.txt` також оновлюватиметься до останньої версії в репозиторії hayabusa-rules щоразу, коли ви запускаєте `update-rules`.
> Тому, якщо ви внесете зміни до цього файлу, ви втратите ці зміни!
> Якщо ви хочете зберегти конфігураційний файл для себе, то створіть конфігураційний файл у `./config/level_tuning.txt` і запустіть `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> Ви також можете спочатку виконати налаштування рівнів за допомогою конфігураційного файлу, наданого Yamato Security, а потім додатково налаштувати за допомогою власного конфігураційного файлу.

## Команда `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## Команда `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### Приклади команди `set-default-profile`

* Встановити профіль за замовчуванням на `minimal`: `hayabusa.exe set-default-profile minimal`
* Встановити профіль за замовчуванням на `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## Команда `update-rules`

Команда `update-rules` синхронізує папку `rules` із [репозиторієм правил Hayabusa на github](https://github.com/Yamato-Security/hayabusa-rules), оновлюючи правила та конфігураційні файли.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### Приклад команди `update-rules`

Зазвичай ви просто виконуватимете це: `hayabusa.exe update-rules`
