# DFIR টাইমলাইন কমান্ডসমূহ

## স্ক্যান উইজার্ড

`csv-timeline` এবং `json-timeline` কমান্ডগুলোতে এখন ডিফল্টভাবে একটি স্ক্যান উইজার্ড সক্রিয় থাকে।
এটির উদ্দেশ্য হলো ব্যবহারকারীদের তাদের প্রয়োজন ও পছন্দ অনুযায়ী কোন ডিটেকশন রুলগুলো সক্রিয় করতে চান তা সহজে বেছে নিতে সাহায্য করা।
লোড করার জন্য ডিটেকশন রুলের সেটগুলো Sigma প্রকল্পের অফিসিয়াল তালিকার উপর ভিত্তি করে তৈরি।
বিস্তারিত [এই ব্লগ পোস্টে](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81) ব্যাখ্যা করা হয়েছে।
আপনি `-w, --no-wizard` অপশনটি যোগ করে সহজেই উইজার্ডটি বন্ধ করতে পারেন এবং Hayabusa-কে তার ঐতিহ্যবাহী উপায়ে ব্যবহার করতে পারেন।

### Core রুলসমূহ

`core` রুল সেটটি এমন রুলগুলো সক্রিয় করে যেগুলোর স্ট্যাটাস `test` বা `stable` এবং লেভেল `high` বা `critical`।
এগুলো উচ্চ আত্মবিশ্বাস ও প্রাসঙ্গিকতার উচ্চমানের রুল এবং খুব বেশি ফলস পজিটিভ তৈরি করবে না।
রুল স্ট্যাটাস `test` বা `stable` মানে হলো ৬ মাসের বেশি সময় ধরে কোনো ফলস পজিটিভ রিপোর্ট করা হয়নি।
রুলগুলো আক্রমণকারীর কৌশল, সাধারণ সন্দেহজনক কার্যকলাপ, অথবা ক্ষতিকর আচরণের সাথে মিলবে।
এটি `--exclude-status deprecated,unsupported,experimental --min-level high` অপশন ব্যবহারের সমতুল্য।

### Core+ রুলসমূহ

`core+` রুল সেটটি এমন রুলগুলো সক্রিয় করে যেগুলোর স্ট্যাটাস `test` বা `stable` এবং লেভেল `medium` বা তার বেশি।
`medium` রুলগুলোর প্রায়ই অতিরিক্ত টিউনিং প্রয়োজন হয় কারণ কোনো প্রতিষ্ঠানের নির্দিষ্ট অ্যাপ্লিকেশন, বৈধ ব্যবহারকারীর আচরণ বা স্ক্রিপ্ট মিলে যেতে পারে।
এটি `--exclude-status deprecated,unsupported,experimental --min-level medium` অপশন ব্যবহারের সমতুল্য।

### Core++ রুলসমূহ

`core++` রুল সেটটি এমন রুলগুলো সক্রিয় করে যেগুলোর স্ট্যাটাস `experimental`, `test` বা `stable` এবং লেভেল `medium` বা তার বেশি।
এই রুলগুলো একদম অত্যাধুনিক।
এগুলো SigmaHQ প্রকল্পে উপলব্ধ বেসলাইন evtx ফাইলগুলোর বিপরীতে যাচাই করা হয় এবং একাধিক ডিটেকশন ইঞ্জিনিয়ার দ্বারা পর্যালোচনা করা হয়।
এছাড়া প্রথম দিকে এগুলো মোটামুটি অপরীক্ষিত থাকে।
যদি আপনি উচ্চতর সীমার ফলস পজিটিভ সামলানোর বিনিময়ে যত তাড়াতাড়ি সম্ভব হুমকি শনাক্ত করতে চান তবে এগুলো ব্যবহার করুন।
এটি `--exclude-status deprecated,unsupported --min-level medium` অপশন ব্যবহারের সমতুল্য।

### Emerging Threats (ET) অ্যাড-অন রুলসমূহ

`Emerging Threats (ET)` রুল সেটটি এমন রুলগুলো সক্রিয় করে যেগুলোর ট্যাগ `detection.emerging_threats`।
এই রুলগুলো নির্দিষ্ট হুমকিকে লক্ষ্য করে এবং বিশেষত বর্তমান হুমকিগুলোর জন্য উপযোগী যেখানে এখনো বেশি তথ্য উপলব্ধ নেই।
এই রুলগুলোতে বেশি ফলস পজিটিভ থাকবে না তবে সময়ের সাথে সাথে এগুলোর প্রাসঙ্গিকতা কমে যাবে।
যখন এই রুলগুলো সক্রিয় করা হয় না, তখন এটি `--exclude-tag detection.emerging_threats` অপশন ব্যবহারের সমতুল্য।
উইজার্ড ছাড়া Hayabusa ঐতিহ্যবাহীভাবে চালানোর সময়, এই রুলগুলো ডিফল্টভাবে অন্তর্ভুক্ত হবে।

### Threat Hunting (TH) অ্যাড-অন রুলসমূহ

`Threat Hunting (TH)` রুল সেটটি এমন রুলগুলো সক্রিয় করে যেগুলোর ট্যাগ `detection.threat_hunting`।
এই রুলগুলো অজানা ক্ষতিকর কার্যকলাপ শনাক্ত করতে পারে, তবে সাধারণত এগুলোতে বেশি ফলস পজিটিভ থাকবে।
যখন এই রুলগুলো সক্রিয় করা হয় না, তখন এটি `--exclude-tag detection.threat_hunting` অপশন ব্যবহারের সমতুল্য।
উইজার্ড ছাড়া Hayabusa ঐতিহ্যবাহীভাবে চালানোর সময়, এই রুলগুলো ডিফল্টভাবে অন্তর্ভুক্ত হবে।

## Channel-ভিত্তিক ইভেন্ট লগ এবং রুল ফিল্টারিং

Hayabusa v2.16.0 থেকে, আমরা `.evtx` ফাইল এবং `.yml` রুল লোড করার সময় একটি Channel-ভিত্তিক ফিল্টার সক্রিয় করি।
এর উদ্দেশ্য হলো কেবল যা প্রয়োজনীয় তা-ই লোড করে স্ক্যানিংকে যথাসম্ভব দক্ষ করে তোলা।
একটি একক ইভেন্ট লগের মধ্যে একাধিক provider থাকা সম্ভব হলেও, একটি একক evtx ফাইলের মধ্যে একাধিক channel থাকা সাধারণ নয়।
(আমরা এটি কেবল তখনই দেখেছি যখন কেউ [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) প্রকল্পের জন্য দুটি ভিন্ন evtx ফাইলকে কৃত্রিমভাবে একত্রিত করেছে।)
আমরা স্ক্যান করার জন্য নির্দিষ্ট প্রতিটি `.evtx` ফাইলের প্রথম রেকর্ডে `Channel` ফিল্ডটি প্রথমে যাচাই করে এর সুবিধা নিতে পারি।
আমরা এটিও যাচাই করি যে কোন `.yml` রুলগুলো রুলের `Channel` ফিল্ডে নির্দিষ্ট কোন channel ব্যবহার করে।
এই দুটি তালিকা দিয়ে, আমরা কেবল সেই রুলগুলোই লোড করি যেগুলো `.evtx` ফাইলগুলোর মধ্যে আসলে বিদ্যমান channel ব্যবহার করে।

তাই উদাহরণস্বরূপ, যদি কোনো ব্যবহারকারী `Security.evtx` স্ক্যান করতে চান, তবে কেবল `Channel: Security` নির্দিষ্ট করা রুলগুলোই ব্যবহার করা হবে।
অন্যান্য ডিটেকশন রুল লোড করার কোনো মানে নেই, উদাহরণস্বরূপ এমন রুল যেগুলো কেবল `Application` লগে ইভেন্ট খোঁজে, ইত্যাদি...
লক্ষ্য করুন যে channel ফিল্ড (উদাহরণ: `Channel: Security`) মূল Sigma রুলের ভেতরে **সুস্পষ্টভাবে** সংজ্ঞায়িত করা থাকে না।
Sigma রুলের জন্য, channel এবং event ID ফিল্ডগুলো `logsource`-এর অধীনে `service` এবং `category` ফিল্ড দিয়ে **পরোক্ষভাবে** সংজ্ঞায়িত হয়। (উদাহরণ: `service: security`)
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) রিপোজিটরিতে Sigma রুল সংকলন করার সময়, আমরা `logsource` ফিল্ডকে de-abstract করি এবং channel ও event ID ফিল্ড সুস্পষ্টভাবে সংজ্ঞায়িত করি।
আমরা কীভাবে এবং কেন এটি করি তা [এখানে](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) বিস্তারিতভাবে ব্যাখ্যা করেছি।

বর্তমানে, কেবল দুটি ডিটেকশন রুল রয়েছে যেগুলোতে `Channel` সংজ্ঞায়িত নেই এবং যেগুলো সমস্ত `.evtx` ফাইল স্ক্যান করার উদ্দেশ্যে তৈরি, সেগুলো হলো নিম্নরূপ:
- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

যদি আপনি এই দুটি রুল ব্যবহার করতে চান এবং লোড করা `.evtx` ফাইলগুলোর বিপরীতে সমস্ত রুল স্ক্যান করতে চান তবে আপনাকে `csv-timeline` এবং `json-timeline` কমান্ডে `-A, --enable-all-rules` অপশনটি যোগ করতে হবে।
আমাদের বেঞ্চমার্কে, কোন ফাইলগুলো স্ক্যান করা হচ্ছে তার উপর নির্ভর করে রুল ফিল্টারিং সাধারণত ২০% থেকে ১০ গুণ গতির উন্নতি দেয় এবং অবশ্যই কম মেমরি ব্যবহার করে।

Channel ফিল্টারিং `.evtx` ফাইল লোড করার সময়ও ব্যবহৃত হয়।
উদাহরণস্বরূপ, যদি আপনি এমন একটি রুল নির্দিষ্ট করেন যা `Security` channel-সহ ইভেন্ট খোঁজে, তবে `Security` লগ থেকে নয় এমন `.evtx` ফাইল লোড করার কোনো মানে নেই।
আমাদের বেঞ্চমার্কে, এটি সাধারণ স্ক্যানে প্রায় ১০% গতির সুবিধা দেয় এবং একটি একক রুল দিয়ে স্ক্যান করার সময় ৬০%+ পর্যন্ত কর্মক্ষমতা বৃদ্ধি দেয়।
যদি আপনি নিশ্চিত হন যে একটি একক `.evtx` ফাইলের মধ্যে একাধিক channel ব্যবহার করা হচ্ছে, উদাহরণস্বরূপ কেউ একাধিক `.evtx` ফাইলকে একত্রিত করতে কোনো টুল ব্যবহার করেছেন, তবে আপনি `csv-timeline` এবং `json-timeline` কমান্ডে `-a, --scan-all-evtx-files` অপশন দিয়ে এই ফিল্টারিং নিষ্ক্রিয় করতে পারেন।

> নোট: Channel ফিল্টারিং কেবল `.evtx` ফাইলের সাথে কাজ করে এবং আপনি যদি `-J, --json-input` দিয়ে একটি JSON ফাইল থেকে ইভেন্ট লগ লোড করার চেষ্টা করেন এবং একই সাথে `-A` বা `-a` নির্দিষ্ট করেন তবে আপনি একটি ত্রুটি পাবেন।

## `csv-timeline` কমান্ড

`csv-timeline` কমান্ডটি CSV ফরম্যাটে ইভেন্টের একটি ফরেনসিক টাইমলাইন তৈরি করবে।

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

### `csv-timeline` কমান্ডের উদাহরণ

* ডিফল্ট `standard` প্রোফাইল দিয়ে একটি Windows ইভেন্ট লগ ফাইলের বিপরীতে hayabusa চালান:

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* verbose প্রোফাইল দিয়ে একাধিক Windows ইভেন্ট লগ ফাইলসহ sample-evtx ডিরেক্টরির বিপরীতে hayabusa চালান:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* LibreOffice, Timeline Explorer, Elastic Stack ইত্যাদি দিয়ে আরও বিশ্লেষণের জন্য একটি একক CSV ফাইলে এক্সপোর্ট করুন এবং সমস্ত ফিল্ড তথ্য অন্তর্ভুক্ত করুন (সতর্কতা: `super-verbose` প্রোফাইল দিয়ে আপনার ফাইল আউটপুটের আকার অনেক বড় হয়ে যাবে!):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* EID (Event ID) ফিল্টার সক্রিয় করুন:

> নোট: EID ফিল্টার সক্রিয় করা আমাদের পরীক্ষায় বিশ্লেষণকে প্রায় ১০-১৫% দ্রুত করবে তবে অ্যালার্ট মিস হওয়ার সম্ভাবনা রয়েছে।

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* কেবল hayabusa রুল চালান (ডিফল্ট হলো `-r .\rules`-এর সমস্ত রুল চালানো):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* কেবল Windows-এ ডিফল্টভাবে সক্রিয় লগগুলোর জন্য hayabusa রুল চালান:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* কেবল sysmon লগের জন্য hayabusa রুল চালান:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* কেবল sigma রুল চালান:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* deprecated রুল (যেগুলোর `status` `deprecated` হিসেবে চিহ্নিত) এবং noisy রুল (যেগুলোর রুল ID `.\rules\config\noisy_rules.txt`-এ তালিকাভুক্ত) সক্রিয় করুন:

> নোট: সম্প্রতি, deprecated রুলগুলো এখন sigma রিপোজিটরির একটি পৃথক ডিরেক্টরিতে অবস্থিত তাই Hayabusa-তে আর ডিফল্টভাবে অন্তর্ভুক্ত নয়।
> তাই, আপনার সম্ভবত deprecated রুল সক্রিয় করার প্রয়োজন নেই।

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* কেবল logon বিশ্লেষণের জন্য রুল চালান এবং UTC টাইমজোনে আউটপুট দিন:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* একটি লাইভ Windows মেশিনে চালান (Administrator অনুমতি প্রয়োজন) এবং কেবল অ্যালার্ট (সম্ভাব্য ক্ষতিকর আচরণ) শনাক্ত করুন:

```
hayabusa.exe csv-timeline -l -m low
```

* verbose তথ্য প্রিন্ট করুন (কোন ফাইলগুলো প্রসেস করতে বেশি সময় নেয়, পার্সিং ত্রুটি ইত্যাদি নির্ধারণে উপযোগী):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* verbose আউটপুটের উদাহরণ:

রুল লোড করা হচ্ছে:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

স্ক্যান চলাকালীন ত্রুটিসমূহ:
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

* [Timesketch](https://timesketch.org/)-এ ইমপোর্ট করার সাথে সামঞ্জস্যপূর্ণ একটি CSV ফরম্যাটে আউটপুট দিন:

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Quiet error মোড:
ডিফল্টভাবে, hayabusa ত্রুটি বার্তা error log ফাইলে সংরক্ষণ করবে।
যদি আপনি ত্রুটি বার্তা সংরক্ষণ করতে না চান, তবে অনুগ্রহ করে `-Q` যোগ করুন।

### উন্নত - GeoIP লগ এনরিচমেন্ট

আপনি বিনামূল্যের GeoLite2 জিওলোকেশন ডেটা দিয়ে SrcIP (source IP) ফিল্ড এবং TgtIP (target IP) ফিল্ডে GeoIP (ASN organization, city ও country) তথ্য যোগ করতে পারেন।

ধাপসমূহ:
1. প্রথমে [এখানে](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) একটি MaxMind অ্যাকাউন্টের জন্য সাইন আপ করুন।
2. [download page](https://www.maxmind.com/en/accounts/current/geoip/downloads) থেকে তিনটি `.mmdb` ফাইল ডাউনলোড করুন এবং একটি ডিরেক্টরিতে সংরক্ষণ করুন। ফাইলনামগুলো `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` এবং `GeoLite2-Country.mmdb` হওয়া উচিত।
3. `csv-timeline` বা `json-timeline` কমান্ড চালানোর সময়, `-G` অপশন যোগ করুন এবং তারপর MaxMind ডেটাবেসসহ ডিরেক্টরিটি দিন।

* যখন `csv-timeline` ব্যবহার করা হয়, তখন নিম্নলিখিত ৬টি কলাম অতিরিক্তভাবে আউটপুট হবে: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`।
* যখন `json-timeline` ব্যবহার করা হয়, তখন একই `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` ফিল্ডগুলো `Details` অবজেক্টে যোগ হবে, তবে কেবল যদি সেগুলোতে তথ্য থাকে।

* যখন `SrcIP` বা `TgtIP` localhost হয় (`127.0.0.1`, `::1` ইত্যাদি...), তখন `SrcASN` বা `TgtASN` `Local` হিসেবে আউটপুট হবে।
* যখন `SrcIP` বা `TgtIP` একটি private IP ঠিকানা হয় (`10.0.0.0/8`, `fe80::/10` ইত্যাদি...), তখন `SrcASN` বা `TgtASN` `Private` হিসেবে আউটপুট হবে।

#### GeoIP কনফিগ ফাইল

GeoIP ডেটাবেসে যে সোর্স ও টার্গেট IP ঠিকানাযুক্ত ফিল্ডের নামগুলো খোঁজা হয় সেগুলো `rules/config/geoip_field_mapping.yaml`-এ সংজ্ঞায়িত।
প্রয়োজনে আপনি এই তালিকায় যোগ করতে পারেন।
এই ফাইলে একটি ফিল্টার সেকশনও রয়েছে যা নির্ধারণ করে কোন ইভেন্ট থেকে IP ঠিকানার তথ্য বের করতে হবে।

#### GeoIP ডেটাবেসের স্বয়ংক্রিয় আপডেট

MaxMind GeoIP ডেটাবেস প্রতি ২ সপ্তাহে আপডেট হয়।
এই ডেটাবেসগুলো স্বয়ংক্রিয়ভাবে আপডেট করার জন্য আপনি [এখানে](https://github.com/maxmind/geoipupdate) MaxMind `geoipupdate` টুলটি ইনস্টল করতে পারেন।

macOS-এ ধাপসমূহ:
1. `brew install geoipupdate`
2. `/usr/local/etc/GeoIP.conf` বা `/opt/homebrew/etc/GeoIP.conf` সম্পাদনা করুন: MaxMind ওয়েবসাইটে লগ ইন করার পর আপনি যে `AccountID` এবং `LicenseKey` তৈরি করেন সেগুলো রাখুন। নিশ্চিত করুন যে `EditionIDs` লাইনটি `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` বলছে।
3. `geoipupdate` চালান।
4. যখন আপনি GeoIP তথ্য যোগ করতে চান তখন `-G /usr/local/var/GeoIP` বা `-G /opt/homebrew/var/GeoIP` যোগ করুন।

Windows-এ ধাপসমূহ:
1. [Releases](https://github.com/maxmind/geoipupdate/releases) পেজ থেকে সর্বশেষ Windows বাইনারি (উদাহরণ: `geoipupdate_4.10.0_windows_amd64.zip`) ডাউনলোড করুন।
2. `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf` সম্পাদনা করুন: MaxMind ওয়েবসাইটে লগ ইন করার পর আপনি যে `AccountID` এবং `LicenseKey` তৈরি করেন সেগুলো রাখুন। নিশ্চিত করুন যে `EditionIDs` লাইনটি `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` বলছে।
3. `geoipupdate` এক্সিকিউটেবলটি চালান।

### `csv-timeline` কমান্ডের কনফিগ ফাইল

`./rules/config/channel_abbreviations.txt`: channel নাম এবং তাদের সংক্ষিপ্ত রূপের ম্যাপিং।

`./rules/config/default_details.txt`: কোনো রুলে যদি `details:` লাইন নির্দিষ্ট না থাকে তবে কী ডিফল্ট ফিল্ড তথ্য (`%Details%` ফিল্ড) আউটপুট হওয়া উচিত তার কনফিগারেশন ফাইল।
এটি provider name এবং event ID-এর উপর ভিত্তি করে।

`./rules/config/eventkey_alias.txt`: এই ফাইলে ফিল্ডগুলোর সংক্ষিপ্ত নামের alias এবং তাদের মূল দীর্ঘতর ফিল্ড নামের ম্যাপিং রয়েছে।

উদাহরণ:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

যদি কোনো ফিল্ড এখানে সংজ্ঞায়িত না থাকে, তবে Hayabusa স্বয়ংক্রিয়ভাবে ফিল্ডটির জন্য `Event.EventData`-এর অধীনে যাচাই করবে।

`./rules/config/exclude_rules.txt`: এই ফাইলে এমন রুল ID-এর একটি তালিকা রয়েছে যেগুলো ব্যবহার থেকে বাদ দেওয়া হবে।
সাধারণত এটি হয় কারণ একটি রুল অন্যটির স্থান নিয়েছে অথবা রুলটি প্রথমেই ব্যবহার করা যায় না।
firewall এবং IDS-এর মতো, যেকোনো signature-ভিত্তিক টুলের আপনার পরিবেশের সাথে মানানসই করতে কিছু টিউনিং প্রয়োজন হবে তাই আপনাকে নির্দিষ্ট রুল স্থায়ীভাবে বা সাময়িকভাবে বাদ দিতে হতে পারে।
আপনি যে কোনো রুল উপেক্ষা করতে চান বা যা ব্যবহার করা যায় না তা উপেক্ষা করতে `./rules/config/exclude_rules.txt`-এ একটি রুল ID (উদাহরণ: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) যোগ করতে পারেন।

`./rules/config/noisy_rules.txt`: এই ফাইলে এমন রুল ID-এর একটি তালিকা রয়েছে যেগুলো ডিফল্টভাবে নিষ্ক্রিয় থাকে তবে `-n, --enable-noisy-rules` অপশন দিয়ে noisy রুল সক্রিয় করে সক্রিয় করা যায়।
এই রুলগুলো সাধারণত স্বভাবগতভাবে বা ফলস পজিটিভের কারণে noisy হয়।

`./rules/config/target_event_IDs.txt`: EID ফিল্টার সক্রিয় থাকলে কেবল এই ফাইলে নির্দিষ্ট event ID-গুলোই স্ক্যান করা হবে।
ডিফল্টভাবে, Hayabusa সমস্ত ইভেন্ট স্ক্যান করবে, তবে আপনি যদি কর্মক্ষমতা উন্নত করতে চান, তবে অনুগ্রহ করে `-E, --EID-filter` অপশন ব্যবহার করুন।
এটি সাধারণত ১০~২৫% গতির উন্নতি ঘটায়।

## `json-timeline` কমান্ড

`json-timeline` কমান্ডটি JSON বা JSONL ফরম্যাটে ইভেন্টের একটি ফরেনসিক টাইমলাইন তৈরি করবে।
JSONL-এ আউটপুট দেওয়া JSON-এর চেয়ে দ্রুত এবং ছোট ফাইলের আকারের হবে তাই আপনি যদি কেবল ফলাফলগুলো Elastic Stack-এর মতো অন্য টুলে ইমপোর্ট করতে যাচ্ছেন তবে এটি ভালো।
আপনি যদি একটি টেক্সট এডিটর দিয়ে ফলাফল ম্যানুয়ালি বিশ্লেষণ করতে যাচ্ছেন তবে JSON ভালো।
LibreOffice বা Timeline Explorer-এর মতো টুলে ছোট টাইমলাইন (সাধারণত ২GB-এর কম) ইমপোর্ট করার জন্য CSV আউটপুট ভালো।
`jq`-এর মতো টুল দিয়ে ডেটার আরও বিস্তারিত বিশ্লেষণের (বড় ফলাফল ফাইলসহ) জন্য JSON সবচেয়ে ভালো কারণ সহজ বিশ্লেষণের জন্য `Details` ফিল্ডগুলো পৃথক করা থাকে।
(CSV আউটপুটে, সমস্ত ইভেন্ট লগ ফিল্ড একটি বড় `Details` কলামে থাকে যা ডেটা সর্ট করা ইত্যাদি আরও কঠিন করে তোলে।)

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

### `json-timeline` কমান্ডের উদাহরণ এবং কনফিগ ফাইল

`json-timeline`-এর অপশন এবং কনফিগ ফাইলগুলো `csv-timeline`-এর মতোই তবে JSONL ফরম্যাটে আউটপুট দেওয়ার জন্য একটি অতিরিক্ত অপশন `-L, --JSONL-output` রয়েছে।

## `level-tuning` কমান্ড

`level-tuning` কমান্ডটি আপনাকে রুলের অ্যালার্ট লেভেল টিউন করতে দেবে, আপনি যেভাবে চান সেভাবে ঝুঁকির লেভেল বাড়াতে বা কমাতে পারবেন।
এই কমান্ডটি `rules` ফোল্ডারের রুলগুলোর ঝুঁকির লেভেল (`level` ফিল্ড) ওভাররাইট করতে একটি কনফিগ ফাইল ব্যবহার করে।

> সতর্কতা: প্রতিবার আপনি `update-rules` কমান্ড চালালে, ঝুঁকির লেভেল মূল মানে ফিরে আসবে তাই আপনাকে পরে আবার `level-tuning` কমান্ড চালাতে হবে।

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` কমান্ডের উদাহরণ

* সাধারণ ব্যবহার: `hayabusa.exe level-tuning`
* আপনার কাস্টম কনফিগ ফাইলের উপর ভিত্তি করে রুলের অ্যালার্ট লেভেল টিউন করুন: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` কনফিগ ফাইল

Hayabusa এবং Sigma রুল লেখকরা তাদের রুল লেখার সময় অ্যালার্টের উপযুক্ত ঝুঁকির লেভেল অনুমান করবেন।
তবে, কখনো কখনো ঝুঁকির লেভেল সামঞ্জস্যপূর্ণ থাকে না এবং আপনার পরিবেশ অনুযায়ী প্রকৃত ঝুঁকির লেভেল ভিন্ন হতে পারে।
Yamato Security `./rules/config/level_tuning.txt`-এ একটি কনফিগ ফাইল সরবরাহ ও রক্ষণাবেক্ষণ করে যা আপনিও আপনার রুল টিউন করতে ব্যবহার করতে পারেন।

`./rules/config/level_tuning.txt` নমুনা:

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

এই ক্ষেত্রে, rules ডিরেক্টরিতে `570ae5ec-33dc-427c-b815-db86228ad43e` `id`-যুক্ত রুলের `level` `informational`-এ পুনর্লিখিত হবে।
সেট করার সম্ভাব্য লেভেলগুলো হলো `critical`, `high`, `medium`, `low` এবং `informational`।

> সতর্কতা: প্রতিবার আপনি `update-rules` চালালে `./rules/config/level_tuning.txt` কনফিগ ফাইলটিও hayabusa-rules রিপোজিটরির সর্বশেষ সংস্করণে আপডেট হবে।
> তাই, আপনি যদি এই ফাইলে পরিবর্তন করেন, তবে আপনি সেই পরিবর্তনগুলো হারাবেন!
> আপনি যদি নিজের জন্য একটি কনফিগ ফাইল রাখতে চান, তবে `./config/level_tuning.txt`-এ একটি কনফিগ ফাইল তৈরি করুন এবং `hayabusa.exe level-tuning -f ./config/level_tuning.txt` চালান।
> আপনি প্রথমে Yamato Security প্রদত্ত কনফিগ ফাইল দিয়ে লেভেল টিউনিং করে তারপর আপনার নিজের কনফিগ ফাইল দিয়ে আরও টিউন করতে পারেন।

## `list-profiles` কমান্ড

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` কমান্ড

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` কমান্ডের উদাহরণ

* ডিফল্ট প্রোফাইল `minimal`-এ সেট করুন: `hayabusa.exe set-default-profile minimal`
* ডিফল্ট প্রোফাইল `super-verbose`-এ সেট করুন: `hayabusa.exe set-default-profile super-verbose`

## `update-rules` কমান্ড

`update-rules` কমান্ডটি `rules` ফোল্ডারকে [Hayabusa rules github রিপোজিটরির](https://github.com/Yamato-Security/hayabusa-rules) সাথে সিঙ্ক করবে, রুল এবং কনফিগ ফাইলগুলো আপডেট করবে।

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` কমান্ডের উদাহরণ

আপনি সাধারণত শুধু এটি এক্সিকিউট করবেন: `hayabusa.exe update-rules`
