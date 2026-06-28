# বিশ্লেষণ কমান্ডসমূহ

## `computer-metrics` কমান্ড

আপনি `computer-metrics` কমান্ড ব্যবহার করে দেখতে পারেন `<System><Computer>` ফিল্ডে সংজ্ঞায়িত প্রতিটি কম্পিউটার অনুযায়ী কতগুলো ইভেন্ট রয়েছে।
মনে রাখবেন যে ইভেন্টগুলোকে তাদের মূল কম্পিউটার অনুযায়ী পৃথক করার জন্য আপনি `Computer` ফিল্ডের উপর সম্পূর্ণভাবে নির্ভর করতে পারবেন না।
Windows 11 কখনও কখনও ইভেন্ট লগে সংরক্ষণ করার সময় সম্পূর্ণ ভিন্ন `Computer` নাম ব্যবহার করে।
এছাড়াও, Windows 10 কখনও কখনও `Computer` নাম পুরোপুরি ছোট হাতের অক্ষরে রেকর্ড করে।
এই কমান্ডটি কোনো ডিটেকশন রুল ব্যবহার করে না, তাই এটি সমস্ত ইভেন্ট বিশ্লেষণ করবে।
কোন কম্পিউটারে সবচেয়ে বেশি লগ রয়েছে তা দ্রুত দেখার জন্য এটি একটি ভালো কমান্ড।
এই তথ্য দিয়ে, আপনি তারপর আপনার টাইমলাইন তৈরির সময় `--include-computer` বা `--exclude-computer` অপশন ব্যবহার করতে পারেন, যাতে কম্পিউটার অনুযায়ী একাধিক টাইমলাইন তৈরি করে বা নির্দিষ্ট কম্পিউটার থেকে ইভেন্ট বাদ দিয়ে আপনার টাইমলাইন তৈরি আরও কার্যকর করা যায়।

```
Usage: computer-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
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

### `computer-metrics` কমান্ডের উদাহরণ

* একটি ডিরেক্টরি থেকে কম্পিউটার নামের মেট্রিক্স প্রিন্ট করুন: `hayabusa.exe computer-metrics -d ../logs`
* ফলাফল একটি CSV ফাইলে সংরক্ষণ করুন: `hayabusa.exe computer-metrics -d ../logs -o computer-metrics.csv`

### `computer-metrics` স্ক্রিনশট

![computer-metrics screenshot](../assets/screenshots/ComputerMetrics.png)

## `eid-metrics` কমান্ড

আপনি `eid-metrics` কমান্ড ব্যবহার করে চ্যানেল অনুযায়ী পৃথক করা ইভেন্ট আইডির (`<System><EventID>` ফিল্ড) মোট সংখ্যা এবং শতকরা হার প্রিন্ট করতে পারেন।
এই কমান্ডটি কোনো ডিটেকশন রুল ব্যবহার করে না, তাই এটি সমস্ত ইভেন্ট স্ক্যান করবে।

```
Usage: eid-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
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
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `eid-metrics` কমান্ডের উদাহরণ

* একটি একক ফাইল থেকে Event ID মেট্রিক্স প্রিন্ট করুন: `hayabusa.exe eid-metrics -f Security.evtx`
* একটি ডিরেক্টরি থেকে Event ID মেট্রিক্স প্রিন্ট করুন: `hayabusa.exe eid-metrics -d ../logs`
* ফলাফল একটি CSV ফাইলে সংরক্ষণ করুন: `hayabusa.exe eid-metrics -f Security.evtx -o eid-metrics.csv`

### `eid-metrics` কমান্ড কনফিগ ফাইল

ইভেন্টের চ্যানেল, ইভেন্ট আইডি এবং টাইটেল `rules/config/channel_eid_info.txt` ফাইলে সংজ্ঞায়িত করা হয়।

উদাহরণ:
```
Channel,EventID,EventTitle
Microsoft-Windows-Sysmon/Operational,1,Process Creation.
Microsoft-Windows-Sysmon/Operational,2,File Creation Timestamp Changed. (Possible Timestomping)
Microsoft-Windows-Sysmon/Operational,3,Network Connection.
Microsoft-Windows-Sysmon/Operational,4,Sysmon Service State Changed.
```

### `eid-metrics` স্ক্রিনশট

![eid-metrics screenshot](../assets/screenshots/EID-Metrics.png)

## `expand-list` কমান্ড

রুল ফোল্ডার থেকে `expand` প্লেসহোল্ডার নিষ্কাশন করুন।
`expand` ফিল্ড মডিফায়ার ব্যবহার করে এমন কোনো রুল ব্যবহার করার জন্য কনফিগ ফাইল তৈরির সময় এটি উপযোগী।
`expand` রুল ব্যবহার করতে, আপনাকে শুধু `./config/expand/` ডিরেক্টরির অধীনে `expand` ফিল্ড মডিফায়ারের নাম দিয়ে একটি `.txt` ফাইল তৈরি করতে হবে এবং যে মানগুলো আপনি যাচাই করতে চান সেগুলো ফাইলের ভিতরে রাখতে হবে।

উদাহরণস্বরূপ, যদি রুলের `detection` লজিক হয়:
```yaml
detection:
    selection:
        EventID: 5145
        RelativeTargetName|contains: '\winreg'
    filter_main:
        IpAddress|expand: '%Admins_Workstations%'
    condition: selection and not filter_main
```

তাহলে আপনি `./config/expand/Admins_Workstations.txt` টেক্সট ফাইলটি তৈরি করবেন এবং এর মতো মান রাখবেন:
```
AdminWorkstation1
AdminWorkstation2
AdminWorkstation3
```

এটি মূলত নিম্নলিখিতটির মতো একই লজিক যাচাই করবে:
```
- IpAddress: 'AdminWorkstation1'
- IpAddress: 'AdminWorkstation2'
- IpAddress: 'AdminWorkstation3'
```

যদি কনফিগ ফাইলটি না থাকে, Hayabusa তবুও `expand` রুলটি লোড করবে কিন্তু এটিকে উপেক্ষা করবে।

```
Usage:  expand-list <INPUT> [OPTIONS]

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify rule directory (default: ./rules)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

### `expand-list` কমান্ডের উদাহরণ

* ডিফল্ট `rules` ডিরেক্টরি থেকে `expand` ফিল্ড মডিফায়ার নিষ্কাশন করুন: `hayabusa.exe expand-list`
* `sigma` ডিরেক্টরি থেকে `expand` ফিল্ড মডিফায়ার নিষ্কাশন করুন: `hayabusa.exe eid-metrics -r ../sigma`

### `expand-list` ফলাফল

```
5 unique expand placeholders found:
Admins_Workstations
DC-MACHINE-NAME
Workstations
internal_domains
domain_controller_hostnames
```

## `extract-base64` কমান্ড

এই কমান্ডটি নিম্নলিখিত ইভেন্টগুলো থেকে base64 স্ট্রিং নিষ্কাশন করবে, সেগুলো ডিকোড করবে এবং কী ধরনের এনকোডিং ব্যবহার করা হচ্ছে তা জানাবে।
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
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
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
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `extract-base64` কমান্ডের উদাহরণ

* একটি ডিরেক্টরি স্ক্যান করুন এবং টার্মিনালে আউটপুট দিন: `hayabusa.exe  extract-base64 -d ../hayabusa-sample-evtx`
* একটি ডিরেক্টরি স্ক্যান করুন এবং একটি CSV ফাইলে আউটপুট দিন: `hayabusa.exe eid-metrics -r ../sigma -o base64-extracted.csv`

### `extract-base64` ফলাফল

টার্মিনালে আউটপুট দেওয়ার সময়, যেহেতু জায়গা সীমিত, শুধুমাত্র নিম্নলিখিত ফিল্ডগুলো প্রদর্শিত হয়:
  * Timestamp
  * Computer
  * Base64 String
  * Decoded String (if not binary)

একটি CSV ফাইলে সংরক্ষণ করার সময়, নিম্নলিখিত ফিল্ডগুলো সংরক্ষিত হয়:
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

## `log-metrics` কমান্ড

আপনি `log-metrics` কমান্ড ব্যবহার করে ইভেন্ট লগের ভিতরে নিম্নলিখিত মেটাডেটা প্রিন্ট করতে পারেন:
  * Filename
  * Computer names
  * Number of events
  * First timestamp
  * Last timestamp
  * Channels
  * Providers

এই কমান্ডটি কোনো ডিটেকশন রুল ব্যবহার করে না, তাই এটি সমস্ত ইভেন্ট স্ক্যান করবে।

```
Usage: log-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
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
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `log-metrics` কমান্ডের উদাহরণ

* একটি একক ফাইল থেকে Event ID মেট্রিক্স প্রিন্ট করুন: `hayabusa.exe log-metrics -f Security.evtx`
* একটি ডিরেক্টরি থেকে Event ID মেট্রিক্স প্রিন্ট করুন: `hayabusa.exe log-metrics -d ../logs`
* ফলাফল একটি CSV ফাইলে সংরক্ষণ করুন: `hayabusa.exe log-metrics -d ../logs -o eid-metrics.csv`

### `log-metrics` স্ক্রিনশট

![log-metrics screenshot](../assets/screenshots/LogMetrics.png)

## `logon-summary` কমান্ড

আপনি `logon-summary` কমান্ড ব্যবহার করে লগইন তথ্যের সারসংক্ষেপ (লগইন ইউজারনেম এবং সফল ও ব্যর্থ লগইন সংখ্যা) আউটপুট দিতে পারেন।
আপনি `-f` দিয়ে একটি evtx ফাইলের জন্য অথবা `-d` অপশন দিয়ে একাধিক evtx ফাইলের জন্য লগইন তথ্য প্রদর্শন করতে পারেন।

সফল লগইনগুলো নিম্নলিখিত ইভেন্ট থেকে নেওয়া হয়:
  * `Security 4624` (Successful Logon)
  * `RDS-LSM 21` (Remote Desktop Service Local Session Manager Logon)
  * `RDS-GTW 302` (Remote Desktop Service Gateway Logon)

ব্যর্থ লগইনগুলো `Security 4625` ইভেন্ট থেকে নেওয়া হয়।

```
Usage: logon-summary <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
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
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `logon-summary` কমান্ডের উদাহরণ

* লগইন সারসংক্ষেপ প্রিন্ট করুন: `hayabusa.exe logon-summary -f Security.evtx`
* লগইন সারসংক্ষেপ ফলাফল সংরক্ষণ করুন: `hayabusa.exe logon-summary -d ../logs -o logon-summary.csv`

### `logon-summary` স্ক্রিনশট

![logon-summary successful logons screenshot](../assets/screenshots/LogonSummarySuccessfulLogons.png)

![logon-summary failed logons screenshot](../assets/screenshots/LogonSummaryFailedLogons.png)

## `pivot-keywords-list` কমান্ড

আপনি `pivot-keywords-list` কমান্ড ব্যবহার করে অনন্য পিভট কীওয়ার্ডের একটি তালিকা তৈরি করতে পারেন, যা অস্বাভাবিক ইউজার, হোস্টনেম, প্রসেস ইত্যাদি দ্রুত শনাক্ত করতে এবং ইভেন্টগুলোকে সম্পর্কযুক্ত করতে সাহায্য করে।

গুরুত্বপূর্ণ: ডিফল্টভাবে, hayabusa সমস্ত ইভেন্ট (informational এবং তার উপরে) থেকে ফলাফল ফেরত দেবে, তাই আমরা দৃঢ়ভাবে `pivot-keywords-list` কমান্ডটি `-m, --min-level` অপশনের সাথে একত্রিত করার পরামর্শ দিই।
উদাহরণস্বরূপ, শুধুমাত্র `critical` অ্যালার্ট থেকে কীওয়ার্ড তৈরি দিয়ে `-m critical` শুরু করুন এবং তারপর `-m high`, `-m medium` ইত্যাদি দিয়ে চালিয়ে যান।
আপনার ফলাফলে সম্ভবত সাধারণ কীওয়ার্ড থাকবে যা অনেক স্বাভাবিক ইভেন্টের সাথে মিলবে, তাই ফলাফলগুলো ম্যানুয়ালি যাচাই করে এবং একটি একক ফাইলে অনন্য কীওয়ার্ডের একটি তালিকা তৈরি করার পরে, আপনি `grep -f keywords.txt timeline.csv` এর মতো একটি কমান্ড দিয়ে সন্দেহজনক কার্যকলাপের একটি সংকুচিত টাইমলাইন তৈরি করতে পারেন।

```
Usage: pivot-keywords-list <INPUT> [OPTIONS]

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
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
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

### `pivot-keywords-list` কমান্ডের উদাহরণ

* পিভট কীওয়ার্ড স্ক্রিনে আউটপুট দিন: `hayabusa.exe pivot-keywords-list -d ../logs -m critical`
* critical অ্যালার্ট থেকে পিভট কীওয়ার্ডের একটি তালিকা তৈরি করুন এবং ফলাফল সংরক্ষণ করুন। (ফলাফল `keywords-Ip Addresses.txt`, `keywords-Users.txt` ইত্যাদিতে সংরক্ষিত হবে):

```
hayabusa.exe pivot-keywords-list -d ../logs -m critical -o keywords`
```

### `pivot-keywords-list` কনফিগ ফাইল

আপনি `./rules/config/pivot_keywords.txt` সম্পাদনা করে কী কীওয়ার্ড অনুসন্ধান করতে চান তা কাস্টমাইজ করতে পারেন।
[এই পৃষ্ঠাটি](https://github.com/Yamato-Security/hayabusa-rules/blob/main/config/pivot_keywords.txt) হলো ডিফল্ট সেটিং।

ফরম্যাটটি হলো `KeywordName.FieldName`। উদাহরণস্বরূপ, `Users` এর তালিকা তৈরি করার সময়, hayabusa `SubjectUserName`, `TargetUserName` এবং `User` ফিল্ডের সমস্ত মান তালিকাভুক্ত করবে।

## `search` কমান্ড

`search` কমান্ড আপনাকে সমস্ত ইভেন্টে কীওয়ার্ড অনুসন্ধান করতে দেবে।
(শুধুমাত্র Hayabusa ডিটেকশন ফলাফল নয়।)
Hayabusa দ্বারা শনাক্ত না হওয়া ইভেন্টগুলোতে কোনো প্রমাণ আছে কিনা তা নির্ধারণ করার জন্য এটি উপযোগী।

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
  -J, --JSON-output            Save the search results in JSON format (ex: -J -o results.json)
  -L, --JSONL-output           Save the search results in JSONL format (ex: -L -o results.jsonl)
  -M, --multiline              Output event field information in multiple rows for CSV output
  -o, --output <FILE>          Save the search results in CSV format (ex: search.csv)
  -S, --tab-separator          Separate event field information by tabs

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `search` কমান্ডের উদাহরণ

* `../hayabusa-sample-evtx` ডিরেক্টরিতে `mimikatz` কীওয়ার্ড অনুসন্ধান করুন:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz"
```

> দ্রষ্টব্য: ডেটার মধ্যে যেকোনো জায়গায় `mimikatz` পাওয়া গেলে কীওয়ার্ডটি মিলবে। এটি কোনো হুবহু মিল নয়।

* `../hayabusa-sample-evtx` ডিরেক্টরিতে `mimikatz` বা `kali` কীওয়ার্ড অনুসন্ধান করুন:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -k "kali"
```

* `../hayabusa-sample-evtx` ডিরেক্টরিতে `mimikatz` কীওয়ার্ড অনুসন্ধান করুন এবং কেস উপেক্ষা করুন:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -i
```

* রেগুলার এক্সপ্রেশন ব্যবহার করে `../hayabusa-sample-evtx` ডিরেক্টরিতে IP অ্যাড্রেস অনুসন্ধান করুন:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
```

* `../hayabusa-sample-evtx` ডিরেক্টরি অনুসন্ধান করুন এবং `WorkstationName` ফিল্ড `kali` এমন সমস্ত ইভেন্ট দেখান:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r ".*" -F WorkstationName:"kali"
```

> দ্রষ্টব্য: `.*` হলো প্রতিটি ইভেন্টের সাথে মিল করার রেগুলার এক্সপ্রেশন।

### `search` কমান্ড কনফিগ ফাইল

`./rules/config/channel_abbreviations.txt`: চ্যানেল নাম এবং তাদের সংক্ষিপ্ত রূপের ম্যাপিং।
