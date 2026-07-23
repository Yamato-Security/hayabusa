# DFIR Timeline Commands

## Scan Wizard

`dfir-timeline` command တွင် ယခုအခါ scan wizard ကို default အနေဖြင့် enable လုပ်ထားပါသည်။
ဤသည်မှာ အသုံးပြုသူများအနေဖြင့် ၎င်းတို့၏ လိုအပ်ချက်နှင့် နှစ်သက်မှုအလိုက် မည်သည့် detection rule များကို enable လုပ်လိုသည်ကို လွယ်ကူစွာရွေးချယ်နိုင်ရန် ရည်ရွယ်ထားပါသည်။
load လုပ်ရန် detection rule အစုအဝေးများသည် Sigma project ၏ တရားဝင်စာရင်းများအပေါ် အခြေခံထားပါသည်။
အသေးစိတ်ကို [ဤ blog post](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81) တွင် ရှင်းပြထားပါသည်။
`-w, --no-wizard` option ကိုထည့်ခြင်းဖြင့် wizard ကို လွယ်ကူစွာ ပိတ်ပြီး Hayabusa ကို ၎င်း၏ ရိုးရာနည်းလမ်းအတိုင်း အသုံးပြုနိုင်ပါသည်။

### Core Rules

`core` rule set သည် `test` သို့မဟုတ် `stable` status နှင့် `high` သို့မဟုတ် `critical` level ရှိသော rule များကို enable လုပ်ပါသည်။
ဤသည်တို့မှာ ယုံကြည်စိတ်ချရမှုနှင့် ဆက်စပ်မှုမြင့်မားသော အရည်အသွေးမြင့် rule များဖြစ်ပြီး false positive များစွာ ထုတ်ပေးမည်မဟုတ်ပါ။
rule status သည် `test` သို့မဟုတ် `stable` ဖြစ်ခြင်းမှာ false positive များ ၆ လကျော် အစီရင်ခံခြင်းမရှိခဲ့ဟု ဆိုလိုပါသည်။
rule များသည် တိုက်ခိုက်သူ၏ နည်းစနစ်များ၊ ယေဘုယျ သံသယဖြစ်ဖွယ်လုပ်ဆောင်ချက်များ သို့မဟုတ် အန္တရာယ်ရှိသော အပြုအမူများနှင့် ကိုက်ညီပါမည်။
ဤသည်မှာ `--exclude-status deprecated,unsupported,experimental --min-level high` option များကို အသုံးပြုခြင်းနှင့် တူညီပါသည်။

### Core+ Rules

`core+` rule set သည် `test` သို့မဟုတ် `stable` status နှင့် `medium` သို့မဟုတ် ၎င်းထက်မြင့်သော level ရှိသော rule များကို enable လုပ်ပါသည်။
`medium` rule များသည် အဖွဲ့အစည်းတစ်ခု၏ အချို့သော application များ၊ တရားဝင်သုံးစွဲသူအပြုအမူ သို့မဟုတ် script များနှင့် ကိုက်ညီနိုင်သောကြောင့် နောက်ထပ် tuning လုပ်ရန် မကြာခဏ လိုအပ်ပါသည်။
ဤသည်မှာ `--exclude-status deprecated,unsupported,experimental --min-level medium` option များကို အသုံးပြုခြင်းနှင့် တူညီပါသည်။

### Core++ Rules

`core++` rule set သည် `experimental`၊ `test` သို့မဟုတ် `stable` status နှင့် `medium` သို့မဟုတ် ၎င်းထက်မြင့်သော level ရှိသော rule များကို enable လုပ်ပါသည်။
ဤ rule များသည် အသစ်စက်စက် (bleeding edge) ဖြစ်ပါသည်။
၎င်းတို့ကို SigmaHQ project တွင်ရရှိနိုင်သော baseline evtx ဖိုင်များနှင့် စစ်ဆေးပြီး detection engineer အများအပြားက ပြန်လည်သုံးသပ်ထားပါသည်။
ထို့အပြင် ၎င်းတို့သည် အစပိုင်းတွင် စမ်းသပ်မှု အလွန်နည်းပါးပါသည်။
false positive များ၏ ပိုမိုမြင့်မားသော threshold ကို စီမံခန့်ခွဲရသည့်အတွက် အလဲအလှယ်အနေဖြင့် ခြိမ်းခြောက်မှုများကို တတ်နိုင်သမျှ စောစီးစွာ ရှာဖွေတွေ့ရှိလိုပါက ၎င်းတို့ကို အသုံးပြုပါ။
ဤသည်မှာ `--exclude-status deprecated,unsupported --min-level medium` option များကို အသုံးပြုခြင်းနှင့် တူညီပါသည်။

### Emerging Threats (ET) Add-On Rules

`Emerging Threats (ET)` rule set သည် `detection.emerging_threats` tag ရှိသော rule များကို enable လုပ်ပါသည်။
ဤ rule များသည် သီးခြားခြိမ်းခြောက်မှုများကို ပစ်မှတ်ထားပြီး အချက်အလက်များစွာ မရရှိသေးသော လက်ရှိခြိမ်းခြောက်မှုများအတွက် အထူးအသုံးဝင်ပါသည်။
ဤ rule များတွင် false positive များစွာ ရှိမည်မဟုတ်သော်လည်း အချိန်ကြာလာသည်နှင့်အမျှ ဆက်စပ်မှု လျော့နည်းသွားပါမည်။
ဤ rule များကို enable မလုပ်ထားသည့်အခါ ၎င်းသည် `--exclude-tag detection.emerging_threats` option ကို အသုံးပြုခြင်းနှင့် တူညီပါသည်။
Hayabusa ကို wizard မပါဘဲ ရိုးရာနည်းအတိုင်း run သည့်အခါ ဤ rule များကို default အနေဖြင့် ထည့်သွင်းပါမည်။

### Threat Hunting (TH) Add-On Rules

`Threat Hunting (TH)` rule set သည် `detection.threat_hunting` tag ရှိသော rule များကို enable လုပ်ပါသည်။
ဤ rule များသည် မသိရသေးသော အန္တရာယ်ရှိလုပ်ဆောင်ချက်များကို ရှာဖွေတွေ့ရှိနိုင်သော်လည်း များသောအားဖြင့် false positive များ ပိုများပါမည်။
ဤ rule များကို enable မလုပ်ထားသည့်အခါ ၎င်းသည် `--exclude-tag detection.threat_hunting` option ကို အသုံးပြုခြင်းနှင့် တူညီပါသည်။
Hayabusa ကို wizard မပါဘဲ ရိုးရာနည်းအတိုင်း run သည့်အခါ ဤ rule များကို default အနေဖြင့် ထည့်သွင်းပါမည်။

## Channel-based event log and rules filtering

Hayabusa v2.16.0 မှစ၍ `.evtx` ဖိုင်များနှင့် `.yml` rule များ load လုပ်သည့်အခါ Channel-based filter ကို enable လုပ်ပါသည်။
ရည်ရွယ်ချက်မှာ လိုအပ်သည်များကိုသာ load လုပ်ခြင်းဖြင့် scan ကို တတ်နိုင်သမျှ ထိရောက်စွာ ပြုလုပ်ရန်ဖြစ်ပါသည်။
event log တစ်ခုတည်းတွင် provider အများအပြား ရှိနိုင်သော်လည်း evtx ဖိုင်တစ်ခုတည်းအတွင်း channel အများအပြား ရှိခြင်းမှာ မတွေ့ရများပါ။
(ဤသို့ဖြစ်သည်ကို ကျွန်ုပ်တို့တွေ့ဖူးသည်မှာ တစ်စုံတစ်ဦးက [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) project အတွက် မတူညီသော evtx ဖိုင်နှစ်ခုကို တုပပေါင်းစပ်ထားသည့်အခါ၌သာ ဖြစ်ပါသည်။)
ကျွန်ုပ်တို့သည် ဤအချက်ကို အကျိုးရှိစွာ အသုံးချနိုင်ရန် scan ရန်သတ်မှတ်ထားသော `.evtx` ဖိုင်တိုင်း၏ ပထမဆုံး record ရှိ `Channel` field ကို ဦးစွာ စစ်ဆေးပါသည်။
rule ၏ `Channel` field တွင် သတ်မှတ်ထားသော channel များကို မည်သည့် `.yml` rule များက အသုံးပြုသည်ကိုလည်း ကျွန်ုပ်တို့ စစ်ဆေးပါသည်။
ဤစာရင်းနှစ်ခုဖြင့် `.evtx` ဖိုင်များအတွင်း အမှန်တကယ်ရှိနေသော channel များကို အသုံးပြုသည့် rule များကိုသာ ကျွန်ုပ်တို့ load လုပ်ပါသည်။

ဥပမာအားဖြင့် အသုံးပြုသူတစ်ဦးသည် `Security.evtx` ကို scan လုပ်လိုပါက `Channel: Security` ကို သတ်မှတ်ထားသော rule များကိုသာ အသုံးပြုပါမည်။
အခြား detection rule များ၊ ဥပမာ `Application` log ၌သာ event များကို ရှာဖွေသော rule များ စသည်တို့ကို load လုပ်ခြင်းသည် အကျိုးမရှိပါ။
channel field များ (ဥပမာ - `Channel: Security`) သည် မူရင်း Sigma rule များအတွင်း **တိတိကျကျ** သတ်မှတ်ထားခြင်း မရှိသည်ကို သတိပြုပါ။
Sigma rule များအတွက် channel နှင့် event ID field များကို `logsource` အောက်ရှိ `service` နှင့် `category` field များဖြင့် **သွယ်ဝိုက်၍** သတ်မှတ်ထားပါသည်။ (ဥပမာ - `service: security`)
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository တွင် Sigma rule များကို စီစဉ်ပြုစုသည့်အခါ ကျွန်ုပ်တို့သည် `logsource` field ကို de-abstract လုပ်ပြီး channel နှင့် event ID field များကို တိတိကျကျ သတ်မှတ်ပါသည်။
ဤသို့ မည်ကဲ့သို့နှင့် အဘယ်ကြောင့်ပြုလုပ်သည်ကို [ဤနေရာတွင်](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) အသေးစိတ်ရှင်းပြထားပါသည်။

လက်ရှိတွင် `Channel` သတ်မှတ်ထားခြင်းမရှိဘဲ `.evtx` ဖိုင်အားလုံးကို scan ရန် ရည်ရွယ်ထားသော detection rule နှစ်ခုသာ ရှိပြီး ၎င်းတို့မှာ အောက်ပါအတိုင်းဖြစ်သည် -

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

ဤ rule နှစ်ခုကို အသုံးပြုပြီး load လုပ်ထားသော `.evtx` ဖိုင်များနှင့် rule အားလုံးကို scan လုပ်လိုပါက `dfir-timeline` command တွင် `-A, --enable-all-rules` option ကို ထည့်ရန် လိုအပ်ပါမည်။
ကျွန်ုပ်တို့၏ benchmark များတွင် rule filtering သည် scan လုပ်နေသော ဖိုင်များပေါ်မူတည်၍ ပုံမှန်အားဖြင့် 20% မှ 10x အထိ မြန်နှုန်းတိုးတက်စေပြီး မေမိုရီကိုလည်း ပိုနည်းနည်းသုံးပါသည်။

Channel filtering ကို `.evtx` ဖိုင်များ load လုပ်သည့်အခါတွင်လည်း အသုံးပြုပါသည်။
ဥပမာအားဖြင့် `Security` channel ရှိ event များကို ရှာဖွေသော rule တစ်ခုကို သတ်မှတ်ထားပါက `Security` log မှ မဟုတ်သော `.evtx` ဖိုင်များကို load လုပ်ခြင်းသည် အကျိုးမရှိပါ။
ကျွန်ုပ်တို့၏ benchmark များတွင် ဤသည်က ပုံမှန် scan များဖြင့် 10% ခန့်နှင့် rule တစ်ခုတည်းဖြင့် scan လုပ်သည့်အခါ 60%+ အထိ စွမ်းဆောင်ရည် မြန်နှုန်းတိုးတက်မှု အကျိုးကျေးဇူး ပေးပါသည်။
`.evtx` ဖိုင်တစ်ခုတည်းအတွင်း channel အများအပြား အသုံးပြုထားသည်ကို သေချာပါက၊ ဥပမာ တစ်စုံတစ်ဦးက `.evtx` ဖိုင်အများအပြားကို tool တစ်ခုဖြင့် ပေါင်းစပ်ထားပါက `dfir-timeline` command ရှိ `-a, --scan-all-evtx-files` option ဖြင့် ဤ filtering ကို ပိတ်နိုင်ပါသည်။

> မှတ်ချက် - Channel filtering သည် `.evtx` ဖိုင်များနှင့်သာ အလုပ်လုပ်ပြီး `-J, --json-input` ဖြင့် JSON ဖိုင်မှ event log များ load လုပ်ရန် ကြိုးစားကာ `-A` သို့မဟုတ် `-a` ကိုလည်း သတ်မှတ်ပါက error တစ်ခု ရရှိပါမည်။

## `dfir-timeline` command

`dfir-timeline` command သည် event များ၏ forensics timeline ကို ဖန်တီးပါသည်။ output format ကို `-t, --output-type` ဖြင့် ရွေးချယ်ပါ - `csv` (default)၊ `json` သို့မဟုတ် `jsonl`။ တန်ဖိုးသည် စာလုံးအကြီးအသေး ခွဲခြားမှုမရှိပါ (ဥပမာ - `-t JSONL`)။

- **CSV** သည် ပိုသေးငယ်သော timeline များ (များသောအားဖြင့် 2GB ထက်နည်းသော) ကို LibreOffice သို့မဟုတ် Timeline Explorer ကဲ့သို့ tool များသို့ import လုပ်ရန် ကောင်းပါသည် (event field အားလုံးကို `Details` column ကြီးတစ်ခုတည်းအတွင်း ထားရှိပါသည်)။
- **JSON** သည် `Details` field များကို ခွဲခြားထားသောကြောင့် `jq` ကဲ့သို့ tool များဖြင့် ကြီးမားသော ရလဒ်များကို ပိုမိုအသေးစိတ် ခွဲခြမ်းစိတ်ဖြာရန် အကောင်းဆုံးဖြစ်ပါသည်။
- **JSONL** သည် JSON ထက် ပိုမြန်ပြီး ဖိုင်အရွယ်အစား ပိုသေးငယ်သောကြောင့် Elastic Stack ကဲ့သို့ tool များသို့ import လုပ်ရန် အထူးသင့်တော်ပါသည်။

**CSV Output** option များဖြစ်သော `-M, --multiline`၊ `-S, --tab-separator` နှင့် `-R, --remove-duplicate-data` တို့သည် CSV output အတွက်သာ သက်ရောက်ပြီး CSV မဟုတ်သော `-t` နှင့် တွဲဖက်အသုံးပြုပါက error ဖြစ်ပေါ်ပါမည်။

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

CSV Output:
  -M, --multiline              Separate event field information by newline characters (CSV output only)
  -R, --remove-duplicate-data  Duplicate field data will be replaced with "DUP" (CSV output only, sort required)
  -S, --tab-separator          Separate event field information by tabs (CSV output only)

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --geo-ip <MAXMIND-DB-DIR>      Add GeoIP (ASN, city, country) info to IP addresses
  -H, --html-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline to a file (ex: results.csv)
  -t, --output-type <OUTPUT_FORMAT>  Output format: csv (default), json, or jsonl
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
  -U, --utc               Output time in UTC format (default: local time)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
```

### `dfir-timeline` command examples

* default `standard` profile ဖြင့် Windows event log ဖိုင်တစ်ခုကို hayabusa ဖြင့် run ပါ -

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* Windows event log ဖိုင်အများအပြားပါသော sample-evtx directory ကို verbose profile ဖြင့် hayabusa ဖြင့် run ပါ -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* LibreOffice၊ Timeline Explorer၊ Elastic Stack စသည်တို့ဖြင့် ပိုမိုခွဲခြမ်းစိတ်ဖြာရန် CSV ဖိုင်တစ်ခုတည်းသို့ export လုပ်ပြီး field အချက်အလက်အားလုံးကို ထည့်သွင်းပါ (သတိ - `super-verbose` profile ဖြင့် သင့်ဖိုင် output အရွယ်အစား များစွာ ကြီးလာပါမည်!) -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* CSV အစား JSON output ထုတ်ပါ (`jq` စသည်တို့ဖြင့် ခွဲခြမ်းစိတ်ဖြာရန်) -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* JSONL output ထုတ်ပါ (Elastic Stack စသည်တို့သို့ import လုပ်ရန်၊ `-t` သည် စာလုံးအကြီးအသေး ခွဲခြားမှုမရှိပါ) -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* EID (Event ID) filter ကို enable လုပ်ပါ -

> မှတ်ချက် - EID filter ကို enable လုပ်ခြင်းသည် ကျွန်ုပ်တို့၏ စမ်းသပ်မှုများတွင် ခွဲခြမ်းစိတ်ဖြာမှုကို 10-15% ခန့် မြန်စေသော်လည်း alert များ လွတ်သွားနိုင်ခြေ ရှိပါသည်။

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* hayabusa rule များကိုသာ run ပါ (default မှာ `-r .\rules` ရှိ rule အားလုံးကို run ခြင်းဖြစ်သည်) -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Windows တွင် default အနေဖြင့် enable လုပ်ထားသော log များအတွက် hayabusa rule များကိုသာ run ပါ -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* sysmon log များအတွက် hayabusa rule များကိုသာ run ပါ -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* sigma rule များကိုသာ run ပါ -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* deprecated rule များ (`status` ကို `deprecated` ဟု မှတ်ထားသူများ) နှင့် noisy rule များ (rule ID ကို `.\rules\config\noisy_rules.txt` တွင် စာရင်းပြုထားသူများ) ကို enable လုပ်ပါ -

> မှတ်ချက် - မကြာသေးမီက deprecated rule များကို sigma repository ၏ သီးခြား directory တွင် ထားရှိသောကြောင့် Hayabusa တွင် default အနေဖြင့် ထည့်သွင်းတော့မည်မဟုတ်ပါ။
> ထို့ကြောင့် သင်သည် deprecated rule များကို enable လုပ်ရန် မလိုအပ်ဖွယ်ရှိပါသည်။

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* logon များကို ခွဲခြမ်းစိတ်ဖြာရန် rule များကိုသာ run ပြီး UTC timezone ဖြင့် output ထုတ်ပါ -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* live Windows စက်တစ်ခုပေါ်တွင် run ပါ (Administrator အခွင့်အရေး လိုအပ်သည်) ပြီး alert များ (အန္တရာယ်ရှိနိုင်သော အပြုအမူများ) ကိုသာ ရှာဖွေတွေ့ရှိပါ -

```
hayabusa.exe dfir-timeline -l -m low
```

* verbose အချက်အလက် print ထုတ်ပါ (မည်သည့်ဖိုင်များ ပြုပြင်ရန် အချိန်ကြာသည်၊ parsing error များ စသည်တို့ကို ဆုံးဖြတ်ရန် အသုံးဝင်သည်) -

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Verbose output ဥပမာ -

rule များ load လုပ်ခြင်း -

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

scan အတွင်း error များ -
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

* [Timesketch](https://timesketch.org/) သို့ import လုပ်ရန် သင့်တော်သော CSV format ဖြင့် output ထုတ်ပါ -

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* Quiet error mode -
default အနေဖြင့် hayabusa သည် error message များကို error log ဖိုင်များသို့ သိမ်းဆည်းပါမည်။
error message များကို မသိမ်းဆည်းလိုပါက `-Q` ကို ထည့်ပါ။

### Advanced - GeoIP Log Enrichment

အခမဲ့ GeoLite2 geolocation data ဖြင့် SrcIP (source IP) field များနှင့် TgtIP (target IP) field များသို့ GeoIP (ASN organization၊ city နှင့် country) အချက်အလက်များကို ထည့်နိုင်ပါသည်။

အဆင့်များ -

1. ဦးစွာ MaxMind account တစ်ခုကို [ဤနေရာတွင်](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) sign up လုပ်ပါ။
2. [download page](https://www.maxmind.com/en/accounts/current/geoip/downloads) မှ `.mmdb` ဖိုင်သုံးခုကို download လုပ်ပြီး directory တစ်ခုသို့ သိမ်းဆည်းပါ။ ဖိုင်အမည်များမှာ `GeoLite2-ASN.mmdb`၊	`GeoLite2-City.mmdb` နှင့် `GeoLite2-Country.mmdb` ဟု ဖြစ်သင့်ပါသည်။
3. `dfir-timeline` command ကို run သည့်အခါ `-G` option ၏နောက်တွင် MaxMind database များပါသော directory ကို ထည့်ပါ။

* CSV output ဖြင့် အောက်ပါ column ၆ ခုကို ထပ်ဆောင်း output ထုတ်ပါမည် - `SrcASN`၊ `SrcCity`၊ `SrcCountry`၊ `TgtASN`၊ `TgtCity`၊ `TgtCountry`။
* JSON/JSONL output ဖြင့် တူညီသော `SrcASN`၊ `SrcCity`၊ `SrcCountry`၊ `TgtASN`၊ `TgtCity`၊ `TgtCountry` field များကို `Details` object သို့ ထည့်ပါမည်၊ သို့သော် ၎င်းတို့တွင် အချက်အလက်ပါဝင်မှသာ ဖြစ်သည်။

* `SrcIP` သို့မဟုတ် `TgtIP` သည် localhost (`127.0.0.1`၊ `::1` စသည်) ဖြစ်သည့်အခါ `SrcASN` သို့မဟုတ် `TgtASN` ကို `Local` အဖြစ် output ထုတ်ပါမည်။
* `SrcIP` သို့မဟုတ် `TgtIP` သည် private IP address (`10.0.0.0/8`၊ `fe80::/10` စသည်) ဖြစ်သည့်အခါ `SrcASN` သို့မဟုတ် `TgtASN` ကို `Private` အဖြစ် output ထုတ်ပါမည်။

#### GeoIP config file

GeoIP database များတွင် ရှာဖွေသော source နှင့် target IP address များပါဝင်သည့် field အမည်များကို `rules/config/geoip_field_mapping.yaml` တွင် သတ်မှတ်ထားပါသည်။
လိုအပ်ပါက ဤစာရင်းသို့ ထပ်ဖြည့်နိုင်ပါသည်။
ဤဖိုင်တွင် မည်သည့် event များမှ IP address အချက်အလက်ကို ထုတ်ယူရမည်ကို ဆုံးဖြတ်သော filter section တစ်ခုလည်း ရှိပါသည်။

#### Automatic updates of GeoIP databases

MaxMind GeoIP database များကို ၂ ပတ်တိုင်း update လုပ်ပါသည်။
ဤ database များကို အလိုအလျောက် update လုပ်ရန် MaxMind `geoipupdate` tool ကို [ဤနေရာတွင်](https://github.com/maxmind/geoipupdate) install လုပ်နိုင်ပါသည်။

macOS တွင် အဆင့်များ -

1. `brew install geoipupdate`
2. `/usr/local/etc/GeoIP.conf` သို့မဟုတ် `/opt/homebrew/etc/GeoIP.conf` ကို တည်းဖြတ်ပါ - MaxMind website သို့ login ဝင်ပြီးနောက် သင်ဖန်တီးသော `AccountID` နှင့် `LicenseKey` ကို ထည့်ပါ။ `EditionIDs` လိုင်းတွင် `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` ဟု ပါရှိစေရန် သေချာပါ။
3. `geoipupdate` ကို run ပါ။
4. GeoIP အချက်အလက် ထည့်လိုသည့်အခါ `-G /usr/local/var/GeoIP` သို့မဟုတ် `-G /opt/homebrew/var/GeoIP` ကို ထည့်ပါ။

Windows တွင် အဆင့်များ -

1. [Releases](https://github.com/maxmind/geoipupdate/releases) page မှ နောက်ဆုံး Windows binary (ဥပမာ - `geoipupdate_4.10.0_windows_amd64.zip`) ကို download လုပ်ပါ။
2. `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf` ကို တည်းဖြတ်ပါ - MaxMind website သို့ login ဝင်ပြီးနောက် သင်ဖန်တီးသော `AccountID` နှင့် `LicenseKey` ကို ထည့်ပါ။ `EditionIDs` လိုင်းတွင် `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` ဟု ပါရှိစေရန် သေချာပါ။
3. `geoipupdate` executable ကို run ပါ။

Linux တွင် အဆင့်များ -

1. `sudo apt install geoip-update` ဖြင့် install လုပ်ပါ။
2. `sudo nano /etc/GeoIP.conf` ဖြင့် config file ကို တည်းဖြတ်ပါ။
3. `sudo geoipupdate` ဖြင့် database file များကို update လုပ်ပါ။
4. GeoIP အချက်အလက် ထည့်လိုသည့်အခါ `-G /var/lib/GeoIP/` ကို ထည့်ပါ။

### `dfir-timeline` command config files

`./rules/config/channel_abbreviations.txt`: channel အမည်များနှင့် ၎င်းတို့၏ အတိုကောက်များ၏ mapping များ။

`./rules/config/default_details.txt`: rule တစ်ခုတွင် `details:` လိုင်း သတ်မှတ်မထားပါက မည်သည့် default field အချက်အလက် (`%Details%` field) ကို output ထုတ်သင့်သည်အတွက် config ဖိုင်။
ဤသည်မှာ provider name နှင့် event ID များအပေါ် အခြေခံပါသည်။

`./rules/config/eventkey_alias.txt`: ဤဖိုင်တွင် field များအတွက် short name alias များနှင့် ၎င်းတို့၏ မူရင်း ပိုရှည်သော field အမည်များ၏ mapping များ ပါဝင်ပါသည်။

ဥပမာ -
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

field တစ်ခုကို ဤနေရာတွင် သတ်မှတ်မထားပါက Hayabusa သည် ၎င်း field အတွက် `Event.EventData` အောက်ကို အလိုအလျောက် စစ်ဆေးပါမည်။

`./rules/config/exclude_rules.txt`: ဤဖိုင်တွင် အသုံးပြုခြင်းမှ ဖယ်ထုတ်မည့် rule ID များ၏ စာရင်း ပါဝင်ပါသည်။
များသောအားဖြင့် ဤသည်မှာ rule တစ်ခုက အခြားတစ်ခုကို အစားထိုးထားသောကြောင့် သို့မဟုတ် rule ကို အစကတည်းက အသုံးမပြုနိုင်သောကြောင့် ဖြစ်ပါသည်။
firewall များနှင့် IDS များကဲ့သို့ မည်သည့် signature-based tool မဆို သင့်ပတ်ဝန်းကျင်နှင့် ကိုက်ညီစေရန် tuning အချို့ လိုအပ်မည်ဖြစ်၍ အချို့ rule များကို အမြဲတမ်း သို့မဟုတ် ယာယီ ဖယ်ထုတ်ရန် လိုအပ်နိုင်ပါသည်။
သင်မလိုအပ်သော သို့မဟုတ် အသုံးမပြုနိုင်သော rule များကို လျစ်လျူရှုရန် rule ID (ဥပမာ - `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) ကို `./rules/config/exclude_rules.txt` သို့ ထည့်နိုင်ပါသည်။

`./rules/config/noisy_rules.txt`: ဤဖိုင်တွင် default အနေဖြင့် disable လုပ်ထားသော်လည်း `-n, --enable-noisy-rules` option ဖြင့် noisy rule များ enable လုပ်ခြင်းဖြင့် enable လုပ်နိုင်သော rule ID များ၏ စာရင်း ပါဝင်ပါသည်။
ဤ rule များသည် များသောအားဖြင့် သဘာဝအားဖြင့်ဖြစ်စေ false positive များကြောင့်ဖြစ်စေ noisy ဖြစ်ပါသည်။

`./rules/config/target_event_IDs.txt`: EID filter ကို enable လုပ်ထားပါက ဤဖိုင်တွင် သတ်မှတ်ထားသော event ID များကိုသာ scan လုပ်ပါမည်။
default အနေဖြင့် Hayabusa သည် event အားလုံးကို scan လုပ်ပါမည်၊ သို့သော် စွမ်းဆောင်ရည်ကို တိုးတက်စေလိုပါက `-E, --eid-filter` option ကို အသုံးပြုပါ။
ဤသည်က များသောအားဖြင့် 10~25% မြန်နှုန်းတိုးတက်မှု ဖြစ်စေပါသည်။

## `level-tuning` command

`level-tuning` command သည် rule များအတွက် alert level များကို သင်လိုချင်သည့်အတိုင်း risk level ကို မြှင့်တင်ခြင်း သို့မဟုတ် လျှော့ချခြင်းဖြင့် tune လုပ်နိုင်စေပါမည်။
ဤ command သည် `rules` folder ရှိ rule များ၏ risk level (`level` field) ကို ပြန်ရေးရန် config ဖိုင်တစ်ခုကို အသုံးပြုပါသည်။

> သတိ - `update-rules` command ကို run တိုင်း risk level သည် မူရင်းတန်ဖိုးသို့ ပြန်ရောက်သွားမည်ဖြစ်၍ ထို့နောက် `level-tuning` command ကို ထပ်မံ run ရန် လိုအပ်ပါမည်။

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` command examples

* ပုံမှန်အသုံးပြုမှု - `hayabusa.exe level-tuning`
* သင့် custom config ဖိုင်အပေါ် အခြေခံ၍ rule alert level များကို tune လုပ်ပါ - `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` config file

Hayabusa နှင့် Sigma rule ရေးသားသူများသည် ၎င်းတို့၏ rule များ ရေးသားသည့်အခါ alert ၏ သင့်တော်သော risk level ကို ခန့်မှန်းကြပါမည်။
သို့သော် တစ်ခါတစ်ရံ risk level များသည် တသမတ်တည်းမဖြစ်သလို အမှန်တကယ် risk level သည်လည်း သင့်ပတ်ဝန်းကျင်အလိုက် ကွဲပြားနိုင်ပါသည်။
Yamato Security သည် သင့် rule များကိုလည်း tune လုပ်ရန် အသုံးပြုနိုင်သော config ဖိုင်ကို `./rules/config/level_tuning.txt` တွင် ပံ့ပိုးပေးပြီး ထိန်းသိမ်းထားပါသည်။

`./rules/config/level_tuning.txt` နမူနာ -

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

ဤကိစ္စတွင် rules directory ရှိ `id` သည် `570ae5ec-33dc-427c-b815-db86228ad43e` ဖြစ်သော rule ၏ risk level ၏ `level` ကို `informational` အဖြစ် ပြန်ရေးပါမည်။
သတ်မှတ်နိုင်သော level များမှာ `critical`၊ `high`၊ `medium`၊ `low` နှင့် `informational` တို့ဖြစ်သည်။

> သတိ - `./rules/config/level_tuning.txt` config ဖိုင်ကိုလည်း `update-rules` ကို run တိုင်း hayabusa-rules repository ရှိ နောက်ဆုံးဗားရှင်းသို့ update လုပ်ပါမည်။
> ထို့ကြောင့် သင်သည် ဤဖိုင်ကို ပြောင်းလဲမှုများ ပြုလုပ်ပါက ထိုပြောင်းလဲမှုများ ဆုံးရှုံးသွားပါမည်!
> သင်ကိုယ်တိုင်အတွက် config ဖိုင်တစ်ခု ထားရှိလိုပါက `./config/level_tuning.txt` တွင် config ဖိုင်တစ်ခု ဖန်တီးပြီး `hayabusa.exe level-tuning -f ./config/level_tuning.txt` ကို run ပါ။
> Yamato Security က ပံ့ပိုးပေးသော config ဖိုင်ဖြင့် level tuning ကို ဦးစွာ လုပ်ပြီးနောက် သင့်ကိုယ်ပိုင် config ဖိုင်ဖြင့် ထပ်မံ tune လုပ်နိုင်ပါသည်။

## `list-profiles` command

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` command

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` command examples

* default profile ကို `minimal` အဖြစ် သတ်မှတ်ပါ - `hayabusa.exe set-default-profile minimal`
* default profile ကို `super-verbose` အဖြစ် သတ်မှတ်ပါ - `hayabusa.exe set-default-profile super-verbose`

## `update-rules` command

`update-rules` command သည် `rules` folder ကို [Hayabusa rules github repository](https://github.com/Yamato-Security/hayabusa-rules) နှင့် sync လုပ်ပြီး rule များနှင့် config ဖိုင်များကို update လုပ်ပါမည်။

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` command example

သင်သည် ပုံမှန်အားဖြင့် ဤအတိုင်းသာ run ရပါမည် - `hayabusa.exe update-rules`
