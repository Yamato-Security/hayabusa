# DFIR टाइमलाइन कमांड

## स्कैन विज़ार्ड

`dfir-timeline` कमांड में अब एक स्कैन विज़ार्ड डिफ़ॉल्ट रूप से सक्षम है।
इसका उद्देश्य उपयोगकर्ताओं को अपनी आवश्यकताओं और प्राथमिकताओं के अनुसार यह आसानी से चुनने में मदद करना है कि वे किन डिटेक्शन नियमों को सक्षम करना चाहते हैं।
लोड किए जाने वाले डिटेक्शन नियमों के सेट Sigma परियोजना की आधिकारिक सूचियों पर आधारित हैं।
विवरण [इस ब्लॉग पोस्ट](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81) में समझाया गया है।
आप `-w, --no-wizard` विकल्प जोड़कर विज़ार्ड को आसानी से बंद कर सकते हैं और Hayabusa को इसके पारंपरिक तरीके से उपयोग कर सकते हैं।

### Core Rules

`core` नियम सेट उन नियमों को सक्षम करता है जिनकी स्थिति `test` या `stable` है और जिनका स्तर `high` या `critical` है।
ये उच्च आत्मविश्वास और प्रासंगिकता वाले उच्च गुणवत्ता वाले नियम हैं और इन्हें अधिक फ़ॉल्स पॉज़िटिव उत्पन्न नहीं करने चाहिए।
नियम की स्थिति `test` या `stable` है, जिसका अर्थ है कि 6 महीने से अधिक समय तक कोई फ़ॉल्स पॉज़िटिव रिपोर्ट नहीं हुआ।
नियम हमलावर तकनीकों, सामान्य संदिग्ध गतिविधि, या दुर्भावनापूर्ण व्यवहार पर मैच करेंगे।
यह `--exclude-status deprecated,unsupported,experimental --min-level high` विकल्पों का उपयोग करने के समान है।

### Core+ Rules

`core+` नियम सेट उन नियमों को सक्षम करता है जिनकी स्थिति `test` या `stable` है और जिनका स्तर `medium` या उच्चतर है।
`medium` नियमों को अक्सर अतिरिक्त ट्यूनिंग की आवश्यकता होती है क्योंकि किसी संगठन के कुछ एप्लिकेशन, वैध उपयोगकर्ता व्यवहार या स्क्रिप्ट मैच हो सकते हैं।
यह `--exclude-status deprecated,unsupported,experimental --min-level medium` विकल्पों का उपयोग करने के समान है।

### Core++ Rules

`core++` नियम सेट उन नियमों को सक्षम करता है जिनकी स्थिति `experimental`, `test` या `stable` है और जिनका स्तर `medium` या उच्चतर है।
ये नियम अत्याधुनिक हैं।
इन्हें SigmaHQ परियोजना में उपलब्ध बेसलाइन evtx फ़ाइलों के विरुद्ध मान्य किया जाता है और कई डिटेक्शन इंजीनियरों द्वारा समीक्षा की जाती है।
इसके अलावा, ये शुरू में काफी हद तक अपरीक्षित होते हैं।
इनका उपयोग तब करें जब आप उच्च फ़ॉल्स पॉज़िटिव सीमा को प्रबंधित करने की लागत पर खतरों का यथाशीघ्र पता लगाने में सक्षम होना चाहते हैं।
यह `--exclude-status deprecated,unsupported --min-level medium` विकल्पों का उपयोग करने के समान है।

### Emerging Threats (ET) ऐड-ऑन नियम

`Emerging Threats (ET)` नियम सेट उन नियमों को सक्षम करता है जिनमें `detection.emerging_threats` टैग होता है।
ये नियम विशिष्ट खतरों को लक्षित करते हैं और विशेष रूप से वर्तमान खतरों के लिए उपयोगी हैं जहां अभी ज़्यादा जानकारी उपलब्ध नहीं है।
इन नियमों में अधिक फ़ॉल्स पॉज़िटिव नहीं होने चाहिए लेकिन समय के साथ इनकी प्रासंगिकता कम होती जाएगी।
जब ये नियम सक्षम नहीं होते हैं, तो यह `--exclude-tag detection.emerging_threats` विकल्प का उपयोग करने के समान है।
जब Hayabusa को विज़ार्ड के बिना पारंपरिक रूप से चलाया जाता है, तो ये नियम डिफ़ॉल्ट रूप से शामिल होंगे।

### Threat Hunting (TH) ऐड-ऑन नियम

`Threat Hunting (TH)` नियम सेट उन नियमों को सक्षम करता है जिनमें `detection.threat_hunting` टैग होता है।
ये नियम अज्ञात दुर्भावनापूर्ण गतिविधि का पता लगा सकते हैं, हालांकि, इनमें आमतौर पर अधिक फ़ॉल्स पॉज़िटिव होंगे।
जब ये नियम सक्षम नहीं होते हैं, तो यह `--exclude-tag detection.threat_hunting` विकल्प का उपयोग करने के समान है।
जब Hayabusa को विज़ार्ड के बिना पारंपरिक रूप से चलाया जाता है, तो ये नियम डिफ़ॉल्ट रूप से शामिल होंगे।

## Channel-आधारित इवेंट लॉग और नियम फ़िल्टरिंग

Hayabusa v2.16.0 के अनुसार, हम `.evtx` फ़ाइलों और `.yml` नियमों को लोड करते समय एक Channel-आधारित फ़िल्टर सक्षम करते हैं।
इसका उद्देश्य केवल आवश्यक चीज़ों को लोड करके स्कैनिंग को यथासंभव कुशल बनाना है।
हालांकि एक ही इवेंट लॉग में कई प्रोवाइडर हो सकते हैं, लेकिन एक ही evtx फ़ाइल के अंदर कई चैनल होना आम बात नहीं है।
(हमने इसे केवल तब देखा है जब किसी ने [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) परियोजना के लिए दो अलग-अलग evtx फ़ाइलों को कृत्रिम रूप से एक साथ मर्ज किया है।)
हम इसका लाभ उठाते हुए पहले स्कैन के लिए निर्दिष्ट प्रत्येक `.evtx` फ़ाइल के पहले रिकॉर्ड में `Channel` फ़ील्ड की जाँच कर सकते हैं।
हम यह भी जाँचते हैं कि कौन से `.yml` नियम, नियम के `Channel` फ़ील्ड में निर्दिष्ट किन चैनलों का उपयोग करते हैं।
इन दो सूचियों के साथ, हम केवल उन नियमों को लोड करते हैं जो उन चैनलों का उपयोग करते हैं जो वास्तव में `.evtx` फ़ाइलों के अंदर मौजूद हैं।

तो उदाहरण के लिए, यदि कोई उपयोगकर्ता `Security.evtx` को स्कैन करना चाहता है, तो केवल वे नियम उपयोग किए जाएंगे जो `Channel: Security` निर्दिष्ट करते हैं।
अन्य डिटेक्शन नियमों को लोड करने का कोई मतलब नहीं है, उदाहरण के लिए वे नियम जो केवल `Application` लॉग आदि में इवेंट खोजते हैं।
ध्यान दें कि चैनल फ़ील्ड (उदा: `Channel: Security`) मूल Sigma नियमों के अंदर **स्पष्ट रूप से** परिभाषित नहीं हैं।
Sigma नियमों के लिए, चैनल और इवेंट ID फ़ील्ड `logsource` के अंतर्गत `service` और `category` फ़ील्ड के साथ **अंतर्निहित रूप से** परिभाषित होते हैं। (उदा: `service: security`)
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) रिपॉज़िटरी में Sigma नियमों को संकलित करते समय, हम `logsource` फ़ील्ड को डी-एब्स्ट्रैक्ट करते हैं और चैनल तथा इवेंट ID फ़ील्ड को स्पष्ट रूप से परिभाषित करते हैं।
हम कैसे और क्यों ऐसा करते हैं, इसे विस्तार से [यहाँ](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) समझाते हैं।

वर्तमान में, केवल दो डिटेक्शन नियम हैं जिनमें `Channel` परिभाषित नहीं है और जो सभी `.evtx` फ़ाइलों को स्कैन करने के लिए अभिप्रेत हैं, वे निम्नलिखित हैं:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

यदि आप इन दो नियमों का उपयोग करना चाहते हैं और लोड की गई `.evtx` फ़ाइलों के विरुद्ध सभी नियमों को स्कैन करना चाहते हैं, तो आपको `dfir-timeline` कमांड में `-A, --enable-all-rules` विकल्प जोड़ना होगा।
हमारे बेंचमार्क में, नियम फ़िल्टरिंग आमतौर पर इस आधार पर 20% से 10x गति सुधार देती है कि कौन सी फ़ाइलें स्कैन की जा रही हैं और निश्चित रूप से कम मेमोरी का उपयोग करती है।

`.evtx` फ़ाइलों को लोड करते समय भी चैनल फ़िल्टरिंग का उपयोग किया जाता है।
उदाहरण के लिए, यदि आप एक ऐसा नियम निर्दिष्ट करते हैं जो `Security` चैनल वाले इवेंट खोजता है, तो उन `.evtx` फ़ाइलों को लोड करने का कोई मतलब नहीं है जो `Security` लॉग से नहीं हैं।
हमारे बेंचमार्क में, यह सामान्य स्कैन के साथ लगभग 10% की गति लाभ देता है और एकल नियम के साथ स्कैन करते समय 60%+ तक प्रदर्शन वृद्धि देता है।
यदि आप निश्चित हैं कि एक ही `.evtx` फ़ाइल के अंदर कई चैनलों का उपयोग किया जा रहा है, उदाहरण के लिए किसी ने कई `.evtx` फ़ाइलों को एक साथ मर्ज करने के लिए एक टूल का उपयोग किया है, तो आप `dfir-timeline` कमांड में `-a, --scan-all-evtx-files` विकल्प के साथ इस फ़िल्टरिंग को अक्षम कर सकते हैं।

> नोट: चैनल फ़िल्टरिंग केवल `.evtx` फ़ाइलों के साथ काम करती है और यदि आप `-J, --json-input` के साथ JSON फ़ाइल से इवेंट लॉग लोड करने का प्रयास करते हैं और साथ ही `-A` या `-a` भी निर्दिष्ट करते हैं तो आपको एक त्रुटि प्राप्त होगी।

## `dfir-timeline` कमांड

`dfir-timeline` कमांड इवेंट की एक फ़ोरेंसिक टाइमलाइन बनाता है। `-t, --output-type` के साथ आउटपुट प्रारूप चुनें: `csv` (डिफ़ॉल्ट), `json`, या `jsonl`। यह मान केस-असंवेदनशील है (उदा: `-t JSONL`)।

- **CSV** छोटी टाइमलाइन (आमतौर पर 2GB से कम) को LibreOffice या Timeline Explorer जैसे टूल में आयात करने के लिए अच्छा है (सभी इवेंट फ़ील्ड एक बड़े `Details` कॉलम में रखे जाते हैं)।
- **JSON** `jq` जैसे टूल के साथ बड़े परिणामों के अधिक विस्तृत विश्लेषण के लिए सबसे अच्छा है, क्योंकि `Details` फ़ील्ड अलग किए जाते हैं।
- **JSONL** JSON की तुलना में तेज़ है और छोटी फ़ाइल बनाता है, जो Elastic Stack जैसे टूल में आयात करने के लिए आदर्श है।

**CSV आउटपुट** विकल्प `-M, --multiline`, `-S, --tab-separator`, और `-R, --remove-duplicate-data` केवल CSV आउटपुट पर लागू होते हैं और यदि इन्हें गैर-CSV `-t` के साथ जोड़ा जाए तो एक त्रुटि उत्पन्न करेंगे।

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

### `dfir-timeline` कमांड उदाहरण

* डिफ़ॉल्ट `standard` प्रोफ़ाइल के साथ एक Windows इवेंट लॉग फ़ाइल के विरुद्ध hayabusa चलाएँ:

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* verbose प्रोफ़ाइल के साथ कई Windows इवेंट लॉग फ़ाइलों वाली sample-evtx निर्देशिका के विरुद्ध hayabusa चलाएँ:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* LibreOffice, Timeline Explorer, Elastic Stack आदि के साथ आगे के विश्लेषण के लिए एकल CSV फ़ाइल में निर्यात करें और सभी फ़ील्ड जानकारी शामिल करें (चेतावनी: `super-verbose` प्रोफ़ाइल के साथ आपकी फ़ाइल आउटपुट का आकार बहुत बड़ा हो जाएगा!):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* CSV के बजाय JSON आउटपुट करें (`jq` आदि के साथ विश्लेषण के लिए):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* JSONL आउटपुट करें (Elastic Stack आदि में आयात करने के लिए; `-t` केस-असंवेदनशील है):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* EID (Event ID) फ़िल्टर सक्षम करें:

> नोट: EID फ़िल्टर सक्षम करने से हमारे परीक्षणों में विश्लेषण लगभग 10-15% तेज़ हो जाएगा लेकिन अलर्ट छूटने की संभावना रहती है।

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* केवल hayabusa नियम चलाएँ (डिफ़ॉल्ट `-r .\rules` में सभी नियम चलाना है):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* केवल उन लॉग के लिए hayabusa नियम चलाएँ जो Windows पर डिफ़ॉल्ट रूप से सक्षम हैं:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* केवल sysmon लॉग के लिए hayabusa नियम चलाएँ:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* केवल sigma नियम चलाएँ:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* deprecated नियम (जिनकी `status` को `deprecated` के रूप में चिह्नित किया गया है) और noisy नियम (जिनकी रूल ID `.\rules\config\noisy_rules.txt` में सूचीबद्ध है) सक्षम करें:

> नोट: हाल ही में, deprecated नियम अब sigma रिपॉज़िटरी में एक अलग निर्देशिका में स्थित हैं इसलिए अब Hayabusa में डिफ़ॉल्ट रूप से शामिल नहीं हैं।
> इसलिए, आपको शायद deprecated नियमों को सक्षम करने की कोई आवश्यकता नहीं है।

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* केवल लॉगऑन का विश्लेषण करने के लिए नियम चलाएँ और UTC टाइमज़ोन में आउटपुट करें:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* एक लाइव Windows मशीन पर चलाएँ (Administrator विशेषाधिकारों की आवश्यकता होती है) और केवल अलर्ट (संभावित रूप से दुर्भावनापूर्ण व्यवहार) का पता लगाएँ:

```
hayabusa.exe dfir-timeline -l -m low
```

* verbose जानकारी प्रिंट करें (यह निर्धारित करने के लिए उपयोगी कि कौन सी फ़ाइलें संसाधित होने में लंबा समय लेती हैं, पार्सिंग त्रुटियाँ आदि):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* verbose आउटपुट उदाहरण:

नियम लोड करना:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

स्कैन के दौरान त्रुटियाँ:
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

* [Timesketch](https://timesketch.org/) में आयात करने के लिए संगत CSV प्रारूप में आउटपुट करें:

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* Quiet error मोड:
डिफ़ॉल्ट रूप से, hayabusa त्रुटि संदेशों को त्रुटि लॉग फ़ाइलों में सहेजेगा।
यदि आप त्रुटि संदेश सहेजना नहीं चाहते हैं, तो कृपया `-Q` जोड़ें।

### उन्नत - GeoIP लॉग एनरिचमेंट

आप मुफ़्त GeoLite2 जियोलोकेशन डेटा के साथ SrcIP (स्रोत IP) फ़ील्ड और TgtIP (लक्ष्य IP) फ़ील्ड में GeoIP (ASN संगठन, शहर और देश) जानकारी जोड़ सकते हैं।

चरण:

1. सबसे पहले [यहाँ](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) एक MaxMind खाते के लिए साइन अप करें।
2. [डाउनलोड पेज](https://www.maxmind.com/en/accounts/current/geoip/downloads) से तीन `.mmdb` फ़ाइलें डाउनलोड करें और उन्हें एक निर्देशिका में सहेजें। फ़ाइल नाम `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` और `GeoLite2-Country.mmdb` होने चाहिए।
3. `dfir-timeline` कमांड चलाते समय, MaxMind डेटाबेस वाली निर्देशिका के बाद `-G` विकल्प जोड़ें।

* CSV आउटपुट के साथ, निम्नलिखित 6 कॉलम अतिरिक्त रूप से आउटपुट होंगे: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`।
* JSON/JSONL आउटपुट के साथ, वही `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` फ़ील्ड `Details` ऑब्जेक्ट में जोड़े जाएंगे, लेकिन केवल तभी जब उनमें जानकारी हो।

* जब `SrcIP` या `TgtIP` लोकलहोस्ट (`127.0.0.1`, `::1`, आदि) हो, तो `SrcASN` या `TgtASN` को `Local` के रूप में आउटपुट किया जाएगा।
* जब `SrcIP` या `TgtIP` एक निजी IP पता (`10.0.0.0/8`, `fe80::/10`, आदि) हो, तो `SrcASN` या `TgtASN` को `Private` के रूप में आउटपुट किया जाएगा।

#### GeoIP कॉन्फ़िग फ़ाइल

स्रोत और लक्ष्य IP पते वाले फ़ील्ड नाम जिन्हें GeoIP डेटाबेस में देखा जाता है, `rules/config/geoip_field_mapping.yaml` में परिभाषित हैं।
यदि आवश्यक हो तो आप इस सूची में जोड़ सकते हैं।
इस फ़ाइल में एक फ़िल्टर अनुभाग भी है जो यह निर्धारित करता है कि किन इवेंट से IP पता जानकारी निकालनी है।

#### GeoIP डेटाबेस के स्वचालित अपडेट

MaxMind GeoIP डेटाबेस हर 2 सप्ताह में अपडेट होते हैं।
इन डेटाबेस को स्वचालित रूप से अपडेट करने के लिए आप MaxMind `geoipupdate` टूल को [यहाँ](https://github.com/maxmind/geoipupdate) इंस्टॉल कर सकते हैं।

macOS पर चरण:

1. `brew install geoipupdate`
2. `/usr/local/etc/GeoIP.conf` या `/opt/homebrew/etc/GeoIP.conf` संपादित करें: MaxMind वेबसाइट में लॉग इन करने के बाद आपके द्वारा बनाई गई अपनी `AccountID` और `LicenseKey` डालें। सुनिश्चित करें कि `EditionIDs` लाइन में `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` लिखा हो।
3. `geoipupdate` चलाएँ।
4. जब आप GeoIP जानकारी जोड़ना चाहते हैं तो `-G /usr/local/var/GeoIP` या `-G /opt/homebrew/var/GeoIP` जोड़ें।

Windows पर चरण:

1. [Releases](https://github.com/maxmind/geoipupdate/releases) पेज से नवीनतम Windows बाइनरी (उदा: `geoipupdate_4.10.0_windows_amd64.zip`) डाउनलोड करें।
2. `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf` संपादित करें: MaxMind वेबसाइट में लॉग इन करने के बाद आपके द्वारा बनाई गई अपनी `AccountID` और `LicenseKey` डालें। सुनिश्चित करें कि `EditionIDs` लाइन में `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` लिखा हो।
3. `geoipupdate` निष्पादन योग्य चलाएँ।

Linux पर चरण:

1. `sudo apt install geoip-update` से इंस्टॉल करें।
2. `sudo nano /etc/GeoIP.conf` से कॉन्फ़िग फ़ाइल संपादित करें।
3. `sudo geoipupdate` से डेटाबेस फ़ाइलें अपडेट करें।
4. जब आप GeoIP जानकारी जोड़ना चाहते हैं तो `-G /var/lib/GeoIP/` जोड़ें।

### `dfir-timeline` कमांड कॉन्फ़िग फ़ाइलें

`./rules/config/channel_abbreviations.txt`: चैनल नामों और उनके संक्षिप्त रूपों की मैपिंग।

`./rules/config/default_details.txt`: यह कॉन्फ़िगरेशन फ़ाइल है कि यदि किसी नियम में कोई `details:` लाइन निर्दिष्ट नहीं है तो कौन सी डिफ़ॉल्ट फ़ील्ड जानकारी (`%Details%` फ़ील्ड) आउटपुट की जानी चाहिए।
यह प्रोवाइडर नाम और इवेंट ID पर आधारित है।

`./rules/config/eventkey_alias.txt`: इस फ़ाइल में फ़ील्ड के लिए छोटे नाम उपनामों और उनके मूल लंबे फ़ील्ड नामों की मैपिंग है।

उदाहरण:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

यदि कोई फ़ील्ड यहाँ परिभाषित नहीं है, तो Hayabusa स्वचालित रूप से `Event.EventData` के अंतर्गत फ़ील्ड की जाँच करेगा।

`./rules/config/exclude_rules.txt`: इस फ़ाइल में रूल ID की एक सूची है जिन्हें उपयोग से बाहर रखा जाएगा।
आमतौर पर ऐसा इसलिए होता है क्योंकि एक नियम ने दूसरे को बदल दिया है या नियम का उपयोग पहले स्थान पर ही नहीं किया जा सकता।
फ़ायरवॉल और IDSes की तरह, किसी भी हस्ताक्षर-आधारित टूल को आपके वातावरण के अनुकूल कुछ ट्यूनिंग की आवश्यकता होगी इसलिए आपको कुछ नियमों को स्थायी या अस्थायी रूप से बाहर करने की आवश्यकता हो सकती है।
आप किसी भी नियम को अनदेखा करने के लिए जिसकी आपको आवश्यकता नहीं है या जिसका उपयोग नहीं किया जा सकता, `./rules/config/exclude_rules.txt` में एक रूल ID (उदाहरण: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) जोड़ सकते हैं।

`./rules/config/noisy_rules.txt`: इस फ़ाइल में रूल ID की एक सूची है जो डिफ़ॉल्ट रूप से अक्षम हैं लेकिन `-n, --enable-noisy-rules` विकल्प के साथ noisy नियमों को सक्षम करके सक्षम किए जा सकते हैं।
ये नियम आमतौर पर स्वभाव से या फ़ॉल्स पॉज़िटिव के कारण noisy होते हैं।

`./rules/config/target_event_IDs.txt`: यदि EID फ़िल्टर सक्षम है तो केवल इस फ़ाइल में निर्दिष्ट इवेंट ID स्कैन किए जाएंगे।
डिफ़ॉल्ट रूप से, Hayabusa सभी इवेंट को स्कैन करेगा, लेकिन यदि आप प्रदर्शन में सुधार करना चाहते हैं, तो कृपया `-E, --eid-filter` विकल्प का उपयोग करें।
इसका परिणाम आमतौर पर 10~25% गति सुधार होता है।

## `level-tuning` कमांड

`level-tuning` कमांड आपको नियमों के लिए अलर्ट स्तरों को ट्यून करने देगा, जैसा आप चाहें जोखिम स्तर को बढ़ाना या घटाना।
यह कमांड `rules` फ़ोल्डर में नियमों के जोखिम स्तरों (`level` फ़ील्ड) को अधिलेखित करने के लिए एक कॉन्फ़िग फ़ाइल का उपयोग करता है।

> चेतावनी: हर बार जब आप `update-rules` कमांड चलाते हैं, तो जोखिम स्तर मूल मान पर वापस आ जाएगा इसलिए आपको बाद में फिर से `level-tuning` कमांड चलाने की आवश्यकता होगी।

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` कमांड उदाहरण

* सामान्य उपयोग: `hayabusa.exe level-tuning`
* अपनी कस्टम कॉन्फ़िग फ़ाइल के आधार पर नियम अलर्ट स्तर ट्यून करें: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` कॉन्फ़िग फ़ाइल

Hayabusa और Sigma नियम लेखक अपने नियम लिखते समय अलर्ट के उपयुक्त जोखिम स्तर का अनुमान लगाएंगे।
हालांकि, कभी-कभी जोखिम स्तर सुसंगत नहीं होते हैं और साथ ही वास्तविक जोखिम स्तर आपके वातावरण के अनुसार भिन्न हो सकता है।
Yamato Security `./rules/config/level_tuning.txt` पर एक कॉन्फ़िग फ़ाइल प्रदान और बनाए रखता है जिसका उपयोग आप अपने नियमों को ट्यून करने के लिए भी कर सकते हैं।

`./rules/config/level_tuning.txt` नमूना:

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

इस मामले में, rules निर्देशिका में `id` `570ae5ec-33dc-427c-b815-db86228ad43e` वाले नियम का `level` फिर से लिखकर `informational` कर दिया जाएगा।
सेट किए जा सकने वाले संभावित स्तर `critical`, `high`, `medium`, `low` और `informational` हैं।

> चेतावनी: हर बार जब आप `update-rules` चलाते हैं तो `./rules/config/level_tuning.txt` कॉन्फ़िग फ़ाइल भी hayabusa-rules रिपॉज़िटरी पर नवीनतम संस्करण में अपडेट हो जाएगी।
> इसलिए, यदि आप इस फ़ाइल में परिवर्तन करते हैं, तो आप उन परिवर्तनों को खो देंगे!
> यदि आप अपने लिए एक कॉन्फ़िग फ़ाइल रखना चाहते हैं, तो `./config/level_tuning.txt` में एक कॉन्फ़िग फ़ाइल बनाएँ और `hayabusa.exe level-tuning -f ./config/level_tuning.txt` चलाएँ।
> आप पहले Yamato Security द्वारा प्रदान की गई कॉन्फ़िग फ़ाइल के साथ लेवल ट्यूनिंग कर सकते हैं और फिर अपनी खुद की कॉन्फ़िग फ़ाइल के साथ आगे ट्यून कर सकते हैं।

## `list-profiles` कमांड

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` कमांड

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` कमांड उदाहरण

* डिफ़ॉल्ट प्रोफ़ाइल को `minimal` पर सेट करें: `hayabusa.exe set-default-profile minimal`
* डिफ़ॉल्ट प्रोफ़ाइल को `super-verbose` पर सेट करें: `hayabusa.exe set-default-profile super-verbose`

## `update-rules` कमांड

`update-rules` कमांड `rules` फ़ोल्डर को [Hayabusa rules github रिपॉज़िटरी](https://github.com/Yamato-Security/hayabusa-rules) के साथ सिंक करेगा, नियमों और कॉन्फ़िग फ़ाइलों को अपडेट करेगा।

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` कमांड उदाहरण

आप सामान्य रूप से बस इसे निष्पादित करेंगे: `hayabusa.exe update-rules`
