# Analiz Komutları

## `computer-metrics` komutu

`computer-metrics` komutunu kullanarak, `<System><Computer>` alanında tanımlanan her bilgisayara göre kaç olay olduğunu kontrol edebilirsiniz.
Olayları orijinal bilgisayarlarına göre ayırmak için `Computer` alanına tamamen güvenemeyeceğinizi unutmayın.
Windows 11 bazen olay günlüklerine kaydederken tamamen farklı `Computer` adları kullanır.
Ayrıca, Windows 10 bazen `Computer` adını tamamen küçük harfle kaydeder.
Bu komut herhangi bir tespit kuralı kullanmaz, bu nedenle tüm olayları analiz eder.
Hangi bilgisayarların en fazla günlüğe sahip olduğunu hızlıca görmek için çalıştırılması iyi bir komuttur.
Bu bilgilerle, zaman çizelgelerinizi oluştururken `--include-computer` veya `--exclude-computer` seçeneklerini kullanarak, bilgisayara göre birden fazla zaman çizelgesi oluşturarak veya belirli bilgisayarlardan gelen olayları hariç tutarak zaman çizelgesi oluşturmanızı daha verimli hale getirebilirsiniz.

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

### `computer-metrics` komut örnekleri

* Bir dizinden bilgisayar adı ölçümlerini yazdırın: `hayabusa.exe computer-metrics -d ../logs`
* Sonuçları bir CSV dosyasına kaydedin: `hayabusa.exe computer-metrics -d ../logs -o computer-metrics.csv`

### `computer-metrics` ekran görüntüsü

![computer-metrics screenshot](../assets/screenshots/ComputerMetrics.png)

## `eid-metrics` komutu

`eid-metrics` komutunu kullanarak, kanallara göre ayrılmış olay kimliklerinin (`<System><EventID>` alanı) toplam sayısını ve yüzdesini yazdırabilirsiniz.
Bu komut herhangi bir tespit kuralı kullanmaz, bu nedenle tüm olayları tarar.

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

### `eid-metrics` komut örnekleri

* Tek bir dosyadan Olay Kimliği ölçümlerini yazdırın: `hayabusa.exe eid-metrics -f Security.evtx`
* Bir dizinden Olay Kimliği ölçümlerini yazdırın: `hayabusa.exe eid-metrics -d ../logs`
* Sonuçları bir CSV dosyasına kaydedin: `hayabusa.exe eid-metrics -f Security.evtx -o eid-metrics.csv`

### `eid-metrics` komut yapılandırma dosyası

Olayların kanalı, olay kimlikleri ve başlıkları `rules/config/channel_eid_info.txt` dosyasında tanımlanır.

Örnek:
```
Channel,EventID,EventTitle
Microsoft-Windows-Sysmon/Operational,1,Process Creation.
Microsoft-Windows-Sysmon/Operational,2,File Creation Timestamp Changed. (Possible Timestomping)
Microsoft-Windows-Sysmon/Operational,3,Network Connection.
Microsoft-Windows-Sysmon/Operational,4,Sysmon Service State Changed.
```

### `eid-metrics` ekran görüntüsü

![eid-metrics screenshot](../assets/screenshots/EID-Metrics.png)

## `expand-list` komutu

Kurallar klasöründen `expand` yer tutucularını çıkarır.
Bu, `expand` alan değiştiricisini kullanan herhangi bir kuralı kullanmak için yapılandırma dosyaları oluştururken kullanışlıdır.
`expand` kurallarını kullanmak için, yalnızca `./config/expand/` dizini altında `expand` alan değiştiricisinin adıyla bir `.txt` dosyası oluşturmanız ve kontrol etmek istediğiniz tüm değerleri dosyanın içine koymanız gerekir.

Örneğin, kural `detection` mantığı şöyleyse:
```yaml
detection:
    selection:
        EventID: 5145
        RelativeTargetName|contains: '\winreg'
    filter_main:
        IpAddress|expand: '%Admins_Workstations%'
    condition: selection and not filter_main
```

`./config/expand/Admins_Workstations.txt` metin dosyasını oluşturur ve şu gibi değerleri eklersiniz:
```
AdminWorkstation1
AdminWorkstation2
AdminWorkstation3
```

Bu, esasen aşağıdaki ile aynı mantığı kontrol eder:
```
- IpAddress: 'AdminWorkstation1'
- IpAddress: 'AdminWorkstation2'
- IpAddress: 'AdminWorkstation3'
```

Yapılandırma dosyası mevcut değilse, Hayabusa yine de `expand` kuralını yükler ancak yok sayar.

```
Usage:  expand-list <INPUT> [OPTIONS]

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify rule directory (default: ./rules)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

### `expand-list` komut örnekleri

* Varsayılan `rules` dizininden `expand` alan değiştiricilerini çıkarın: `hayabusa.exe expand-list`
* `sigma` dizininden `expand` alan değiştiricilerini çıkarın: `hayabusa.exe eid-metrics -r ../sigma`

### `expand-list` sonuçları

```
5 unique expand placeholders found:
Admins_Workstations
DC-MACHINE-NAME
Workstations
internal_domains
domain_controller_hostnames
```

## `extract-base64` komutu

Bu komut, aşağıdaki olaylardan base64 dizelerini çıkaracak, bunların kodunu çözecek ve ne tür bir kodlamanın kullanıldığını söyleyecektir.
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

### `extract-base64` komut örnekleri

* Bir dizini tarayın ve terminale çıktı verin: `hayabusa.exe  extract-base64 -d ../hayabusa-sample-evtx`
* Bir dizini tarayın ve bir CSV dosyasına çıktı verin: `hayabusa.exe eid-metrics -r ../sigma -o base64-extracted.csv`

### `extract-base64` sonuçları

Terminale çıktı verirken, alan sınırlı olduğundan yalnızca aşağıdaki alanlar görüntülenir:
  * Timestamp
  * Computer
  * Base64 String
  * Decoded String (if not binary)

Bir CSV dosyasına kaydederken, aşağıdaki alanlar kaydedilir:
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

## `log-metrics` komutu

`log-metrics` komutunu kullanarak, olay günlüklerinin içindeki aşağıdaki meta verileri yazdırabilirsiniz:
  * Dosya adı
  * Bilgisayar adları
  * Olay sayısı
  * İlk zaman damgası
  * Son zaman damgası
  * Kanallar
  * Sağlayıcılar

Bu komut herhangi bir tespit kuralı kullanmaz, bu nedenle tüm olayları tarar.

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

### `log-metrics` komut örnekleri

* Tek bir dosyadan Olay Kimliği ölçümlerini yazdırın: `hayabusa.exe log-metrics -f Security.evtx`
* Bir dizinden Olay Kimliği ölçümlerini yazdırın: `hayabusa.exe log-metrics -d ../logs`
* Sonuçları bir CSV dosyasına kaydedin: `hayabusa.exe log-metrics -d ../logs -o eid-metrics.csv`

### `log-metrics` ekran görüntüsü

![log-metrics screenshot](../assets/screenshots/LogMetrics.png)

## `logon-summary` komutu

`logon-summary` komutunu kullanarak oturum açma bilgileri özetini (oturum açma kullanıcı adları ile başarılı ve başarısız oturum açma sayısı) çıktı verebilirsiniz.
Bir evtx dosyasının oturum açma bilgilerini `-f` ile veya birden fazla evtx dosyasının oturum açma bilgilerini `-d` seçeneğiyle görüntüleyebilirsiniz.

Başarılı oturum açmalar aşağıdaki olaylardan alınır:
  * `Security 4624` (Successful Logon)
  * `RDS-LSM 21` (Remote Desktop Service Local Session Manager Logon)
  * `RDS-GTW 302` (Remote Desktop Service Gateway Logon)

Başarısız oturum açmalar `Security 4625` olaylarından alınır.

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

### `logon-summary` komut örnekleri

* Oturum açma özetini yazdırın: `hayabusa.exe logon-summary -f Security.evtx`
* Oturum açma özeti sonuçlarını kaydedin: `hayabusa.exe logon-summary -d ../logs -o logon-summary.csv`

### `logon-summary` ekran görüntüleri

![logon-summary successful logons screenshot](../assets/screenshots/LogonSummarySuccessfulLogons.png)

![logon-summary failed logons screenshot](../assets/screenshots/LogonSummaryFailedLogons.png)

## `pivot-keywords-list` komutu

`pivot-keywords-list` komutunu kullanarak, anormal kullanıcıları, ana bilgisayar adlarını, işlemleri vb. hızlıca tanımlamak ve ayrıca olayları ilişkilendirmek için benzersiz pivot anahtar kelimelerinden oluşan bir liste oluşturabilirsiniz.

Önemli: varsayılan olarak, hayabusa tüm olaylardan (bilgilendirici ve üzeri) sonuç döndürür, bu nedenle `pivot-keywords-list` komutunu `-m, --min-level` seçeneğiyle birleştirmenizi şiddetle öneririz.
Örneğin, `-m critical` ile yalnızca `critical` uyarılardan anahtar kelimeler oluşturarak başlayın ve ardından `-m high`, `-m medium` vb. ile devam edin.
Sonuçlarınızda büyük olasılıkla birçok normal olayla eşleşecek ortak anahtar kelimeler olacaktır, bu nedenle sonuçları manuel olarak kontrol edip benzersiz anahtar kelimelerden oluşan bir listeyi tek bir dosyada oluşturduktan sonra, `grep -f keywords.txt timeline.csv` gibi bir komutla şüpheli etkinliğin daraltılmış bir zaman çizelgesini oluşturabilirsiniz.

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

### `pivot-keywords-list` komut örnekleri

* Pivot anahtar kelimelerini ekrana çıktı verin: `hayabusa.exe pivot-keywords-list -d ../logs -m critical`
* Kritik uyarılardan pivot anahtar kelimelerinden oluşan bir liste oluşturun ve sonuçları kaydedin. (Sonuçlar `keywords-Ip Addresses.txt`, `keywords-Users.txt` vb. dosyalara kaydedilecektir):

```
hayabusa.exe pivot-keywords-list -d ../logs -m critical -o keywords`
```

### `pivot-keywords-list` yapılandırma dosyası

`./rules/config/pivot_keywords.txt` dosyasını düzenleyerek hangi anahtar kelimeleri aramak istediğinizi özelleştirebilirsiniz.
[Bu sayfa](https://github.com/Yamato-Security/hayabusa-rules/blob/main/config/pivot_keywords.txt) varsayılan ayardır.

Biçim `KeywordName.FieldName` şeklindedir. Örneğin, `Users` listesi oluşturulurken, hayabusa `SubjectUserName`, `TargetUserName` ve `User` alanlarındaki tüm değerleri listeleyecektir.

## `search` komutu

`search` komutu, tüm olaylarda anahtar kelime araması yapmanızı sağlar.
(Yalnızca Hayabusa tespit sonuçları değil.)
Bu, Hayabusa tarafından tespit edilmeyen olaylarda herhangi bir kanıt olup olmadığını belirlemek için kullanışlıdır.

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

### `search` komut örnekleri

* `../hayabusa-sample-evtx` dizininde `mimikatz` anahtar kelimesini arayın:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz"
```

> Not: Anahtar kelime, `mimikatz` verilerde herhangi bir yerde bulunursa eşleşecektir. Tam eşleşme değildir.

* `../hayabusa-sample-evtx` dizininde `mimikatz` veya `kali` anahtar kelimelerini arayın:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -k "kali"
```

* `../hayabusa-sample-evtx` dizininde `mimikatz` anahtar kelimesini büyük/küçük harfe duyarsız olarak arayın:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -i
```

* `../hayabusa-sample-evtx` dizininde düzenli ifadeler kullanarak IP adreslerini arayın:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
```

* `../hayabusa-sample-evtx` dizinini arayın ve `WorkstationName` alanının `kali` olduğu tüm olayları gösterin:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r ".*" -F WorkstationName:"kali"
```

> Not: `.*`, her olayla eşleşmek için kullanılan düzenli ifadedir.

### `search` komut yapılandırma dosyaları

`./rules/config/channel_abbreviations.txt`: Kanal adlarının ve kısaltmalarının eşleştirmeleri.
