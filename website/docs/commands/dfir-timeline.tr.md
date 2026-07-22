# DFIR Zaman Çizelgesi Komutları

## Tarama Sihirbazı

`dfir-timeline` komutu artık varsayılan olarak etkin bir tarama sihirbazına sahiptir.
Bu, kullanıcıların ihtiyaçlarına ve tercihlerine göre hangi tespit kurallarını etkinleştirmek istediklerini kolayca seçmelerine yardımcı olmayı amaçlamaktadır.
Yüklenecek tespit kurallarının kümeleri, Sigma projesindeki resmi listelere dayanmaktadır.
Ayrıntılar [bu blog gönderisinde](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81) açıklanmaktadır.
`-w, --no-wizard` seçeneğini ekleyerek sihirbazı kolayca kapatabilir ve Hayabusa'yı geleneksel şekilde kullanabilirsiniz.

### Core Kuralları

`core` kural kümesi, `test` veya `stable` durumuna ve `high` veya `critical` seviyesine sahip kuralları etkinleştirir.
Bunlar yüksek güvenilirlik ve uygunluğa sahip yüksek kaliteli kurallardır ve fazla yanlış pozitif üretmemelidir.
Kural durumu `test` veya `stable`'dır, bu da 6 aydan uzun süredir hiçbir yanlış pozitif raporlanmadığı anlamına gelir.
Kurallar saldırgan tekniklerine, genel şüpheli etkinliğe veya kötü amaçlı davranışa eşleşecektir.
Bu, `--exclude-status deprecated,unsupported,experimental --min-level high` seçeneklerini kullanmakla aynıdır.

### Core+ Kuralları

`core+` kural kümesi, `test` veya `stable` durumuna ve `medium` veya daha yüksek bir seviyeye sahip kuralları etkinleştirir.
`medium` kurallar çoğunlukla ek ayarlama gerektirir çünkü belirli uygulamalar, meşru kullanıcı davranışı veya bir kuruluşun komut dosyaları eşleşebilir.
Bu, `--exclude-status deprecated,unsupported,experimental --min-level medium` seçeneklerini kullanmakla aynıdır.

### Core++ Kuralları

`core++` kural kümesi, `experimental`, `test` veya `stable` durumuna ve `medium` veya daha yüksek bir seviyeye sahip kuralları etkinleştirir.
Bu kurallar en son teknolojiye sahiptir.
SigmaHQ projesinde mevcut olan temel evtx dosyalarına karşı doğrulanır ve birden fazla tespit mühendisi tarafından incelenir.
Bunun dışında başlangıçta neredeyse hiç test edilmemişlerdir.
Daha yüksek bir yanlış pozitif eşiğini yönetme pahasına tehditleri mümkün olduğunca erken tespit edebilmek istiyorsanız bunları kullanın.
Bu, `--exclude-status deprecated,unsupported --min-level medium` seçeneklerini kullanmakla aynıdır.

### Yükselen Tehditler (ET) Eklenti Kuralları

`Emerging Threats (ET)` kural kümesi, `detection.emerging_threats` etiketine sahip kuralları etkinleştirir.
Bu kurallar belirli tehditleri hedefler ve özellikle henüz fazla bilgi bulunmayan güncel tehditler için kullanışlıdır.
Bu kuralların fazla yanlış pozitifi olmamalıdır ancak zamanla uygunlukları azalacaktır.
Bu kurallar etkinleştirilmediğinde, bu `--exclude-tag detection.emerging_threats` seçeneğini kullanmakla aynıdır.
Hayabusa'yı sihirbaz olmadan geleneksel şekilde çalıştırırken, bu kurallar varsayılan olarak dahil edilecektir.

### Tehdit Avcılığı (TH) Eklenti Kuralları

`Threat Hunting (TH)` kural kümesi, `detection.threat_hunting` etiketine sahip kuralları etkinleştirir.
Bu kurallar bilinmeyen kötü amaçlı etkinliği tespit edebilir, ancak genellikle daha fazla yanlış pozitife sahip olacaktır.
Bu kurallar etkinleştirilmediğinde, bu `--exclude-tag detection.threat_hunting` seçeneğini kullanmakla aynıdır.
Hayabusa'yı sihirbaz olmadan geleneksel şekilde çalıştırırken, bu kurallar varsayılan olarak dahil edilecektir.

## Kanal tabanlı olay günlüğü ve kural filtreleme

Hayabusa v2.16.0 itibarıyla, `.evtx` dosyalarını ve `.yml` kurallarını yüklerken Kanal tabanlı bir filtre etkinleştiriyoruz.
Amaç, yalnızca gerekli olanı yükleyerek taramayı mümkün olduğunca verimli hale getirmektir.
Tek bir olay günlüğünde birden fazla sağlayıcı bulunması mümkün olsa da, tek bir evtx dosyasının içinde birden fazla kanal bulunması yaygın değildir.
(Bunu gördüğümüz tek durum, birisinin [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) projesi için iki farklı evtx dosyasını yapay olarak birleştirmesidir.)
Bunu kendi avantajımıza kullanarak, taranacağı belirtilen her `.evtx` dosyasının ilk kaydındaki `Channel` alanını önce kontrol edebiliriz.
Ayrıca hangi `.yml` kurallarının, kuralın `Channel` alanında belirtilen hangi kanalları kullandığını da kontrol ederiz.
Bu iki listeyle, yalnızca `.evtx` dosyalarının içinde gerçekten bulunan kanalları kullanan kuralları yükleriz.

Örneğin, bir kullanıcı `Security.evtx` dosyasını taramak isterse, yalnızca `Channel: Security` belirten kurallar kullanılacaktır.
Diğer tespit kurallarını, örneğin yalnızca `Application` günlüğündeki olayları arayan kuralları vb. yüklemenin bir anlamı yoktur.
Kanal alanlarının (Örn: `Channel: Security`) orijinal Sigma kurallarının içinde **açıkça** tanımlanmadığını unutmayın.
Sigma kuralları için kanal ve olay kimliği alanları, `logsource` altındaki `service` ve `category` alanlarıyla **örtük** olarak tanımlanır. (Örn: `service: security`)
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) deposunda Sigma kurallarını düzenlerken, `logsource` alanını soyutlamasından arındırır ve kanal ile olay kimliği alanlarını açıkça tanımlarız.
Bunu nasıl ve neden yaptığımızı ayrıntılı olarak [burada](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) açıklıyoruz.

Şu anda, `Channel` tanımlanmamış ve tüm `.evtx` dosyalarını taramak için tasarlanmış yalnızca iki tespit kuralı vardır:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Bu iki kuralı kullanmak ve yüklenen `.evtx` dosyalarına karşı tüm kuralları taramak istiyorsanız, `dfir-timeline` komutunda `-A, --enable-all-rules` seçeneğini eklemeniz gerekecektir.
Karşılaştırmalarımızda, kural filtreleme genellikle hangi dosyaların tarandığına bağlı olarak 20%'den 10 kata kadar hız iyileştirmesi sağlar ve elbette daha az bellek kullanır.

Kanal filtreleme, `.evtx` dosyalarını yüklerken de kullanılır.
Örneğin, `Security` kanalına sahip olayları arayan bir kural belirtirseniz, o zaman `Security` günlüğünden olmayan `.evtx` dosyalarını yüklemenin bir anlamı yoktur.
Karşılaştırmalarımızda, bu normal taramalarda yaklaşık 10%'lik bir hız avantajı ve tek bir kuralla tararken 60%+ performans artışına kadar sağlar.
Tek bir `.evtx` dosyasının içinde birden fazla kanalın kullanıldığından eminseniz, örneğin birisi birden fazla `.evtx` dosyasını birleştirmek için bir araç kullandıysa, bu filtrelemeyi `dfir-timeline` komutundaki `-a, --scan-all-evtx-files` seçeneğiyle devre dışı bırakabilirsiniz.

> Not: Kanal filtreleme yalnızca `.evtx` dosyalarıyla çalışır ve `-J, --json-input` ile bir JSON dosyasından olay günlüklerini yüklemeye çalışırsanız ve ayrıca `-A` veya `-a` belirtirseniz bir hata alacaksınız.

## `dfir-timeline` komutu

`dfir-timeline` komutu, olayların adli zaman çizelgesini oluşturur. Çıktı formatını `-t, --output-type` ile seçin: `csv` (varsayılan), `json` veya `jsonl`. Değer büyük/küçük harfe duyarlı değildir (örneğin `-t JSONL`).

- **CSV**, daha küçük zaman çizelgelerini (genellikle 2GB'tan az) LibreOffice veya Timeline Explorer gibi araçlara aktarmak için iyidir (tüm olay alanları tek bir büyük `Details` sütununda yer alır).
- **JSON**, `Details` alanları ayrıldığından, `jq` gibi araçlarla büyük sonuçların daha ayrıntılı analizi için en iyisidir.
- **JSONL**, JSON'dan daha hızlıdır ve JSON'a göre daha küçük bir dosya üretir, bu da Elastic Stack gibi araçlara aktarmak için idealdir.

**CSV Çıktısı** (`CSV Output`) seçenekleri `-M, --multiline`, `-S, --tab-separator` ve `-R, --remove-duplicate-data` yalnızca CSV çıktısı için geçerlidir ve CSV olmayan bir `-t` ile birlikte kullanılırsa hata verir.

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

### `dfir-timeline` komutu örnekleri

* Hayabusa'yı varsayılan `standard` profili ile tek bir Windows olay günlüğü dosyasına karşı çalıştırın:

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* Hayabusa'yı, verbose profili ile birden fazla Windows olay günlüğü dosyası içeren sample-evtx dizinine karşı çalıştırın:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* LibreOffice, Timeline Explorer, Elastic Stack vb. ile daha fazla analiz için tek bir CSV dosyasına dışa aktarın ve tüm alan bilgilerini dahil edin (Uyarı: `super-verbose` profili ile dosya çıktı boyutunuz çok daha büyük olacaktır!):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* CSV yerine JSON çıktısı verin (`jq` vb. ile analiz için):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* JSONL çıktısı verin (Elastic Stack vb. içine aktarmak için; `-t` büyük/küçük harfe duyarlı değildir):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* EID (Olay Kimliği) filtresini etkinleştirin:

> Not: EID filtresini etkinleştirmek, testlerimizde analizi yaklaşık 10-15% hızlandıracaktır ancak uyarıların kaçırılması olasılığı vardır.

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Yalnızca hayabusa kurallarını çalıştırın (varsayılan, `-r .\rules` içindeki tüm kuralları çalıştırmaktır):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Yalnızca Windows'ta varsayılan olarak etkinleştirilmiş günlükler için hayabusa kurallarını çalıştırın:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Yalnızca sysmon günlükleri için hayabusa kurallarını çalıştırın:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Yalnızca sigma kurallarını çalıştırın:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Kullanımdan kaldırılmış kuralları (`status` değeri `deprecated` olarak işaretlenmiş olanlar) ve gürültülü kuralları (kural kimliği `.\rules\config\noisy_rules.txt` içinde listelenmiş olanlar) etkinleştirin:

> Not: Son zamanlarda, kullanımdan kaldırılmış kurallar artık sigma deposunda ayrı bir dizinde bulunduğundan, Hayabusa'da varsayılan olarak artık dahil edilmemektedir.
> Bu nedenle, muhtemelen kullanımdan kaldırılmış kuralları etkinleştirmenize gerek yoktur.

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Yalnızca oturum açmaları analiz eden kuralları çalıştırın ve UTC saat diliminde çıktı verin:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Canlı bir Windows makinesinde çalıştırın (Yönetici ayrıcalıkları gerektirir) ve yalnızca uyarıları (potansiyel olarak kötü amaçlı davranış) tespit edin:

```
hayabusa.exe dfir-timeline -l -m low
```

* Ayrıntılı bilgi yazdırın (hangi dosyaların işlenmesinin uzun sürdüğünü, ayrıştırma hatalarını vb. belirlemek için kullanışlıdır):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Ayrıntılı çıktı örneği:

Kuralların yüklenmesi:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Tarama sırasındaki hatalar:
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

* [Timesketch](https://timesketch.org/) içine aktarmaya uyumlu bir CSV formatına çıktı verin:

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* Sessiz hata modu:
Varsayılan olarak, hayabusa hata mesajlarını hata günlüğü dosyalarına kaydedecektir.
Hata mesajlarını kaydetmek istemiyorsanız, lütfen `-Q` ekleyin.

### Gelişmiş - GeoIP Günlük Zenginleştirme

Ücretsiz GeoLite2 coğrafi konum verileriyle SrcIP (kaynak IP) alanlarına ve TgtIP (hedef IP) alanlarına GeoIP (ASN kuruluşu, şehir ve ülke) bilgisi ekleyebilirsiniz.

Adımlar:

1. Önce [buradan](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) bir MaxMind hesabı için kaydolun.
2. [İndirme sayfasından](https://www.maxmind.com/en/accounts/current/geoip/downloads) üç `.mmdb` dosyasını indirin ve bir dizine kaydedin. Dosya adları `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` ve `GeoLite2-Country.mmdb` olmalıdır.
3. `dfir-timeline` komutunu çalıştırırken, `-G` seçeneğini ardından MaxMind veritabanlarının bulunduğu dizini ekleyin.

* CSV çıktısı ile, aşağıdaki 6 sütun ek olarak çıktı verilecektir: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* JSON/JSONL çıktısı ile, aynı `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` alanları `Details` nesnesine eklenecektir, ancak yalnızca bilgi içeriyorlarsa.

* `SrcIP` veya `TgtIP` localhost olduğunda (`127.0.0.1`, `::1`, vb.), `SrcASN` veya `TgtASN` `Local` olarak çıktı verilecektir.
* `SrcIP` veya `TgtIP` özel bir IP adresi olduğunda (`10.0.0.0/8`, `fe80::/10`, vb.), `SrcASN` veya `TgtASN` `Private` olarak çıktı verilecektir.

#### GeoIP yapılandırma dosyası

GeoIP veritabanlarında aranan kaynak ve hedef IP adreslerini içeren alan adları `rules/config/geoip_field_mapping.yaml` içinde tanımlanır.
Gerekirse bu listeye ekleme yapabilirsiniz.
Bu dosyada ayrıca hangi olaylardan IP adresi bilgisi çıkarılacağını belirleyen bir filtre bölümü vardır.

#### GeoIP veritabanlarının otomatik güncellemeleri

MaxMind GeoIP veritabanları her 2 haftada bir güncellenir.
Bu veritabanlarını otomatik olarak güncellemek için MaxMind `geoipupdate` aracını [buradan](https://github.com/maxmind/geoipupdate) kurabilirsiniz.

macOS'ta adımlar:

1. `brew install geoipupdate`
2. `/usr/local/etc/GeoIP.conf` veya `/opt/homebrew/etc/GeoIP.conf` dosyasını düzenleyin: MaxMind web sitesine giriş yaptıktan sonra oluşturduğunuz `AccountID` ve `LicenseKey` bilgilerinizi girin. `EditionIDs` satırının `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` dediğinden emin olun.
3. `geoipupdate` çalıştırın.
4. GeoIP bilgisi eklemek istediğinizde `-G /usr/local/var/GeoIP` veya `-G /opt/homebrew/var/GeoIP` ekleyin.

Windows'ta adımlar:

1. [Releases](https://github.com/maxmind/geoipupdate/releases) sayfasından en son Windows ikili dosyasını (Örn: `geoipupdate_4.10.0_windows_amd64.zip`) indirin.
2. `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf` dosyasını düzenleyin: MaxMind web sitesine giriş yaptıktan sonra oluşturduğunuz `AccountID` ve `LicenseKey` bilgilerinizi girin. `EditionIDs` satırının `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` dediğinden emin olun.
3. `geoipupdate` yürütülebilir dosyasını çalıştırın.

Linux'ta adımlar:

1. `sudo apt install geoip-update` ile kurun.
2. Yapılandırma dosyasını `sudo nano /etc/GeoIP.conf` ile düzenleyin.
3. Veritabanı dosyalarını `sudo geoipupdate` ile güncelleyin.
4. GeoIP bilgisi eklemek istediğinizde `-G /var/lib/GeoIP/` ekleyin.

### `dfir-timeline` komutu yapılandırma dosyaları

`./rules/config/channel_abbreviations.txt`: Kanal adlarının ve kısaltmalarının eşlemeleri.

`./rules/config/default_details.txt`: Bir kuralda `details:` satırı belirtilmemişse hangi varsayılan alan bilgisinin (`%Details%` alanı) çıktı verileceğine ilişkin yapılandırma dosyası.
Bu, sağlayıcı adına ve olay kimliklerine dayanır.

`./rules/config/eventkey_alias.txt`: Bu dosya, alanlar için kısa ad takma adlarının ve bunların orijinal daha uzun alan adlarının eşlemelerine sahiptir.

Örnek:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Bir alan burada tanımlanmamışsa, Hayabusa alanı otomatik olarak `Event.EventData` altında kontrol edecektir.

`./rules/config/exclude_rules.txt`: Bu dosya, kullanımdan çıkarılacak kural kimliklerinin bir listesine sahiptir.
Genellikle bunun nedeni, bir kuralın başka bir kuralın yerini almış olması veya kuralın en başta kullanılamamasıdır.
Güvenlik duvarları ve IDS'ler gibi, imza tabanlı herhangi bir araç ortamınıza uyması için biraz ayarlama gerektirecektir, bu nedenle belirli kuralları kalıcı olarak veya geçici olarak hariç tutmanız gerekebilir.
İhtiyacınız olmayan veya kullanılamayan herhangi bir kuralı yok saymak için `./rules/config/exclude_rules.txt` dosyasına bir kural kimliği (Örnek: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) ekleyebilirsiniz.

`./rules/config/noisy_rules.txt`: Bu dosya, varsayılan olarak devre dışı bırakılan ancak `-n, --enable-noisy-rules` seçeneğiyle gürültülü kuralları etkinleştirerek etkinleştirilebilen kural kimliklerinin bir listesine sahiptir.
Bu kurallar genellikle doğası gereği veya yanlış pozitifler nedeniyle gürültülüdür.

`./rules/config/target_event_IDs.txt`: EID filtresi etkinleştirilmişse yalnızca bu dosyada belirtilen olay kimlikleri taranacaktır.
Varsayılan olarak, Hayabusa tüm olayları tarayacaktır, ancak performansı artırmak istiyorsanız lütfen `-E, --eid-filter` seçeneğini kullanın.
Bu genellikle 10~25%'lik bir hız iyileştirmesi ile sonuçlanır.

## `level-tuning` komutu

`level-tuning` komutu, kuralların uyarı seviyelerini, risk seviyesini istediğiniz gibi yükselterek veya düşürerek ayarlamanıza olanak tanır.
Bu komut, `rules` klasöründeki kuralların risk seviyelerini (`level` alanı) üzerine yazmak için bir yapılandırma dosyası kullanır.

> Uyarı: `update-rules` komutunu her çalıştırdığınızda, risk seviyesi orijinal değerine geri döndürülecektir, bu nedenle daha sonra `level-tuning` komutunu tekrar çalıştırmanız gerekecektir.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` komutu örnekleri

* Normal kullanım: `hayabusa.exe level-tuning`
* Özel yapılandırma dosyanıza göre kural uyarı seviyelerini ayarlayın: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` yapılandırma dosyası

Hayabusa ve Sigma kural yazarları, kurallarını yazarken uyarının uygun risk seviyesini tahmin edeceklerdir.
Ancak bazen risk seviyeleri tutarlı değildir ve ayrıca gerçek risk seviyesi ortamınıza göre farklılık gösterebilir.
Yamato Security, kurallarınızı da ayarlamak için kullanabileceğiniz `./rules/config/level_tuning.txt` konumunda bir yapılandırma dosyası sağlar ve bakımını yapar.

`./rules/config/level_tuning.txt` örneği:

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

Bu durumda, kurallar dizinindeki `id` değeri `570ae5ec-33dc-427c-b815-db86228ad43e` olan kuralın `level` değeri `informational` olarak yeniden yazılacaktır.
Ayarlanabilecek olası seviyeler `critical`, `high`, `medium`, `low` ve `informational`'dır.

> Uyarı: `./rules/config/level_tuning.txt` yapılandırma dosyası da `update-rules` komutunu her çalıştırdığınızda hayabusa-rules deposundaki en son sürüme güncellenecektir.
> Bu nedenle, bu dosyada değişiklik yaparsanız, bu değişiklikleri kaybedersiniz!
> Kendiniz için bir yapılandırma dosyası tutmak istiyorsanız, `./config/level_tuning.txt` içinde bir yapılandırma dosyası oluşturun ve `hayabusa.exe level-tuning -f ./config/level_tuning.txt` çalıştırın.
> Ayrıca önce Yamato Security tarafından sağlanan yapılandırma dosyasıyla seviye ayarlaması yapabilir ve ardından kendi yapılandırma dosyanızla daha fazla ayarlama yapabilirsiniz.

## `list-profiles` komutu

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` komutu

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` komutu örnekleri

* Varsayılan profili `minimal` olarak ayarlayın: `hayabusa.exe set-default-profile minimal`
* Varsayılan profili `super-verbose` olarak ayarlayın: `hayabusa.exe set-default-profile super-verbose`

## `update-rules` komutu

`update-rules` komutu, `rules` klasörünü [Hayabusa rules github deposu](https://github.com/Yamato-Security/hayabusa-rules) ile senkronize ederek kuralları ve yapılandırma dosyalarını güncelleyecektir.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` komutu örneği

Normalde sadece bunu yürütürsünüz: `hayabusa.exe update-rules`
