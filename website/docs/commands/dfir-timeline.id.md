# Perintah DFIR Timeline

## Wizard Pemindaian

Perintah `dfir-timeline` kini memiliki wizard pemindaian yang diaktifkan secara default.
Ini dimaksudkan untuk membantu pengguna dengan mudah memilih aturan deteksi mana yang ingin mereka aktifkan sesuai dengan kebutuhan dan preferensi mereka.
Kumpulan aturan deteksi yang akan dimuat didasarkan pada daftar resmi dalam proyek Sigma.
Detailnya dijelaskan dalam [postingan blog ini](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
Anda dapat dengan mudah mematikan wizard dan menggunakan Hayabusa dengan cara tradisionalnya dengan menambahkan opsi `-w, --no-wizard`.

### Aturan Core

Kumpulan aturan `core` mengaktifkan aturan yang memiliki status `test` atau `stable` dan level `high` atau `critical`.
Ini adalah aturan berkualitas tinggi dengan kepercayaan dan relevansi yang tinggi serta tidak akan menghasilkan banyak false positive.
Status aturan adalah `test` atau `stable` yang berarti tidak ada false positive yang dilaporkan selama lebih dari 6 bulan.
Aturan akan cocok dengan teknik penyerang, aktivitas mencurigakan umum, atau perilaku berbahaya.
Ini sama dengan menggunakan opsi `--exclude-status deprecated,unsupported,experimental --min-level high`.

### Aturan Core+

Kumpulan aturan `core+` mengaktifkan aturan yang memiliki status `test` atau `stable` dan level `medium` atau lebih tinggi.
Aturan `medium` paling sering memerlukan penyetelan tambahan karena aplikasi tertentu, perilaku pengguna yang sah, atau skrip suatu organisasi mungkin cocok.
Ini sama dengan menggunakan opsi `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### Aturan Core++

Kumpulan aturan `core++` mengaktifkan aturan yang memiliki status `experimental`, `test` atau `stable` dan level `medium` atau lebih tinggi.
Aturan-aturan ini sangat mutakhir.
Aturan-aturan ini divalidasi terhadap file evtx baseline yang tersedia di proyek SigmaHQ dan ditinjau oleh beberapa insinyur deteksi.
Selain itu, aturan-aturan ini pada awalnya hampir tidak teruji.
Gunakan ini jika Anda ingin dapat mendeteksi ancaman sedini mungkin dengan biaya mengelola ambang false positive yang lebih tinggi.
Ini sama dengan menggunakan opsi `--exclude-status deprecated,unsupported --min-level medium`.

### Aturan Tambahan Emerging Threats (ET)

Kumpulan aturan `Emerging Threats (ET)` mengaktifkan aturan yang memiliki tag `detection.emerging_threats`.
Aturan-aturan ini menargetkan ancaman tertentu dan sangat berguna untuk ancaman terkini yang belum banyak informasinya tersedia.
Aturan-aturan ini seharusnya tidak menghasilkan banyak false positive tetapi relevansinya akan menurun seiring waktu.
Ketika aturan-aturan ini tidak diaktifkan, ini sama dengan menggunakan opsi `--exclude-tag detection.emerging_threats`.
Saat menjalankan Hayabusa secara tradisional tanpa wizard, aturan-aturan ini akan disertakan secara default.

### Aturan Tambahan Threat Hunting (TH)

Kumpulan aturan `Threat Hunting (TH)` mengaktifkan aturan yang memiliki tag `detection.threat_hunting`.
Aturan-aturan ini mungkin mendeteksi aktivitas berbahaya yang tidak diketahui, namun, biasanya akan memiliki lebih banyak false positive.
Ketika aturan-aturan ini tidak diaktifkan, ini sama dengan menggunakan opsi `--exclude-tag detection.threat_hunting`.
Saat menjalankan Hayabusa secara tradisional tanpa wizard, aturan-aturan ini akan disertakan secara default.

## Pemfilteran log event dan aturan berbasis Channel

Sejak Hayabusa v2.16.0, kami mengaktifkan filter berbasis Channel saat memuat file `.evtx` dan aturan `.yml`.
Tujuannya adalah membuat pemindaian seefisien mungkin dengan hanya memuat apa yang diperlukan.
Meskipun mungkin ada beberapa provider dalam satu log event, jarang ada beberapa channel di dalam satu file evtx.
(Satu-satunya kali kami melihat hal ini adalah ketika seseorang secara artifisial menggabungkan dua file evtx yang berbeda untuk proyek [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).)
Kami dapat memanfaatkan ini dengan terlebih dahulu memeriksa field `Channel` pada record pertama dari setiap file `.evtx` yang ditentukan untuk dipindai.
Kami juga memeriksa aturan `.yml` mana yang menggunakan channel apa yang ditentukan dalam field `Channel` dari aturan.
Dengan kedua daftar ini, kami hanya memuat aturan yang menggunakan channel yang benar-benar ada di dalam file `.evtx`.

Jadi misalnya, jika pengguna ingin memindai `Security.evtx`, hanya aturan yang menentukan `Channel: Security` yang akan digunakan.
Tidak ada gunanya memuat aturan deteksi lain, misalnya aturan yang hanya mencari event di log `Application`, dll...
Perhatikan bahwa field channel (Mis: `Channel: Security`) tidak didefinisikan secara **eksplisit** di dalam aturan Sigma asli.
Untuk aturan Sigma, field channel dan event ID didefinisikan secara **implisit** dengan field `service` dan `category` di bawah `logsource`. (Mis: `service: security`)
Saat mengkurasi aturan Sigma di repositori [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), kami melakukan de-abstraksi field `logsource` dan secara eksplisit mendefinisikan field channel dan event ID.
Kami menjelaskan bagaimana dan mengapa kami melakukan ini secara mendalam [di sini](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Saat ini, hanya ada dua aturan deteksi yang tidak memiliki `Channel` yang didefinisikan dan dimaksudkan untuk memindai semua file `.evtx` yaitu sebagai berikut:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Jika Anda ingin menggunakan kedua aturan ini dan memindai semua aturan terhadap file `.evtx` yang dimuat, maka Anda perlu menambahkan opsi `-A, --enable-all-rules` pada perintah `dfir-timeline`.
Dalam benchmark kami, pemfilteran aturan biasanya memberikan peningkatan kecepatan 20% hingga 10x tergantung pada file apa yang dipindai dan tentu saja menggunakan lebih sedikit memori.

Pemfilteran channel juga digunakan saat memuat file `.evtx`.
Misalnya, jika Anda menentukan aturan yang mencari event dengan channel `Security`, maka tidak ada gunanya memuat file `.evtx` yang bukan dari log `Security`.
Dalam benchmark kami, ini memberikan manfaat kecepatan sekitar 10% dengan pemindaian normal dan peningkatan kinerja hingga 60%+ saat memindai dengan satu aturan.
Jika Anda yakin bahwa beberapa channel digunakan di dalam satu file `.evtx`, misalnya seseorang menggunakan alat untuk menggabungkan beberapa file `.evtx`, maka Anda menonaktifkan pemfilteran ini dengan opsi `-a, --scan-all-evtx-files` pada perintah `dfir-timeline`.

> Catatan: Pemfilteran channel hanya berfungsi dengan file `.evtx` dan Anda akan menerima error jika mencoba memuat log event dari file JSON dengan `-J, --json-input` dan juga menentukan `-A` atau `-a`.

## Perintah `dfir-timeline`

Perintah `dfir-timeline` membuat timeline forensik dari event. Pilih format output dengan `-t, --output-type`: `csv` (default), `json`, atau `jsonl`. Nilai ini tidak peka huruf besar/kecil (mis. `-t JSONL`).

- **CSV** cocok untuk mengimpor timeline yang lebih kecil (biasanya kurang dari 2GB) ke alat seperti LibreOffice atau Timeline Explorer (semua field event ditempatkan dalam satu kolom `Details` yang besar).
- **JSON** paling baik untuk analisis yang lebih rinci dari hasil yang besar dengan alat seperti `jq`, karena field `Details` dipisahkan.
- **JSONL** lebih cepat dan menghasilkan file yang lebih kecil daripada JSON, yang ideal untuk mengimpor ke alat seperti Elastic Stack.

Opsi **CSV Output** `-M, --multiline`, `-S, --tab-separator`, dan `-R, --remove-duplicate-data` hanya berlaku untuk output CSV dan akan menghasilkan error jika digabungkan dengan `-t` non-CSV.

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

### Contoh perintah `dfir-timeline`

* Jalankan hayabusa terhadap satu file log event Windows dengan profil `standard` default:

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* Jalankan hayabusa terhadap direktori sample-evtx dengan beberapa file log event Windows menggunakan profil verbose:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* Ekspor ke satu file CSV untuk analisis lebih lanjut dengan LibreOffice, Timeline Explorer, Elastic Stack, dll... dan sertakan semua informasi field (Peringatan: ukuran output file Anda akan menjadi jauh lebih besar dengan profil `super-verbose`!):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Output JSON alih-alih CSV (untuk analisis dengan `jq`, dll.):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* Output JSONL (untuk mengimpor ke Elastic Stack, dll.; `-t` tidak peka huruf besar/kecil):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* Aktifkan filter EID (Event ID):

> Catatan: Mengaktifkan filter EID akan mempercepat analisis sekitar 10-15% dalam pengujian kami tetapi ada kemungkinan kehilangan alert.

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Hanya jalankan aturan hayabusa (defaultnya adalah menjalankan semua aturan di `-r .\rules`):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Hanya jalankan aturan hayabusa untuk log yang diaktifkan secara default pada Windows:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Hanya jalankan aturan hayabusa untuk log sysmon:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Hanya jalankan aturan sigma:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Aktifkan aturan deprecated (yang `status`-nya ditandai sebagai `deprecated`) dan aturan noisy (yang ID aturannya tercantum dalam `.\rules\config\noisy_rules.txt`):

> Catatan: Baru-baru ini, aturan deprecated kini berada di direktori terpisah dalam repositori sigma sehingga tidak lagi disertakan secara default di Hayabusa.
> Oleh karena itu, Anda mungkin tidak perlu mengaktifkan aturan deprecated.

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Hanya jalankan aturan untuk menganalisis logon dan output dalam zona waktu UTC:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Jalankan pada mesin Windows live (memerlukan hak istimewa Administrator) dan hanya deteksi alert (perilaku yang berpotensi berbahaya):

```
hayabusa.exe dfir-timeline -l -m low
```

* Cetak informasi verbose (berguna untuk menentukan file mana yang membutuhkan waktu lama untuk diproses, error parsing, dll...):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Contoh output verbose:

Memuat aturan:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Error selama pemindaian:
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

* Output ke format CSV yang kompatibel untuk diimpor ke [Timesketch](https://timesketch.org/):

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* Mode quiet error:
Secara default, hayabusa akan menyimpan pesan error ke file log error.
Jika Anda tidak ingin menyimpan pesan error, harap tambahkan `-Q`.

### Lanjutan - Pengayaan Log GeoIP

Anda dapat menambahkan informasi GeoIP (organisasi ASN, kota dan negara) ke field SrcIP (IP sumber) dan field TgtIP (IP target) dengan data geolokasi GeoLite2 gratis.

Langkah-langkah:

1. Pertama, daftar untuk akun MaxMind [di sini](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Unduh ketiga file `.mmdb` dari [halaman unduhan](https://www.maxmind.com/en/accounts/current/geoip/downloads) dan simpan ke sebuah direktori. Nama file tersebut harus `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` dan `GeoLite2-Country.mmdb`.
3. Saat menjalankan perintah `dfir-timeline`, tambahkan opsi `-G` diikuti dengan direktori yang berisi database MaxMind.

* Dengan output CSV, 6 kolom berikut akan dikeluarkan secara tambahan: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* Dengan output JSON/JSONL, field `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` yang sama akan ditambahkan ke objek `Details`, tetapi hanya jika berisi informasi.

* Ketika `SrcIP` atau `TgtIP` adalah localhost (`127.0.0.1`, `::1`, dll...), `SrcASN` atau `TgtASN` akan dikeluarkan sebagai `Local`.
* Ketika `SrcIP` atau `TgtIP` adalah alamat IP privat (`10.0.0.0/8`, `fe80::/10`, dll...), `SrcASN` atau `TgtASN` akan dikeluarkan sebagai `Private`.

#### File konfigurasi GeoIP

Nama field yang berisi alamat IP sumber dan target yang dicari di database GeoIP didefinisikan dalam `rules/config/geoip_field_mapping.yaml`.
Anda dapat menambahkan ke daftar ini jika diperlukan.
Ada juga bagian filter dalam file ini yang menentukan event mana yang akan diekstraksi informasi alamat IP-nya.

#### Pembaruan otomatis database GeoIP

Database MaxMind GeoIP diperbarui setiap 2 minggu.
Anda dapat menginstal alat MaxMind `geoipupdate` [di sini](https://github.com/maxmind/geoipupdate) untuk memperbarui database ini secara otomatis.

Langkah-langkah pada macOS:

1. `brew install geoipupdate`
2. Edit `/usr/local/etc/GeoIP.conf` atau `/opt/homebrew/etc/GeoIP.conf`: Masukkan `AccountID` dan `LicenseKey` yang Anda buat setelah masuk ke situs web MaxMind. Pastikan baris `EditionIDs` berbunyi `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Jalankan `geoipupdate`.
4. Tambahkan `-G /usr/local/var/GeoIP` atau `-G /opt/homebrew/var/GeoIP` saat Anda ingin menambahkan informasi GeoIP.

Langkah-langkah pada Windows:

1. Unduh biner Windows terbaru (Mis: `geoipupdate_4.10.0_windows_amd64.zip`) dari halaman [Releases](https://github.com/maxmind/geoipupdate/releases).
2. Edit `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: Masukkan `AccountID` dan `LicenseKey` yang Anda buat setelah masuk ke situs web MaxMind. Pastikan baris `EditionIDs` berbunyi `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Jalankan executable `geoipupdate`.

Langkah-langkah pada Linux:

1. Instal dengan `sudo apt install geoip-update`.
2. Edit file konfigurasi dengan `sudo nano /etc/GeoIP.conf`.
3. Perbarui file database dengan `sudo geoipupdate`.
4. Tambahkan `-G /var/lib/GeoIP/` saat Anda ingin menambahkan informasi GeoIP.

### File konfigurasi perintah `dfir-timeline`

`./rules/config/channel_abbreviations.txt`: Pemetaan nama channel dan singkatannya.

`./rules/config/default_details.txt`: File konfigurasi untuk informasi field default (field `%Details%`) apa yang harus dikeluarkan jika tidak ada baris `details:` yang ditentukan dalam suatu aturan.
Ini didasarkan pada nama provider dan event ID.

`./rules/config/eventkey_alias.txt`: File ini memiliki pemetaan alias nama pendek untuk field dan nama field aslinya yang lebih panjang.

Contoh:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Jika sebuah field tidak didefinisikan di sini, Hayabusa akan secara otomatis memeriksa di bawah `Event.EventData` untuk field tersebut.

`./rules/config/exclude_rules.txt`: File ini memiliki daftar ID aturan yang akan dikecualikan dari penggunaan.
Biasanya ini karena satu aturan telah menggantikan aturan lain atau aturan tersebut tidak dapat digunakan sejak awal.
Seperti firewall dan IDS, alat berbasis signature apa pun akan memerlukan penyetelan untuk menyesuaikan dengan lingkungan Anda sehingga Anda mungkin perlu mengecualikan aturan tertentu secara permanen atau sementara.
Anda dapat menambahkan ID aturan (Contoh: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) ke `./rules/config/exclude_rules.txt` untuk mengabaikan aturan apa pun yang tidak Anda perlukan atau tidak dapat digunakan.

`./rules/config/noisy_rules.txt`: File ini berisi daftar ID aturan yang dinonaktifkan secara default tetapi dapat diaktifkan dengan mengaktifkan aturan noisy dengan opsi `-n, --enable-noisy-rules`.
Aturan-aturan ini biasanya noisy secara alami atau karena false positive.

`./rules/config/target_event_IDs.txt`: Hanya event ID yang ditentukan dalam file ini yang akan dipindai jika filter EID diaktifkan.
Secara default, Hayabusa akan memindai semua event, tetapi jika Anda ingin meningkatkan kinerja, harap gunakan opsi `-E, --eid-filter`.
Ini biasanya menghasilkan peningkatan kecepatan 10~25%.

## Perintah `level-tuning`

Perintah `level-tuning` memungkinkan Anda menyetel level alert untuk aturan, baik menaikkan atau menurunkan tingkat risiko sesuai keinginan Anda.
Perintah ini menggunakan file konfigurasi untuk menimpa tingkat risiko (field `level`) dari aturan di folder `rules`.

> Peringatan: setiap kali Anda menjalankan perintah `update-rules`, tingkat risiko akan dikembalikan ke nilai aslinya sehingga Anda perlu menjalankan perintah `level-tuning` lagi setelahnya.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### Contoh perintah `level-tuning`

* Penggunaan normal: `hayabusa.exe level-tuning`
* Setel level alert aturan berdasarkan file konfigurasi kustom Anda: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### File konfigurasi `level-tuning`

Penulis aturan Hayabusa dan Sigma akan memperkirakan tingkat risiko alert yang sesuai saat menulis aturan mereka.
Namun, terkadang tingkat risiko tidak konsisten dan juga tingkat risiko sebenarnya mungkin berbeda sesuai dengan lingkungan Anda.
Yamato Security menyediakan dan memelihara file konfigurasi di `./rules/config/level_tuning.txt` yang dapat Anda gunakan untuk menyetel aturan Anda juga.

Contoh `./rules/config/level_tuning.txt`:

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

Dalam hal ini, tingkat risiko aturan dengan `id` `570ae5ec-33dc-427c-b815-db86228ad43e` di direktori rules akan memiliki `level`-nya ditulis ulang menjadi `informational`.
Level yang mungkin untuk disetel adalah `critical`, `high`, `medium`, `low` dan `informational`.

> Peringatan: File konfigurasi `./rules/config/level_tuning.txt` juga akan diperbarui ke versi terbaru di repositori hayabusa-rules setiap kali Anda menjalankan `update-rules`.
> Oleh karena itu, jika Anda membuat perubahan pada file ini, Anda akan kehilangan perubahan tersebut!
> Jika Anda ingin menyimpan file konfigurasi untuk diri Anda sendiri, maka buat file konfigurasi di `./config/level_tuning.txt` dan jalankan `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> Anda juga dapat terlebih dahulu melakukan level tuning dengan file konfigurasi yang disediakan oleh Yamato Security dan kemudian menyetel lebih lanjut dengan file konfigurasi Anda sendiri.

## Perintah `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## Perintah `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### Contoh perintah `set-default-profile`

* Setel profil default ke `minimal`: `hayabusa.exe set-default-profile minimal`
* Setel profil default ke `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## Perintah `update-rules`

Perintah `update-rules` akan menyinkronkan folder `rules` dengan [repositori github Hayabusa rules](https://github.com/Yamato-Security/hayabusa-rules), memperbarui aturan dan file konfigurasi.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### Contoh perintah `update-rules`

Anda biasanya hanya akan menjalankan ini: `hayabusa.exe update-rules`
