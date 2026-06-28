- [Mengimpor Hasil Ke Dalam SOF-ELK (Elastic Stack)](#importing-results-into-sof-elk-elastic-stack)
  - [Memasang dan menjalankan SOF-ELK](#install-and-start-sof-elk)
    - [Masalah konektivitas jaringan pada Mac](#network-connectivity-trouble-on-macs)
  - [Perbarui SOF-ELK!](#update-sof-elk)
  - [Menjalankan Hayabusa](#run-hayabusa)
  - [Opsional: Menghapus data lama yang telah diimpor](#optional-deleting-old-imported-data)
  - [Mengonfigurasi berkas konfigurasi logstash Hayabusa di SOF-ELK](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Mengimpor hasil Hayabusa ke dalam SOF-ELK](#import-hayabusa-results-into-sof-elk)
  - [Memeriksa bahwa impor berhasil di Kibana](#check-that-the-import-worked-in-kibana)
  - [Melihat hasil di Discover](#view-results-in-discover)
  - [Menganalisis hasil](#analyzing-results)
    - [Menambahkan kolom](#adding-columns)
    - [Pemfilteran](#filtering)
    - [Mengalihkan Detail](#toggling-details)
    - [Melihat dokumen di sekitarnya](#view-surrounding-documents)
    - [Mendapatkan metrik cepat pada field](#get-quick-metrics-on-fields)
  - [Rencana Masa Depan](#future-plans)

# Mengimpor Hasil Ke Dalam SOF-ELK (Elastic Stack)

## Memasang dan menjalankan SOF-ELK

Hasil Hayabusa dapat dengan mudah diimpor ke dalam Elastic Stack.
Kami merekomendasikan penggunaan [SOF-ELK](https://github.com/philhagen/sof-elk), sebuah distro Linux elastic stack gratis yang berfokus pada investigasi DFIR.

Pertama, unduh dan ekstrak image VMware SOF-ELK yang dikompres dengan 7-zip dari [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README).

Terdapat dua versi, x86 untuk CPU Intel dan versi ARM untuk komputer Apple seri-M.

Saat Anda menyalakan VM, Anda akan mendapatkan layar yang mirip dengan ini:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Catat URL Kibana dan alamat IP dari server SSH.

Anda dapat masuk dengan kredensial berikut:

* Nama pengguna: `elk_user`
* Kata sandi: `forensics`

Buka Kibana di peramban web sesuai dengan URL yang ditampilkan.
Misalnya: http://172.16.23.128:5601/

> Catatan: Kibana mungkin membutuhkan waktu sejenak untuk dimuat.

Anda akan melihat halaman web sebagai berikut:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

Kami merekomendasikan Anda untuk SSH ke dalam VM alih-alih mengetik perintah di dalam VM dengan `ssh elk_user@172.16.23.128`.

> Catatan: tata letak keyboard default adalah keyboard US.

### Masalah konektivitas jaringan pada Mac

Jika Anda menggunakan macOS dan Anda mendapatkan kesalahan `no route to host` di terminal atau Anda tidak dapat mengakses Kibana di peramban Anda, hal itu kemungkinan disebabkan oleh kontrol privasi jaringan lokal macOS.

Di `System Settings`, buka `Privacy & Security` -> `Local Network` dan pastikan bahwa peramban dan program terminal Anda diaktifkan agar dapat berkomunikasi dengan perangkat di jaringan lokal Anda.

## Perbarui SOF-ELK!

Sebelum mengimpor data, pastikan untuk memperbarui SOF-ELK dengan perintah `sudo sof-elk_update.sh`.

## Menjalankan Hayabusa

Jalankan Hayabusa dan simpan hasil ke JSONL.

Mis: `./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## Opsional: Menghapus data lama yang telah diimpor

Jika ini bukan kali pertama mengimpor hasil Hayabusa dan Anda ingin membersihkan semuanya, Anda dapat melakukannya dengan cara berikut:

1. Periksa rekaman apa yang saat ini ada di SOF-ELK: `sof-elk_clear.py -i list`
2. Hapus data saat ini: `sof-elk_clear.py -a`
3. Hapus berkas-berkas di direktori logstash: `rm /logstash/hayabusa/*`

## Mengonfigurasi berkas konfigurasi logstash Hayabusa di SOF-ELK

Sudah ada berkas konfigurasi logstash Hayabusa yang disertakan dalam SOF-ELK yang mengonversi nama field ke dalam format Elastic Common Schema.
Jika Anda lebih nyaman dengan nama field Hayabusa, kami merekomendasikan untuk menggunakan yang kami sediakan.

1. Pertama SSH ke dalam SOF-ELK: `ssh elk_user@172.16.23.128`
2. Hapus atau pindahkan berkas konfigurasi logstash saat ini: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. Unggah berkas [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) yang baru ke `/etc/logstash/conf.d/`: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. Mulai ulang logstash: `sudo systemctl restart logstash`

Berkas konfigurasi ini akan membuat field `DetailsText` dan `ExtraFieldInfoText` terkonsolidasi yang memungkinkan Anda dengan cepat melihat field-field paling penting sekilas alih-alih harus meluangkan waktu membuka setiap rekaman satu per satu untuk memeriksa semua field.

## Mengimpor hasil Hayabusa ke dalam SOF-ELK

Log diserap ke dalam SOF-ELK dengan menyalin log ke dalam direktori yang sesuai di dalam direktori `/logstash`.

Pertama `exit` keluar dari SSH dan kemudian, salin berkas hasil Hayabusa yang Anda buat:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Memeriksa bahwa impor berhasil di Kibana

Pertama catat `Total detections`, `First Timestamp` dan `Last Timestamp` di `Results Summary` dari pemindaian Hayabusa Anda.

Jika Anda tidak dapat memperoleh informasi ini, Anda dapat menjalankan `wc -l results.jsonl` di *nix untuk mendapatkan jumlah total baris untuk `Total detections`.

Secara default, Hayabusa tidak mengurutkan hasil demi meningkatkan kinerja sehingga Anda tidak dapat melihat baris pertama dan terakhir untuk mendapatkan timestamp pertama dan terakhir.
Jika Anda tidak mengetahui timestamp pertama dan terakhir yang tepat, cukup atur tanggal pertama di Kibana ke tahun 2007 dan hari terakhir sebagai `now` sehingga Anda akan memiliki semua hasil.

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

Anda sekarang akan melihat `Total Records` serta timestamp pertama dan terakhir dari event yang telah diimpor.

Terkadang dibutuhkan waktu sejenak untuk mengimpor semua event, jadi cukup terus segarkan halaman hingga `Total Records` sesuai dengan jumlah yang Anda harapkan.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

Anda juga dapat memeriksa dari terminal dengan menjalankan `sof-elk_clear.py -i list` untuk melihat apakah impor berhasil.
Anda akan melihat bahwa indeks `evtxlogs` Anda seharusnya memiliki lebih banyak rekaman:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

Mohon buat issue di GitHub jika Anda mengalami kesalahan parsing saat mengimpor.
Anda dapat memeriksanya dengan melihat bagian akhir dari berkas log `/var/log/logstash/logstash-plain.log`.

## Melihat hasil di Discover

Klik ikon sidebar di kiri atas dan klik `Discover`:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

Anda mungkin akan melihat `No results match your search criteria`.

Di sudut kiri atas yang bertuliskan indeks `logstash-*`, klik dan ubah menjadi `evtxlogs-*`.
Anda sekarang akan melihat timeline Discover.

## Menganalisis hasil

Tampilan Discover default seharusnya terlihat mirip dengan ini:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

Anda dapat memperoleh gambaran umum tentang kapan event terjadi dan frekuensi event dengan melihat histogram di bagian atas. 

### Menambahkan kolom

Di sidebar sisi kiri, Anda dapat menambahkan field yang ingin Anda tampilkan di kolom dengan mengklik tanda plus setelah mengarahkan kursor ke sebuah field.
Karena terdapat banyak field, Anda mungkin ingin mengetik nama field yang Anda cari di kotak pencarian.

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

Untuk memulai, kami merekomendasikan kolom-kolom berikut:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

Jika monitor Anda cukup lebar, Anda mungkin juga ingin menambahkan `ExtraFieldInfoText` sehingga Anda melihat semua informasi field.

Tampilan Discover Anda sekarang seharusnya terlihat seperti ini:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### Pemfilteran

Anda dapat memfilter dengan KQL(Kibana Query Language) untuk mencari event dan alert tertentu. Misalnya:
  * `Level: "crit"`: Hanya menampilkan alert critical.
  * `Level: "crit" OR Level: "high"`: Menampilkan alert high dan critical.
  * `NOT Level: info`: Tidak menampilkan event informasional, hanya alert.
  * `MitreTactics: *LatMov*`: Menampilkan event dan alert yang terkait dengan lateral movement.
  * `"PW Spray"`: Hanya menampilkan serangan spesifik seperti "Password Spray".
  * `"LID: 0x8724ead"`: Menampilkan semua aktivitas yang terkait dengan Logon ID 0x8724ead.
  * `Details_TgtUser: admmig`: Mencari semua event di mana target user adalah `admmig`.

### Mengalihkan Detail

Untuk memeriksa semua field dalam sebuah rekaman, cukup klik ikon (Toggle dialog with details) di sebelah timestamp:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### Melihat dokumen di sekitarnya

Jika Anda ingin melihat event tepat sebelum dan sesudah alert tertentu, pertama buka detail dari alert tersebut lalu klik `View surrounding documents` di kanan atas:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

Dalam contoh ini, kita melihat event sebelum dan sesudah alert serangan Pass the Hash:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Catatan: Ubah angka di bagian atas `Load x newer documents` atau bagian bawah `Load x older documents` untuk mengambil lebih banyak event.

### Mendapatkan metrik cepat pada field

Di kolom kiri, jika Anda mengklik nama field, ia akan memberikan Anda metrik cepat tentang penggunaannya:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> Perhatikan bahwa data diambil sebagai sampel demi kecepatan sehingga tidak 100% akurat.

## Rencana Masa Depan

* Parser Logstash untuk CSV
* Dashboard yang telah dibuat sebelumnya
