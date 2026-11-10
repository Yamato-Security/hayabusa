# Menjalankan Hayabusa

## Perhatian: Peringatan Anti-Virus/EDR dan Waktu Proses yang Lambat

Anda mungkin menerima peringatan dari produk anti-virus atau EDR ketika mencoba menjalankan hayabusa atau bahkan hanya ketika mengunduh aturan `.yml` karena akan ada kata kunci seperti `mimikatz` dan perintah PowerShell yang mencurigakan dalam signature deteksi.
Ini adalah positif palsu sehingga Anda perlu mengonfigurasi pengecualian pada produk keamanan Anda agar hayabusa dapat berjalan.
Jika Anda khawatir tentang malware atau serangan rantai pasokan, silakan periksa kode sumber hayabusa dan kompilasi binari-nya sendiri.

Anda mungkin mengalami waktu proses yang lambat terutama pada proses pertama setelah reboot karena perlindungan real-time dari Windows Defender.
Anda dapat menghindari ini dengan menonaktifkan sementara perlindungan real-time atau menambahkan pengecualian ke direktori runtime hayabusa.
(Harap pertimbangkan risiko keamanan sebelum melakukan hal ini.)

## Windows

Di Command/PowerShell Prompt atau Windows Terminal, jalankan saja binari Windows 32-bit atau 64-bit yang sesuai.

### Error saat mencoba memindai file atau direktori dengan spasi pada path

Saat menggunakan Command atau PowerShell prompt bawaan di Windows, Anda mungkin menerima error bahwa Hayabusa tidak dapat memuat file .evtx apa pun jika terdapat spasi pada path file atau direktori Anda.
Untuk memuat file .evtx dengan benar, pastikan Anda melakukan hal berikut:

1. Apit path file atau direktori dengan tanda kutip ganda.
2. Jika itu adalah path direktori, pastikan Anda tidak menyertakan backslash sebagai karakter terakhir.

### Karakter tidak ditampilkan dengan benar

Dengan font default `Lucida Console` di Windows, berbagai karakter yang digunakan dalam logo dan tabel tidak akan ditampilkan dengan benar.
Anda harus mengubah font ke `Consalas` untuk memperbaiki hal ini.

Ini akan memperbaiki sebagian besar render teks kecuali tampilan karakter Jepang pada pesan penutup:

![Mojibake](../assets/screenshots/Mojibake.png)

Anda memiliki empat opsi untuk memperbaiki ini:

1. Gunakan [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) sebagai pengganti Command atau PowerShell prompt. (Direkomendasikan)
2. Gunakan font `MS Gothic`. Perhatikan bahwa backslash akan berubah menjadi simbol Yen.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. Instal font [HackGen](https://github.com/yuru7/HackGen/releases) dan gunakan `HackGen Console NF`.
4. Gunakan `-q, --quiet` untuk tidak menampilkan pesan penutup yang mengandung bahasa Jepang.

## Linux

Anda terlebih dahulu perlu membuat binari dapat dieksekusi.

```bash
chmod +x ./hayabusa
```

Kemudian jalankan dari direktori root Hayabusa:

```bash
./hayabusa
```

## macOS

Dari Terminal atau iTerm2, Anda terlebih dahulu perlu membuat binari dapat dieksekusi.

```bash
chmod +x ./hayabusa
```

Kemudian, coba jalankan dari direktori root Hayabusa:

```bash
./hayabusa
```

Pada versi macOS terbaru, Anda mungkin menerima error keamanan berikut ketika mencoba menjalankannya:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

Klik "Cancel" lalu dari System Preferences, buka "Security & Privacy" dan dari tab General, klik "Allow Anyway".

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

Setelah itu, coba jalankan kembali.

```bash
./hayabusa
```

Peringatan berikut akan muncul, jadi silakan klik "Open".

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

Anda sekarang seharusnya dapat menjalankan hayabusa.

## Input VHDX


Semua perintah analisis log peristiwa mendukung `--vhdx` dengan `-f <IMAGE.vhdx>` atau `-d <DIR>`. Pencarian mencakup direktori yang diberikan dan tiga tingkat subdirektori. Di dalam citra, semua volume NTFS yang dapat dibaca diperiksa tanpa batas kedalaman tersebut.

```bash
./hayabusa dfir-timeline --vhdx -f host.vhdx -w -U -p verbose -o timeline.csv
./hayabusa dfir-timeline --vhdx -d images/ -w -U -p verbose -o timeline.csv
```


Pemindaian native berjalan di **Linux, macOS, dan Windows** melalui API NTFS portabel yang digunakan bersama Juntei. Berkas dibaca langsung sebagai aliran hanya-baca yang dapat diposisikan, tanpa FUSE, driver mount, hak administrator, atau ekstraksi sementara. Citra sumber tidak diubah. Jalur bukti menggunakan `host.vhdx!/path/log.evtx`. BitLocker dan citra yang memerlukan citra induk eksternal tidak didukung.

[English: VHDX input details and limitations](https://yamato-security.github.io/hayabusa/getting-started/running/#vhdx-inputs).

## E01/Ex01 { #e01-inputs }

`--e01` memindai image fisik EWF1 (`.E01`) dan EWF2 (`.Ex01`) langsung di Linux, macOS, dan Windows tanpa FUSE, hak administrator, atau ekstraksi sementara. Tentukan segmen pertama dan simpan segmen lain dengan nama aslinya di direktori yang sama. `-d` mencari hingga tiga tingkat subdirektori; `--vhdx --e01` menerima direktori campuran. Disk dengan partisi NTFS dan volume NTFS tunggal didukung. Kerusakan dilaporkan, hasil yang terbaca dipertahankan, dan kode keluar bukan nol. Ini bukan verifikasi integritas seluruh media. `.L01`/`.Lx01` logis, EWF yang memerlukan kata sandi, dan BitLocker tidak didukung.

```bash
./hayabusa dfir-timeline --e01 -f disk.E01 -w -U -p verbose -o timeline.csv
./hayabusa log-metrics --e01 -d images/ -U -o logs.csv
./hayabusa dfir-timeline --vhdx --e01 -d images/ -w -U -o timeline.csv
```

[English: E01/Ex01 details](https://yamato-security.github.io/hayabusa/getting-started/running/#e01-inputs).
