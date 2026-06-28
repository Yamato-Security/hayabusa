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
