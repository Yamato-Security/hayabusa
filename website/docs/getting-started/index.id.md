# Unduhan

Silakan unduh versi stabil terbaru Hayabusa dengan biner yang telah dikompilasi atau kompilasi kode sumber dari halaman [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Kami menyediakan biner untuk arsitektur berikut:

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [Untuk beberapa alasan biner Linux ARM MUSL tidak berjalan dengan benar](https://github.com/Yamato-Security/hayabusa/issues/1332) sehingga kami tidak menyediakan biner tersebut. Hal ini di luar kendali kami, jadi kami berencana menyediakannya di masa mendatang setelah diperbaiki.

## Paket respons langsung Windows

Sejak v2.18.0, kami menyediakan paket Windows khusus yang menggunakan aturan berkode XOR yang disediakan dalam satu file serta seluruh file konfigurasi yang digabung menjadi satu file (di-host di [repositori hayabusa-encoded-rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Cukup unduh paket zip dengan `live-response` pada namanya.
File zip tersebut hanya mencakup tiga file: biner Hayabusa, file aturan berkode XOR, dan file konfigurasi.
Tujuan dari paket respons langsung ini adalah agar ketika menjalankan Hayabusa pada endpoint klien, kami ingin memastikan bahwa pemindai anti-virus seperti Windows Defender tidak memberikan positif palsu pada file aturan `.yml`.
Selain itu, kami ingin meminimalkan jumlah file yang ditulis ke sistem sehingga artefak forensik seperti USN Journal tidak tertimpa.
