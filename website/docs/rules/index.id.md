# Aturan Hayabusa

Aturan deteksi Hayabusa ditulis dalam format YML yang mirip sigma dan terletak di folder `rules`.
Aturan-aturan ini di-host di [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) jadi mohon kirimkan semua issue dan pull request untuk aturan ke sana alih-alih ke repositori utama Hayabusa.

Lihat [Membuat File Aturan](creating-rules.md), [Field Deteksi](detection-fields.md) dan [Korelasi Sigma](correlations.md) di bagian ini untuk memahami format aturan dan cara membuat aturan. (Sumber: [repositori hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).)

Semua aturan dari repositori hayabusa-rules harus ditempatkan di folder `rules`.
Aturan level `informational` dianggap sebagai `events`, sedangkan apa pun dengan `level` `low` dan lebih tinggi dianggap sebagai `alerts`.

Struktur direktori aturan hayabusa dipisahkan menjadi 2 direktori:

* `builtin`: log yang dapat dihasilkan oleh fungsionalitas bawaan Windows.
* `sysmon`: log yang dihasilkan oleh [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

Aturan selanjutnya dipisahkan ke dalam direktori berdasarkan jenis log (Contoh: Security, System, dll...) dan diberi nama dalam format berikut:

Silakan periksa aturan yang ada saat ini untuk digunakan sebagai templat dalam membuat aturan baru atau untuk memeriksa logika deteksi.

## Aturan Sigma v.s. Hayabusa (Kompatibel dengan Sigma Bawaan)

Hayabusa mendukung aturan Sigma secara native dengan satu pengecualian yaitu menangani field `logsource` secara internal.
Untuk mengurangi false positive, , aturan Sigma harus dijalankan melalui konverter kami yang dijelaskan [di sini](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md).
Ini akan menambahkan `Channel` dan `EventID` yang tepat, dan melakukan pemetaan field untuk kategori tertentu seperti `process_creation`.

Hampir semua aturan Hayabusa kompatibel dengan format Sigma sehingga Anda dapat menggunakannya seperti aturan Sigma untuk dikonversi ke format SIEM lainnya.
Aturan Hayabusa dirancang khusus untuk analisis log event Windows dan memiliki manfaat berikut:

1. Field `details` tambahan untuk menampilkan informasi tambahan yang diambil hanya dari field yang berguna dalam log.
2. Semuanya diuji terhadap log sampel dan diketahui berfungsi.
3. Agregator tambahan yang tidak ditemukan di sigma, seperti `|equalsfield` dan `|endswithfield`.

Sepengetahuan kami, hayabusa menyediakan dukungan native terbaik untuk aturan sigma di antara semua alat analisis log event Windows open source.
