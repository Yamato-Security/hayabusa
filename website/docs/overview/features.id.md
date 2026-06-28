# Fitur

* Dukungan lintas platform: Windows, Linux, macOS.
* Dikembangkan dalam Rust agar aman terhadap memori dan cepat.
* Dukungan multi-thread yang memberikan peningkatan kecepatan hingga 5x.
* Membuat timeline tunggal yang mudah dianalisis untuk investigasi forensik dan respons insiden.
* Threat hunting berdasarkan signature IoC yang ditulis dalam aturan hayabusa berbasis YML yang mudah dibaca/dibuat/diedit.
* Dukungan aturan Sigma untuk mengonversi aturan sigma menjadi aturan hayabusa.
* Saat ini mendukung aturan sigma terbanyak dibandingkan tool serupa lainnya dan bahkan mendukung aturan count serta aggregator baru seperti `|equalsfield` dan `|endswithfield`.
* Metrik komputer. (Berguna untuk memfilter masuk/keluar komputer tertentu dengan jumlah event yang besar.)
* Metrik Event ID. (Berguna untuk mendapatkan gambaran jenis-jenis event yang ada dan untuk menyetel pengaturan log Anda.)
* Konfigurasi penyetelan aturan dengan mengecualikan aturan yang tidak diperlukan atau berisik.
* Pemetaan taktik MITRE ATT&CK.
* Penyetelan level aturan.
* Membuat daftar kata kunci pivot unik untuk mengidentifikasi pengguna, hostname, proses, dll. yang abnormal dengan cepat serta mengorelasikan event.
* Mengeluarkan semua field untuk investigasi yang lebih menyeluruh.
* Ringkasan logon yang berhasil dan gagal.
* Threat hunting dan DFIR skala perusahaan pada semua endpoint dengan [Velociraptor](https://docs.velociraptor.app/).
* Output ke CSV, JSON/JSONL dan Laporan Ringkasan HTML.
* Pembaruan aturan Sigma harian.
* Dukungan untuk input log berformat JSON.
* Normalisasi field log. (Mengonversi beberapa field dengan konvensi penamaan yang berbeda menjadi nama field yang sama.)
* Pengayaan log dengan menambahkan informasi GeoIP (ASN, kota, negara) ke alamat IP.
* Mencari semua event untuk kata kunci atau regular expression.
* Pemetaan data field. (Contoh: `0xc0000234` -> `ACCOUNT LOCKED`)
* Carving record evtx dari slack space evtx.
* Deduplikasi event saat output. (Berguna ketika recovery record diaktifkan atau ketika Anda menyertakan file evtx cadangan, file evtx dari VSS, dll.)
* Wizard pengaturan scan untuk membantu memilih aturan mana yang akan diaktifkan dengan lebih mudah. (Untuk mengurangi false positive, dll.)
* Parsing dan ekstraksi field log PowerShell classic.
* Penggunaan memori yang rendah. (Catatan: ini dimungkinkan dengan tidak mengurutkan hasil. Terbaik untuk dijalankan pada agen atau big data.)
* Pemfilteran pada Channel dan Rule untuk performa yang paling efisien.
* Mendeteksi, mengekstrak, dan mendekode string Base64 yang ditemukan dalam log.
* Penyesuaian level alert berdasarkan sistem kritis.
