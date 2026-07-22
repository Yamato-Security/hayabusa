# Daftar Perintah

## Perintah Analisis:
* `computer-metrics`: Mencetak jumlah event berdasarkan nama komputer.
* `eid-metrics`: Mencetak jumlah dan persentase event berdasarkan Event ID.
* `expand-list`: Mengekstrak placeholder `expand` dari folder `rules`.
* `extract-base64`: Mengekstrak dan mendekode string base64 dari event.
* `log-metrics`: Mencetak metrik file log.
* `logon-summary`: Mencetak ringkasan event logon.
* `pivot-keywords-list`: Mencetak daftar kata kunci mencurigakan untuk dijadikan pivot.
* `search`: Mencari semua event berdasarkan kata kunci atau ekspresi reguler

## Perintah Konfigurasi:
* `config-critical-systems`: Menemukan sistem kritis seperti domain controller dan file server.

## Perintah Timeline DFIR:
* `dfir-timeline`: Menyimpan timeline dalam format CSV.
* `dfir-timeline`: Menyimpan timeline dalam format JSON/JSONL.
* `level-tuning`: Menyetel `level` alert secara kustom.
* `list-profiles`: Menampilkan daftar profil output yang tersedia.
* `set-default-profile`: Mengubah profil default.
* `update-rules`: Menyinkronkan rules ke rules terbaru di repositori GitHub [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

## Perintah Umum:
* `help`: Mencetak pesan ini atau bantuan dari subperintah yang diberikan
* `list-contributors`: Mencetak daftar kontributor
