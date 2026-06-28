# Tampilan & Ringkasan Output

## Progress Bar

Progress bar hanya akan berfungsi dengan beberapa file evtx.
Ia akan menampilkan secara real time jumlah dan persentase file evtx yang telah selesai dianalisis.

## Output Berwarna

Peringatan akan dikeluarkan dalam warna berdasarkan `level` peringatan.
Anda dapat mengubah warna default di file konfigurasi pada `./config/level_color.txt` dalam format `level,(RGB 6-digit ColorHex)`.
Jika Anda ingin menonaktifkan output berwarna, Anda dapat menggunakan opsi `-K, --no-color`.

## Ringkasan Hasil

Total event, jumlah event yang cocok, metrik pengurangan data, total dan deteksi unik, tanggal dengan deteksi terbanyak, komputer teratas dengan deteksi, serta peringatan teratas ditampilkan setelah setiap pemindaian.

### Timeline Frekuensi Deteksi

Jika Anda menambahkan opsi `-T, --visualize-timeline`, fitur Event Frequency Timeline menampilkan timeline frekuensi sparkline dari event yang terdeteksi.
Catatan: Diperlukan lebih dari 5 event. Selain itu, karakter-karakter tidak akan dirender dengan benar pada Command Prompt atau PowerShell Prompt default, jadi silakan gunakan terminal seperti Windows Terminal, iTerm2, dll...
