# Menganalisis Hasil Hayabusa Dengan Timesketch

## Tentang

"[Timesketch](https://timesketch.org/) adalah alat sumber terbuka untuk analisis lini masa forensik secara kolaboratif. Dengan menggunakan sketch, Anda dan kolaborator Anda dapat dengan mudah mengatur lini masa dan menganalisisnya secara bersamaan. Tambahkan makna pada data mentah Anda dengan anotasi, komentar, tag, dan bintang yang kaya."

Untuk investigasi kecil di mana Anda menganalisis sebuah file CSV yang hanya berukuran beberapa ratus MB dan bekerja sendiri, Timeline Explorer sudah memadai, namun, ketika Anda bekerja dengan data yang lebih besar atau bersama tim, alat seperti Timesketch jauh lebih baik.

Timesketch menawarkan manfaat berikut:

1. Ia sangat cepat dan dapat menangani data berukuran besar
2. Ia merupakan alat kolaboratif di mana banyak pengguna dapat menggunakannya secara bersamaan
3. Ia menyediakan analisis data lanjutan, histogram, dan visualisasi
4. Ia tidak terbatas pada Windows
5. Ia mendukung kueri lanjutan

Ada banyak manfaat lain seperti dukungan CTI, berbagai penganalisis, notebook interaktif, dll...
Silakan periksa [panduan pengguna](https://timesketch.org/guides/user/upload-data/) dan [kanal YouTube](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) untuk informasi lebih lanjut.

Satu-satunya kekurangan adalah Anda harus menyiapkan server Timesketch di lingkungan lab Anda, namun untungnya hal ini sangat mudah dilakukan.

## Memasang
### Docker
Ikuti instruksi resmi [di sini](https://docs.docker.com/compose/install).

### Ubuntu
**Catatan:** Docker harus dipasang sebelum melanjutkan. Silakan ikuti [instruksi pemasangan Docker di atas](#docker) jika Anda belum memasang Docker.
Kami menyarankan untuk menggunakan edisi Ubuntu LTS Server terbaru dengan memori setidaknya 8GB.
Anda dapat mengunduhnya [di sini](https://ubuntu.com/download/server).
Pilih instalasi minimal saat menyiapkannya.
Jangan memasang docker saat menyiapkan OS.
Anda tidak akan memiliki `ifconfig` yang tersedia, jadi pasanglah dengan `sudo apt install net-tools`.

Setelah itu, jalankan `ifconfig` untuk menemukan alamat IP dari VM dan secara opsional ssh ke dalamnya.

Jalankan perintah berikut:
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**Catatan:** Sebelum melanjutkan, pastikan Anda telah memasang dan menjalankan [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/) pada sistem Anda.
Kloning repositori Timesketch dan masuk ke dalam direktori tersebut.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
Mulai kontainer Docker dengan mengikuti langkah-langkah di bawah ini.

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Masuk

Cari tahu alamat IP server Timesketch dengan `ifconfig` dan buka dengan peramban web.
Anda akan dialihkan ke halaman masuk.
Masuklah dengan kredensial pengguna yang Anda gunakan saat menambahkan pengguna.

## Membuat sketch baru

Di bawah `Start a new investigation`, klik `BLANK SKETCH`.
Beri nama sketch tersebut dengan sesuatu yang relevan dengan investigasi Anda.

## Mengunggah lini masa Anda

Setelah Anda mengklik `+ ADD TIMELINE`, Anda akan melihat kotak dialog yang meminta Anda untuk mengunggah file Plaso, JSONL, atau CSV.
Sayangnya, Timesketch saat ini tidak dapat mengimpor format `JSONL` Hayabusa, jadi buat dan unggah lini masa CSV dengan perintah berikut:

```shell
hayabusa-x.x.x-win-x64.exe csv-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --ISO-8601
```

> Catatan: Anda perlu memilih profil `timesketch*` dan menentukan timestamp sebagai `--ISO-8601` untuk UTC atau `--RFC-3339` untuk waktu lokal. Anda dapat menambahkan opsi Hayabusa lainnya jika Anda mau, namun, jangan tambahkan opsi `-M, --multiline` karena karakter baris baru akan merusak proses impor.

Pada kotak dialog "Select file to upload", beri nama lini masa Anda dengan sesuatu seperti `hayabusa`, pilih pembatas CSV `Comma (,)` dan klik `SUBMIT`.

> Jika file CSV Anda terlalu besar untuk diunggah, Anda dapat memecah file tersebut menjadi beberapa file CSV dengan perintah [split-csv-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-csv-timeline-command) dari Takajo.

Saat file sedang diimpor, Anda akan melihat lingkaran berputar, jadi harap tunggu hingga selesai dan Anda melihat `hayabusa` muncul.

## Tips analisis

### Menampilkan lini masa

**Catatan: Bahkan setelah impor berhasil selesai, ia akan menampilkan `Your search did not match any events` dan akan ada `0` peristiwa pada lini masa `hayabusa`.**

Cari `*` dan peristiwa-peristiwa akan muncul seperti yang ditunjukkan di bawah ini:

![Hasil Timesketch](../assets/doc/TimesketchImport/TimesketchResults.png)

### Detail peringatan

Jika Anda mengklik judul aturan peringatan di bawah kolom `message`, Anda akan mendapatkan informasi terperinci tentang peringatan tersebut:

![Detail peringatan](../assets/doc/TimesketchImport/AlertDetails.png)

Jika Anda ingin memahami logika aturan sigma, mencari deskripsi dan referensi, dll... silakan cari aturan tersebut di repositori [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

#### Pemfilteran bidang

Setelah membuka detail sebuah peristiwa dengan mengklik judul aturannya, Anda dapat mengarahkan kursor ke bidang mana pun untuk dengan mudah memfilter masuk atau keluar nilainya:

![Filter Masuk Keluar](../assets/doc/TimesketchImport/FilterInOut.png)

#### Analitik agregasi

Saat mengarahkan kursor, jika Anda mengklik ikon `Aggregation dialog` paling kiri, Anda akan mendapatkan analitik data peristiwa yang sangat bagus terkait bidang tersebut:

![Analitik Data Peristiwa](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### Komentar pengguna

Saat Anda mengklik sebuah peringatan untuk mendapatkan informasi terperinci, sebuah ikon kotak dialog komentar baru akan ditampilkan di sisi kanan, seperti yang ditunjukkan di bawah ini:

![Ikon Komentar](../assets/doc/TimesketchImport/CommentIcon.png)

Di sini, pengguna dapat memulai obrolan dan menulis komentar tentang investigasi.

> Jika Anda bekerja dalam sebuah tim, sebaiknya Anda membuat akun pengguna yang berbeda untuk setiap anggota sehingga Anda tahu siapa yang menulis apa.

![Obrolan komentar](../assets/doc/TimesketchImport/CommentChat.png)

> Jika Anda mengarahkan kursor ke sebuah komentar, Anda dapat dengan mudah menyunting dan menghapus pesan-pesan tersebut.

### Memodifikasi kolom

Secara default, hanya timestamp dan judul aturan peringatan yang akan ditampilkan, jadi klik ikon `Modify columns` untuk menyesuaikan bidang-bidangnya:

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

Ini akan membuka kotak dialog berikut:

![Pilih kolom](../assets/doc/TimesketchImport/SelectColumns.png)

Kami menyarankan untuk menambahkan setidaknya kolom-kolom berikut **secara berurutan**:

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

Urutan kolom akan berubah tergantung pada urutan Anda menambahkannya, jadi tambahkan bidang yang lebih penting terlebih dahulu.

Jika Anda masih memiliki ruang di layar Anda, kami menyarankan untuk juga menambahkan `Details`, seperti yang ditunjukkan di sini:

![Details](../assets/doc/TimesketchImport/Details.png)

Jika Anda masih memiliki ruang di layar Anda, kami menyarankan untuk juga menambahkan `ExtraFieldInfo`, namun, seperti yang Anda lihat di sini, jika Anda menambahkan terlalu banyak kolom maka bidang `message` akan menjadi terlalu sempit dan Anda tidak akan dapat membaca judul peringatan lagi:

![Terlalu banyak detail](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Ikon atas

#### Ikon elipsis

Jika Anda mengklik ikon `···`, Anda dapat membuat baris menjadi lebih ringkas dan menghapus `Timeline name` untuk menciptakan lebih banyak ruang bagi hasil:

![Lebih banyak ruang](../assets/doc/TimesketchImport/MoreRoom.png)

#### Histogram peristiwa

Anda dapat mengaktifkan histogram peristiwa untuk memvisualisasikan lini masa:

![Histogram Peristiwa](../assets/doc/TimesketchImport/EventHistogram.png)

Jika Anda mengklik salah satu batang, ia akan membuat filter waktu untuk hanya menampilkan hasil selama periode waktu tersebut.

#### Simpan pencarian saat ini

Jika Anda mengklik ikon `Save current search` tepat di atas timestamp dan di sebelah kiri ikon `Toggle Event Histogram`, Anda dapat menyimpan kueri pencarian Anda saat ini serta konfigurasi kolom ke `Saved Searches`.
Nanti, dari bilah sisi sebelah kiri Anda dapat dengan mudah mengakses pencarian favorit Anda.

### Bilah pencarian

Berikut adalah beberapa kueri praktis untuk memulai dengan hanya menampilkan peringatan dengan tingkat keparahan tertentu:

1. `Level:crit` untuk hanya menampilkan peringatan critical.
2. `Level:crit OR Level:high` untuk menampilkan peringatan high dan critical
3. `NOT Level:info` untuk menyembunyikan peringatan informational

Anda dapat dengan mudah memfilter dengan mengetik nama bidang ditambah `:` ditambah nilainya.
Anda dapat menggabungkan filter dengan `AND`, `OR`, dan `NOT`.
Wildcard dan ekspresi reguler didukung.

Lihat panduan pengguna [di sini](https://timesketch.org/guides/user/search-query-guide/) untuk kueri yang lebih lanjut.

#### Riwayat pencarian

Jika Anda mengklik ikon jam di sebelah kiri bilah pencarian, Anda dapat menampilkan kueri yang dimasukkan sebelumnya.
Anda juga dapat mengklik ikon panah kiri dan kanan untuk menjalankan kueri sebelumnya dan berikutnya.

![Riwayat Pencarian](../assets/doc/TimesketchImport/SearchHistory.png)

### Elipsis vertikal

Jika Anda mengklik elipsis vertikal di sebelah kiri sebuah timestamp dan mengklik `Context search`, Anda dapat melihat peringatan yang terjadi sebelum dan sesudah suatu peristiwa tertentu:

![Elipsis vertikal](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

Ini akan memunculkan tampilan berikut:

![Pencarian Konteks](../assets/doc/TimesketchImport/ContextSearch.png)

Pada contoh di atas, peristiwa sebelum dan sesudah 60 detik (`60S`) sedang ditampilkan, tetapi Anda dapat menyesuaikannya dari +- 1 detik (`1S`) hingga +- 60 menit (`60M`).

Jika Anda ingin menelusuri lebih dalam peristiwa-peristiwa yang ditampilkan, klik `Replace Search` untuk menampilkan peristiwa tersebut pada lini masa standar.

### Bintang dan tag

Anda dapat mengklik ikon bintang di sebelah kiri sebuah timestamp untuk memberi bintang dan menandainya sebagai peristiwa penting.

Anda juga dapat menambahkan tag ke peristiwa.
Ini berguna untuk menunjukkan kepada orang lain bahwa Anda telah mengonfirmasi bahwa suatu peristiwa mencurigakan, berbahaya, false positive, dll...
Jika Anda bekerja dalam sebuah tim, Anda dapat membuat tag seperti `under investigation by xxx` untuk menunjukkan bahwa seseorang sedang menyelidiki peringatan tersebut.

![Bintang dan tag](../assets/doc/TimesketchImport/StarsAndTags.png)
