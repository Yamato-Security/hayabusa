# Menganalisis Hasil Hayabusa Dengan Timeline Explorer

## Tentang

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) adalah alat gratis namun bersifat tertutup (closed-source) untuk menggantikan Excel saat menganalisis file CSV untuk keperluan DFIR.
Ini adalah alat GUI khusus Windows yang ditulis dalam C#.
Alat ini sangat bagus untuk investigasi kecil oleh seorang analis tunggal dan bagi orang yang baru pertama kali mempelajari analisis DFIR, namun, antarmukanya bisa sulit dipahami pada awalnya jadi silakan gunakan panduan ini untuk memahami berbagai fiturnya.

## Instalasi dan Menjalankan

Tidak perlu menginstal aplikasinya.
Cukup unduh versi terbaru dari [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md), ekstrak (unzip) dan jalankan `TimelineExplorer.exe`.
Jika Anda tidak memiliki runtime .NET yang sesuai, sebuah pesan akan muncul memberi tahu Anda bahwa Anda perlu menginstalnya.
Pada saat penulisan ini (2025/2/14), versi terbaru adalah `2.1.0` yang berjalan pada .NET versi `9`.

## Memuat file CSV

Cukup klik `File` -> `Open` dari menu untuk memuat file CSV.

Anda akan melihat tampilan seperti ini:

![First Start](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

Di bagian paling bawah, Anda dapat melihat nama file, `Total lines` dan `Visible lines`.

Selain kolom-kolom yang ada di file CSV, ada dua kolom di sebelah kiri yang ditambahkan oleh Timeline Explorer: `Line` dan `Tag`.
`Line` menunjukkan nomor baris tetapi biasanya tidak berguna untuk investigasi, jadi Anda mungkin ingin menyembunyikan kolom ini.
`Tag` memungkinkan Anda memberi tanda centang untuk peristiwa yang ingin Anda catat untuk analisis lebih lanjut nanti, dll...
Sayangnya, tidak ada cara untuk menambahkan tag khusus ke peristiwa maupun menuliskan komentar tentang peristiwa karena file CSV dibuka dalam mode hanya-baca (read-only) untuk mencegah data ditimpa.

## Pemfilteran Data

Jika Anda mengarahkan kursor mouse ke bagian kanan atas dari sebuah header, Anda akan melihat ikon filter berwarna hitam muncul.

![Basic Data Filtering](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

Anda dapat memberi tanda centang pada tingkat severity untuk pertama-tama melakukan triase pada alert `high` dan `crit` (`critical`).
Pemfilteran ini juga sangat berguna untuk menyaring alert yang berisik (noisy) dengan mencentang semua di bawah `Rule Title` lalu menghilangkan centang pada aturan yang berisik.

Seperti ditunjukkan di bawah, jika Anda mengklik `Text Filters`, Anda dapat membuat filter yang lebih canggih:

![Advanced Data Filtering](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

Namun, alih-alih membuat filter di sini, biasanya lebih mudah mengklik ikon `ABC` di bawah header dan menerapkan filter di sini:

![ABC Filtering](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

Sayangnya, kedua tempat ini menyediakan opsi pemfilteran yang sedikit berbeda jadi Anda harus mengetahui kedua tempat untuk memfilter data.

Sebagai contoh, jika Anda memiliki terlalu banyak peristiwa `Proc Exec` yang ingin Anda saring, Anda dapat memilih `Does not contain` dan mengetik `Proc Exec` untuk mengabaikan peristiwa-peristiwa tersebut:

![Rule Filtering](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

Jika Anda melihat ke arah bawah, Anda dapat melihat aturan untuk filter dalam warna yang berbeda.
Jika Anda ingin menonaktifkan filter untuk sementara, cukup hilangkan centangnya.
Jika Anda ingin menghapus semua filter, klik tombol `X`.

Jika Anda ingin mengabaikan aturan berisik lainnya, Anda harus membuka `Filter Editor` dengan mengklik `Edit Filter` di sudut kanan bawah:

![Filter Editor](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

Salin teks `Not Contains([Rule Title], 'Proc Exec')`, tambahkan `and`, tempel filter yang sama dan ubah `Proc Exec` menjadi `Possible LOLBIN` dan sekarang Anda dapat mengabaikan kedua aturan ini:

![Multiple Filters](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

Cara termudah untuk menggabungkan beberapa filter adalah dengan pertama-tama membuat sintaks filter dari ikon `ABC`, lalu menyalin, menempel, dan mengedit teks tersebut serta menggabungkan filter dengan `and`, `or` dan `not`.

Anda juga dapat mengklik teks berwarna mana pun untuk mendapatkan kotak dropdown berisi opsi yang mungkin untuk mengedit filter Anda:

![Dropdown editing](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Opsi Header

Jika Anda mengklik kanan pada header mana pun, Anda akan mendapatkan opsi berikut:

![Header Options](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

Sebagian besar opsi ini cukup jelas dengan sendirinya.

* Setelah Anda menyembunyikan sebuah kolom, Anda dapat menampilkannya kembali dengan membuka `Column Chooser`, klik kanan pada nama kolom dan klik `Show Column`.
* `Group By This Column` memiliki efek yang sama dengan menyeret header kolom ke atas untuk mengelompokkan. (Dijelaskan lebih rinci nanti.)
* `Hide Group By Box` hanya akan menyembunyikan teks `Drag a column header here to group by that column` dan memindahkan bilah pencarian.

### Conditional Formatting

Anda dapat memformat teks dengan warna, font tebal, dll... dengan mengklik `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...`:

![Conditional Formatting](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

Sebagai contoh, jika Anda ingin menampilkan alert `critical` dengan `Red Fill`, maka cukup ketik `crit` dan pilih `Red Fill` dari opsi, centang `Apply formatting to an entire row` dan tekan `OK`.

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

Sekarang alert `critical` akan ditampilkan dengan warna merah seperti ditunjukkan di bawah:

![Red fill](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

Anda dapat melanjutkan melakukan ini dengan menambahkan warna untuk alert `low`, `medium` dan `high` juga.

## Pencarian

Secara default, ketika Anda mengetik teks di bilah pencarian, ia akan melakukan pemfilteran dan hanya menampilkan hasil yang mengandung teks tersebut di suatu tempat dalam baris.
Anda dapat melihat berapa banyak hit yang Anda miliki dengan memeriksa kolom `Visible lines` di bagian bawah.

Anda dapat mengubah perilaku ini dengan mengklik `Search options` di pojok kanan paling bawah.
Ini akan menampilkan hal berikut:

![Search Options](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

Jika Anda mengubah `Behavior` dari `Filter` menjadi `Search` Anda dapat mencari teks secara normal.

> Catatan: Biasanya butuh waktu untuk mengubah perilaku dan Timeline Explorer akan macet sebentar, jadi bersabarlah setelah mengklik.

`Match criteria` default adalah `Mixed` tetapi dapat diubah menjadi `Or`, `And`, atau `Exact`.
Jika Anda mengubahnya menjadi apa pun selain `Mixed`, Anda kemudian dapat mengatur `Condition` dari `Contains` menjadi `Starts with`, `Like` atau `Equals`.

`Match criteria` `Mixed` itu rumit karena kadang menggunakan logika `AND` dan kadang `OR` tetapi bisa sangat fleksibel setelah dipelajari.
Ia beroperasi sebagai berikut:

* Jika Anda memisahkan kata dengan spasi, ia akan diperlakukan sebagai logika `OR`.
* Jika Anda ingin menyertakan spasi dalam pencarian Anda, maka Anda perlu menambahkan tanda kutip.
* Awali sebuah kondisi dengan `+` untuk logika `AND`.
* Awali sebuah kondisi dengan `-` untuk mengecualikan hasil.
* Filter pada kolom tertentu dengan format `ColumnName:FilterString`.
* Jika Anda memfilter pada kolom tertentu dan juga menyertakan kata kunci terpisah, ia akan menjadi logika `AND`.

Contoh:

| Search Criteria                  | Description                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Memilih rekaman yang mengandung string `mimikatz` di kolom pencarian mana pun.                                                                        |
| one two three                    | Memilih rekaman yang mengandung `one` ATAU `two` ATAU `three` di kolom pencarian mana pun.                                                             |
| "hoge hoge"                      | Memilih rekaman yang mengandung `hoge hoge` di kolom pencarian mana pun.                                                                                  |
| mimikatz +"Bad Guy"              | Memilih rekaman yang mengandung baik `mimikatz` MAUPUN `Bad Guy` di kolom pencarian mana pun.                                                                |
| EventID:4624 kali                | Memilih rekaman yang mengandung `4624` di kolom yang dimulai dengan `EventID` DAN mengandung `kali` di kolom pencarian mana pun.                          |
| data +entry -mark                | Memilih rekaman yang mengandung baik `data` MAUPUN `entry` di kolom pencarian mana pun, mengecualikan rekaman yang mengandung `mark`.                               |
| manu mask -file                  | Memilih rekaman yang mengandung `menu` ATAU `mask`, mengecualikan rekaman yang mengandung `file`.                                                           |
| From:Roller Subj:"currency mask" | Memilih rekaman yang mengandung `Roller` di kolom yang dimulai dengan `From` DAN mengandung `currency mask` di kolom yang dimulai dengan `Subj`. |
| import -From:Steve               | Memilih rekaman yang mengandung `import` di kolom pencarian mana pun, mengecualikan rekaman yang mengandung `Steve` di kolom yang dimulai dengan `From`.       |

## Membekukan kolom

Meskipun bukan opsi pencarian, Anda dapat mengonfigurasi `First scrollable column` di bawah menu `Search options`.
Sebagian besar analis akan mengatur ini ke `Timestamp` sehingga mereka selalu dapat melihat waktu terjadinya peristiwa tertentu.

## Menyeret header kolom untuk mengelompokkan

Jika Anda menyeret header kolom ke `Drag a column header here to group by that column`, Timeline Explorer akan mengelompokkan berdasarkan kolom tersebut.
Sudah umum untuk mengelompokkan berdasarkan `Level` sehingga Anda dapat memprioritaskan alert berdasarkan severity:

![Group by](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

Jika Anda memiliki beberapa komputer dalam hasil Anda, Anda dapat lebih lanjut mengelompokkan berdasarkan `Computer` untuk melakukan triase berdasarkan tingkat severity yang berbeda untuk setiap komputer.

## Memeriksa field

Secara default, Hayabusa akan memisahkan data field dengan simbol broken pipe: `¦`.
Ketika data field berada pada satu garis horizontal, ini membuatnya sangat mudah untuk membedakan beberapa field karena karakter ini tidak sering ditemukan dalam log:

![Field Information](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

Namun terkadang, akan ada terlalu banyak informasi field dalam log dan semuanya tidak dapat muat dalam satu layar.
Dalam kasus ini, Anda dapat mengklik dua kali pada sel untuk mendapatkan pop-up yang menampilkan semua informasi field:

![Cell Contents](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

Masalahnya adalah Timeline Explorer hanya memungkinkan Anda memformat data field dengan karakter baris baru (`CRLF`, `CR`, `LF`), koma dan tab.

Jika Anda menggunakan opsi `-M, --multiline`, Anda dapat memisahkan field dengan karakter baris baru dan ketika Anda mengklik dua kali untuk membuka isi sebuah sel, ia akan diformat dengan benar:

![Multi-line formatting](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

Masalahnya adalah sekarang hanya field pertama yang akan ditampilkan dalam timeline jadi Anda harus mengklik dua kali dan membuka jendela baru setiap kali Anda ingin memeriksa data field lainnya:

![Multiline single fiels](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

Sayangnya, Timeline Explorer tidak mendukung beberapa baris dalam tampilan timeline.

Untuk mengatasi ini, mulai dari Hayabusa `v3.1.0`, Anda dapat memisahkan field dengan tab:

![Tab separation](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

Sedikit lebih sulit untuk membedakan di mana satu field berakhir dan field berikutnya dimulai.
Selain itu, ketika Anda mengklik dua kali dan membuka isi sel, field tidak diformat secara otomatis:

![Tab separation not formatted](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

Namun, jika Anda mengklik `Tab` di bagian bawah lalu `Format` Anda dapat memformat field menjadi tampilan yang mudah dibaca:

![Tab separation formatted](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Skin

Anda dapat mengubah tema warna dari `Tools` -> `Skins` jika Anda lebih menyukai mode gelap, dll...

## Sesi

Jika Anda menyesuaikan kolom, tampilan, menambahkan filter, dll... dan Anda ingin menyimpan pengaturan tersebut untuk nanti, pastikan untuk menyimpan sesi Anda dari `File` -> `Session` -> `Save`.
