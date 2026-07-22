# Menganalisis Hasil Hayabusa dengan jq

# Penulis

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# Tentang

Mampu mengidentifikasi, mengekstrak, dan membuat metrik terhadap field penting dalam log merupakan keterampilan esensial bagi analis DFIR dan threat hunting.
Hasil Hayabusa biasanya disimpan ke file `.csv` agar dapat diimpor ke program seperti Excel atau Timeline Explorer untuk analisis timeline.
Namun, ketika terdapat ratusan atau lebih event yang sama, akan menjadi tidak praktis atau mustahil untuk memeriksanya secara manual.
Dalam situasi ini, analis biasanya mengurutkan dan menghitung jenis data yang serupa untuk mencari pencilan (outlier).
Hal ini juga dikenal sebagai long tail analysis, stack ranking, frequency analysis, dan sebagainya...
Hal ini dapat dilakukan dengan Hayabusa dengan menghasilkan output ke file `.json` atau `.jsonl` lalu menganalisisnya dengan `jq`.

Sebagai contoh, seorang analis dapat membandingkan service yang terpasang pada semua workstation di sebuah organisasi.
Meskipun mungkin saja sebuah malware tertentu terpasang di setiap workstation, kemungkinan besar malware tersebut hanya ada pada segelintir sistem.
Dalam kasus ini, service yang terpasang pada semua sistem lebih mungkin bersifat jinak, sementara service yang jarang ditemukan cenderung lebih mencurigakan dan harus diperiksa secara berkala.

Kasus penggunaan lainnya adalah membantu menentukan seberapa mencurigakan sesuatu.
Sebagai contoh, seorang analis dapat menganalisis log logon gagal `4625` untuk menentukan berapa kali sebuah alamat IP tertentu gagal melakukan logon.
Jika hanya ada beberapa logon gagal, maka kemungkinan besar seorang administrator hanya salah mengetik kata sandinya.
Namun, jika terdapat ratusan atau lebih logon gagal dalam waktu singkat oleh sebuah alamat IP tertentu, maka kemungkinan besar alamat IP tersebut berbahaya.

Mempelajari cara menggunakan `jq` akan membantu Anda menguasai bukan hanya analisis log event Windows, tetapi juga semua log berformat JSON.
Karena JSON kini telah menjadi format log yang sangat populer dan sebagian besar penyedia cloud menggunakannya untuk log mereka, mampu mem-parsing log tersebut dengan `jq` telah menjadi keterampilan esensial bagi analis keamanan modern.

Dalam panduan ini, saya pertama-tama akan menjelaskan cara memanfaatkan `jq` bagi mereka yang belum pernah menggunakannya, lalu menjelaskan penggunaan yang lebih kompleks beserta contoh dunia nyata.
Saya merekomendasikan menggunakan linux, macOS, atau linux di Windows agar dapat menggabungkan `jq` dengan perintah berguna lainnya seperti `sort`, `uniq`, `grep`, `sed`, dan sebagainya...

# Menginstal jq

Silakan merujuk ke [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) dan instal perintah `jq`.

# Tentang Format JSON

Log JSON adalah sebuah daftar object yang berada di dalam kurung kurawal `{` `}`.
Di dalam object ini terdapat pasangan key-value yang dipisahkan oleh titik dua.
Key harus berupa string, tetapi value dapat berupa salah satu dari berikut:
  * string (Contoh: `"string"`)
  * angka (Contoh: `10`)
  * object lain (Contoh: `{ xxxx }`)
  * array (Contoh: `["string", 10]`)
  * boolean (Contoh: `true`, `false`)
  * `null`

Anda dapat menyarangkan (nest) sebanyak mungkin object di dalam object.

Dalam contoh ini, `Details` adalah object tersarang di dalam sebuah root object:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Tentang Format JSON dan JSONL dengan Hayabusa

Pada versi-versi sebelumnya, Hayabusa menggunakan format JSON tradisional yang memasukkan semua object log `{ xxx }` ke dalam satu array raksasa.

Contoh:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

Ada dua masalah dengan ini.
Masalah pertama adalah kueri `jq` akan menjadi lebih merepotkan karena segala sesuatunya harus dimulai dengan tambahan `.[]` untuk memberi tahu agar melihat ke dalam array tersebut.
Masalah yang jauh lebih besar adalah agar dapat mem-parsing log seperti itu, perlu terlebih dahulu memuat seluruh data dalam array.
Ini menjadi masalah jika Anda memiliki file JSON yang sangat besar dan memori yang tidak melimpah.
Untuk mengurangi penggunaan CPU dan memori yang dibutuhkan, format JSONL (JSON Lines), yang tidak memasukkan segala sesuatunya ke dalam array raksasa, menjadi lebih populer.
Hayabusa menghasilkan output dalam format JSON dan JSONL, namun format JSON tidak lagi disimpan di dalam sebuah array.
Satu-satunya perbedaan adalah format JSON lebih mudah dibaca dalam editor teks atau di konsol, sementara format JSONL menyimpan setiap object JSON pada satu baris tunggal.
Format JSONL akan sedikit lebih cepat dan lebih kecil ukurannya sehingga ideal jika Anda hanya akan mengimpor log ke dalam SIEM, dan sebagainya... tetapi tidak melihatnya.
Format JSON ideal jika Anda juga akan melakukan beberapa pemeriksaan manual.

# Membuat File Hasil JSON

Pada versi Hayabusa 2.x saat ini, Anda dapat menyimpan hasil dalam JSON dengan `hayabusa dfir-timeline -t json -d <directory> -o results.json` atau `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` untuk format JSONL.

Hayabusa akan menggunakan profil `standard` default dan hanya menyimpan jumlah data minimal untuk analisis dalam object `Details`.
Jika Anda ingin menyimpan semua informasi field asli dalam log .evtx, Anda dapat menggunakan profil `all-field-info` dengan opsi `--profile all-field-info`.
Ini akan menyimpan semua informasi field ke dalam object `AllFieldInfo`.
Jika Anda ingin menyimpan kedua object `Details` dan `AllFieldInfo` untuk berjaga-jaga, Anda dapat menggunakan profil `super-verbose`.

## Manfaat Menggunakan Details Dibanding AllFieldInfo

Manfaat pertama menggunakan `Details` dibanding `AllFieldInfo` adalah hanya field penting yang disimpan, dan nama field telah dipersingkat untuk menghemat ruang file.
Kekurangannya adalah ada kemungkinan kehilangan data yang sebenarnya Anda pedulikan tetapi terlewatkan.
Manfaat kedua adalah Hayabusa akan menyimpan field dengan cara yang lebih seragam dengan menormalkan nama field.
Sebagai contoh, dalam log Windows asli, nama pengguna biasanya berada dalam field `SubjectUserName` atau `TargetUserName`. 
Namun, terkadang nama pengguna akan berada dalam field `AccountName`, terkadang pengguna target sebenarnya berada dalam field `SubjectUserName`, dan sebagainya...
Sayangnya, terdapat banyak nama field yang tidak konsisten dalam log event Windows.
Hayabusa berusaha menormalkan field-field ini, sehingga seorang analis hanya perlu mem-parsing satu nama yang umum alih-alih harus memahami begitu banyak keanehan dan perbedaan antar event ID di Windows.

Berikut adalah contoh field pengguna.
Hayabusa akan menormalkan `SubjectUserName`, `TargetUserName`, `AccountName`, dan sebagainya... dengan cara berikut:
  * `SrcUser` (Source User): ketika sebuah aksi terjadi **dari** seorang pengguna. (Biasanya pengguna jarak jauh.)
  * `TgtUser` (Target User): ketika sebuah aksi terjadi **kepada** seorang pengguna. (Sebagai contoh, sebuah logon **kepada** seorang pengguna.)
  * `User`: ketika sebuah aksi terjadi oleh pengguna yang sedang login. (Tidak ada arah tertentu dalam aksi tersebut.)

Contoh lainnya adalah proses.
Dalam log event Windows asli, field proses dirujuk dengan berbagai konvensi penamaan: `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName`, dan sebagainya...
Tanpa normalisasi field, seorang analis harus terlebih dahulu mengetahui semua nama field yang berbeda, lalu mengekstrak semua log dengan nama field tersebut, lalu menggabungkannya. 

Seorang analis dapat menghemat banyak waktu dan kerumitan hanya dengan menggunakan satu field `Proc` yang telah dinormalkan yang disediakan Hayabusa dalam object `Details`.

# Pelajaran/Resep jq

Sekarang saya akan mencantumkan beberapa pelajaran/resep contoh praktis yang mungkin membantu Anda dalam pekerjaan Anda.

## 1. Pemeriksaan Manual dengan jq dan Less Berwarna

Ini adalah salah satu hal pertama yang harus dilakukan untuk memahami field apa saja yang ada dalam log.
Anda cukup melakukan `less results.json` tetapi cara yang lebih baik adalah berikut:
`cat results.json | jq -C | less -R`

Dengan meneruskannya ke `jq`, ia akan memformat semua field dengan rapi untuk Anda jika sebelumnya belum terformat dengan rapi.
Dengan menggunakan opsi `-C` (color) pada `jq` dan opsi `-R` (raw output) pada `less`, Anda dapat menggulir ke atas dan ke bawah dalam warna.

## 2. Metrik

Hayabusa sudah memiliki fungsionalitas untuk mencetak jumlah dan persentase event berdasarkan event ID, namun, ini juga bagus untuk diketahui cara melakukannya dengan `jq`.
Ini akan memungkinkan Anda menyesuaikan data yang ingin Anda buat metriknya.

Mari kita pertama-tama mengekstrak daftar Event ID dengan perintah berikut:

`cat results.json | jq '.EventID'`

Ini akan mengekstrak hanya nomor Event ID dari setiap log.
Setelah `jq`, dalam tanda kutip tunggal, cukup ketik `.` dan nama field yang ingin Anda ekstrak.
Anda akan melihat daftar panjang seperti ini:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Sekarang, salurkan (pipe) hasilnya ke perintah `sort` dan `uniq -c` untuk menghitung berapa kali event ID muncul:

`cat results.json | jq '.EventID' | sort | uniq -c`

Opsi `-c` untuk `uniq` akan menghitung berapa kali sebuah event ID unik muncul.

Anda akan melihat sesuatu seperti ini:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 Bagian kiri adalah jumlahnya, dan bagian kanan adalah Event ID.
 Seperti yang Anda lihat, ini tidak terurut, sehingga sulit untuk mengetahui event ID mana yang paling banyak muncul.

 Anda dapat menambahkan `sort -n` di bagian akhir untuk memperbaikinya:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

Opsi `-n` memberi tahu `sort` untuk mengurutkan berdasarkan angka.

Anda akan melihat sesuatu seperti ini:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

Kita dapat melihat bahwa event `4688` (Process creation) tercatat paling banyak.
Event yang tercatat terbanyak kedua adalah `4625` (Failed Logon).

Jika Anda ingin mencetak event yang paling banyak tercatat di bagian atas, maka Anda dapat membalik urutan dengan `sort -n -r` atau `sort -nr`.
Anda juga dapat mencetak hanya 10 event yang paling banyak tercatat dengan menyalurkan hasilnya ke `head -n 10`.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

Ini akan memberi Anda:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

Penting untuk dipertimbangkan bahwa EID (Event ID) tidaklah unik, jadi Anda mungkin memiliki event yang benar-benar berbeda dengan Event ID yang sama.
Oleh karena itu, penting juga untuk memeriksa `Channel`.

Kita dapat menambahkan informasi field ini seperti ini:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Kita menambahkan opsi `-j` (join) pada `jq` untuk menggabungkan semua field bersama yang dipisahkan oleh koma dan diakhiri dengan karakter baris baru `\n`.

Ini akan memberi kita:
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 Catatan: `Security` disingkat menjadi `Sec`, `System` menjadi `Sys`, dan `PowerShell` menjadi `PwSh`.

Kita dapat menambahkan rule title sebagai berikut:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Ini akan memberi kita:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

Sekarang Anda dapat dengan bebas mengekstrak data apa pun dari log dan menghitung kemunculannya.

## 3. Memfilter pada Data Tertentu

Sering kali Anda ingin memfilter pada Event ID, pengguna, proses, LID (Logon ID), dan sebagainya... tertentu.
Anda dapat melakukannya dengan `select` di dalam kueri `jq`.

Sebagai contoh, mari kita ekstrak semua event logon sukses `4624`:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

Ini akan mengembalikan semua object JSON untuk EID `4624`:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

Jika Anda ingin memfilter pada beberapa kondisi, Anda dapat menggunakan kata kunci seperti `and`, `or`, dan `not`.

Sebagai contoh, mari kita cari event `4624` di mana type-nya `3` (Network logon).

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

Ini akan mengembalikan semua object di mana `EventID` adalah `4624` dan field tersarang `"Details": { "Type" }` adalah `3`.

Namun ada masalah.
Anda mungkin memperhatikan error yang berbunyi `jq: error (at <stdin>:10636): Cannot index string with string "Type"`.
Setiap kali Anda melihat error `Cannot index string with string`, itu berarti Anda menyuruh `jq` untuk menghasilkan output sebuah field yang tidak ada atau bertipe salah.
Anda dapat menghilangkan error ini dengan menambahkan `?` di akhir field.
Ini memberi tahu `jq` untuk mengabaikan error.

Contoh: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

Sekarang, setelah memfilter pada kriteria tertentu, kita dapat menggunakan `|` di dalam kueri `jq` untuk memilih field tertentu yang menarik.

Sebagai contoh, mari kita ekstrak nama pengguna target `TgtUser` dan alamat IP sumber `SrcIP`:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

Sekali lagi, kita menambahkan opsi `-j` (join) pada `jq` untuk memilih beberapa field untuk dihasilkan.
Anda kemudian dapat menjalankan `sort`, `uniq -c`, dan sebagainya... seperti pada contoh sebelumnya untuk mengetahui berapa kali sebuah alamat IP tertentu masuk ke seorang pengguna melalui network logon type 3.

## 4. Menyimpan Output ke Format CSV

Sayangnya, field dalam log event Windows akan berbeda sepenuhnya menurut jenis event-nya, sehingga tidak mudah untuk membuat timeline yang dipisahkan koma berdasarkan field tanpa memiliki ratusan kolom.
Namun, dimungkinkan untuk membuat timeline yang dipisahkan field untuk satu jenis event tunggal.
Dua contoh umum adalah Security `4624` (Successful Logons) dan `4625` (Failed Logons) untuk memeriksa lateral movement dan password guessing/spraying.

Dalam contoh ini, kita mengekstrak hanya log Security 4624 dan menghasilkan timestamp, nama komputer, dan semua informasi `Details`.
Kita menyimpannya ke file CSV dengan menggunakan `| @csv`, namun, kita perlu meneruskan data sebagai array.
Kita dapat melakukannya dengan memilih field yang ingin kita hasilkan seperti yang kita lakukan sebelumnya dan mengapitnya dengan kurung siku `[ ]` untuk mengubahnya menjadi array.

Contoh: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

Catatan:
  * Untuk memilih semua field dalam object `Details` kita menambahkan `[]`.
  * Ada kasus di mana `Details` adalah string dan bukan array sehingga akan memberikan error `Cannot iterate over string`, jadi Anda perlu menambahkan `?`.
  * Kita menambahkan opsi `-r` (Raw output) pada `jq` agar tidak meng-escape tanda kutip ganda dengan backslash.

Hasil:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

Jika kita hanya memeriksa siapa yang berhasil logon, kita mungkin tidak memerlukan field `LID` (Logon ID) terakhir.
Anda dapat menghapus kolom yang tidak diperlukan dengan fungsi `del`.

Contoh: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

Array dihitung mulai dari `0` jadi untuk menghapus field ke-7, kita menggunakan `6`.

Anda sekarang dapat menyimpan file CSV dengan menambahkan `> 4624-logs.csv` lalu mengimpornya ke Excel atau Timeline Explorer untuk analisis lebih lanjut.

Perhatikan bahwa Anda perlu menambahkan header untuk melakukan pemfilteran.
Meskipun dimungkinkan untuk menambahkan heading di dalam kueri `jq`, biasanya paling mudah hanya menambahkan baris atas secara manual setelah menyimpan file.

## 5. Menemukan Tanggal dengan Alert Terbanyak

Hayabusa, secara default, akan memberi tahu Anda tanggal yang memiliki alert terbanyak menurut tingkat severity.
Namun, Anda mungkin ingin menemukan tanggal dengan alert terbanyak kedua, ketiga, dan sebagainya... juga.
Kita dapat melakukannya dengan string slicing pada timestamp untuk mengelompokkan berdasarkan tahun, bulan, atau tanggal tergantung kebutuhan Anda.

Contoh: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` memberi tahu `jq` untuk mengekstrak hanya 10 byte pertama dari `Timestamp`.

Ini akan memberi kita tanggal dengan event terbanyak:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

Jika Anda ingin mengetahui bulan dengan event terbanyak, Anda cukup mengubah `.[:10]` menjadi `.[:7]` untuk mengekstrak 7 byte pertama.

Jika Anda ingin mendaftar tanggal dengan alert `high` terbanyak, Anda dapat melakukan ini:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

Anda dapat terus menambahkan kondisi filter ke fungsi `select` sesuai dengan nama komputer, event ID, dan sebagainya... tergantung kebutuhan Anda.

## 6. Merekonstruksi Log PowerShell

Hal yang disayangkan tentang log PowerShell adalah log tersebut sering terpecah menjadi beberapa log sehingga sulit dibaca.
Kita dapat membuat log jauh lebih mudah dibaca dengan mengekstrak hanya perintah yang dijalankan oleh penyerang.

Sebagai contoh, jika Anda memiliki log ScriptBlock EID `4104`, Anda dapat mengekstrak hanya field tersebut untuk membuat timeline yang mudah dibaca.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

Ini akan menghasilkan timeline sebagai berikut:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. Menemukan Koneksi Jaringan Mencurigakan

Anda pertama-tama dapat memperoleh daftar semua alamat IP target dengan perintah berikut:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

Jika Anda memiliki threat intelligence, Anda dapat memeriksa apakah ada alamat IP yang diketahui berbahaya.

Anda dapat menghitung berapa kali sebuah alamat IP target tertentu terhubung dengan perintah berikut:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

Dengan mengubah `TgtIP` menjadi `SrcIP`, Anda dapat melakukan pemeriksaan threat intelligence yang sama untuk alamat IP berbahaya berdasarkan alamat IP sumber.

Misalkan Anda menemukan bahwa alamat IP berbahaya `93.184.220.29` terhubung dari lingkungan Anda.
Anda dapat memperoleh detail tentang event tersebut dengan kueri berikut:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

Ini akan memberi Anda hasil JSON seperti ini:
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

Jika Anda ingin mendaftar domain yang dihubungi, Anda dapat menggunakan perintah berikut:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> Catatan: Saya menambahkan filter grep untuk `.` untuk menghapus nama host NETBIOS.

## 8. Mengekstrak Hash Binary Executable

Dalam log Process Creation Sysmon EID `1`, sysmon dapat dikonfigurasi untuk menghitung hash dari binary.
Analis keamanan dapat membandingkan hash ini dengan hash berbahaya yang diketahui menggunakan threat intelligence.
Anda dapat mengekstrak field `Hashes` dengan perintah berikut:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

Ini akan memberi Anda daftar hash seperti ini:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon biasanya akan menghitung beberapa hash seperti `MD5`, `SHA1`, dan `IMPHASH`.
Anda dapat mengekstrak hash ini dengan ekspresi reguler dalam `jq` atau cukup menggunakan string splicing untuk performa yang lebih baik.

Sebagai contoh, Anda dapat mengekstrak hash MD5 dan menghapus duplikat dengan perintah berikut:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. Mengekstrak Log PowerShell

Log Scriptblock PowerShell (EID: 4104) biasanya terpecah menjadi banyak log dan ketika menghasilkan output ke format CSV, Hayabusa akan menghapus karakter tab dan return untuk membuat output lebih ringkas.
Namun, paling mudah menganalisis log powershell dengan format karakter tab dan return asli serta menggabungkan log bersama-sama.
Berikut adalah contoh mengekstrak log PowerShell EID 4104 dari `COMPUTER-A` dan menyimpannya ke file `.ps1` agar dapat dibuka dan dianalisis dengan VSCode, dan sebagainya...
Setelah mengekstrak field ScriptBlock, kita menggunakan `awk` untuk mengganti `\r\n` dan `\n` dengan karakter return dan `\t` dengan tab.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

Setelah analis menganalisis log untuk perintah PowerShell berbahaya, mereka biasanya perlu mencari kapan perintah tersebut dijalankan.
Berikut adalah contoh menghasilkan output Timestamp dan log PowerShell ke dalam file CSV untuk mencari waktu sebuah perintah dijalankan:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

Catatan: Pembatas string yang digunakan adalah `¦` karena tanda kutip tunggal dan ganda sering ditemukan dalam log PowerShell dan akan merusak output CSV.
Ketika Anda mengimpor file CSV, Anda perlu menentukan pembatas string `¦` kepada aplikasi.
