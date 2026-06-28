# Field deteksi

## Dasar-dasar seleksi

Pertama, dasar-dasar tentang cara membuat aturan seleksi akan dijelaskan.

### Cara menulis logika AND dan OR

Untuk menulis logika AND, kita menggunakan dictionary bersarang.
Aturan deteksi di bawah ini mendefinisikan bahwa **kedua kondisi** harus benar agar aturan tersebut cocok.

- EventID harus tepat `7040`.
- **AND**
- Channel harus tepat `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

Untuk menulis logika OR, kita menggunakan list (Dictionary yang dimulai dengan `-`).
Pada aturan deteksi di bawah ini, **salah satu** dari kondisi akan menyebabkan aturan terpicu.

- EventID harus tepat `7040`.
- **OR**
- Channel harus tepat `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

Kita juga dapat menggabungkan logika `AND` dan `OR` seperti yang ditunjukkan di bawah ini.
Dalam kasus ini, aturan cocok ketika kedua kondisi berikut benar.

- EventID tepat `7040` **OR** `7041`.
- **AND**
- Channel tepat `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkey

Berikut adalah kutipan dari log peristiwa Windows, diformat dalam XML asli.
Field `Event.System.Channel` pada contoh file aturan di atas merujuk pada tag XML asli: `<Event><System><Channel>System<Channel><System></Event>`
Tag XML bersarang diganti dengan nama tag yang dipisahkan oleh titik (`.`).
Dalam aturan hayabusa, string-string field yang dihubungkan bersama dengan titik ini disebut sebagai `eventkeys`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Alias Eventkey

Eventkey panjang dengan banyak pemisah `.` adalah hal yang umum, jadi hayabusa akan menggunakan alias untuk membuatnya lebih mudah digunakan. Alias didefinisikan dalam file `rules/config/eventkey_alias.txt`. File ini adalah file CSV yang terdiri dari pemetaan `alias` dan `event_key`. Anda dapat menulis ulang aturan di atas seperti yang ditunjukkan di bawah ini dengan alias yang membuat aturan lebih mudah dibaca.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Perhatian: Alias Eventkey yang Tidak Terdefinisi

Tidak semua alias eventkey didefinisikan dalam `rules/config/eventkey_alias.txt`. Jika Anda tidak mendapatkan data yang benar pada pesan `details` (`Alert details`), dan sebaliknya mendapatkan `n/a` (not available) atau jika seleksi dalam logika deteksi Anda tidak bekerja dengan benar, maka Anda mungkin perlu memperbarui `rules/config/eventkey_alias.txt` dengan alias baru.

### Cara menggunakan atribut XML dalam kondisi

Elemen XML dapat memiliki atribut yang ditetapkan dengan menambahkan spasi pada elemen. Misalnya, `Name` dalam `Provider Name` di bawah ini adalah atribut XML dari elemen `Provider`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

Untuk menentukan atribut XML dalam eventkey, gunakan format `{eventkey}_attributes.{attribute_name}`. Misalnya, untuk menentukan atribut `Name` dari elemen `Provider` dalam file aturan, akan terlihat seperti ini:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### pencarian grep

Hayabusa dapat melakukan pencarian grep pada file log peristiwa Windows dengan tidak menentukan eventkey apa pun.

Untuk melakukan pencarian grep, tentukan deteksi seperti yang ditunjukkan di bawah ini. Dalam kasus ini, jika string `mimikatz` atau `metasploit` termasuk dalam log Peristiwa Windows, maka akan cocok. Dimungkinkan juga untuk menentukan wildcard.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Catatan: Hayabusa secara internal mengonversi data log peristiwa Windows ke format JSON sebelum memproses data sehingga tidak mungkin mencocokkan pada tag XML.

### EventData

Log peristiwa Windows dibagi menjadi dua bagian: bagian `System` tempat data fundamental (Event ID, Timestamp, Record ID, Nama log (Channel)) ditulis, dan bagian `EventData` atau `UserData` tempat data sembarang ditulis bergantung pada Event ID.
Salah satu masalah yang sering muncul adalah bahwa nama field yang bersarang dalam `EventData` semuanya disebut `Data` sehingga eventkey yang dijelaskan sejauh ini tidak dapat membedakan antara `SubjectUserSid` dan `SubjectUserName`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

Untuk mengatasi masalah ini, Anda dapat menentukan nilai yang ditetapkan dalam `Data Name`. Misalnya, jika Anda ingin menggunakan `SubjectUserName` dan `SubjectDomainName` dalam EventData sebagai kondisi suatu aturan, Anda dapat menuliskannya sebagai berikut:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Pola abnormal dalam EventData

Beberapa tag yang bersarang dalam `EventData` tidak memiliki atribut `Name`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

Untuk mendeteksi log peristiwa seperti di atas, Anda dapat menentukan eventkey bernama `Data`.
Dalam kasus ini, kondisi akan cocok selama salah satu dari tag `Data` yang bersarang sama dengan `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Menampilkan data field dari beberapa nama field dengan nama yang sama

Beberapa peristiwa akan menyimpan datanya ke nama field yang semuanya disebut `Data` seperti pada contoh sebelumnya.
Jika Anda menentukan `%Data%` dalam `details:`, semua data akan ditampilkan dalam sebuah array.

Misalnya:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Jika Anda ingin mencetak hanya data field `Data` pertama, Anda dapat menentukan `%Data[1]%` dalam string peringatan `details:` Anda dan hanya `rundll32.exe` yang akan ditampilkan.

## Field Modifier

Karakter pipa dapat digunakan dengan eventkey seperti yang ditunjukkan di bawah ini untuk mencocokkan string.
Semua kondisi yang telah kami jelaskan sejauh ini menggunakan pencocokan tepat, tetapi dengan menggunakan field modifier, Anda dapat mendeskripsikan aturan deteksi yang lebih fleksibel.
Pada contoh berikut, jika nilai `Data` berisi string `EngineVersion=2`, maka akan cocok dengan kondisi.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

Pencocokan string tidak peka huruf besar/kecil. Namun, menjadi peka huruf besar/kecil setiap kali `|re` atau `|equalsfield` digunakan.

### Field Modifier Sigma yang Didukung

Hayabusa saat ini adalah satu-satunya alat sumber terbuka yang sepenuhnya mendukung seluruh spesifikasi Sigma.

Anda dapat memeriksa status terkini dari semua field modifier yang didukung serta berapa kali modifier ini digunakan dalam aturan Sigma dan Hayabusa di https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
Dokumen ini diperbarui secara dinamis setiap kali ada pembaruan pada aturan Sigma atau Hayabusa.

- `'|all':`: Field modifier ini berbeda dari yang di atas karena tidak diterapkan pada field tertentu tetapi pada semua field.

    Dalam contoh ini, kedua string `Keyword-1` dan `Keyword-2` harus ada tetapi dapat berada di mana saja di field mana pun:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Data akan dikodekan ke base64 dalam tiga cara berbeda bergantung pada posisinya dalam string yang dikodekan. Modifier ini akan mengodekan string ke ketiga variasi dan memeriksa apakah string tersebut dikodekan di suatu tempat dalam string base64.
- `|cased`: Membuat pencarian peka huruf besar/kecil.
- `|cidr`: Memeriksa apakah nilai field cocok dengan notasi CIDR IPv4 atau IPv6. (Contoh: `192.0.2.0/24`)
- `|contains`: Memeriksa apakah nilai field berisi string tertentu.
- `|contains|all`: Memeriksa apakah beberapa kata terkandung dalam data.
- `|contains|all|windash`: Sama seperti `|contains|windash` tetapi semua kata kunci harus ada.
- `|contains|cased`: Memeriksa apakah nilai field berisi string tertentu yang peka huruf besar/kecil.
- `|contains|expand`: Memeriksa apakah nilai field berisi string dalam file konfigurasi `expand` di dalam `/config/expand/`.
- `|contains|windash`: Akan memeriksa string apa adanya, serta mengonversi karakter `-` pertama menjadi permutasi karakter `/`, `–` (en dash), `—` (em dash), dan `―` (horizontal bar).
- `|endswith`: Memeriksa apakah nilai field diakhiri dengan string tertentu.
- `|endswith|cased`: Memeriksa apakah nilai field diakhiri dengan string tertentu yang peka huruf besar/kecil.
- `|endswith|windash`: Memeriksa akhir string dan melakukan variasi untuk dash.
- `|exists`: Memeriksa apakah suatu field ada.
- `|expand`: Memeriksa apakah nilai field sama dengan string dalam file konfigurasi `expand` di dalam `/config/expand/`.
- `|fieldref`: Memeriksa apakah nilai dalam dua field sama. Anda dapat menggunakan `not` dalam `condition` jika Anda ingin memeriksa apakah dua field berbeda.
- `|fieldref|contains`: Memeriksa apakah nilai satu field terkandung dalam field lain.
- `|fieldref|endswith`: Memeriksa apakah field di sebelah kiri diakhiri dengan string dari field di sebelah kanan. Anda dapat menggunakan `not` dalam `condition` untuk memeriksa apakah keduanya berbeda.
- `|fieldref|startswith`: Memeriksa apakah field di sebelah kiri dimulai dengan string dari field di sebelah kanan. Anda dapat menggunakan `not` dalam `condition` untuk memeriksa apakah keduanya berbeda.
- `|gt`: Memeriksa apakah nilai field lebih besar dari angka tertentu.
- `|gte`: Memeriksa apakah nilai field lebih besar dari atau sama dengan angka tertentu.
- `|lt`: Memeriksa apakah nilai field lebih kecil dari angka tertentu.
- `|lte`: Memeriksa apakah nilai field lebih kecil dari atau sama dengan angka tertentu.
- `|re`: Gunakan ekspresi reguler yang peka huruf besar/kecil. (Kami menggunakan crate regex jadi silakan lihat dokumentasi di <https://docs.rs/regex/latest/regex/#syntax> untuk mempelajari cara menulis ekspresi reguler yang didukung.)
    > Perhatian: [Sintaks ekspresi reguler dalam aturan Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) menggunakan PCRE dengan metakarakter tertentu untuk kelas karakter, lookbehind, atomic grouping, dll... yang tidak didukung. Crate regex Rust seharusnya dapat menggunakan semua ekspresi reguler dalam aturan Sigma tetapi ada kemungkinan inkompatibilitas. 
- `|re|i`: (Insensitive) Gunakan ekspresi reguler yang tidak peka huruf besar/kecil.
- `|re|m`: (Multi-line) Cocokkan di beberapa baris. `^` / `$` mencocokkan awal/akhir baris.
- `|re|s`: (Single-line) titik (`.`) mencocokkan semua karakter, termasuk karakter baris baru.
- `|startswith`: Memeriksa apakah nilai field dimulai dengan string tertentu.
- `|startswith|cased`: Memeriksa apakah nilai field dimulai dengan string tertentu yang peka huruf besar/kecil.
- `|utf16|base64offset|contains`: Memeriksa apakah string UTF-16 tertentu dikodekan di dalam string base64.
- `|utf16be|base64offset|contains`: Memeriksa apakah string UTF-16 big-endian tertentu dikodekan di dalam string base64.
- `|utf16le|base64offset|contains`: Memeriksa apakah string UTF-16 little-endian tertentu dikodekan di dalam string base64.
- `|wide|base64offset|contains`: Alias untuk `utf16le|base64offset|contains`, memeriksa string UTF-16 little-endian.

### Field Modifier yang Tidak Digunakan Lagi

Modifier berikut sekarang tidak digunakan lagi dan diganti oleh modifier yang lebih sesuai dengan spesifikasi sigma.

- `|equalsfield`: Sekarang diganti oleh `|fieldref`.
- `|endswithfield`: Sekarang diganti oleh `|fieldref|endswith`.

### Field Modifier Expand

Field modifier `expand` unik karena merupakan satu-satunya field modifier yang memerlukan konfigurasi sebelumnya untuk digunakan.
Misalnya, mereka menggunakan placeholder seperti `%DC-MACHINE-NAME%` dan memerlukan file konfigurasi bernama `/config/expand/DC-MACHINE-NAME.txt` yang berisi semua kemungkinan nama mesin DC.

Cara mengonfigurasinya dijelaskan lebih rinci [di sini](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## Wildcard

Wildcard dapat digunakan dalam eventkey. Pada contoh di bawah ini, jika `ProcessCommandLine` dimulai dengan string "malware", aturan akan cocok.
Spesifikasinya pada dasarnya sama dengan wildcard aturan sigma sehingga tidak akan peka huruf besar/kecil.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Dua wildcard berikut dapat digunakan.

- `*`: Mencocokkan string apa pun yang terdiri dari nol atau lebih karakter. (Secara internal dikonversi menjadi ekspresi reguler `.*`)
- `?`: Mencocokkan satu karakter apa pun. (Secara internal dikonversi menjadi ekspresi reguler `.`)

Tentang escaping wildcard:

- Wildcard (`*` dan `?`) dapat di-escape dengan menggunakan backslash: `\*`, `\?`.
- Jika Anda ingin menggunakan backslash tepat sebelum wildcard maka tulis `\\*` atau `\\?`.
- Escaping tidak diperlukan jika Anda menggunakan backslash dengan sendirinya.

## kata kunci null

Kata kunci `null` dapat digunakan untuk memeriksa apakah suatu field tidak ada.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Catatan: Ini berbeda dari `ProcessCommandLine: ''` yang memeriksa apakah nilai suatu field kosong.

## condition

Dengan notasi yang kami jelaskan di atas, Anda dapat mengekspresikan logika `AND` dan `OR` tetapi akan membingungkan jika Anda mencoba mendefinisikan logika yang kompleks.
Ketika Anda ingin membuat aturan yang lebih kompleks, Anda harus menggunakan kata kunci `condition` seperti yang ditunjukkan di bawah ini.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

Ekspresi berikut dapat digunakan untuk `condition`.

- `{expression1} and {expression2}`: Memerlukan {expression1} AND {expression2}
- `{expression1} or {expression2}`: Memerlukan {expression1} OR {expression2}
- `not {expression}`: Membalikkan logika dari {expression}
- `( {expression} )`: Menetapkan presedensi dari {expression}. Mengikuti logika presedensi yang sama seperti dalam matematika.

Pada contoh di atas, nama seleksi seperti `SELECTION_1`, `SELECTION_2`, dll... digunakan tetapi mereka dapat dinamai apa saja selama hanya berisi karakter berikut: `a-z A-Z 0-9 _`
> Namun, harap gunakan konvensi standar `selection_1`, `selection_2`, `filter_1`, `filter_2`, dll... agar mudah dibaca bila memungkinkan.

## logika not

Banyak aturan akan menghasilkan false positive sehingga sangat umum untuk memiliki seleksi untuk signature yang dicari tetapi juga seleksi filter agar tidak memberikan peringatan pada false positive.
Misalnya:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Korelasi Sigma

Kami telah mengimplementasikan semua korelasi Sigma versi 2.0.0 sebagaimana didefinisikan [di sini](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

Korelasi yang didukung:

- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

Aturan korelasi "metrics" baru (`value_sum`, `value_avg`, `value_percentile`) yang dirilis pada 12 September 2025 di Sigma versi 2.1.0 saat ini tidak didukung.
