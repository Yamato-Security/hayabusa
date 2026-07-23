## Aturan Event Count

Ini adalah aturan yang menghitung peristiwa tertentu dan memberi peringatan jika terlalu banyak atau terlalu sedikit jumlah peristiwa ini yang terjadi dalam suatu rentang waktu.
Contoh umum untuk mendeteksi banyak peristiwa dalam periode waktu tertentu adalah untuk mendeteksi serangan menebak kata sandi, serangan password spray, dan serangan denial of service.
Anda juga dapat menggunakan aturan ini untuk mendeteksi masalah keandalan sumber log, seperti ketika peristiwa tertentu turun di bawah ambang batas tertentu.

### Contoh aturan Event Count:

Contoh berikut menggunakan dua aturan untuk mendeteksi serangan menebak kata sandi.
Akan ada peringatan ketika aturan yang dirujuk cocok 5 kali atau lebih dalam 5 menit dan field `IpAddress` sama untuk peristiwa-peristiwa tersebut.

> Perhatikan bahwa kami hanya menyertakan field yang diperlukan untuk memahami konsepnya.
> Aturan lengkap yang menjadi dasar contoh ini terletak [di sini](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) untuk referensi Anda.

### Aturan korelasi Event Count:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Aturan Failed Logon - Incorrect Password:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### Contoh aturan `count` yang sudah usang:

Aturan korelasi dan aturan yang dirujuk di atas memberikan hasil yang sama dengan aturan berikut yang menggunakan modifier `count` yang lebih lama:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Output aturan Event Count:

Aturan di atas akan menghasilkan output berikut:
```
% ./hayabusa dfir-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Aturan Value Count

Aturan ini menghitung peristiwa yang sama dalam suatu rentang waktu dengan nilai yang **berbeda** dari suatu field tertentu.

Contoh:

- Pemindaian jaringan di mana satu alamat IP sumber mencoba terhubung ke banyak alamat IP dan/atau port tujuan yang berbeda.
- Serangan password spraying di mana satu sumber gagal melakukan otentikasi dengan banyak pengguna yang berbeda.
- Mendeteksi alat seperti BloodHound yang menghitung banyak grup AD dengan hak istimewa tinggi dalam rentang waktu yang singkat.

### Contoh aturan Value Count:

Aturan berikut mendeteksi ketika seorang penyerang mencoba menebak nama pengguna.
Yaitu, ketika alamat IP sumber yang **sama** (`IpAddress`) gagal melakukan logon dengan lebih dari 3 nama pengguna yang **berbeda** (`TargetUserName`) dalam 5 menit.

> Perhatikan bahwa kami hanya menyertakan field yang diperlukan untuk memahami konsepnya.
> Aturan lengkap yang menjadi dasar contoh ini terletak [di sini](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) untuk referensi Anda.

### Aturan korelasi Value Count:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Aturan Value Count Logon Failure (Pengguna Tidak Ada):

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### Aturan modifier `count` yang sudah usang:

Aturan korelasi dan aturan yang dirujuk di atas memberikan hasil yang sama dengan aturan berikut yang menggunakan modifier `count` yang lebih lama:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Output aturan Value Count:

Aturan di atas akan menghasilkan output berikut:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Aturan Temporal Proximity

Semua peristiwa yang didefinisikan oleh aturan yang dirujuk oleh field rule harus terjadi dalam rentang waktu yang didefinisikan oleh timespan.
Nilai dari field yang didefinisikan dalam `group-by` semuanya harus memiliki nilai yang sama (mis: host yang sama, pengguna yang sama, dll...).

### Contoh aturan Temporal Proximity:

Contoh: Perintah pengintaian yang didefinisikan dalam tiga aturan Sigma dipanggil dalam urutan acak dalam 5 menit pada suatu sistem oleh pengguna yang sama.

### Aturan korelasi Temporal Proximity:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Aturan Ordered Temporal Proximity

Tipe korelasi `temporal_ordered` berperilaku seperti `temporal` dan selain itu mengharuskan peristiwa muncul dalam urutan yang diberikan dalam atribut `rules`.

### Contoh aturan Ordered Temporal Proximity:

Contoh: banyak login yang gagal seperti yang didefinisikan di atas diikuti oleh login yang berhasil oleh akun pengguna yang sama dalam 1 jam:

### Aturan korelasi Ordered Temporal Proximity:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## Catatan tentang aturan korelasi

1. Anda harus menyertakan semua aturan korelasi dan aturan yang dirujuk dalam satu file dan memisahkannya dengan pemisah YAML berupa `---`.

2. Secara default, aturan korelasi yang dirujuk tidak akan ditampilkan. Jika Anda ingin melihat output dari aturan yang dirujuk, maka Anda perlu menambahkan `generate: true` di bawah `correlation`. Ini sangat berguna untuk diaktifkan dan diperiksa saat membuat aturan korelasi.

    Contoh:
    ```
    correlation:
        generate: true
    ```
3. Anda dapat menggunakan nama alias alih-alih ID aturan saat merujuk aturan agar lebih mudah dipahami.

4. Anda dapat merujuk beberapa aturan.

5. Anda dapat menggunakan beberapa field dalam `group-by`. Jika Anda melakukannya, maka semua nilai dalam field tersebut harus sama atau Anda tidak akan mendapatkan peringatan. Sebagian besar waktu, Anda akan menulis aturan yang memfilter field tertentu dengan `group-by` untuk mengurangi false positive, namun, dimungkinkan untuk menghilangkan `group-by` untuk membuat aturan yang lebih umum.

6. Timestamp dari aturan korelasi akan menjadi awal dari serangan sehingga Anda harus memeriksa peristiwa setelah itu untuk mengonfirmasi apakah itu false positive atau bukan.
