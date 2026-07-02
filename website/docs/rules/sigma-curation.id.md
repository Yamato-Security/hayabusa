# Mengkurasi Aturan Sigma untuk Log Peristiwa Windows

Halaman ini mendokumentasikan bagaimana Yamato Security mengkurasi aturan [Sigma](https://github.com/SigmaHQ/sigma) upstream untuk log peristiwa Windows menjadi bentuk yang lebih mudah digunakan dengan cara mengurai abstraksi bidang `logsource` dan menyaring aturan yang tidak dapat digunakan atau sulit digunakan. Hal ini dilakukan dengan alat [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter), yang terutama digunakan untuk membuat kumpulan aturan Sigma terkurasi yang di-host di [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules). Kumpulan aturan tersebut digunakan oleh [Hayabusa](https://github.com/Yamato-Security/hayabusa) dan [Velociraptor](https://github.com/Velocidex/velociraptor).

!!! info "Sumber"
    Dokumentasi ini dipelihara bersama dengan alat konverter di [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter). Kami berharap informasi ini juga bermanfaat bagi proyek lain yang ingin menggunakan aturan Sigma untuk mendeteksi serangan dalam log peristiwa Windows. Lihat juga [Membuat Berkas Aturan](creating-rules.md) dan [Pengubah Bidang](field-modifiers.md).

## TL;DR

* Mengurai abstraksi bidang `logsource` dan membuat berkas aturan `.yml` baru untuk aturan bawaan (built-in) serta aturan berbasis Sysmon yang asli membuat dukungan penuh peristiwa bawaan untuk aturan Sigma menjadi lebih mudah, dan membuat aturan lebih mudah dibaca oleh analis.
* Saat menulis aturan Sigma untuk log peristiwa Windows, penting untuk memahami perbedaan antara log berbasis Sysmon yang asli dan log bawaan yang kompatibel, dan idealnya menulis aturan Anda agar kompatibel dengan keduanya.
* Banyak organisasi tidak dapat atau tidak ingin memasang dan memelihara agen Sysmon di semua endpoint Windows mereka karena mereka tidak memiliki sumber daya khusus untuk menanganinya, atau mereka ingin menghindari risiko perlambatan atau crash apa pun yang disebabkan oleh Sysmon. Oleh karena itu, penting untuk mengaktifkan sebanyak mungkin log peristiwa bawaan dan menggunakan alat yang dapat mendeteksi serangan dalam log bawaan tersebut.

## Tantangan dengan aturan Sigma upstream untuk log peristiwa Windows

Tantangan utama dalam membuat parser aturan Sigma native untuk log peristiwa Windows, menurut pengalaman kami, adalah mendukung bidang `logsource`. Saat ini hal ini merupakan salah satu dari sedikit hal yang belum didukung Hayabusa secara native, karena masih sangat kompleks dan sedang dalam pengerjaan. Untuk sementara, kami mengatasinya dengan mengonversi aturan upstream ke dalam format yang lebih mudah digunakan, seperti dijelaskan secara rinci di bawah ini.

### Tentang bidang `logsource`

Dalam aturan Sigma untuk log peristiwa Windows, bidang `product` diatur ke `windows`, diikuti oleh bidang `service` atau bidang `category`.

Contoh bidang `service`:

```yaml
logsource:
    product: windows
    service: application
```

Contoh bidang `category`:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Bidang service

Bidang `service` relatif sederhana untuk ditangani dan memberi tahu backend apa pun yang menggunakan aturan Sigma untuk mencari satu channel atau beberapa channel berdasarkan bidang `Channel` dalam log peristiwa XML Windows.

**Contoh channel tunggal**

`service: application` sama dengan menambahkan kondisi seleksi `Channel: Application` ke aturan Sigma.

**Contoh beberapa channel**

`service: applocker` saat ini menghasilkan channel terbanyak untuk dicari, karena AppLocker menyimpan informasi dalam empat log yang berbeda. Untuk mencari hanya log AppLocker dengan benar, kondisi berikut perlu ditambahkan ke logika aturan Sigma:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Daftar pemetaan service saat ini**

| Service                                    | Channel                                                                                                                             |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**Sumber pemetaan service**

Kami telah membuat berkas pemetaan YAML dari service ke nama channel, yang kami pelihara secara berkala dan host di repositori konverter. Berkas tersebut didasarkan pada informasi pemetaan service dari [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml): meskipun ini tampaknya bukan berkas konfigurasi generik resmi untuk digunakan orang, tampaknya ini yang paling mutakhir.

#### Bidang category

Sebagian besar bidang `category` hanya menambahkan kondisi untuk memeriksa event ID tertentu dalam bidang `EventID`, selain mencari `Channel` tertentu. Nama kategori sebagian besar didasarkan pada peristiwa [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), dengan beberapa kategori tambahan untuk log PowerShell bawaan dan Windows Defender.

**Contoh bidang category**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Daftar pemetaan category saat ini**

Beberapa kategori dipetakan ke lebih dari satu service/EventID (ditampilkan dengan **huruf tebal**).

| Category                  | Service            | EventIDs                                                               |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**Tantangan bidang category**

Seperti ditunjukkan di atas, `category` yang sama dapat menggunakan beberapa service dan event ID (ditandai dengan **huruf tebal**). Itu berarti dimungkinkan untuk menggunakan beberapa aturan Sigma yang dirancang untuk `sysmon` dengan log peristiwa `security` bawaan Windows yang serupa, jika bidang yang digunakan aturan tersebut juga ada dalam log peristiwa bawaan. Dalam hal itu, nama bidang — dan terkadang juga nilainya — mungkin perlu dikonversi agar sesuai dengan nama bidang dan nilai log peristiwa `security` bawaan. Meskipun hal ini bisa jadi semudah mengganti nama beberapa bidang untuk kategori tertentu, untuk kategori lain mungkin memerlukan berbagai konversi nilai bidang juga. Bagaimana kami melakukan konversi ini, dan kompatibilitas antara log `sysmon` dan log `security`, dijelaskan secara rinci [di bawah ini](#sysmon-builtin-comparison).

**Sumber pemetaan category**

Berkas pemetaan YAML untuk kategori juga di-host di repositori konverter dan juga didasarkan pada informasi dari [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

## Manfaat dan tantangan mengabstraksi sumber log

Terdapat manfaat sekaligus tantangan dalam mengabstraksi sumber log dan membuat pemetaan untuk `Channel`, `EventID`, dan bidang yang berbeda di backend.

### Manfaat

1. Mungkin lebih mudah untuk mengonversi nama bidang `Channel` dan `EventID` ke nama bidang backend yang tepat saat mengonversi aturan Sigma ke kueri backend lain.
2. Dimungkinkan untuk menggabungkan dua aturan menjadi satu. Misalnya, peristiwa pembuatan proses dapat dicatat di `Sysmon 1` maupun `Security 4688`. Alih-alih menulis dua aturan yang melihat channel, event ID, dan bidang yang berbeda tetapi selebihnya berisi logika yang sama, dimungkinkan untuk menstandarkan bidang ke apa yang digunakan Sysmon dan kemudian membiarkan konverter backend menambahkan bidang `Channel` dan `EventID` serta mengonversi informasi bidang lain jika diperlukan. Ini membuat pemeliharaan aturan lebih mudah, karena lebih sedikit aturan yang harus dipelihara.
3. Meskipun sangat jarang, jika suatu sumber log mulai mencatat datanya dalam `Channel` atau `EventID` yang berbeda, hanya logika pemetaan yang perlu diperbarui alih-alih memperbarui semua aturan Sigma, sehingga mempermudah pemeliharaan.

### Tantangan

1. Apa yang terjadi jika aturan Sigma asli yang berbasis Sysmon menggunakan bidang yang tidak ada dalam log bawaan untuk menyaring false positive? Apakah Anda harus tetap membuat aturannya, dengan memprioritaskan kemungkinan deteksi, atau mengabaikannya untuk memprioritaskan lebih sedikit false positive? Idealnya, dua aturan perlu dibuat dengan `severity`, `status`, dan informasi false positive yang berbeda agar pengguna dapat menanganinya dengan lebih baik.
2. Hal ini membuat penyaringan aturan lebih sulit, karena Anda tidak dapat sekadar menyaring berdasarkan bidang `Channel` atau `EventID` dalam berkas `.yml` atau jalur berkas aturan jika berkasnya belum dibuat — karena ini merupakan aturan turunan untuk log bawaan alih-alih aturan Sysmon yang asli. Selain itu, karena ID aturannya sama, Anda tidak dapat menyaring berdasarkan ID aturan.
3. Hal ini membuat konfirmasi peringatan (alert) lebih sulit ketika peringatan tersebut berasal dari aturan untuk log bawaan yang diturunkan dari log Sysmon. Nama dan nilai bidang tidak akan cocok, sehingga analis perlu memahami proses konversi yang cukup kompleks.
4. Hal ini membuat pembuatan logika backend menjadi lebih kompleks.

Meskipun kami tidak dapat berbuat apa-apa mengenai masalah pertama selain membuat dan memelihara aturan baru ketika ada kasus penggunaan signifikan yang membenarkan upaya tersebut, untuk mengatasi masalah 2–4 kami telah memutuskan untuk mengurai abstraksi bidang `logsource` dan membuat dua set aturan untuk setiap aturan yang dapat menghasilkan beberapa aturan. Aturan yang dapat mendeteksi serangan dalam log bawaan dikeluarkan ke direktori `builtin`, dan aturan untuk Sysmon dikeluarkan ke direktori `sysmon`.

## Contoh konversi

Berikut adalah contoh sederhana untuk lebih memahami proses konversi.

**Sebelum konversi** — aturan Sigma asli:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Setelah konversi** — aturan yang kompatibel dengan Hayabusa untuk log Sysmon:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

...dan aturan yang kompatibel dengan Hayabusa untuk log bawaan Windows:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

Seperti yang Anda lihat, dua aturan telah dibuat: satu untuk log Sysmon 1 dan satu untuk log Security 4688 bawaan. Sebuah kondisi `process_creation` baru telah ditambahkan dengan informasi channel dan event ID, dan kondisi tersebut telah ditambahkan ke bidang `condition` untuk mewajibkan kondisi ini. Selain itu, nama bidang `Image` yang asli telah diubah menjadi `NewProcessName`.

## Kesamaan dalam konversi

Sebelum menjelaskan secara rinci bagaimana kami mengonversi kategori tertentu, berikut adalah bagian dari konversi yang berlaku untuk semua aturan.

1. Setiap aturan yang memiliki ID dalam `ignore-uuid-list.txt` diabaikan. Saat ini kami hanya mengabaikan aturan yang menyebabkan false positive pada Windows Defender karena memiliki kata kunci seperti `mimikatz` di dalamnya.
2. Aturan "placeholder" diabaikan karena tidak dapat digunakan apa adanya. Ini adalah aturan yang ditempatkan dalam folder [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) di repositori Sigma.
3. Aturan yang menggunakan pengubah bidang (field modifier) yang tidak kompatibel akan dibuang. Hayabusa mendukung sebagian besar pengubah bidang, sehingga konverter tidak akan mengeluarkan aturan apa pun yang menggunakan pengubah selain berikut ini, guna menghindari galat penguraian (lihat [Pengubah Bidang](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Aturan dengan galat sintaksis tidak dikonversi.
5. Tag dalam aturan `deprecated` dan `unsupported` diperbarui dari format V1 ke format V2, yang menggunakan `-` alih-alih `_`, guna menjaga semuanya tetap konsisten dan menangani singkatan di Hayabusa dengan lebih mudah. Contoh: `initial_access` menjadi `initial-access`.
6. Karena kami menambahkan informasi `Channel` dan `EventID` ke aturan, kami membuat ID UUIDv4 baru dengan menggunakan hash MD5 dari ID asli, menentukan ID asli dalam bidang `related`, dan menandai `type` sebagai `derived`. Untuk aturan yang dapat dikonversi menjadi beberapa aturan (`sysmon` dan `builtin`), kami juga perlu membuat ID aturan baru untuk aturan `builtin` turunan. Untuk melakukan ini, kami menghitung hash MD5 dari ID aturan `sysmon` dan menggunakannya untuk ID UUIDv4. Contohnya:

    Aturan Sigma asli:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Aturan `sysmon` baru:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Aturan `builtin` baru:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Aturan yang mendeteksi hal-hal dalam log peristiwa Windows bawaan dikeluarkan ke direktori `builtin`, sementara aturan yang bergantung pada log Sysmon dikeluarkan ke direktori `sysmon`, dengan sub-direktori yang sesuai dengan direktori di repositori Sigma upstream.

## Keterbatasan konversi

Saat ini hanya ada satu [bug yang diketahui](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2): baris komentar dalam aturan Sigma tidak akan disertakan dalam aturan keluaran kecuali komentar tersebut mengikuti suatu kode sumber.

## Perbandingan peristiwa Sysmon dan bawaan serta konversi aturan { #sysmon-builtin-comparison }

### Pembuatan proses

* Kategori: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Log bawaan
    * Channel: `Security`
    * Event ID: `4688`

**Perbandingan**

![Perbandingan pembuatan proses](../assets/rules-doc/process_creation_comparison.png)

**Catatan konversi**

1. Informasi bidang `User` perlu dipisahkan menjadi bidang `SubjectUserName` dan `SubjectDomainName`.
2. Nama bidang `LogonId` berubah menjadi `SubjectLogonId`, dan huruf apa pun dalam nilai heksadesimal perlu menjadi huruf kecil.
3. Nama bidang `ProcessId` berubah menjadi `NewProcessId`, dan nilainya perlu dikonversi ke heksadesimal.
4. Nama bidang `Image` berubah menjadi `NewProcessName`.
5. Nama bidang `ParentProcessId` berubah menjadi `ProcessId`, dan nilainya perlu dikonversi ke heksadesimal.
6. Nama bidang `ParentImage` berubah menjadi `ParentProcessName`.
7. Nama bidang `IntegrityLevel` berubah menjadi `MandatoryLabel`, dan konversi nilai berikut diperlukan:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. Jika aturan berisi bidang berikut yang hanya ada dalam peristiwa `Security 4688`, maka kami tidak membuat aturan `Sysmon 1`:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Jika aturan berisi bidang berikut yang hanya ada dalam peristiwa `Sysmon 1`, maka kami tidak membuat aturan `Security 4688`:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. Ada pengecualian untuk #8 dan #9: bahkan jika suatu bidang yang hanya ada dalam satu peristiwa log digunakan, jika bidang tersebut berada dalam kondisi `OR` maka Anda tetap harus membuat aturan tersebut. Misalnya, aturan berikut **tidak seharusnya** menghasilkan aturan `Security 4688` karena bidang `OriginalFileName` bersifat wajib (logika `AND` di dalam seleksi):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    Namun, aturan dengan kondisi berikut **seharusnya** membuat aturan `Security 4688` karena `OriginalFileName` bersifat opsional (logika `OR` di dalam seleksi):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    Hal-hal menjadi rumit karena parser Anda harus memahami tidak hanya logika di dalam seleksi tetapi juga di dalam bidang `condition`. Misalnya, aturan berikut **tidak seharusnya** membuat aturan `Security 4688` karena menggunakan logika `AND`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    Namun, aturan berikut **seharusnya** membuat aturan `Security 4688` karena menggunakan logika `OR`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Catatan lain**

* Bidang `SubjectUserSid` dalam `Security 4688` menampilkan SID; namun, dalam `Message` log peristiwa yang telah dirender, ia dikonversi menjadi `DOMAIN\User`.
* Peristiwa `Security 4688` mungkin tidak menyertakan informasi opsi baris perintah dalam `CommandLine` tergantung pada pengaturannya.
* `TokenElevationType` ditampilkan apa adanya dalam `Message` dan tidak dirender.
* `S-1-16-4096`, dll. di dalam `MandatoryLabel` dikonversi menjadi `Mandatory Label\Low Mandatory Level`, dll. dalam `Message` yang telah dirender.

**Pengaturan log bawaan**

!!! warning "Tidak diaktifkan secara default"
    Log peristiwa pembuatan proses `Security 4688` bawaan yang penting tidak diaktifkan secara default. Anda perlu mengaktifkan baik peristiwa `4688` maupun pencatatan opsi baris perintah untuk dapat menggunakan sebagian besar aturan Sigma.

*Mengaktifkan dengan group policy:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*Mengaktifkan pada baris perintah:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Koneksi jaringan

* Kategori: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Log bawaan
    * Channel: `Security`
    * Event ID: `5156`

**Perbandingan**

![Perbandingan koneksi jaringan](../assets/rules-doc/network_connection_comparison.png)

**Catatan konversi**

1. Nama bidang `ProcessId` berubah menjadi `ProcessID`.
2. Nama bidang `Image` berubah menjadi `Application`, dan `C:\` berubah menjadi `\device\harddiskvolume?\`. (Catatan: karena kami tidak mengetahui nomor volume hard disk, kami menggantinya dengan wildcard satu karakter `?`.)
3. Nilai bidang `Protocol` `tcp` berubah menjadi `6` dan `udp` berubah menjadi `17`.
4. Nama bidang `Initiated` berubah menjadi `Direction`, dan nilai `true` berubah menjadi `%%14593` dan `false` berubah menjadi `%%14592`.
5. Nama bidang `SourceIp` berubah menjadi `SourceAddress`.
6. Nama bidang `DestinationIp` berubah menjadi `DestAddress`.
7. Nama bidang `DestinationPort` berubah menjadi `DestPort`.

**Pengaturan log bawaan**

!!! warning "Tidak diaktifkan secara default"
    Log koneksi jaringan `Security 5156` bawaan tidak diaktifkan secara default. Log ini menghasilkan sejumlah besar log, yang dapat menimpa log penting lainnya dalam log peristiwa `Security` dan berpotensi memperlambat sistem jika memiliki jumlah koneksi jaringan yang tinggi. Pastikan ukuran berkas maksimum untuk log `Security` tinggi, dan lakukan pengujian untuk memastikan tidak ada efek buruk pada sistem.

*Mengaktifkan dengan group policy:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*Mengaktifkan pada baris perintah:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...atau yang berikut ini jika Anda menggunakan lokal (locale) non-Inggris:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Lihat juga"
    Untuk informasi lebih lanjut tentang mengaktifkan log peristiwa Windows bawaan yang diperlukan untuk menangkap bukti yang menjadi sandaran aturan-aturan ini, lihat [Pencatatan Windows & Sysmon](../resources/logging.md) dan proyek [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

## Saran penulisan aturan Sigma

!!! tip
    Jika Anda menggunakan bidang apa pun yang ada dalam log `sysmon` tetapi tidak dalam log `builtin`, pastikan Anda menjadikan bidang tersebut opsional sehingga aturan tersebut tetap dapat digunakan untuk log `builtin`.

Misalnya:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Seleksi ini mencari saat proses (`Image`) bernama `addinutil.exe`. Masalahnya adalah penyerang bisa saja mengganti nama berkas untuk melewati aturan tersebut. Bidang `OriginalFileName`, yang hanya ada dalam log Sysmon, adalah nama berkas yang tertanam ke dalam biner pada saat kompilasi. Meskipun penyerang mengganti nama berkas, nama yang tertanam tidak akan berubah, sehingga aturan ini dapat mendeteksi serangan yang penyerangnya telah mengganti nama berkas saat menggunakan Sysmon, dan juga dapat mendeteksi serangan yang nama berkasnya tidak diubah saat menggunakan log bawaan standar.

## Aturan Sigma yang telah dikonversi sebelumnya

Aturan Sigma yang dikurasi dengan cara yang dijelaskan di halaman ini — dengan mengurai abstraksi bidang `logsource` — di-host di repositori [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) di dalam folder `sigma`.

## Lingkungan alat

Jika Anda ingin mengonversi aturan Sigma ke format yang kompatibel dengan Hayabusa secara lokal, Anda perlu menginstal [Poetry](https://python-poetry.org/) terlebih dahulu. Silakan merujuk ke [dokumentasi instalasi](https://python-poetry.org/docs/#installation) Poetry resmi.

## Penggunaan alat

`sigma-to-hayabusa-converter.py` adalah alat utama kami untuk mengonversi bidang `logsource` dari aturan Sigma ke format yang kompatibel dengan Hayabusa. Lakukan tugas-tugas berikut untuk menjalankannya:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Setelah menjalankan perintah di atas, aturan yang telah dikonversi ke format yang kompatibel dengan Hayabusa akan dikeluarkan ke direktori `./converted_sigma_rules`.
