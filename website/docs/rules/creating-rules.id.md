# Membuat Berkas Aturan

## Tentang Hayabusa-Rules

Ini adalah repositori yang berisi aturan sigma terkurasi yang mendeteksi serangan dalam log event Windows.
Repositori ini terutama digunakan untuk aturan deteksi dan berkas konfigurasi [Hayabusa](https://github.com/Yamato-Security/hayabusa), serta deteksi sigma bawaan [Velociraptor](https://github.com/Velocidex/velociraptor).
Keuntungan menggunakan repositori ini dibandingkan [repositori sigma upstream](https://github.com/SigmaHQ/sigma) adalah kami hanya menyertakan aturan yang seharusnya dapat diurai oleh sebagian besar alat native sigma.
Kami juga melakukan de-abstraksi pada field `logsource` dengan menambahkan field `Channel`, `EventID`, dll... yang diperlukan ke dalam aturan agar lebih mudah memahami apa yang difilter oleh aturan dan yang lebih penting untuk mengurangi false positive.
Kami juga membuat aturan baru dengan nama dan nilai field yang telah dikonversi untuk aturan `process_creation` dan aturan berbasis `registry` sehingga aturan sigma tidak hanya akan mendeteksi pada log Sysmon, tetapi juga akan mendeteksi pada log bawaan Windows.

## Tentang membuat berkas aturan

Aturan deteksi Hayabusa ditulis dalam format [YAML](https://en.wikipedia.org/wiki/YAML) dengan ekstensi berkas `.yml`. (Berkas `.yaml` akan diabaikan.)
Aturan ini merupakan subset dari aturan sigma tetapi juga mengandung beberapa fitur tambahan.
Kami berusaha membuatnya semirip mungkin dengan aturan sigma agar mudah mengonversi aturan Hayabusa kembali ke sigma untuk dikembalikan ke komunitas.
Aturan Hayabusa dapat mengekspresikan aturan deteksi yang kompleks dengan menggabungkan tidak hanya pencocokan string sederhana tetapi juga ekspresi reguler, kondisi `AND`, `OR`, dan lainnya.
Pada bagian ini, kami akan menjelaskan cara menulis aturan deteksi Hayabusa.

### Format berkas aturan

Contoh:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## Author section

- **author [required]**: Nama penulis.
- **date [required]**: Tanggal aturan dibuat.
- **modified** [optional]: Tanggal aturan diperbarui.

> ## Alert section

- **title [required]**: Judul berkas aturan. Ini juga akan menjadi nama alert yang ditampilkan sehingga semakin ringkas semakin baik. (Sebaiknya tidak lebih dari 85 karakter.)
- **details** [optional]: Detail alert yang ditampilkan. Harap keluarkan field apa pun dalam log event Windows yang berguna untuk analisis. Field dipisahkan oleh `" ¦ "`. Placeholder field diapit dengan `%` (Contoh: `%MemberName%`) dan perlu didefinisikan di `rules/config/eventkey_alias.txt`. (Dijelaskan di bawah.)
- **description** [optional]: Deskripsi aturan. Ini tidak ditampilkan sehingga Anda dapat membuatnya panjang dan terperinci.

> ## Rule section

- **id [required]**: UUID versi 4 yang dihasilkan secara acak yang digunakan untuk mengidentifikasi aturan secara unik. Anda dapat menghasilkannya [di sini](https://www.uuidgenerator.net/version4).
- **level [required]**: Tingkat keparahan berdasarkan [definisi sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Harap tulis salah satu dari berikut: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: Status berdasarkan [definisi sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Harap tulis salah satu dari berikut: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [required]**: Meskipun ini sebenarnya saat ini tidak digunakan oleh Hayabusa, kami mendefinisikan logsource dengan cara yang sama seperti sigma agar kompatibel dengan aturan sigma.
- **detection  [required]**: Logika deteksi diletakkan di sini. (Dijelaskan di bawah.)
- **falsepositives [required]**: Kemungkinan terjadinya false positive. Misalnya: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Jika tidak diketahui, harap tulis `unknown`.
- **tags** [optional]: Jika teknik tersebut merupakan teknik [LOLBINS/LOLBAS](https://lolbas-project.github.io/), harap tambahkan tag `lolbas`. Jika alert dapat dipetakan ke suatu teknik dalam kerangka [MITRE ATT&CK](https://attack.mitre.org/), harap tambahkan ID taktik (Contoh: `attack.t1098`) dan taktik yang berlaku di bawah ini:
  - `attack.reconnaissance` -> Reconnaissance (Recon)
  - `attack.resource-development` -> Resource Development  (ResDev)
  - `attack.initial-access` -> Initial Access (InitAccess)
  - `attack.execution` -> Execution (Exec)
  - `attack.persistence` -> Persistence (Persis)
  - `attack.privilege-escalation` -> Privilege Escalation (PrivEsc)
  - `attack.stealth` -> Stealth (Stealth)
  - `attack.defense-impairment` -> Defense Impairment (DefImpair)
  - `attack.credential-access` -> Credential Access (CredAccess)
  - `attack.discovery` -> Discovery (Disc)
  - `attack.lateral-movement` -> Lateral Movement (LatMov)
  - `attack.collection` -> Collection (Collect)
  - `attack.command-and-control` -> Command and Control (C2)
  - `attack.exfiltration` -> Exfiltration (Exfil)
  - `attack.impact` -> Impact (Impact)
- **references** [optional]: Tautan apa pun ke referensi.
- **ruletype [required]**: `Hayabusa` untuk aturan hayabusa. Aturan yang dikonversi secara otomatis dari aturan Windows sigma akan menjadi `Sigma`.

> ## Sample XML Event

- **sample-message [required]**: Mulai sekarang, kami meminta penulis aturan untuk menyertakan contoh pesan untuk aturan mereka. Ini adalah pesan terender yang ditampilkan oleh Event Viewer Windows.
- **sample-evtx [required]**: Mulai sekarang, kami meminta penulis aturan untuk menyertakan contoh event XML untuk aturan mereka.
