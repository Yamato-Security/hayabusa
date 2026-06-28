# Output Timeline

## Profil Output

Hayabusa memiliki 5 profil output yang telah ditentukan sebelumnya untuk digunakan dalam `config/profiles.yaml`:

1. `minimal`
2. `standard` (default)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Anda dapat dengan mudah menyesuaikan atau menambahkan profil Anda sendiri dengan mengedit file ini.
Anda juga dapat dengan mudah mengubah profil default dengan `set-default-profile --profile <profile>`.
Gunakan perintah `list-profiles` untuk menampilkan profil yang tersedia beserta informasi field-nya.

### 1. Output profil `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. Output profil `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. Output profil `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. Output profil `all-field-info`

Alih-alih menampilkan informasi `details` yang minimal, semua informasi field dalam bagian `EventData` dan `UserData` akan ditampilkan beserta nama field aslinya.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. Output profil `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. Output profil `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. Output profil `timesketch-minimal`

Output ke format yang kompatibel untuk diimpor ke dalam [Timesketch](https://timesketch.org/).

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. Output profil `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Perbandingan Profil

Benchmark berikut dilakukan pada Lenovo P51 tahun 2018 (Xeon 4 Core CPU / 64GB RAM) dengan 3GB data evtx dan 3891 rule yang diaktifkan. (2023/06/01)

| Profil | Waktu Pemrosesan | Ukuran File Output | Peningkatan Ukuran File |
| :---: | :---: | :---: | :---: |
| minimal | 8 menit 50 detik | 770 MB | -30% |
| standard (default) | 9 menit 00 detik | 1.1 GB | Tidak ada |
| verbose | 9 menit 10 detik | 1.3 GB | +20% |
| all-field-info | 9 menit 3 detik | 1.2 GB | +10% |
| all-field-info-verbose | 9 menit 10 detik | 1.3 GB | +20% |
| super-verbose | 9 menit 12 detik | 1.5 GB | +35% |

### Alias Field Profil

Informasi berikut dapat ditampilkan dengan profil output bawaan:

| Nama alias | Informasi output Hayabusa |
| :--- | :--- |
|%AllFieldInfo% | Semua informasi field. |
|%Channel% | Nama log. Field `<Event><System><Channel>`. |
|%Computer% | Field `<Event><System><Computer>`. |
|%Details% | Field `details` dalam rule deteksi YML, namun, hanya rule hayabusa yang memiliki field ini. Field ini memberikan informasi tambahan tentang alert atau event dan dapat mengekstrak data berguna dari field dalam event log. Misalnya, nama pengguna, informasi command line, informasi proses, dll... Ketika sebuah placeholder menunjuk ke field yang tidak ada atau terdapat pemetaan alias yang salah, maka akan ditampilkan sebagai `n/a` (not available). Jika field `details` tidak ditentukan (yaitu rule sigma), pesan `details` default untuk mengekstrak field yang didefinisikan dalam `./rules/config/default_details.txt` akan ditampilkan. Anda dapat menambahkan lebih banyak pesan `details` default dengan menambahkan `Provider Name`, `EventID`, dan pesan `details` yang ingin Anda tampilkan dalam `default_details.txt`. Ketika tidak ada field `details` yang didefinisikan dalam sebuah rule maupun dalam `default_details.txt`, semua field akan ditampilkan ke kolom `details`. |
|%ExtraFieldInfo% | Menampilkan informasi field yang tidak ditampilkan dalam %Details%. |
|%EventID% | Field `<Event><System><EventID>`. |
|%EvtxFile% | Nama file evtx yang menyebabkan alert atau event. |
|%Level% | Field `level` dalam rule deteksi YML. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [tactics](https://attack.mitre.org/tactics/enterprise/) (Contoh: Initial Access, Lateral Movement, dll...). |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID, dan Software ID. |
|%OtherTags% | Kata kunci apa pun dalam field `tags` di rule deteksi YML yang tidak termasuk dalam `MitreTactics` atau `MitreTags`. |
|%Provider% | Atribut `Name` dalam field `<Event><System><Provider>`. |
|%RecordID% | Event Record ID dari field `<Event><System><EventRecordID>`. |
|%RuleAuthor% | Field `author` dalam rule deteksi YML. |
|%RuleCreationDate% | Field `date` dalam rule deteksi YML. |
|%RuleFile% | Nama file rule deteksi yang menghasilkan alert atau event. |
|%RuleID% | Field `id` dalam rule deteksi YML. |
|%RuleModifiedDate% | Field `modified` dalam rule deteksi YML. |
|%RuleTitle% | Field `title` dalam rule deteksi YML. |
|%Status% | Field `status` dalam rule deteksi YML. |
|%Timestamp% | Default adalah format `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. Field `<Event><System><TimeCreated SystemTime>` dalam event log. Zona waktu default adalah zona waktu lokal tetapi Anda dapat mengubah zona waktu menjadi UTC dengan opsi `--UTC`. |

#### Alias Field Profil Tambahan

Anda juga dapat menambahkan alias tambahan ini ke profil output Anda jika Anda membutuhkannya:

| Nama alias | Informasi output Hayabusa |
| :--- | :--- |
|%RenderedMessage% | Field `<Event><RenderingInfo><Message>` dalam log yang diteruskan WEC. |

Catatan: ini **tidak** termasuk dalam profil bawaan mana pun sehingga Anda perlu mengedit secara manual file `config/default_profile.yaml` dan menambahkan baris berikut:

```
Message: "%RenderedMessage%"
```

Anda juga dapat mendefinisikan [event key aliases](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) untuk menampilkan field lainnya.
