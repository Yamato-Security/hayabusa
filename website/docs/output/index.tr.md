# Zaman Çizelgesi Çıktısı

## Çıktı Profilleri

Hayabusa'nın `config/profiles.yaml` dosyasında kullanılabilecek 5 önceden tanımlanmış çıktı profili vardır:

1. `minimal`
2. `standard` (varsayılan)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Bu dosyayı düzenleyerek kendi profillerinizi kolayca özelleştirebilir veya ekleyebilirsiniz.
Ayrıca `set-default-profile --profile <profile>` ile varsayılan profili kolayca değiştirebilirsiniz.
Kullanılabilir profilleri ve alan bilgilerini göstermek için `list-profiles` komutunu kullanın.

### 1. `minimal` profil çıktısı

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard` profil çıktısı

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose` profil çıktısı

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info` profil çıktısı

Minimal `details` bilgisini çıktılamak yerine, `EventData` ve `UserData` bölümlerindeki tüm alan bilgileri orijinal alan adlarıyla birlikte çıktılanır.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose` profil çıktısı

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose` profil çıktısı

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal` profil çıktısı

[Timesketch](https://timesketch.org/) içine içe aktarmayla uyumlu bir biçime çıktı verir.

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose` profil çıktısı

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Profil Karşılaştırması

Aşağıdaki kıyaslamalar, 3GB evtx verisi ve 3891 etkin kuralla bir 2018 Lenovo P51 (Xeon 4 Çekirdekli CPU / 64GB RAM) üzerinde gerçekleştirilmiştir. (2023/06/01)

| Profil | İşleme Süresi | Çıktı Dosya Boyutu | Dosya Boyutu Artışı |
| :---: | :---: | :---: | :---: |
| minimal | 8 dakika 50 saniye | 770 MB | -30% |
| standard (varsayılan) | 9 dakika 00 saniye | 1.1 GB | Yok |
| verbose | 9 dakika 10 saniye | 1.3 GB | +20% |
| all-field-info | 9 dakika 3 saniye | 1.2 GB | +10% |
| all-field-info-verbose | 9 dakika 10 saniye | 1.3 GB | +20% |
| super-verbose | 9 dakika 12 saniye | 1.5 GB | +35% |

### Profil Alan Takma Adları

Aşağıdaki bilgiler yerleşik çıktı profilleriyle çıktılanabilir:

| Takma ad | Hayabusa çıktı bilgisi|
| :--- | :--- |
|%AllFieldInfo% | Tüm alan bilgileri. |
|%Channel% | Günlüğün adı. `<Event><System><Channel>` alanı. |
|%Computer% | `<Event><System><Computer>` alanı. |
|%Details% | YML algılama kuralındaki `details` alanı, ancak yalnızca hayabusa kurallarında bu alan bulunur. Bu alan, uyarı veya olay hakkında ek bilgi sağlar ve olay günlüklerindeki alanlardan yararlı veriler çıkarabilir. Örneğin, kullanıcı adları, komut satırı bilgileri, işlem bilgileri, vb... Bir yer tutucu var olmayan bir alana işaret ettiğinde veya yanlış bir takma ad eşlemesi olduğunda, `n/a` (kullanılamaz) olarak çıktılanır. `details` alanı belirtilmemişse (yani sigma kuralları), `./rules/config/default_details.txt` içinde tanımlanan alanları çıkarmak için varsayılan `details` iletileri çıktılanır. `default_details.txt` içine çıktılamak istediğiniz `Provider Name`, `EventID` ve `details` iletisini ekleyerek daha fazla varsayılan `details` iletisi ekleyebilirsiniz. Bir kuralda veya `default_details.txt` içinde hiçbir `details` alanı tanımlanmadığında, tüm alanlar `details` sütununa çıktılanır. |
|%ExtraFieldInfo% | %Details% içinde çıktılanmayan alan bilgilerini yazdırır. |
|%EventID% | `<Event><System><EventID>` alanı. |
|%EvtxFile% | Uyarıya veya olaya neden olan evtx dosya adı. |
|%Level% | YML algılama kuralındaki `level` alanı. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [taktikleri](https://attack.mitre.org/tactics/enterprise/) (Örn: Initial Access, Lateral Movement, vb...). |
|%MitreTags% | MITRE ATT&CK Grup ID'si, Teknik ID'si ve Yazılım ID'si. |
|%OtherTags% | Bir YML algılama kuralındaki `tags` alanında bulunan, `MitreTactics` veya `MitreTags` içinde yer almayan herhangi bir anahtar kelime. |
|%Provider% | `<Event><System><Provider>` alanındaki `Name` özniteliği. |
|%RecordID% | `<Event><System><EventRecordID>` alanından gelen Olay Kayıt ID'si. |
|%RuleAuthor% | YML algılama kuralındaki `author` alanı. |
|%RuleCreationDate% | YML algılama kuralındaki `date` alanı. |
|%RuleFile% | Uyarıyı veya olayı oluşturan algılama kuralının dosya adı. |
|%RuleID% | YML algılama kuralındaki `id` alanı. |
|%RuleModifiedDate% | YML algılama kuralındaki `modified` alanı. |
|%RuleTitle% | YML algılama kuralındaki `title` alanı. |
|%Status% | YML algılama kuralındaki `status` alanı. |
|%Timestamp% | Varsayılan `YYYY-MM-DD HH:mm:ss.sss +hh:mm` biçimidir. Olay günlüğündeki `<Event><System><TimeCreated SystemTime>` alanı. Varsayılan saat dilimi yerel saat dilimi olacaktır ancak `--UTC` seçeneğiyle saat dilimini UTC olarak değiştirebilirsiniz. |

#### Ek Profil Alan Takma Adı

İhtiyaç duyarsanız çıktı profilinize bu ek takma adları da ekleyebilirsiniz:

| Takma ad | Hayabusa çıktı bilgisi|
| :--- | :--- |
|%RenderedMessage% | WEC iletilen günlüklerindeki `<Event><RenderingInfo><Message>` alanı. |

Not: bu, yerleşik profillerin hiçbirinde dahil **değildir**, bu nedenle `config/default_profile.yaml` dosyasını manuel olarak düzenleyip aşağıdaki satırı eklemeniz gerekir:

```
Message: "%RenderedMessage%"
```

Diğer alanları çıktılamak için [olay anahtarı takma adları](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) da tanımlayabilirsiniz.
