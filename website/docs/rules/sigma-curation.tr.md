# Windows Olay Günlükleri için Sigma Kurallarının Düzenlenmesi

Bu sayfa, Yamato Security'nin Windows olay günlükleri için üst kaynaktaki [Sigma](https://github.com/SigmaHQ/sigma) kurallarını, `logsource` alanını soyutlamadan arındırarak ve kullanılamayan veya kullanımı zor kuralları filtreleyerek nasıl daha kullanışlı bir biçime dönüştürdüğünü belgelemektedir. Bu işlem, ağırlıklı olarak [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) içinde barındırılan düzenlenmiş Sigma kural setini oluşturmak için kullanılan [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) aracıyla yapılır. Bu kural seti [Hayabusa](https://github.com/Yamato-Security/hayabusa) ve [Velociraptor](https://github.com/Velocidex/velociraptor) tarafından kullanılmaktadır.

!!! info "Kaynak"
    Bu belge, dönüştürücü aracıyla birlikte [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) adresinde tutulmaktadır. Bu bilgilerin, Windows olay günlüklerinde saldırıları tespit etmek için Sigma kurallarını kullanmak isteyen diğer projeler için de faydalı olmasını umuyoruz. Ayrıca bkz. [Kural Dosyaları Oluşturma](creating-rules.md) ve [Alan Değiştiricileri](field-modifiers.md).

## Özet

* `logsource` alanını soyutlamadan arındırmak ve hem yerleşik kurallar hem de orijinal Sysmon tabanlı kurallar için yeni `.yml` kural dosyaları oluşturmak, Sigma kuralları için tam yerleşik olay desteğini kolaylaştırır ve kuralları analistlerin okuması için daha anlaşılır hale getirir.
* Windows olay günlükleri için Sigma kuralları yazarken, orijinal Sysmon tabanlı günlükler ile bunlarla uyumlu yerleşik günlükler arasındaki farkları anlamak ve ideal olarak kurallarınızı her ikisiyle de uyumlu olacak şekilde yazmak önemlidir.
* Birçok kuruluş, bunu ele alacak özel kaynaklara sahip olmadığı veya Sysmon kaynaklı olası yavaşlamalar ya da çökmeler riskinden kaçınmak istediği için, tüm Windows uç noktalarına Sysmon aracılarını kuramaz veya kurmak istemez. Bu nedenle, mümkün olduğunca çok sayıda yerleşik olay günlüğünü etkinleştirmek ve bu yerleşik günlüklerdeki saldırıları tespit edebilen araçlar kullanmak önemlidir.

## Windows olay günlükleri için üst kaynaktaki Sigma kurallarıyla ilgili zorluklar

Deneyimlerimize göre, Windows olay günlükleri için yerel (native) bir Sigma kural ayrıştırıcısı oluşturmadaki temel zorluk, `logsource` alanını desteklemek olmuştur. Şu anda bu, hâlâ çok karmaşık olduğu ve üzerinde çalışıldığı için Hayabusa'nın henüz yerel olarak desteklemediği birkaç şeyden biridir. Şimdilik, aşağıda ayrıntılı olarak açıklandığı gibi, üst kaynaktaki kuralları daha kullanışlı bir biçime dönüştürerek bu duruma geçici bir çözüm buluyoruz.

### `logsource` alanı hakkında

Windows olay günlükleri için Sigma kurallarında, `product` alanı `windows` olarak ayarlanır ve bunu bir `service` alanı ya da bir `category` alanı izler.

`service` alanı örneği:

```yaml
logsource:
    product: windows
    service: application
```

`category` alanı örneği:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Service alanları

`service` alanlarının ele alınması nispeten basittir ve Sigma kuralını kullanan arka uca (backend), Windows XML olay günlüğündeki `Channel` alanına dayanarak tek bir kanalda veya birden fazla kanalda arama yapmasını söyler.

**Tek kanal örneği**

`service: application`, Sigma kuralına `Channel: Application` şeklinde bir seçim koşulu eklemekle aynı şeydir.

**Birden fazla kanal örneği**

AppLocker bilgilerini dört farklı günlükte sakladığından, şu anda içinde arama yapılacak en fazla kanalı `service: applocker` oluşturur. Yalnızca AppLocker günlüklerinde düzgün bir şekilde arama yapabilmek için, Sigma kural mantığına aşağıdaki koşulun eklenmesi gerekir:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Mevcut service eşleme listesi**

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

**Service eşleme kaynakları**

Service adlarını kanal adlarına eşleyen YAML eşleme dosyaları oluşturduk; bunları periyodik olarak güncelliyor ve dönüştürücü deposunda barındırıyoruz. Bunlar, [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) dosyasındaki service eşleme bilgilerine dayanmaktadır: bu dosya, insanların kullanması için resmi bir genel yapılandırma dosyası gibi görünmese de, en güncel olanı gibi görünmektedir.

#### Category alanları

Çoğu `category` alanı, belirli bir `Channel` araması yapmanın yanı sıra, `EventID` alanında belirli olay kimliklerini kontrol etmek için basitçe bir koşul ekler. Kategori adları çoğunlukla [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) olaylarına dayanır ve yerleşik PowerShell günlükleri ile Windows Defender için bazı ek kategoriler içerir.

**Category alanı örneği**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Mevcut category eşleme listesi**

Bazı kategoriler birden fazla service/EventID ile eşleşir (**kalın** olarak gösterilmiştir).

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

**Category alanıyla ilgili zorluklar**

Yukarıda gösterildiği gibi, aynı `category` birden fazla service ve olay kimliği kullanabilir (**kalın** olarak belirtilmiştir). Bu, kuralın kullandığı alanlar yerleşik olay günlüğünde de mevcutsa, `sysmon` için tasarlanmış bazı Sigma kurallarını benzer yerleşik Windows `security` olay günlükleriyle kullanmanın mümkün olduğu anlamına gelir. Bu durumda, alan adlarının ve bazen de değerlerinin, yerleşik `security` olay günlüğünün alan adları ve değerleriyle eşleşecek şekilde dönüştürülmesi gerekebilir. Bu, bazı kategoriler için yalnızca bazı alan adlarının yeniden adlandırılması kadar basit olabilirken, diğer kategoriler için alan değerlerinde de çeşitli dönüştürmeler gerektirebilir. Bu dönüştürmeyi nasıl yaptığımız ve `sysmon` günlükleri ile `security` günlükleri arasındaki uyumluluk, [aşağıda](#sysmon-builtin-comparison) ayrıntılı olarak açıklanmıştır.

**Category eşleme kaynakları**

Kategorilere yönelik YAML eşleme dosyaları da dönüştürücü deposunda barındırılır ve yine [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) dosyasındaki bilgilere dayanır.

## Günlük kaynağını soyutlamanın faydaları ve zorlukları

Günlük kaynağını soyutlamanın ve arka uçta farklı `Channel`, `EventID` ve alanlar için eşlemeler oluşturmanın hem faydaları hem de zorlukları vardır.

### Faydalar

1. Sigma kuralları diğer arka uç sorgularına dönüştürülürken, `Channel` ve `EventID` alan adlarını uygun arka uç alan adlarına dönüştürmek daha kolay olabilir.
2. İki kuralı tek bir kurala birleştirmek mümkündür. Örneğin, süreç oluşturma olayları hem `Sysmon 1` hem de `Security 4688` içinde günlüğe kaydedilebilir. Farklı kanallara, olay kimliklerine ve alanlara bakan ancak bunun dışında aynı mantığı içeren iki kural yazmak yerine, alanları Sysmon'un kullandığı biçime standartlaştırıp ardından bir arka uç dönüştürücüsünün `Channel` ve `EventID` alanlarını eklemesini ve gerekirse diğer alan bilgilerini dönüştürmesini sağlamak mümkündür. Bu, sürdürülecek daha az kural olduğundan kuralların bakımını kolaylaştırır.
3. Çok nadir olsa da, bir günlük kaynağı verilerini farklı bir `Channel` veya `EventID` içinde günlüğe kaydetmeye başlarsa, tüm Sigma kurallarını güncellemek yerine yalnızca eşleme mantığının güncellenmesi gerekir ve bu da bakımı kolaylaştırır.

### Zorluklar

1. Sysmon tabanlı orijinal Sigma kuralı, yanlış pozitifleri filtrelemek için yerleşik günlüklerde bulunmayan bir alan kullanıyorsa ne olur? Olası tespiti önceliklendirerek kuralı yine de oluşturmalı mısınız, yoksa daha az yanlış pozitifi önceliklendirmek için görmezden mi gelmelisiniz? İdeal olarak, kullanıcının durumu daha iyi ele alabilmesi için farklı `severity`, `status` ve yanlış pozitif bilgileriyle iki kuralın oluşturulması gerekir.
2. Bu, kuralları filtrelemeyi daha zor hale getirir; çünkü dosya henüz oluşturulmamışsa `.yml` dosyasındaki ya da kuralın dosya yolundaki `Channel` veya `EventID` alanlarına dayanarak filtreleme yapamazsınız — çünkü bu, orijinal Sysmon kuralı yerine yerleşik bir günlük için türetilmiş bir kuraldır. Ayrıca, kural kimliği aynı olduğundan kural kimliklerine göre de filtreleme yapamazsınız.
3. Bir uyarı, bir Sysmon günlüğünden türetilmiş yerleşik günlüklere yönelik bir kuraldan geldiğinde, uyarıyı doğrulamak daha zor hale gelir. Alan adları ve değerleri örtüşmeyeceğinden, analistin biraz karmaşık olan dönüştürme sürecini anlaması gerekir.
4. Arka uç mantığını oluşturmayı daha karmaşık hale getirir.

Çabayı haklı çıkaracak önemli bir kullanım durumu olduğunda yeni kurallar oluşturup sürdürmek dışında ilk sorunla ilgili bir şey yapamasak da, 2-4 arasındaki sorunları ele almak için `logsource` alanını soyutlamadan arındırmaya ve birden fazla kural üretebilen herhangi bir kural için iki set kural oluşturmaya karar verdik. Yerleşik günlüklerde saldırıları tespit edebilen kurallar `builtin` dizinine, Sysmon'a dayanan kurallar ise `sysmon` dizinine çıktı olarak verilir.

## Dönüştürme örneği

Dönüştürme sürecini daha iyi anlamak için basit bir örnek verelim.

**Dönüştürmeden önce** — orijinal Sigma kuralı:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Dönüştürmeden sonra** — Sysmon günlükleri için Hayabusa uyumlu bir kural:

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

...ve Windows yerleşik günlükleri için Hayabusa uyumlu bir kural:

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

Görebileceğiniz gibi, iki kural oluşturuldu: biri Sysmon 1 günlükleri için, diğeri yerleşik Security 4688 günlükleri için. Kanal ve olay kimliği bilgilerini içeren yeni bir `process_creation` koşulu eklendi ve bu koşulun gerekli kılınması için `condition` alanına da eklendi. Ayrıca, orijinal `Image` alan adı `NewProcessName` olarak değiştirildi.

## Dönüştürmedeki ortak noktalar

Belirli kategorileri nasıl dönüştürdüğümüzü ayrıntılı olarak açıklamadan önce, dönüştürmenin tüm kurallara uygulanan kısmı şöyledir.

1. `ignore-uuid-list.txt` içinde bir kimliği bulunan herhangi bir kural yok sayılır. Şu anda yalnızca içinde `mimikatz` gibi anahtar kelimeler bulunduğu için Windows Defender'da yanlış pozitiflere neden olan kuralları yok sayıyoruz.
2. "Placeholder" (yer tutucu) kuralları olduğu gibi kullanılamadıkları için yok sayılır. Bunlar, Sigma deposundaki [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) klasörüne yerleştirilmiş kurallardır.
3. Uyumsuz alan değiştiricileri kullanan kurallar bırakılır. Hayabusa alan değiştiricilerinin çoğunu destekler, bu nedenle dönüştürücü, ayrıştırma hatalarından kaçınmak için bunların dışında bir değiştirici kullanan hiçbir kuralı çıktı olarak vermez (bkz. [Alan Değiştiricileri](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Söz dizimi hataları olan kurallar dönüştürülmez.
5. `deprecated` ve `unsupported` kurallarındaki etiketler, her şeyi tutarlı tutmak ve Hayabusa'daki kısaltmaları daha kolay ele almak için, `_` yerine `-` kullanan V1 biçiminden V2 biçimine güncellenir. Örnek: `initial_access`, `initial-access` olur.
6. Kurallara `Channel` ve `EventID` bilgisi eklediğimiz için, orijinal kimliğin MD5 karmasını kullanarak yeni bir UUIDv4 kimliği oluşturur, orijinal kimliği `related` alanında belirtir ve `type` alanını `derived` olarak işaretleriz. Birden fazla kurala dönüştürülebilen kurallar için (`sysmon` ve `builtin`), türetilmiş `builtin` kuralları için de yeni kural kimlikleri oluşturmamız gerekir. Bunun için, `sysmon` kural kimliğinin MD5 karmasını hesaplar ve bunu UUIDv4 kimliği için kullanırız. Örneğin:

    Orijinal Sigma kuralı:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Yeni `sysmon` kuralı:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Yeni `builtin` kuralı:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Yerleşik Windows olay günlüklerinde bir şeyler tespit eden kurallar `builtin` dizinine, Sysmon günlüklerine dayanan kurallar ise `sysmon` dizinine, üst kaynaktaki Sigma deposundaki dizinlerle eşleşen alt dizinlerle birlikte çıktı olarak verilir.

## Dönüştürme sınırlamaları

Şu anda yalnızca bir [bilinen hata](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2) vardır: Sigma kurallarındaki yorum satırları, yorumlar bir kaynak kodun ardından gelmediği sürece çıktı kurallarına dahil edilmez.

## Sysmon ve yerleşik olay karşılaştırması ile kural dönüştürme { #sysmon-builtin-comparison }

### Süreç oluşturma

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Yerleşik günlük
    * Channel: `Security`
    * Event ID: `4688`

**Karşılaştırma**

![Süreç oluşturma karşılaştırması](../assets/rules-doc/process_creation_comparison.png)

**Dönüştürme notları**

1. `User` alan bilgisinin `SubjectUserName` ve `SubjectDomainName` alanlarına ayrılması gerekir.
2. `LogonId` alan adı `SubjectLogonId` olarak değişir ve onaltılık (hex) değerdeki tüm harflerin küçük harfe dönüştürülmesi gerekir.
3. `ProcessId` alan adı `NewProcessId` olarak değişir ve değerin onaltılık biçime dönüştürülmesi gerekir.
4. `Image` alan adı `NewProcessName` olarak değişir.
5. `ParentProcessId` alan adı `ProcessId` olarak değişir ve değerin onaltılık biçime dönüştürülmesi gerekir.
6. `ParentImage` alan adı `ParentProcessName` olarak değişir.
7. `IntegrityLevel` alan adı `MandatoryLabel` olarak değişir ve aşağıdaki değer dönüştürmesi gerekir:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. Kural yalnızca `Security 4688` olaylarında bulunan aşağıdaki alanları içeriyorsa, bir `Sysmon 1` kuralı oluşturmayız:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Kural yalnızca `Sysmon 1` olaylarında bulunan aşağıdaki alanları içeriyorsa, bir `Security 4688` kuralı oluşturmayız:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. #8 ve #9 için bir istisna vardır: yalnızca bir günlük olayında bulunan bir alan kullanılsa bile, o alan bir `OR` koşulunun içindeyse yine de o kuralı oluşturmalısınız. Örneğin, aşağıdaki kural, `OriginalFileName` alanı zorunlu olduğundan (seçim içinde `AND` mantığı) bir `Security 4688` kuralı **oluşturmamalıdır**:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    Ancak, aşağıdaki koşula sahip bir kural, `OriginalFileName` isteğe bağlı olduğundan (seçim içinde `OR` mantığı) bir `Security 4688` kuralı **oluşturmalıdır**:

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    İşler şu bakımdan zorlaşır: ayrıştırıcınızın yalnızca seçimlerin içindeki mantığı değil, aynı zamanda `condition` alanının içindeki mantığı da anlaması gerekir. Örneğin, aşağıdaki kural `AND` mantığı kullandığı için bir `Security 4688` kuralı **oluşturmamalıdır**:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    Ancak, aşağıdaki kural `OR` mantığı kullandığı için bir `Security 4688` kuralı **oluşturmalıdır**:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Diğer notlar**

* `Security 4688` içindeki `SubjectUserSid` alanı SID'yi gösterir; ancak, işlenmiş (rendered) olay günlüğü `Message` alanında `DOMAIN\User` biçimine dönüştürülür.
* `Security 4688` olayları, ayarlara bağlı olarak `CommandLine` içinde komut satırı seçenek bilgisini içermeyebilir.
* `TokenElevationType`, `Message` içinde olduğu gibi gösterilir ve işlenmez (rendered değildir).
* `MandatoryLabel` içindeki `S-1-16-4096` vb. değerler, işlenmiş `Message` içinde `Mandatory Label\Low Mandatory Level` vb. biçime dönüştürülür.

**Yerleşik günlük ayarları**

!!! warning "Varsayılan olarak etkin değil"
    Önemli olan yerleşik `Security 4688` süreç oluşturma olay günlükleri varsayılan olarak etkin değildir. Sigma kurallarının çoğunu kullanabilmek için hem `4688` olaylarını hem de komut satırı seçeneği günlüklemesini etkinleştirmeniz gerekir.

*Grup ilkesiyle etkinleştirme:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*Komut satırında etkinleştirme:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Ağ bağlantısı

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Yerleşik günlük
    * Channel: `Security`
    * Event ID: `5156`

**Karşılaştırma**

![Ağ bağlantısı karşılaştırması](../assets/rules-doc/network_connection_comparison.png)

**Dönüştürme notları**

1. `ProcessId` alan adı `ProcessID` olarak değişir.
2. `Image` alan adı `Application` olarak değişir ve `C:\`, `\device\harddiskvolume?\` olarak değişir. (Not: Sabit disk birim numarasını bilmediğimizden, onu tek karakterlik bir joker karakter `?` ile değiştiriyoruz.)
3. `Protocol` alan değeri `tcp`, `6` olarak ve `udp`, `17` olarak değişir.
4. `Initiated` alan adı `Direction` olarak değişir ve `true` değeri `%%14593` olarak, `false` değeri `%%14592` olarak değişir.
5. `SourceIp` alan adı `SourceAddress` olarak değişir.
6. `DestinationIp` alan adı `DestAddress` olarak değişir.
7. `DestinationPort` alan adı `DestPort` olarak değişir.

**Yerleşik günlük ayarları**

!!! warning "Varsayılan olarak etkin değil"
    Yerleşik `Security 5156` ağ bağlantısı günlükleri varsayılan olarak etkin değildir. Bunlar büyük miktarda günlük oluşturur; bu da `Security` olay günlüğündeki diğer önemli günlüklerin üzerine yazılmasına ve sistemin çok sayıda ağ bağlantısı varsa potansiyel olarak yavaşlamasına neden olabilir. `Security` günlüğü için maksimum dosya boyutunun yüksek olduğundan emin olun ve sistemde olumsuz bir etki olmadığından emin olmak için test edin.

*Grup ilkesiyle etkinleştirme:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*Komut satırında etkinleştirme:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...veya İngilizce olmayan bir yerel ayar (locale) kullanıyorsanız aşağıdakini kullanın:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Ayrıca bkz."
    Bu kuralların dayandığı kanıtları yakalamak için gereken yerleşik Windows olay günlüklerini etkinleştirme hakkında daha fazla bilgi için bkz. [Windows Günlükleme ve Sysmon](../resources/logging.md) ve [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) projesi.

## Sigma kuralı yazma tavsiyesi

!!! tip
    Bir `sysmon` günlüğünde bulunan ancak bir `builtin` günlüğünde bulunmayan herhangi bir alanı kullanırsanız, kuralın `builtin` günlükler için hâlâ kullanılabilir olması amacıyla o alanı isteğe bağlı yaptığınızdan emin olun.

Örneğin:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Bu seçim, sürecin (`Image`) `addinutil.exe` olarak adlandırıldığı durumları arar. Sorun şu ki, bir saldırgan kuralı atlatmak için dosyayı yeniden adlandırabilir. Yalnızca Sysmon günlüklerinde bulunan `OriginalFileName` alanı, derleme sırasında ikili dosyaya (binary) gömülen dosya adıdır. Bir saldırgan dosyayı yeniden adlandırsa bile gömülü ad değişmez, dolayısıyla bu kural, Sysmon kullanırken saldırganın dosyayı yeniden adlandırdığı saldırıları tespit edebildiği gibi, standart yerleşik günlükleri kullanırken dosya adının değiştirilmediği saldırıları da tespit edebilir.

## Önceden dönüştürülmüş Sigma kuralları

Bu sayfada açıklanan şekilde — `logsource` alanı soyutlamadan arındırılarak — düzenlenen Sigma kuralları, [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) deposunda `sigma` klasörü altında barındırılmaktadır.

## Araç ortamı

Sigma kurallarını yerel olarak Hayabusa uyumlu biçime dönüştürmek istiyorsanız, önce [Poetry](https://python-poetry.org/) kurmanız gerekir. Lütfen resmi Poetry [kurulum belgesine](https://python-poetry.org/docs/#installation) bakın.

## Aracın kullanımı

`sigma-to-hayabusa-converter.py`, Sigma kurallarının `logsource` alanını Hayabusa uyumlu biçime dönüştürmek için kullandığımız ana araçtır. Çalıştırmak için aşağıdaki işlemleri gerçekleştirin:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Yukarıdaki komutları çalıştırdıktan sonra, Hayabusa uyumlu biçime dönüştürülen kurallar `./converted_sigma_rules` dizinine çıktı olarak verilecektir.

## Yazarlar

Bu belge Zach Mathis (@yamatosecurity) tarafından oluşturulmuş ve Fukusuke Takahashi (@fukusuket) tarafından Japoncaya çevrilmiştir.

`sigma-to-hayabusa-converter.py` aracının uygulanması ve bakımı Fukusuke Takahashi tarafından yapılmaktadır.

Artık kullanımdan kaldırılmış olan `sigmac` aracına dayanan orijinal dönüştürme aracı, ItiB ([@itiB_S144](https://x.com/itib_s144)) ve James Takai / hachiyone (@hach1yon) tarafından uygulanmıştır.
