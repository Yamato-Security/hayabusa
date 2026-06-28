# Kural Dosyaları Oluşturma

## Hayabusa-Rules Hakkında

Bu, Windows olay günlüklerindeki saldırıları tespit eden özenle seçilmiş sigma kurallarını içeren bir depodur.
Esas olarak [Hayabusa](https://github.com/Yamato-Security/hayabusa) tespit kuralları ve yapılandırma dosyaları için, ayrıca [Velociraptor](https://github.com/Velocidex/velociraptor)'un yerleşik sigma tespiti için kullanılır.
Bu depoyu [üst akış sigma deposu](https://github.com/SigmaHQ/sigma) yerine kullanmanın avantajı, yalnızca çoğu sigma-yerel aracının ayrıştırabilmesi gereken kuralları içermemizdir.
Ayrıca, kuralın neye göre filtreleme yaptığını anlamayı kolaylaştırmak ve daha da önemlisi yanlış pozitifleri azaltmak için gerekli `Channel`, `EventID` vb. alanları kurallara ekleyerek `logsource` alanını soyutlamaktan çıkarıyoruz.
Ayrıca, sigma kurallarının yalnızca Sysmon günlüklerinde değil, yerleşik Windows günlüklerinde de tespit yapabilmesi için `process_creation` kuralları ve `registry` tabanlı kurallar için dönüştürülmüş alan adları ve değerleriyle yeni kurallar oluşturuyoruz.

## Kural dosyaları oluşturma hakkında

Hayabusa tespit kuralları, `.yml` dosya uzantısıyla [YAML](https://en.wikipedia.org/wiki/YAML) biçiminde yazılır. (`.yaml` dosyaları yok sayılacaktır.)
Bunlar sigma kurallarının bir alt kümesidir ancak bazı eklenmiş özellikler de içerirler.
Hayabusa kurallarını sigma'ya geri dönüştürmenin ve topluluğa geri vermenin kolay olması için bunları mümkün olduğunca sigma kurallarına yakın hale getirmeye çalışıyoruz.
Hayabusa kuralları, yalnızca basit dize eşleştirmeyi değil, aynı zamanda düzenli ifadeleri, `AND`, `OR` ve diğer koşulları birleştirerek karmaşık tespit kurallarını ifade edebilir.
Bu bölümde, Hayabusa tespit kurallarının nasıl yazılacağını açıklayacağız.

### Kural dosyası biçimi

Örnek:

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

> ## Yazar bölümü

- **author [gerekli]**: Yazar(lar)ın adı.
- **date [gerekli]**: Kuralın oluşturulduğu tarih.
- **modified** [isteğe bağlı]: Kuralın güncellendiği tarih.

> ## Uyarı bölümü

- **title [gerekli]**: Kural dosyası başlığı. Bu aynı zamanda görüntülenen uyarının adı olacaktır, bu yüzden ne kadar kısa olursa o kadar iyidir. (85 karakterden uzun olmamalıdır.)
- **details** [isteğe bağlı]: Görüntülenen uyarının ayrıntıları. Lütfen Windows olay günlüğünde analiz için yararlı olan herhangi bir alanı çıktı olarak verin. Alanlar `" ¦ "` ile ayrılır. Alan yer tutucuları bir `%` ile çevrelenir (Örnek: `%MemberName%`) ve `rules/config/eventkey_alias.txt` içinde tanımlanması gerekir. (Aşağıda açıklanmıştır.)
- **description** [isteğe bağlı]: Kuralın bir açıklaması. Bu görüntülenmez, bu yüzden uzun ve ayrıntılı yapabilirsiniz.

> ## Kural bölümü

- **id [gerekli]**: Kuralı benzersiz şekilde tanımlamak için kullanılan rastgele oluşturulmuş bir sürüm 4 UUID. [Buradan](https://www.uuidgenerator.net/version4) bir tane oluşturabilirsiniz.
- **level [gerekli]**: [sigma'nın tanımına](https://github.com/SigmaHQ/sigma/wiki/Specification) dayalı önem düzeyi. Lütfen şunlardan birini yazın: `informational`,`low`,`medium`,`high`,`critical`
- **status[gerekli]**: [sigma'nın tanımına](https://github.com/SigmaHQ/sigma/wiki/Specification) dayalı durum. Lütfen şunlardan birini yazın: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [gerekli]**: Bu şu anda Hayabusa tarafından gerçekte kullanılmasa da, sigma kurallarıyla uyumlu olmak için logsource'u sigma ile aynı şekilde tanımlarız.
- **detection  [gerekli]**: Tespit mantığı buraya gelir. (Aşağıda açıklanmıştır.)
- **falsepositives [gerekli]**: Yanlış pozitif olasılıkları. Örneğin: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Bilinmiyorsa, lütfen `unknown` yazın.
- **tags** [isteğe bağlı]: Teknik bir [LOLBINS/LOLBAS](https://lolbas-project.github.io/) tekniğiyse, lütfen `lolbas` etiketini ekleyin. Uyarı [MITRE ATT&CK](https://attack.mitre.org/) çerçevesindeki bir tekniğe eşlenebiliyorsa, lütfen taktik kimliğini (Örnek: `attack.t1098`) ve aşağıdaki uygulanabilir taktikleri ekleyin:
  - `attack.reconnaissance` -> Keşif (Recon)
  - `attack.resource-development` -> Kaynak Geliştirme  (ResDev)
  - `attack.initial-access` -> İlk Erişim (InitAccess)
  - `attack.execution` -> Yürütme (Exec)
  - `attack.persistence` -> Kalıcılık (Persis)
  - `attack.privilege-escalation` -> Ayrıcalık Yükseltme (PrivEsc)
  - `attack.stealth` -> Gizlilik (Stealth)
  - `attack.defense-impairment` -> Savunma Bozma (DefImpair)
  - `attack.credential-access` -> Kimlik Bilgisi Erişimi (CredAccess)
  - `attack.discovery` -> Keşfetme (Disc)
  - `attack.lateral-movement` -> Yanal Hareket (LatMov)
  - `attack.collection` -> Toplama (Collect)
  - `attack.command-and-control` -> Komuta ve Kontrol (C2)
  - `attack.exfiltration` -> Sızdırma (Exfil)
  - `attack.impact` -> Etki (Impact)
- **references** [isteğe bağlı]: Referanslara herhangi bir bağlantı.
- **ruletype [gerekli]**: Hayabusa kuralları için `Hayabusa`. Sigma Windows kurallarından otomatik olarak dönüştürülen kurallar `Sigma` olacaktır.

> ## Örnek XML Olayı

- **sample-message [gerekli]**: Bundan sonra, kural yazarlarından kuralları için örnek mesajlar eklemelerini istiyoruz. Bu, Windows'un Olay Görüntüleyici'sinin görüntülediği işlenmiş mesajdır.
- **sample-evtx [gerekli]**: Bundan sonra, kural yazarlarından kuralları için örnek XML olayları eklemelerini istiyoruz.
