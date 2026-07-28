## Olay Sayımı (Event Count) kuralları

Bunlar, belirli olayları sayan ve bir zaman aralığında bu olaylardan çok fazla veya çok az sayıda meydana gelirse uyarı veren kurallardır.
Belirli bir zaman diliminde çok sayıda olayın tespit edilmesine yönelik yaygın örnekler arasında parola tahmin etme saldırılarının, parola püskürtme (password spray) saldırılarının ve hizmet reddi (denial of service) saldırılarının tespiti yer alır.
Bu kuralları, belirli olayların belirli bir eşiğin altına düşmesi gibi günlük kaynağı güvenilirliği sorunlarını tespit etmek için de kullanabilirsiniz.

### Olay Sayımı kuralı örneği:

Aşağıdaki örnek, parola tahmin etme saldırılarını tespit etmek için iki kural kullanır.
Atıfta bulunulan kural 5 dakika içinde 5 veya daha fazla kez eşleştiğinde ve bu olaylar için `IpAddress` alanı aynı olduğunda bir uyarı oluşur.

> Yalnızca kavramı anlamak için gerekli olan alanları dahil ettiğimizi unutmayın.
> Bu örneğin dayandığı tam kural, referansınız için [burada](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) bulunmaktadır.

### Olay Sayımı korelasyon kuralı:

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

### Başarısız Oturum Açma - Yanlış Parola kuralı:

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

### Kullanımdan kaldırılmış `count` kuralı örneği:

Yukarıdaki korelasyon ve atıfta bulunulan kurallar, daha eski `count` değiştiricisini kullanan aşağıdaki kuralla aynı sonuçları sağlar:

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
### Olay Sayımı kuralı çıktısı:

Yukarıdaki kurallar aşağıdaki çıktıyı oluşturacaktır:
```
% ./hayabusa dfir-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Değer Sayımı (Value Count) kuralları

Bu kurallar, belirli bir alanın **farklı** değerleriyle bir zaman aralığında aynı olayları sayar.

Örnekler:

- Tek bir kaynak IP adresinin birçok farklı hedef IP adresine ve/veya bağlantı noktasına bağlanmaya çalıştığı ağ taramaları.
- Tek bir kaynağın birçok farklı kullanıcı ile kimlik doğrulamasının başarısız olduğu parola püskürtme (password spraying) saldırıları.
- BloodHound gibi, kısa bir zaman aralığında birçok yüksek ayrıcalıklı AD grubunu numaralandıran araçların tespiti.

### Değer Sayımı kuralı örneği:

Aşağıdaki kural, bir saldırganın kullanıcı adlarını tahmin etmeye çalıştığını tespit eder.
Yani, **aynı** kaynak IP adresinin (`IpAddress`) 5 dakika içinde 3'ten fazla **farklı** kullanıcı adıyla (`TargetUserName`) oturum açmada başarısız olduğunda.

> Yalnızca kavramı anlamak için gerekli olan alanları dahil ettiğimizi unutmayın.
> Bu örneğin dayandığı tam kural, referansınız için [burada](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) bulunmaktadır.

### Değer Sayımı korelasyon kuralı:

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

### Değer Sayımı Oturum Açma Hatası (Var Olmayan Kullanıcı) kuralı:

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

### Kullanımdan kaldırılmış `count` değiştirici kuralı:

Yukarıdaki korelasyon ve atıfta bulunulan kurallar, daha eski `count` değiştiricisini kullanan aşağıdaki kuralla aynı sonuçları sağlar:

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

### Değer Sayımı kuralı çıktısı:

Yukarıdaki kurallar aşağıdaki çıktıyı oluşturacaktır:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Zamansal Yakınlık (Temporal Proximity) kuralları

rule alanında atıfta bulunulan kurallar tarafından tanımlanan tüm olayların, timespan tarafından tanımlanan zaman aralığında meydana gelmesi gerekir.
`group-by` içinde tanımlanan alanların değerlerinin tümü aynı değere sahip olmalıdır (ör: aynı ana bilgisayar, kullanıcı vb.).

### Zamansal Yakınlık kuralı örneği:

Örnek: Üç Sigma kuralında tanımlanan keşif komutları, aynı kullanıcı tarafından bir sistemde 5 dakika içinde rastgele bir sırayla çağrılır.

### Zamansal Yakınlık korelasyon kuralı:

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

## Sıralı Zamansal Yakınlık (Ordered Temporal Proximity) kuralları

`temporal_ordered` korelasyon türü `temporal` gibi davranır ve ek olarak olayların `rules` özniteliğinde sağlanan sırada görünmesini gerektirir.

### Sıralı Zamansal Yakınlık kuralı örneği:

Örnek: Yukarıda tanımlandığı gibi birçok başarısız oturum açma işleminin ardından aynı kullanıcı hesabıyla 1 saat içinde başarılı bir oturum açma gerçekleşir:

### Sıralı Zamansal Yakınlık korelasyon kuralı:

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

## Korelasyon kuralları hakkında notlar

1. Tüm korelasyon ve atıfta bulunulan kurallarınızı tek bir dosyaya dahil etmeli ve bunları `---` YAML ayırıcısıyla ayırmalısınız.

2. Varsayılan olarak, atıfta bulunulan korelasyon kuralları çıktıya yansıtılmaz. Atıfta bulunulan kuralların çıktısını görmek istiyorsanız, `correlation` altına `generate: true` eklemeniz gerekir. Bu, korelasyon kuralları oluştururken açıp kontrol etmek için çok kullanışlıdır.

    Örnek:
    ```
    correlation:
        generate: true
    ```
3. İşleri daha anlaşılır hale getirmek için kurallara atıfta bulunurken kural kimlikleri yerine takma adlar kullanabilirsiniz.

4. Birden fazla kurala atıfta bulunabilirsiniz.

5. `group-by` içinde birden fazla alan kullanabilirsiniz. Bunu yaparsanız, o alanlardaki tüm değerlerin aynı olması gerekir, aksi takdirde bir uyarı almazsınız. Çoğu zaman, yanlış pozitifleri azaltmak için `group-by` ile belirli alanları filtreleyen kurallar yazarsınız; ancak, daha genel bir kural oluşturmak için `group-by` öğesini atlamak mümkündür.

6. Korelasyon kuralının zaman damgası, saldırının en başlangıcı olacaktır; bu nedenle yanlış pozitif olup olmadığını doğrulamak için bundan sonraki olayları kontrol etmelisiniz.
