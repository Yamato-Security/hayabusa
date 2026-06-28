# Tespit alanı

## Selection temelleri

İlk olarak, bir selection kuralının nasıl oluşturulacağının temelleri açıklanacaktır.

### AND ve OR mantığı nasıl yazılır

AND mantığını yazmak için iç içe geçmiş sözlükler kullanırız.
Aşağıdaki tespit kuralı, kuralın eşleşmesi için **her iki koşulun** da doğru olması gerektiğini tanımlar.

- EventID tam olarak `7040` olmalıdır.
- **AND**
- Channel tam olarak `System` olmalıdır.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

OR mantığını yazmak için listeler (`-` ile başlayan sözlükler) kullanırız.
Aşağıdaki tespit kuralında, koşullardan **herhangi biri** kuralın tetiklenmesine neden olur.

- EventID tam olarak `7040` olmalıdır.
- **OR**
- Channel tam olarak `System` olmalıdır.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

Aşağıda gösterildiği gibi `AND` ve `OR` mantığını da birleştirebiliriz.
Bu durumda, kural aşağıdaki iki koşulun her ikisi de doğru olduğunda eşleşir.

- EventID tam olarak `7040` **OR** `7041` değerlerinden biridir.
- **AND**
- Channel tam olarak `System`'dir.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

Aşağıdaki, orijinal XML biçiminde biçimlendirilmiş bir Windows olay günlüğünün bir alıntısıdır.
Yukarıdaki kural dosyası örneğindeki `Event.System.Channel` alanı, orijinal XML etiketine atıfta bulunur: `<Event><System><Channel>System<Channel><System></Event>`
İç içe geçmiş XML etiketleri, noktalarla (`.`) ayrılmış etiket adlarıyla değiştirilir.
hayabusa kurallarında, noktalarla birbirine bağlanan bu alan dizelerine `eventkeys` denir.

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

#### Eventkey Takma Adları (Aliases)

Çok sayıda `.` ayrımı içeren uzun eventkey'ler yaygındır, bu nedenle hayabusa bunlarla çalışmayı kolaylaştırmak için takma adlar kullanır. Takma adlar `rules/config/eventkey_alias.txt` dosyasında tanımlanır. Bu dosya, `alias` ve `event_key` eşlemelerinden oluşan bir CSV dosyasıdır. Yukarıdaki kuralı, kuralı okumayı kolaylaştıran takma adlarla aşağıda gösterildiği gibi yeniden yazabilirsiniz.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Dikkat: Tanımlanmamış Eventkey Takma Adları

Tüm eventkey takma adları `rules/config/eventkey_alias.txt` içinde tanımlanmamıştır. `details` (`Alert details`) mesajında doğru veriyi alamıyorsanız ve bunun yerine `n/a` (kullanılamıyor) alıyorsanız veya tespit mantığınızdaki selection düzgün çalışmıyorsa, o zaman `rules/config/eventkey_alias.txt` dosyasını yeni bir takma adla güncellemeniz gerekebilir.

### Koşullarda XML niteliklerinin nasıl kullanılacağı

XML öğeleri, öğeye bir boşluk eklenerek ayarlanmış niteliklere sahip olabilir. Örneğin, aşağıdaki `Provider Name` içindeki `Name`, `Provider` öğesinin bir XML niteliğidir.

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

Bir eventkey'de XML niteliklerini belirtmek için `{eventkey}_attributes.{attribute_name}` biçimini kullanın. Örneğin, bir kural dosyasında `Provider` öğesinin `Name` niteliğini belirtmek için şöyle görünür:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep araması

Hayabusa, herhangi bir eventkey belirtmeyerek Windows olay günlüğü dosyalarında grep aramaları gerçekleştirebilir.

Bir grep araması yapmak için, tespiti aşağıda gösterildiği gibi belirtin. Bu durumda, Windows olay günlüğünde `mimikatz` veya `metasploit` dizeleri yer alıyorsa eşleşir. Joker karakterler belirtmek de mümkündür.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Not: Hayabusa, veriyi işlemeden önce Windows olay günlüğü verisini dahili olarak JSON biçimine dönüştürür, bu nedenle XML etiketleri üzerinde eşleşme yapmak mümkün değildir.

### EventData

Windows olay günlükleri iki bölüme ayrılır: temel verinin (Event ID, Timestamp, Record ID, Log adı (Channel)) yazıldığı `System` bölümü ve Event ID'ye bağlı olarak rastgele verinin yazıldığı `EventData` veya `UserData` bölümü.
Sıklıkla ortaya çıkan bir sorun, `EventData` içinde iç içe geçmiş alanların adlarının tümünün `Data` olarak adlandırılmasıdır, bu nedenle şimdiye kadar açıklanan eventkey'ler `SubjectUserSid` ile `SubjectUserName` arasında ayrım yapamaz.

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

Bu sorunla başa çıkmak için, `Data Name` içinde atanan değeri belirtebilirsiniz. Örneğin, EventData içindeki `SubjectUserName` ve `SubjectDomainName` öğelerini bir kuralın koşulu olarak kullanmak istiyorsanız, bunu aşağıdaki gibi tanımlayabilirsiniz:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventData'daki anormal kalıplar

`EventData` içinde iç içe geçmiş etiketlerden bazılarının bir `Name` niteliği yoktur.

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

Yukarıdaki gibi bir olay günlüğünü tespit etmek için `Data` adlı bir eventkey belirtebilirsiniz.
Bu durumda, iç içe geçmiş `Data` etiketlerinden herhangi biri `None` değerine eşit olduğu sürece koşul eşleşir.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Aynı ada sahip birden fazla alan adından alan verisi çıktısı alma

Bazı olaylar, bir önceki örnekteki gibi verilerini tümü `Data` olarak adlandırılan alan adlarına kaydeder.
`details:` içinde `%Data%` belirtirseniz, tüm veriler bir dizi içinde çıktılanır.

Örneğin:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Yalnızca ilk `Data` alan verisini yazdırmak istiyorsanız, `details:` uyarı dizenizde `%Data[1]%` belirtebilirsiniz ve yalnızca `rundll32.exe` çıktılanır.

## Alan Değiştiriciler (Field Modifiers)

Dize eşleştirmesi için aşağıda gösterildiği gibi eventkey'lerle bir pipe (boru) karakteri kullanılabilir.
Şimdiye kadar açıkladığımız tüm koşullar tam eşleşmeler kullanır, ancak alan değiştiricileri kullanarak daha esnek tespit kuralları tanımlayabilirsiniz.
Aşağıdaki örnekte, bir `Data` değeri `EngineVersion=2` dizesini içeriyorsa, koşulla eşleşir.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

Dize eşleşmeleri büyük/küçük harfe duyarlı değildir. Ancak, `|re` veya `|equalsfield` kullanıldığında büyük/küçük harfe duyarlı hale gelirler.

### Desteklenen Sigma Alan Değiştiricileri

Hayabusa şu anda Sigma spesifikasyonunun tamamını tam olarak destekleyen tek açık kaynaklı araçtır.

Desteklenen tüm alan değiştiricilerinin mevcut durumunu ve bu değiştiricilerin Sigma ve Hayabusa kurallarında kaç kez kullanıldığını https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md adresinde kontrol edebilirsiniz.
Bu belge, Sigma veya Hayabusa kurallarında her güncelleme olduğunda dinamik olarak güncellenir.

- `'|all':`: Bu alan değiştirici, yukarıdakilerden farklıdır çünkü belirli bir alana değil, tüm alanlara uygulanır.

    Bu örnekte, hem `Keyword-1` hem de `Keyword-2` dizelerinin var olması gerekir ancak herhangi bir alanda herhangi bir yerde bulunabilirler:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Veri, kodlanmış dizedeki konumuna bağlı olarak üç farklı şekilde base64'e kodlanır. Bu değiştirici, bir dizeyi üç varyasyonun tümüne kodlar ve dizenin base64 dizesinin bir yerinde kodlanıp kodlanmadığını kontrol eder.
- `|cased`: Aramayı büyük/küçük harfe duyarlı hale getirir.
- `|cidr`: Bir alan değerinin bir IPv4 veya IPv6 CIDR gösterimiyle eşleşip eşleşmediğini kontrol eder. (Örnek: `192.0.2.0/24`)
- `|contains`: Bir alan değerinin belirli bir dizeyi içerip içermediğini kontrol eder.
- `|contains|all`: Birden fazla kelimenin verinin içinde yer alıp almadığını kontrol eder.
- `|contains|all|windash`: `|contains|windash` ile aynıdır ancak tüm anahtar kelimelerin mevcut olması gerekir.
- `|contains|cased`: Bir alan değerinin belirli bir büyük/küçük harfe duyarlı dizeyi içerip içermediğini kontrol eder.
- `|contains|expand`: Bir alan değerinin `/config/expand/` içindeki `expand` yapılandırma dosyasında bir dize içerip içermediğini kontrol eder.
- `|contains|windash`: Dizeyi olduğu gibi kontrol eder ve ayrıca ilk `-` karakterini `/`, `–` (en dash), `—` (em dash) ve `―` (yatay çubuk) karakter permütasyonlarına dönüştürür.
- `|endswith`: Bir alan değerinin belirli bir dize ile bitip bitmediğini kontrol eder.
- `|endswith|cased`: Bir alan değerinin belirli bir büyük/küçük harfe duyarlı dize ile bitip bitmediğini kontrol eder.
- `|endswith|windash`: Dizenin sonunu kontrol eder ve tireler için varyasyonlar gerçekleştirir.
- `|exists`: Bir alanın var olup olmadığını kontrol eder.
- `|expand`: Bir alan değerinin `/config/expand/` içindeki `expand` yapılandırma dosyasındaki bir dizeye eşit olup olmadığını kontrol eder.
- `|fieldref`: İki alandaki değerlerin aynı olup olmadığını kontrol eder. İki alanın farklı olup olmadığını kontrol etmek isterseniz `condition` içinde `not` kullanabilirsiniz.
- `|fieldref|contains`: Bir alanın değerinin başka bir alanda yer alıp almadığını kontrol eder.
- `|fieldref|endswith`: Soldaki alanın, sağdaki alanın dizesi ile bitip bitmediğini kontrol eder. Farklı olup olmadıklarını kontrol etmek için `condition` içinde `not` kullanabilirsiniz.
- `|fieldref|startswith`: Soldaki alanın, sağdaki alanın dizesi ile başlayıp başlamadığını kontrol eder. Farklı olup olmadıklarını kontrol etmek için `condition` içinde `not` kullanabilirsiniz.
- `|gt`: Bir alan değerinin belirli bir sayıdan büyük olup olmadığını kontrol eder.
- `|gte`: Bir alan değerinin belirli bir sayıdan büyük veya ona eşit olup olmadığını kontrol eder.
- `|lt`: Bir alan değerinin belirli bir sayıdan küçük olup olmadığını kontrol eder.
- `|lte`: Bir alan değerinin belirli bir sayıdan küçük veya ona eşit olup olmadığını kontrol eder.
- `|re`: Büyük/küçük harfe duyarlı düzenli ifadeler kullanın. (regex crate kullanıyoruz, bu nedenle desteklenen düzenli ifadelerin nasıl yazılacağını öğrenmek için lütfen <https://docs.rs/regex/latest/regex/#syntax> adresindeki belgelere bakın.)
    > Dikkat: [Sigma kurallarındaki düzenli ifade sözdizimi](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression), karakter sınıfları, lookbehind, atomik gruplama vb. için belirli meta karakterlerin desteklenmediği PCRE kullanır. Rust regex crate'i, Sigma kurallarındaki tüm düzenli ifadeleri kullanabilmelidir ancak uyumsuzluk olasılığı vardır. 
- `|re|i`: (Insensitive / Duyarsız) Büyük/küçük harfe duyarlı olmayan düzenli ifadeler kullanın.
- `|re|m`: (Multi-line / Çok satırlı) Birden fazla satırda eşleşir. `^` / `$`, satırın başını/sonunu eşleştirir.
- `|re|s`: (Single-line / Tek satırlı) nokta (`.`), satır sonu karakteri dahil tüm karakterleri eşleştirir.
- `|startswith`: Bir alan değerinin belirli bir dize ile başlayıp başlamadığını kontrol eder.
- `|startswith|cased`: Bir alan değerinin belirli bir büyük/küçük harfe duyarlı dize ile başlayıp başlamadığını kontrol eder.
- `|utf16|base64offset|contains`: Belirli bir UTF-16 dizesinin bir base64 dizesi içinde kodlanıp kodlanmadığını kontrol eder.
- `|utf16be|base64offset|contains`: Belirli bir UTF-16 big-endian dizesinin bir base64 dizesi içinde kodlanıp kodlanmadığını kontrol eder.
- `|utf16le|base64offset|contains`: Belirli bir UTF-16 little-endian dizesinin bir base64 dizesi içinde kodlanıp kodlanmadığını kontrol eder.
- `|wide|base64offset|contains`: `utf16le|base64offset|contains` için takma ad, UTF-16 little-endian dizelerini kontrol eder.

### Kullanımdan Kaldırılan Alan Değiştiricileri

Aşağıdaki değiştiriciler artık kullanımdan kaldırılmıştır ve sigma spesifikasyonlarına daha uygun olan değiştiricilerle değiştirilmiştir.

- `|equalsfield`: Artık `|fieldref` ile değiştirilmiştir.
- `|endswithfield`: Artık `|fieldref|endswith` ile değiştirilmiştir.

### Expand Alan Değiştiricileri

`expand` alan değiştiricileri, kullanmak için önceden yapılandırma gerektiren tek alan değiştirici olmaları bakımından benzersizdir.
Örneğin, `%DC-MACHINE-NAME%` gibi yer tutucular kullanırlar ve olası tüm DC makine adlarını içeren `/config/expand/DC-MACHINE-NAME.txt` adlı bir yapılandırma dosyası gerektirirler.

Bunun nasıl yapılandırılacağı [burada](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command) daha ayrıntılı olarak açıklanmıştır.

## Joker Karakterler (Wildcards)

Joker karakterler eventkey'lerde kullanılabilir. Aşağıdaki örnekte, `ProcessCommandLine` "malware" dizesi ile başlıyorsa, kural eşleşir.
Spesifikasyon temelde sigma kuralı joker karakterleriyle aynıdır, bu nedenle büyük/küçük harfe duyarlı olmaz.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Aşağıdaki iki joker karakter kullanılabilir.

- `*`: Sıfır veya daha fazla karakterden oluşan herhangi bir dizeyle eşleşir. (Dahili olarak `.*` düzenli ifadesine dönüştürülür)
- `?`: Herhangi bir tek karakterle eşleşir. (Dahili olarak `.` düzenli ifadesine dönüştürülür)

Joker karakterlerin kaçış (escape) işlemi hakkında:

- Joker karakterler (`*` ve `?`) bir ters eğik çizgi kullanılarak kaçırılabilir: `\*`, `\?`.
- Bir joker karakterin hemen önünde bir ters eğik çizgi kullanmak istiyorsanız `\\*` veya `\\?` yazın.
- Ters eğik çizgileri tek başlarına kullanıyorsanız kaçış işlemi gerekmez.

## null anahtar kelimesi

`null` anahtar kelimesi, bir alanın var olmadığını kontrol etmek için kullanılabilir.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Not: Bu, bir alanın değerinin boş olup olmadığını kontrol eden `ProcessCommandLine: ''` ifadesinden farklıdır.

## condition

Yukarıda açıkladığımız gösterimle `AND` ve `OR` mantığını ifade edebilirsiniz, ancak karmaşık mantık tanımlamaya çalışıyorsanız kafa karıştırıcı olacaktır.
Daha karmaşık kurallar yapmak istediğinizde, aşağıda gösterildiği gibi `condition` anahtar kelimesini kullanmalısınız.

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

`condition` için aşağıdaki ifadeler kullanılabilir.

- `{expression1} and {expression2}`: Hem {expression1} HEM DE {expression2} gerektirir
- `{expression1} or {expression2}`: {expression1} VEYA {expression2}'den birini gerektirir
- `not {expression}`: {expression} mantığını tersine çevirir
- `( {expression} )`: {expression} önceliğini ayarlar. Matematikteki aynı öncelik mantığını izler.

Yukarıdaki örnekte, `SELECTION_1`, `SELECTION_2` vb. gibi selection adları kullanılır, ancak yalnızca şu karakterleri içerdikleri sürece herhangi bir şekilde adlandırılabilirler: `a-z A-Z 0-9 _`
> Ancak, mümkün olduğunca okumayı kolaylaştırmak için lütfen `selection_1`, `selection_2`, `filter_1`, `filter_2` vb. standart kuralı kullanın.

## not mantığı

Birçok kural yanlış pozitiflerle sonuçlanır, bu nedenle aranacak imzalar için bir selection'a ve ayrıca yanlış pozitifler üzerinde uyarı vermemek için bir filter selection'a sahip olmak çok yaygındır.
Örneğin:

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

# Sigma korelasyonları

[Burada](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md) tanımlandığı şekilde tüm Sigma sürüm 2.0.0 korelasyonlarını uyguladık.

Desteklenen korelasyonlar:

- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

Sigma sürüm 2.1.0'da 12 Eylül 2025'te yayınlanan yeni "metrics" korelasyon kuralları (`value_sum`, `value_avg`, `value_percentile`) şu anda desteklenmemektedir.
