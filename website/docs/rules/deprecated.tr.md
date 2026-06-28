# Kullanımdan kaldırılan özellikler

Kullanımdan kaldırılan özel anahtar sözcükler ve `count` toplama işlevi Hayabusa'da hâlâ desteklenmektedir, ancak gelecekte kurallar içinde kullanılmayacaktır.

## Kullanımdan kaldırılan özel anahtar sözcükler

Şu anda aşağıdaki özel anahtar sözcükler belirtilebilir:

- `value`: dizeye göre eşleşir (joker karakterler ve borular da belirtilebilir).
- `min_length`: karakter sayısı belirtilen sayıdan büyük veya eşit olduğunda eşleşir.
- `regexes`: bu alanda belirttiğiniz dosyadaki düzenli ifadelerden biri eşleşirse eşleşir.
- `allowlist`: bu alanda belirttiğiniz dosyadaki düzenli ifadeler listesinde herhangi bir eşleşme bulunursa kural atlanır.

Aşağıdaki örnekte, aşağıdakiler doğruysa kural eşleşecektir:

- `ServiceName`, `malicious-service` olarak adlandırılır veya `./rules/config/regex/detectlist_suspicous_services.txt` içinde bir düzenli ifade içerir.
- `ImagePath` en az 1000 karakter içerir.
- `ImagePath`, `allowlist` içinde herhangi bir eşleşmeye sahip değildir.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### regexes ve allowlist anahtar sözcüğü örnek dosyaları

Hayabusa'nın `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml` dosyası için kullanılan iki yerleşik düzenli ifade dosyası vardı:

- `./rules/config/regex/detectlist_suspicous_services.txt`: şüpheli hizmet adlarını tespit etmek için
- `./rules/config/regex/allowlist_legitimate_services.txt`: meşru hizmetlere izin vermek için

`regexes` ve `allowlist` içinde tanımlanan dosyalar, herhangi bir kural dosyasının kendisini değiştirmeye gerek kalmadan, onlara başvuran tüm kuralların davranışını değiştirmek için düzenlenebilir.

Ayrıca oluşturduğunuz farklı detectlist ve allowlist metin dosyalarını da kullanabilirsiniz.

## Kullanımdan kaldırılan toplama koşulları (`count` kuralları)

Bu, Hayabusa'da hâlâ desteklenmektedir ancak gelecekte Sigma korelasyon kurallarıyla değiştirilecektir.

### Temeller

Yukarıda açıklanan `condition` anahtar sözcüğü yalnızca `AND` ve `OR` mantığını uygulamakla kalmaz, aynı zamanda olayları sayabilir veya "toplayabilir".
Bu işlev "toplama koşulu" olarak adlandırılır ve bir koşulu bir boru ile bağlayarak belirtilir.
Aşağıdaki parola spreyi tespit örneğinde, 5 dakikalık bir zaman dilimi içinde tek bir kaynak `IpAddress` adresinden 5 veya daha fazla `TargetUserName` değeri olup olmadığını belirlemek için koşullu bir ifade kullanılır.

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

Toplama koşulları aşağıdaki biçimde tanımlanabilir:

- `count() {operator} {number}`: Borudan önceki ilk koşulla eşleşen günlük olayları için, eşleşen günlüklerin sayısı `{operator}` ve `{number}` ile belirtilen koşul ifadesini karşılarsa koşul eşleşir.

`{operator}` aşağıdakilerden biri olabilir:

- `==`: Değer belirtilen değere eşitse, koşulla eşleşiyor olarak kabul edilir.
- `>=`: Değer belirtilen değerden büyük veya eşitse, koşulun karşılandığı kabul edilir.
- `>`: Değer belirtilen değerden büyükse, koşulun karşılandığı kabul edilir.
- `<=`: Değer belirtilen değerden küçük veya eşitse, koşulun karşılandığı kabul edilir.
- `<`: Değer belirtilen değerden küçükse, koşulun karşılandığı gibi işlem görür.

`{number}` bir sayı olmalıdır.

`timeframe` aşağıdaki biçimde tanımlanabilir:

- `15s`: 15 saniye
- `30m`: 30 dakika
- `12h`: 12 saat
- `7d`: 7 gün
- `3M`: 3 ay

### Toplama koşulları için dört kalıp

1. count argümanı veya `by` anahtar sözcüğü yok. Örnek: `selection | count() > 10`
   > Zaman dilimi içinde `selection` 10 defadan fazla eşleşirse, koşul eşleşir.
   > Bunlar, `group-by` alanını kullanmayan Event Count korelasyon kurallarıyla değiştirilir.
2. count argümanı yok ancak bir `by` anahtar sözcüğü var. Örnek: `selection | count() by IpAddress > 10`
   > **Aynı** `IpAddress` için `selection` 10 defadan fazla doğru olmalıdır.
   > Bu #2 kuralları, #1 kurallarından daha yaygındır.
   > Gruplamak için birden çok alan da belirtebilirsiniz. Örneğin: `by IpAddress, Computer`
   > Bunlar, `group-by` alanını kullanan Event Count korelasyon kurallarıyla değiştirilir.
3. count argümanı var ancak `by` anahtar sözcüğü yok. Örnek: `selection | count(TargetUserName) > 10`
   > Zaman dilimi içinde `selection` eşleşir ve `TargetUserName` 10 defadan fazla **farklı** olursa, koşul eşleşir.
   > Bunlar, `group-by` alanını kullanmayan Value Count korelasyon kurallarıyla değiştirilir.
4. Hem count argümanı hem de `by` anahtar sözcüğü var. Örnek: `selection | count(Users) by IpAddress > 10`
   > **Aynı** `IpAddress` için, koşulun eşleşmesi için 10 defadan fazla **farklı** `TargetUserName` olması gerekir.
   > Bu #4 kuralları, #3 kurallarından daha yaygındır.
   > Bunlar, `group-by` alanını kullanan Value Count korelasyon kurallarıyla değiştirilir.

### Kalıp 1 örneği

Bu en temel kalıptır: `count() {operator} {number}`. Aşağıdaki kural, `selection` 3 veya daha fazla defa gerçekleşirse eşleşir.

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### Kalıp 2 örneği

`count() by {eventkey} {operator} {number}`: Borudan önceki `condition` ile eşleşen günlük olayları **aynı** `{eventkey}` ile gruplanır. Her gruplama için eşleşen olay sayısı `{operator}` ve `{number}` ile belirtilen koşulu karşılarsa, koşul eşleşir.

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### Kalıp 3 örneği

`count({eventkey}) {operator} {number}`: Koşul borusundan önceki koşulla eşleşen günlük olayında `{eventkey}` değerinin kaç tane **farklı** değerinin bulunduğunu sayar. Sayı `{operator}` ve `{number}` içinde belirtilen koşullu ifadeyi karşılarsa, koşulun karşılandığı kabul edilir.

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### Kalıp 4 örneği

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: Koşul borusundan önceki koşulla eşleşen günlükler **aynı** `{eventkey_2}` ile gruplanır ve her gruptaki `{eventkey_1}` değerinin **farklı** değerlerinin sayısı sayılır. Her gruplama için sayılan değerler `{operator}` ve `{number}` ile belirtilen koşullu ifadeyi karşılarsa, koşul eşleşir.

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Count kuralı çıktısı

Count kuralları için ayrıntı çıktısı sabittir ve orijinal count koşulunu `[condition]` içinde ve ardından kaydedilen eventkey'leri `[result]` içinde yazdırır.

Aşağıdaki örnekte, kaba kuvvet saldırısına uğrayan `TargetUserName` kullanıcı adlarının bir listesi ve ardından kaynak `IpAddress` yer almaktadır:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

Uyarının zaman damgası, tespit edilen ilk olayın zamanı olacaktır.
