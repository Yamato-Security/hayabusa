# Hayabusa Kuralları

Hayabusa tespit kuralları sigma benzeri bir YML formatında yazılır ve `rules` klasöründe bulunur.
Kurallar [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) adresinde barındırılır, bu nedenle kurallarla ilgili sorunları ve pull request'leri ana Hayabusa deposu yerine lütfen oraya gönderin.

Kural formatını ve kuralların nasıl oluşturulacağını anlamak için bu bölümdeki [Kural Dosyaları Oluşturma](creating-rules.md), [Tespit Alanları](detection-fields.md) ve [Sigma Korelasyonları](correlations.md) sayfalarına bakın. (Kaynak: [hayabusa-rules deposu](https://github.com/Yamato-Security/hayabusa-rules).)

hayabusa-rules deposundaki tüm kurallar `rules` klasörüne yerleştirilmelidir.
`informational` seviyesindeki kurallar `events` olarak kabul edilirken, `low` ve daha yüksek bir `level` değerine sahip olan her şey `alerts` olarak kabul edilir.

Hayabusa kural dizini yapısı 2 dizine ayrılmıştır:

* `builtin`: Windows yerleşik işlevselliği tarafından üretilebilen günlükler.
* `sysmon`: [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) tarafından üretilen günlükler.

Kurallar ayrıca günlük türüne göre dizinlere ayrılır (Örnek: Security, System, vb...) ve aşağıdaki formatta adlandırılır:

Yeni kurallar oluştururken şablon olarak kullanmak veya tespit mantığını kontrol etmek için lütfen mevcut kurallara göz atın.

## Sigma v.s. Hayabusa (Yerleşik Sigma Uyumlu) Kuralları

Hayabusa, yalnızca `logsource` alanlarını dahili olarak işleme istisnasıyla, Sigma kurallarını yerel olarak destekler.
Yanlış pozitifleri azaltmak için, Sigma kuralları [burada](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md) açıklanan dönüştürücümüzden geçirilmelidir.
Bu, uygun `Channel` ve `EventID` değerlerini ekler ve `process_creation` gibi belirli kategoriler için alan eşlemesi gerçekleştirir.

Neredeyse tüm Hayabusa kuralları Sigma formatıyla uyumludur, bu nedenle bunları tıpkı Sigma kuralları gibi diğer SIEM formatlarına dönüştürmek için kullanabilirsiniz.
Hayabusa kuralları yalnızca Windows olay günlüğü analizi için tasarlanmıştır ve aşağıdaki avantajlara sahiptir:

1. Günlükteki yalnızca yararlı alanlardan alınan ek bilgileri görüntülemek için fazladan bir `details` alanı.
2. Hepsi örnek günlüklere karşı test edilmiştir ve çalıştığı bilinmektedir.
3. `|equalsfield` ve `|endswithfield` gibi sigma'da bulunmayan ekstra toplayıcılar.

Bildiğimiz kadarıyla hayabusa, herhangi bir açık kaynaklı Windows olay günlüğü analiz aracı arasında sigma kuralları için en iyi yerel desteği sağlar.
