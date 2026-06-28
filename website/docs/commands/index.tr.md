# Komut Listesi

## Analiz Komutları:
* `computer-metrics`: Bilgisayar adlarına göre olayların sayısını yazdırır.
* `eid-metrics`: Event ID'ye göre olayların sayısını ve yüzdesini yazdırır.
* `expand-list`: `rules` klasöründen `expand` yer tutucularını çıkarır.
* `extract-base64`: Olaylardan base64 dizelerini çıkarır ve çözer.
* `log-metrics`: Günlük dosyası metriklerini yazdırır.
* `logon-summary`: Oturum açma olaylarının bir özetini yazdırır.
* `pivot-keywords-list`: Üzerinde pivot yapılacak şüpheli anahtar kelimelerin bir listesini yazdırır.
* `search`: Tüm olayları anahtar kelime(ler) veya düzenli ifadelerle arar

## Yapılandırma Komutları:
* `config-critical-systems`: Etki alanı denetleyicileri ve dosya sunucuları gibi kritik sistemleri bulur.

## DFIR Zaman Çizelgesi Komutları:
* `csv-timeline`: Zaman çizelgesini CSV formatında kaydeder.
* `json-timeline`: Zaman çizelgesini JSON/JSONL formatında kaydeder.
* `level-tuning`: Uyarıların `level` değerini özel olarak ayarlar.
* `list-profiles`: Kullanılabilir çıktı profillerini listeler.
* `set-default-profile`: Varsayılan profili değiştirir.
* `update-rules`: Kuralları [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) GitHub deposundaki en son kurallarla senkronize eder.

## Genel Komutlar:
* `help`: Bu mesajı veya verilen alt komut(lar)ın yardımını yazdırır
* `list-contributors`: Katkıda bulunanların listesini yazdırır
