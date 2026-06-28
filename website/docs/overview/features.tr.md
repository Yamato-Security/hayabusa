# Özellikler

* Platformlar arası destek: Windows, Linux, macOS.
* Bellek güvenliği ve hız için Rust ile geliştirilmiştir.
* 5 kata kadar hız iyileştirmesi sağlayan çoklu iş parçacığı desteği.
* Adli soruşturmalar ve olay müdahalesi için tek ve analizi kolay zaman çizelgeleri oluşturur.
* Okunması/oluşturulması/düzenlenmesi kolay YML tabanlı hayabusa kurallarında yazılmış IoC imzalarına dayalı tehdit avcılığı.
* Sigma kurallarını hayabusa kurallarına dönüştürmek için Sigma kuralı desteği.
* Şu anda benzer diğer araçlara kıyasla en fazla sigma kuralını desteklemektedir ve hatta sayım kurallarını ve `|equalsfield` ile `|endswithfield` gibi yeni toplayıcıları da destekler.
* Bilgisayar metrikleri. (Çok sayıda olaya sahip belirli bilgisayarları filtrelemek/filtre dışı bırakmak için kullanışlıdır.)
* Event ID metrikleri. (Ne tür olaylar olduğuna dair bir resim elde etmek ve günlük ayarlarınızı düzenlemek için kullanışlıdır.)
* Gereksiz veya gürültülü kuralları hariç tutarak kural ince ayarı yapılandırması.
* Taktiklerin MITRE ATT&CK eşlemesi.
* Kural seviyesi ince ayarı.
* Anormal kullanıcıları, ana bilgisayar adlarını, süreçleri vb. hızla tespit etmek ve olayları ilişkilendirmek için benzersiz pivot anahtar kelimelerinden oluşan bir liste oluşturun.
* Daha kapsamlı soruşturmalar için tüm alanları çıktı olarak verin.
* Başarılı ve başarısız oturum açma özeti.
* [Velociraptor](https://docs.velociraptor.app/) ile tüm uç noktalarda kuruluş genelinde tehdit avcılığı ve DFIR.
* CSV, JSON/JSONL ve HTML Özet Raporları olarak çıktı.
* Günlük Sigma kuralı güncellemeleri.
* JSON biçimli günlük girişi desteği.
* Günlük alanı normalleştirme. (Farklı adlandırma kurallarına sahip birden çok alanı aynı alan adına dönüştürme.)
* IP adreslerine GeoIP (ASN, şehir, ülke) bilgisi ekleyerek günlük zenginleştirme.
* Tüm olaylarda anahtar kelime veya düzenli ifade araması yapın.
* Alan verisi eşlemesi. (Örn: `0xc0000234` -> `ACCOUNT LOCKED`)
* Evtx boş alanından evtx kaydı çıkarma (carving).
* Çıktı verirken olay tekilleştirme. (Kurtarma kayıtları etkinleştirildiğinde veya yedeklenmiş evtx dosyalarını, VSS'den evtx dosyalarını vb. dahil ettiğinizde kullanışlıdır.)
* Hangi kuralların etkinleştirileceğini daha kolay seçmeye yardımcı olan tarama ayarı sihirbazı. (Yanlış pozitifleri azaltmak için vb.)
* PowerShell klasik günlük alanı ayrıştırma ve çıkarma.
* Düşük bellek kullanımı. (Not: bu, sonuçlar sıralanmayarak mümkün olur. Aracılarda veya büyük veride çalıştırmak için en iyisidir.)
* En verimli performans için Kanallar ve Kurallar üzerinde filtreleme.
* Günlüklerde bulunan Base64 dizelerini tespit edin, çıkarın ve çözün.
* Kritik sistemlere dayalı uyarı seviyesi ayarlaması.
