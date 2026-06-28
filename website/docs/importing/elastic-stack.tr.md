- [Sonuçları SOF-ELK'ye (Elastic Stack) Aktarma](#importing-results-into-sof-elk-elastic-stack)
  - [SOF-ELK'yi kurma ve başlatma](#install-and-start-sof-elk)
    - [Mac'lerde ağ bağlantısı sorunu](#network-connectivity-trouble-on-macs)
  - [SOF-ELK'yi güncelleyin!](#update-sof-elk)
  - [Hayabusa'yı çalıştırma](#run-hayabusa)
  - [İsteğe bağlı: Eski içe aktarılmış verileri silme](#optional-deleting-old-imported-data)
  - [SOF-ELK'de Hayabusa logstash yapılandırma dosyasını ayarlama](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Hayabusa sonuçlarını SOF-ELK'ye aktarma](#import-hayabusa-results-into-sof-elk)
  - [İçe aktarmanın Kibana'da çalıştığını kontrol etme](#check-that-the-import-worked-in-kibana)
  - [Sonuçları Discover'da görüntüleme](#view-results-in-discover)
  - [Sonuçları analiz etme](#analyzing-results)
    - [Sütun ekleme](#adding-columns)
    - [Filtreleme](#filtering)
    - [Ayrıntıları açıp kapatma](#toggling-details)
    - [Çevredeki belgeleri görüntüleme](#view-surrounding-documents)
    - [Alanlar üzerinde hızlı metrikler alma](#get-quick-metrics-on-fields)
  - [Gelecek Planları](#future-plans)

# Sonuçları SOF-ELK'ye (Elastic Stack) Aktarma

## SOF-ELK'yi kurma ve başlatma

Hayabusa sonuçları kolayca Elastic Stack'e aktarılabilir.
DFIR araştırmalarına odaklanan ücretsiz bir elastic stack Linux dağıtımı olan [SOF-ELK](https://github.com/philhagen/sof-elk) kullanmanızı öneririz.

İlk olarak SOF-ELK 7-zip ile sıkıştırılmış VMware imajını [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README) adresinden indirip açın.

İki sürüm vardır: Intel CPU'lar için x86 ve Apple M serisi bilgisayarlar için bir ARM sürümü.

VM'yi başlattığınızda, buna benzer bir ekranla karşılaşacaksınız:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Kibana URL'sini ve SSH sunucusunun IP adresini not edin.

Aşağıdaki kimlik bilgileriyle oturum açabilirsiniz:
* Kullanıcı adı: `elk_user`
* Parola: `forensics`

Görüntülenen URL'ye göre bir web tarayıcısında Kibana'yı açın.
Örneğin: http://172.16.23.128:5601/

> Not: Kibana'nın yüklenmesi biraz zaman alabilir.

Aşağıdaki gibi bir web sayfası görmelisiniz:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

VM içinde komutları yazmak yerine `ssh elk_user@172.16.23.128` ile VM'ye SSH ile bağlanmanızı öneririz.

> Not: Varsayılan klavye düzeni ABD klavyesidir.

### Mac'lerde ağ bağlantısı sorunu

macOS kullanıyorsanız ve terminalde `no route to host` hatası alıyorsanız veya tarayıcınızda Kibana'ya erişemiyorsanız, bu muhtemelen macOS'un yerel ağ gizlilik kontrolleri nedeniyledir.

`System Settings` içinde, `Privacy & Security` -> `Local Network` bölümünü açın ve tarayıcınızın ve terminal programınızın yerel ağınızdaki cihazlarla iletişim kurabilmesi için etkinleştirildiğinden emin olun.

## SOF-ELK'yi güncelleyin!

Verileri içe aktarmadan önce, `sudo sof-elk_update.sh` komutuyla SOF-ELK'yi güncellediğinizden emin olun.

## Hayabusa'yı çalıştırma

Hayabusa'yı çalıştırın ve sonuçları JSONL olarak kaydedin.

Örn: `./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## İsteğe bağlı: Eski içe aktarılmış verileri silme

Hayabusa sonuçlarını ilk kez içe aktarmıyorsanız ve her şeyi temizlemek istiyorsanız, bunu aşağıdaki şekilde yapabilirsiniz:

1. SOF-ELK'de şu anda hangi kayıtların bulunduğunu kontrol edin: `sof-elk_clear.py -i list`
2. Mevcut verileri silin: `sof-elk_clear.py -a`
3. logstash dizinindeki dosyaları silin: `rm /logstash/hayabusa/*`

## SOF-ELK'de Hayabusa logstash yapılandırma dosyasını ayarlama

SOF-ELK'de zaten alan adlarını Elastic Common Schema formatına dönüştüren bir Hayabusa logstash yapılandırma dosyası bulunmaktadır.
Hayabusa alan adlarıyla daha rahatsanız, bizim sağladığımız dosyayı kullanmanızı öneririz.

1. İlk olarak SOF-ELK'ye SSH ile bağlanın: `ssh elk_user@172.16.23.128`
2. Mevcut logstash yapılandırma dosyasını silin veya taşıyın: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. Yeni [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) dosyasını `/etc/logstash/conf.d/` dizinine yükleyin: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. logstash'i yeniden başlatın: `sudo systemctl restart logstash`

Bu yapılandırma dosyası, tüm alanları görmek için her kaydı tek tek açmaya zaman harcamak yerine en önemli alanları bir bakışta hızlıca görmenizi sağlayan birleştirilmiş `DetailsText` ve `ExtraFieldInfoText` alanları oluşturacaktır.

## Hayabusa sonuçlarını SOF-ELK'ye aktarma

Loglar, `/logstash` dizini içindeki uygun dizine kopyalanarak SOF-ELK'ye alınır.

İlk olarak SSH'tan `exit` ile çıkın ve ardından oluşturduğunuz Hayabusa sonuç dosyasını kopyalayın:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## İçe aktarmanın Kibana'da çalıştığını kontrol etme

İlk olarak Hayabusa taramanızın `Results Summary` bölümündeki `Total detections`, `First Timestamp` ve `Last Timestamp` değerlerini not edin.

Bu bilgiyi alamazsanız, `Total detections` için toplam satır sayısını almak üzere *nix üzerinde `wc -l results.jsonl` komutunu çalıştırabilirsiniz.

Varsayılan olarak, Hayabusa performansı artırmak için sonuçları sıralamaz, bu nedenle ilk ve son zaman damgasını almak için ilk ve son satırlara bakamazsınız.
İlk ve son zaman damgalarını tam olarak bilmiyorsanız, tüm sonuçlara sahip olmak için Kibana'da ilk tarihi 2007 yılı ve son günü `now` olarak ayarlayın.

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

Artık `Total Records` değerini ve içe aktarılan olayların ilk ve son zaman damgalarını görmelisiniz.

Tüm olayları içe aktarmak bazen biraz zaman alır, bu nedenle `Total Records` beklediğiniz sayıya ulaşana kadar sayfayı yenilemeye devam edin.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

İçe aktarmanın başarılı olup olmadığını görmek için terminalden `sof-elk_clear.py -i list` çalıştırarak da kontrol edebilirsiniz.
`evtxlogs` dizininizin daha fazla kayda sahip olduğunu görmelisiniz:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

İçe aktarırken herhangi bir ayrıştırma hatasıyla karşılaşırsanız lütfen GitHub'da bir issue oluşturun.
Bunu `/var/log/logstash/logstash-plain.log` log dosyasının sonuna bakarak kontrol edebilirsiniz.

## Sonuçları Discover'da görüntüleme

Sol üst kenar çubuğu simgesine tıklayın ve `Discover`'a tıklayın:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

Muhtemelen `No results match your search criteria` mesajını göreceksiniz.

Sol üst köşede `logstash-*` dizininin yazdığı yere tıklayın ve onu `evtxlogs-*` olarak değiştirin.
Artık Discover zaman çizelgesini görmelisiniz.

## Sonuçları analiz etme

Varsayılan Discover görünümü buna benzer görünmelidir:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

Üstteki histograma bakarak olayların ne zaman gerçekleştiğine ve olayların sıklığına dair genel bir bakış elde edebilirsiniz. 

### Sütun ekleme

Sol taraftaki kenar çubuğunda, bir alanın üzerine geldikten sonra artı işaretine tıklayarak sütunlarda görüntülemek istediğiniz alanları ekleyebilirsiniz.
Birçok alan olduğundan, aradığınız alan adının adını arama kutusuna yazmak isteyebilirsiniz.

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

Başlamak için aşağıdaki sütunları öneririz:
- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

Monitörünüz yeterince genişse, tüm alan bilgilerini görmek için `ExtraFieldInfoText` de eklemek isteyebilirsiniz.

Discover görünümünüz şimdi şöyle görünmelidir:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### Filtreleme

Belirli olayları ve uyarıları aramak için KQL (Kibana Query Language) ile filtreleyebilirsiniz. Örneğin:
  * `Level: "crit"`: Yalnızca kritik uyarıları göster.
  * `Level: "crit" OR Level: "high"`: Yüksek ve kritik uyarıları göster.
  * `NOT Level: info`: Bilgilendirici olayları gösterme, yalnızca uyarıları göster.
  * `MitreTactics: *LatMov*`: Yatay hareketle ilgili olayları ve uyarıları göster.
  * `"PW Spray"`: Yalnızca "Password Spray" gibi belirli saldırıları göster.
  * `"LID: 0x8724ead"`: Logon ID 0x8724ead ile ilişkili tüm etkinlikleri görüntüle.
  * `Details_TgtUser: admmig`: Hedef kullanıcının `admmig` olduğu tüm olayları ara.

### Ayrıntıları açıp kapatma

Bir kayıttaki tüm alanları kontrol etmek için, zaman damgasının yanındaki simgeye (Toggle dialog with details) tıklamanız yeterlidir:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### Çevredeki belgeleri görüntüleme

Belirli bir uyarıdan hemen önceki ve sonraki olayları görüntülemek istiyorsanız, önce o uyarının ayrıntılarını açın ve ardından sağ üstteki `View surrounding documents`'a tıklayın:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

Bu örnekte, Pass the Hash saldırı uyarısından önceki ve sonraki olayları görüyoruz:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Not: Daha fazla olay almak için üstteki `Load x newer documents` veya alttaki `Load x older documents` sayılarını değiştirin.

### Alanlar üzerinde hızlı metrikler alma

Sol sütunda, bir alan adına tıklarsanız size kullanımıyla ilgili hızlı metrikler verecektir:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> Verilerin hız için örneklendiğini ve dolayısıyla %100 doğru olmadığını unutmayın.

## Gelecek Planları

* CSV için Logstash ayrıştırıcıları
* Önceden oluşturulmuş gösterge paneli
