# Hayabusa Sonuclarini Timesketch ile Analiz Etme

## Hakkinda

"[Timesketch](https://timesketch.org/), isbirlikci adli zaman cizelgesi analizi icin acik kaynakli bir aractir. Sketch'leri kullanarak siz ve isbirlikcileriniz zaman cizelgelerinizi kolayca duzenleyebilir ve hepsini ayni anda analiz edebilirsiniz. Ham verilerinize zengin aciklamalar, yorumlar, etiketler ve yildizlar ile anlam katin."

Yalnizca birkac yuz MB boyutunda bir CSV dosyasini analiz ettiginiz ve tek basina calistiginiz kucuk arastirmalar icin Timeline Explorer uygundur, ancak daha buyuk verilerle veya bir ekiple calisirken Timesketch gibi bir arac cok daha iyidir.

Timesketch su faydalari sunar:
1. Cok hizlidir ve buyuk verileri isleyebilir
2. Birden fazla kullanicinin ayni anda kullanabildigi isbirlikci bir aractir
3. Gelismis veri analizi, histogramlar ve gorsellestirmeler saglar
4. Windows ile sinirli degildir
5. Gelismis sorgulamayi destekler

CTI destegi, cesitli analizorler, etkilesimli not defterleri vb. gibi daha bircok fayda vardir...
Daha fazla bilgi icin lutfen [kullanici kilavuzuna](https://timesketch.org/guides/user/upload-data/) ve [YouTube kanalina](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) goz atin.

Tek dezavantaji, lab ortaminizda bir Timesketch sunucusu kurmaniz gerekmesidir, ancak neyse ki bu yapmasi cok kolaydir.

## Kurulum
### Docker
Resmi talimatlari [burada](https://docs.docker.com/compose/install) takip edin.

### Ubuntu
**Not:** Devam etmeden once Docker kurulmus olmalidir. Docker'i henuz kurmadiysaniz lutfen [yukaridaki Docker kurulum talimatlarini](#docker) takip edin.
En az 8GB bellege sahip en son Ubuntu LTS Server surumunu kullanmanizi oneririz.
Bunu [buradan](https://ubuntu.com/download/server) indirebilirsiniz.
Kurarken minimal kurulumu secin.
Isletim sistemini kurarken docker'i kurmayin.
`ifconfig` kullanilamayacak, bu yuzden onu `sudo apt install net-tools` ile kurun.

Bundan sonra, VM'nin IP adresini bulmak icin `ifconfig` calistirin ve istege bagli olarak ssh ile baglanin.

Asagidaki komutlari calistirin:
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**Not:** Devam etmeden once sisteminizde [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/) kurulu ve calisir durumda oldugundan emin olun.
Timesketch deposunu klonlayin ve dizine gecin.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
Asagidaki adimlari izleyerek Docker konteynerini baslatin.
- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Oturum acma

Timesketch sunucusunun IP adresini `ifconfig` ile bulun ve bir web tarayicisiyla acin.
Bir oturum acma sayfasina yonlendirileceksiniz.
Kullanici eklerken kullandiginiz kullanici kimlik bilgileriyle oturum acin.

## Yeni bir sketch olusturma

`Start a new investigation` altinda `BLANK SKETCH`'e tiklayin.
Sketch'i arastirmanizla ilgili bir seyle adlandirin.

## Zaman cizelgenizi yukleme

`+ ADD TIMELINE`'a tikladiktan sonra, sizden bir Plaso, JSONL veya CSV dosyasi yuklemenizi isteyen bir iletisim kutusu goreceksiniz.
Ne yazik ki, Timesketch su anda Hayabusa'nin `JSONL` formatini iceri aktaramamaktadir, bu nedenle asagidaki komutla bir CSV zaman cizelgesi olusturup yukleyin:

```shell
hayabusa-x.x.x-win-x64.exe csv-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --ISO-8601
```

> Not: Bir `timesketch*` profili secmek ve zaman damgasini UTC icin `--ISO-8601` veya yerel saat icin `--RFC-3339` olarak belirtmek gereklidir. Isterseniz diger Hayabusa seceneklerini ekleyebilirsiniz, ancak yeni satir karakterleri iceri aktarmayi bozacagindan `-M, --multiline` secenegini eklemeyin.

"Select file to upload" iletisim kutusunda, zaman cizelgenizi `hayabusa` gibi bir seyle adlandirin, `Comma (,)` CSV ayiricisini secin ve `SUBMIT`'e tiklayin.

> CSV dosyaniz yuklenemeyecek kadar buyukse, dosyayi Takajo'nun [split-csv-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-csv-timeline-command) komutuyla birden fazla CSV dosyasina bolebilirsiniz.

Dosya iceri aktarilirken donen bir daire goreceksiniz, bu yuzden lutfen islem bitene ve `hayabusa` gorunene kadar bekleyin.

## Analiz ipuclari

### Zaman cizelgesini gosterme

**Not: Iceri aktarma basariyla tamamlandiktan sonra bile `Your search did not match any events` gosterilecek ve `hayabusa` zaman cizelgesinde `0` olay olacaktir.**

`*` aramasi yapin ve olaylar asagida gosterildigi gibi gorunecektir:

![Timesketch sonuclari](../assets/doc/TimesketchImport/TimesketchResults.png)

### Uyari ayrintilari

`message` sutunu altinda bir uyari kural basligina tiklarsaniz, uyari hakkinda ayrintili bilgi alirsiniz:

![Uyari ayrintilari](../assets/doc/TimesketchImport/AlertDetails.png)

Sigma kural mantigini anlamak, aciklamayi ve referanslari vb. aramak istiyorsaniz... lutfen kurali [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) deposunda arayin.

#### Alan filtreleme

Bir olayin kural basligina tiklayarak ayrintilarini actiktan sonra, degeri kolayca dahil etmek veya haric tutmak icin herhangi bir alanin uzerine gelebilirsiniz:

![Dahil Et Haric Tut](../assets/doc/TimesketchImport/FilterInOut.png)

#### Toplama analitigi

Uzerine gelirken, en soldaki `Aggregation dialog` simgesine tiklarsaniz, o alanla ilgili gercekten harika olay verisi analitigi elde edersiniz:

![Olay Verisi Analitigi](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### Kullanici yorumlari

Ayrintili bilgi almak icin bir uyariya tikladiginizda, asagida gosterildigi gibi sag tarafta yeni bir yorum iletisim kutusu simgesi gosterilir:

![Yorum Simgesi](../assets/doc/TimesketchImport/CommentIcon.png)

Burada, kullanicilar bir sohbet baslatabilir ve arastirma hakkinda yorumlar yazabilir.

> Bir ekipte calisiyorsaniz, muhtemelen her uye icin farkli bir kullanici hesabi olusturmalisiniz, boylece kimin ne yazdigini bilirsiniz.

![Yorum sohbeti](../assets/doc/TimesketchImport/CommentChat.png)

> Bir yorumun uzerine gelirseniz, mesajlari kolayca duzenleyebilir ve silebilirsiniz.

### Sutunlari degistirme

Varsayilan olarak yalnizca zaman damgasi ve uyari kural basligi goruntulenecektir, bu nedenle alanlari ozellestirmek icin `Modify columns` simgelerine tiklayin:

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

Bu, asagidaki iletisim kutusunu acacaktir:

![Sutunlari sec](../assets/doc/TimesketchImport/SelectColumns.png)

En azindan asagidaki sutunlari **sirayla** eklemenizi oneririz:

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

Sutunlarin sirasi, onlari ekleme sirasina gore degisecektir, bu yuzden daha onemli alanlari once ekleyin.

Ekraninizda hala yer varsa, burada gosterildigi gibi `Details`'i de eklemenizi oneririz:

![Ayrintilar](../assets/doc/TimesketchImport/Details.png)

Ekraninizda hala yer varsa, `ExtraFieldInfo`'yu da eklemenizi oneririz, ancak burada gordugunuz gibi, cok fazla sutun eklerseniz `message` alani cok dar hale gelir ve uyari basliklarini artik okuyamazsiniz:

![Cok fazla ayrinti](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Ust simgeler

#### Uc nokta simgesi

`···` simgesine tiklarsaniz, satirlari daha kompakt hale getirebilir ve sonuclar icin daha fazla yer acmak amaciyla `Timeline name`'i kaldirabilirsiniz:

![Daha fazla yer](../assets/doc/TimesketchImport/MoreRoom.png)

#### Olay histogrami

Zaman cizelgesini gorsellestirmek icin olay histogramini acabilirsiniz:

![Olay Histogrami](../assets/doc/TimesketchImport/EventHistogram.png)

Cubuklardan birine tiklarsaniz, yalnizca o zaman dilimindeki sonuclari gostermek icin bir zaman filtresi olusturacaktir.

#### Mevcut aramayi kaydet

Zaman damgalarinin hemen ustunde ve `Toggle Event Histogram` simgesinin solunda bulunan `Save current search` simgesine tiklarsaniz, mevcut arama sorgunuzu ve sutun yapilandirmanizi `Saved Searches`'e kaydedebilirsiniz.
Daha sonra, sol taraftaki kenar cubugundan favori aramalariniza kolayca erisebilirsiniz.

### Arama cubugu

Iste yalnizca belirli onem duzeylerine sahip uyarilari gostererek baslamak icin bazi kullanisli sorgular:
1. Yalnizca kritik uyarilari gostermek icin `Level:crit`.
2. Yuksek ve kritik uyarilari gostermek icin `Level:crit OR Level:high`
3. Bilgilendirici uyarilari gizlemek icin `NOT Level:info`

Alan adini, arti `:`, arti degeri yazarak kolayca filtreleyebilirsiniz.
Filtreleri `AND`, `OR` ve `NOT` ile birlestirebilirsiniz.
Joker karakterler ve duzenli ifadeler desteklenir.

Daha gelismis sorgular icin [buradaki](https://timesketch.org/guides/user/search-query-guide/) kullanici kilavuzuna bakin.

#### Arama gecmisi

Arama cubugunun solundaki saat simgesine tiklarsaniz, daha once girilen sorgulari gosterebilirsiniz.
Onceki ve sonraki sorgulari calistirmak icin sol ve sag ok simgelerine de tiklayabilirsiniz.

![Arama Gecmisi](../assets/doc/TimesketchImport/SearchHistory.png)

### Dikey uc nokta

Bir zaman damgasinin solundaki dikey uc noktaya tiklarsaniz ve `Context search`'e tiklarsaniz, belirli bir olaydan once ve sonra gerceklesen uyarilari gorebilirsiniz:

![Dikey uc nokta](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

Bu sunu getirecektir:

![Baglam Aramasi](../assets/doc/TimesketchImport/ContextSearch.png)

Yukaridaki ornekte, 60 saniye (`60S`) once ve sonraki olaylar gosterilmektedir, ancak bunu +- 1 saniye (`1S`) ile +- 60 dakika (`60M`) arasinda ayarlayabilirsiniz.

Gosterilen olaylari daha fazla incelemek istiyorsaniz, olaylari standart zaman cizelgesinde gostermek icin `Replace Search`'e tiklayin.

### Yildizlar ve etiketler

Bir zaman damgasini yildizlamak ve onu onemli bir olay olarak not etmek icin solundaki yildiz simgesine tiklayabilirsiniz.

Olaylara etiket de ekleyebilirsiniz.
Bu, bir olayin supheli, kotu amacli, yanlis pozitif vb. oldugunu dogruladiginizi baskalarina belirtmek icin kullanislidir...
Bir ekipte calisiyorsaniz, birinin su anda uyariyi arastirdigini belirtmek icin `under investigation by xxx` gibi etiketler olusturabilirsiniz.

![Yildizlar ve etiketler](../assets/doc/TimesketchImport/StarsAndTags.png)
