# Hayabusa Sonuçlarını jq ile Analiz Etme

# Yazar

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# Hakkında

Günlüklerdeki önemli alanları tanımlayabilmek, çıkarabilmek ve bunlara karşı metrikler oluşturabilmek, DFIR ve tehdit avcılığı analistleri için temel bir beceridir.
Hayabusa sonuçları, zaman çizelgesi analizi için Excel veya Timeline Explorer gibi programlara aktarmak amacıyla genellikle `.csv` dosyalarına kaydedilir.
Ancak, aynı olaydan yüzlerce veya daha fazla olduğunda, bunları manuel olarak kontrol etmek pratik olmaktan çıkar veya imkânsız hale gelir.
Bu durumlarda, analistler genellikle aykırı değerleri arayarak benzer veri türlerini sıralar ve sayar.
Bu, uzun kuyruk analizi, yığın sıralaması, frekans analizi vb. olarak da bilinir.
Bu, sonuçları `.json` veya `.jsonl` dosyalarına çıkararak ve ardından `jq` ile analiz ederek Hayabusa ile gerçekleştirilebilir.

Örneğin, bir analist bir kurumdaki tüm iş istasyonlarına yüklenmiş hizmetleri karşılaştırabilir.
Belirli bir kötü amaçlı yazılım parçasının her iş istasyonuna yüklenmesi mümkün olsa da, büyük olasılıkla yalnızca birkaç sistemde bulunacaktır.
Bu durumda, tüm sistemlere yüklenmiş hizmetlerin zararsız olma olasılığı daha yüksektir, nadir hizmetler ise daha şüpheli olma eğilimindedir ve periyodik olarak kontrol edilmelidir.

Bir başka kullanım senaryosu da bir şeyin ne kadar şüpheli olduğunu belirlemeye yardımcı olmaktır.
Örneğin, bir analist belirli bir IP adresinin kaç kez oturum açmayı başaramadığını belirlemek için `4625` başarısız oturum açma günlüklerini analiz edebilir.
Yalnızca birkaç başarısız oturum açma varsa, muhtemelen bir yönetici parolasını yanlış yazmıştır.
Ancak, belirli bir IP adresi tarafından kısa bir süre içinde yüzlerce veya daha fazla başarısız oturum açma varsa, muhtemelen IP adresi kötü amaçlıdır.

`jq` kullanmayı öğrenmek, yalnızca Windows olay günlüklerini değil, tüm JSON biçimli günlükleri analiz etmede ustalaşmanıza yardımcı olur.
JSON çok popüler bir günlük biçimi haline geldiğinden ve çoğu bulut sağlayıcısı günlükleri için bunu kullandığından, bunları `jq` ile ayrıştırabilmek modern güvenlik analisti için temel bir beceri haline gelmiştir.

Bu kılavuzda, önce `jq`'yu daha önce hiç kullanmamış olanlar için nasıl kullanacağımı açıklayacağım, ardından gerçek dünya örnekleriyle birlikte daha karmaşık kullanımları açıklayacağım.
`jq`'yu `sort`, `uniq`, `grep`, `sed` vb. gibi diğer kullanışlı komutlarla birleştirebilmek için linux, macOS veya Windows üzerinde linux kullanmanızı öneririm.

# jq Kurulumu

Lütfen [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) adresine bakın ve `jq` komutunu kurun.

# JSON Biçimi Hakkında

JSON günlükleri, süslü parantezler `{` `}` içinde yer alan bir nesneler listesidir.
Bu nesnelerin içinde iki nokta üst üste ile ayrılmış anahtar-değer çiftleri bulunur.
Anahtarlar dizgi olmalıdır, ancak değerler aşağıdakilerden biri olabilir:
  * dizgi (Örn: `"string"`)
  * sayı (Örn: `10`)
  * başka bir nesne (Örn: `{ xxxx }`)
  * dizi (Örn: `["string", 10]`)
  * boolean (Örn: `true`, `false`)
  * `null`

Nesnelerin içine istediğiniz kadar nesne yerleştirebilirsiniz.

Bu örnekte, `Details` bir kök nesne içinde yer alan iç içe bir nesnedir:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Hayabusa ile JSON ve JSONL Biçimleri Hakkında

Önceki sürümlerde, Hayabusa tüm `{ xxx }` günlük nesnelerini tek bir dev dizinin içine koyan geleneksel JSON biçimini kullanırdı.

Örnek:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

Bunun iki sorunu vardır.
İlk sorun, `jq` sorgularının her şeyin o diziye bakması gerektiğini söyleyen fazladan bir `.[]` ile başlaması gerektiğinden daha hantal hale gelmesidir.
Çok daha büyük sorun ise, böyle günlükleri herhangi bir şeyin ayrıştırabilmesi için önce dizideki tüm verilerin yüklenmesinin gerekli olmasıdır.
Bu, çok büyük JSON dosyalarınız ve bol miktarda bellek yoksa bir sorun haline gelir.
Gerekli CPU ve bellek kullanımını azaltmak için, her şeyi dev bir diziye koymayan JSONL (JSON Lines) biçimi daha popüler hale gelmiştir.
Hayabusa, JSON ve JSONL biçimlerinde çıktı verir, ancak JSON biçimi artık bir dizinin içine kaydedilmez.
Tek fark, JSON biçiminin bir metin düzenleyicide veya konsolda okunmasının daha kolay olması, JSONL biçiminin ise her JSON nesnesini tek bir satırda saklamasıdır.
JSONL biçimi biraz daha hızlı ve boyut olarak daha küçük olacaktır, bu nedenle günlükleri yalnızca bir SIEM vb.'ye aktaracaksanız ancak bunlara bakmayacaksanız idealdir.
JSON biçimi, ayrıca bazı manuel kontroller de yapacaksanız idealdir.

# JSON Sonuç Dosyaları Oluşturma

Hayabusa'nın mevcut 2.x sürümünde, sonuçları JSON olarak `hayabusa json-timeline -d <directory> -o results.json` ile veya JSONL biçimi için `hayabusa json-timeline -d <directory> -J -o results.jsonl` ile kaydedebilirsiniz.

Hayabusa varsayılan `standard` profilini kullanır ve `Details` nesnesinde analiz için yalnızca asgari miktarda veriyi kaydeder.
.evtx günlüklerindeki tüm orijinal alan bilgisini kaydetmek isterseniz, `--profile all-field-info` seçeneği ile `all-field-info` profilini kullanabilirsiniz.
Bu, tüm alan bilgisini `AllFieldInfo` nesnesine kaydeder.
Her ihtimale karşı hem `Details` hem de `AllFieldInfo` nesnelerini kaydetmek isterseniz, `super-verbose` profilini kullanabilirsiniz.

## Details'i AllFieldInfo Yerine Kullanmanın Faydaları

`Details`'i `AllFieldInfo` yerine kullanmanın ilk faydası, yalnızca önemli alanların kaydedilmesi ve dosya alanından tasarruf etmek için alan adlarının kısaltılmış olmasıdır.
Olumsuz yanı, aslında önemsediğiniz ancak gözden kaçırılan verileri kaçırma olasılığının bulunmasıdır.
İkinci fayda, Hayabusa'nın alan adlarını normalleştirerek alanları daha tekdüze bir şekilde kaydetmesidir.
Örneğin, orijinal Windows günlüklerinde, kullanıcı adı genellikle bir `SubjectUserName` veya `TargetUserName` alanında bulunur. 
Ancak, bazen kullanıcı adı bir `AccountName` alanında olur, bazen hedef kullanıcı aslında `SubjectUserName` alanında olur vb.
Ne yazık ki, Windows olay günlüklerinde birçok tutarsız alan adı vardır.
Hayabusa bu alanları normalleştirmeye çalışır, böylece bir analistin Windows'taki olay kimlikleri arasındaki sonsuz sayıda tuhaflığı ve tutarsızlığı anlamak zorunda kalmadan yalnızca ortak bir adı ayrıştırması yeterli olur.

İşte kullanıcı alanına bir örnek.
Hayabusa, `SubjectUserName`, `TargetUserName`, `AccountName` vb.'yi aşağıdaki şekilde normalleştirir:
  * `SrcUser` (Kaynak Kullanıcı): bir eylem bir kullanıcı**dan** gerçekleştiğinde. (Genellikle uzak bir kullanıcı.)
  * `TgtUser` (Hedef Kullanıcı): bir eylem bir kullanıcı**ya** gerçekleştiğinde. (Örneğin, bir kullanıcı**ya** oturum açma.)
  * `User`: bir eylem o anda oturum açmış bir kullanıcı tarafından gerçekleştiğinde. (Eylemde belirli bir yön yoktur.)

Bir başka örnek de süreçlerdir.
Orijinal Windows olay günlüklerinde, süreç alanı birden fazla adlandırma kuralıyla anılır: `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName` vb.
Alan normalleştirmesi olmadan, bir analistin önce tüm farklı alan adları hakkında bilgi sahibi olması, ardından bu alan adlarına sahip tüm günlükleri çıkarması, sonra da bunları bir araya getirmesi gerekirdi. 

Bir analist, Hayabusa'nın `Details` nesnesinde sağladığı normalleştirilmiş tek `Proc` alanını kullanarak çok fazla zaman ve zahmetten tasarruf edebilir.

# jq Dersleri/Tarifleri

Şimdi işinizde size yardımcı olabilecek pratik örneklerden oluşan birkaç ders/tarif listeleyeceğim.

## 1. jq ve Less ile Renkli Manuel Kontrol

Bu, günlüklerde hangi alanların bulunduğunu anlamak için yapılacak ilk şeylerden biridir.
Basitçe bir `less results.json` yapabilirsiniz, ancak daha iyi bir yol aşağıdaki gibidir:
`cat results.json | jq -C | less -R`

`jq`'ya geçirerek, başlangıçta düzgün biçimlendirilmemişlerse tüm alanları sizin için düzgün bir şekilde biçimlendirir.
`jq` ile `-C` (renk) seçeneğini ve `less` ile `-R` (ham çıktı) seçeneğini kullanarak renkli olarak yukarı ve aşağı kaydırabilirsiniz.

## 2. Metrikler

Hayabusa, olay kimliklerine göre olayların sayısını ve yüzdesini yazdırma işlevine zaten sahiptir, ancak bunu `jq` ile nasıl yapacağınızı bilmek de iyidir.
Bu, metrik oluşturmak istediğiniz verileri özelleştirmenize olanak tanır.

Önce aşağıdaki komutla bir Olay Kimlikleri listesi çıkaralım:

`cat results.json | jq '.EventID'`

Bu, her günlükten yalnızca Olay Kimliği numarasını çıkaracaktır.
`jq`'dan sonra, tek tırnak içinde, sadece bir `.` ve çıkarmak istediğiniz alan adını yazın.
Bunun gibi uzun bir liste görmelisiniz:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Şimdi, olay kimliklerinin kaç kez gerçekleştiğini saymak için sonuçları `sort` ve `uniq -c` komutlarına geçirin:

`cat results.json | jq '.EventID' | sort | uniq -c`

`uniq` için `-c` seçeneği, benzersiz bir olay kimliğinin kaç kez gerçekleştiğini sayar.

Bunun gibi bir şey görmelisiniz:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 Sol taraf sayı, sağ taraf ise Olay Kimliğidir.
 Gördüğünüz gibi sıralanmamış, bu yüzden hangi olay kimliklerinin en çok gerçekleştiğini söylemek zor.

 Bunu düzeltmek için sona bir `sort -n` ekleyebilirsiniz:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

`-n` seçeneği `sort`'a sayıya göre sıralamasını söyler.

Bunun gibi bir şey görmelisiniz:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

`4688` (Süreç oluşturma) olaylarının en çok kaydedildiğini görebiliriz.
İkinci en çok kaydedilen olay `4625` (Başarısız Oturum Açma) idi.

En çok kaydedilen olayları en üstte yazdırmak isterseniz, sıralamayı `sort -n -r` veya `sort -nr` ile tersine çevirebilirsiniz.
Ayrıca sonuçları `head -n 10`'a geçirerek yalnızca en çok kaydedilen ilk 10 olayı da yazdırabilirsiniz.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

Bu size şunu verecektir:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

EID'lerin (Olay Kimlikleri) benzersiz olmadığını göz önünde bulundurmak önemlidir, bu nedenle aynı Olay Kimliğine sahip tamamen farklı olaylarınız olabilir.
Bu nedenle, `Channel`'ı da kontrol etmek önemlidir.

Bu alan bilgisini şu şekilde ekleyebiliriz:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Tüm alanları virgüllerle ayrılmış ve bir `\n` yeni satır karakteriyle bitecek şekilde birleştirmek için `jq`'ya `-j` (join) seçeneğini ekliyoruz.

Bu bize şunu verecektir:
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 Not: `Security`, `Sec` olarak; `System`, `Sys` olarak; ve `PowerShell`, `PwSh` olarak kısaltılır.

Kural başlığını şu şekilde ekleyebiliriz:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Bu bize şunu verecektir:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

Artık günlüklerden istediğiniz herhangi bir veriyi serbestçe çıkarabilir ve gerçekleşme sayısını sayabilirsiniz.

## 3. Belirli Verilere Göre Filtreleme

Çoğu zaman belirli Olay Kimlikleri, kullanıcılar, süreçler, LID'ler (Oturum Açma Kimlikleri) vb. üzerinde filtreleme yapmak isteyeceksiniz.
Bunu `jq` sorgusu içindeki `select` ile yapabilirsiniz.

Örneğin, tüm `4624` başarılı oturum açma olaylarını çıkaralım:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

Bu, EID `4624` için tüm JSON nesnelerini döndürecektir:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

Birden fazla koşulda filtreleme yapmak isterseniz, `and`, `or` ve `not` gibi anahtar kelimeleri kullanabilirsiniz.

Örneğin, türün `3` (Ağ oturum açması) olduğu `4624` olaylarını arayalım.

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

Bu, `EventID`'nin `4624` ve iç içe `"Details": { "Type" }` alanının `3` olduğu tüm nesneleri döndürecektir.

Ancak bir sorun var.
`jq: error (at <stdin>:10636): Cannot index string with string "Type"` diyen hatalar fark edebilirsiniz.
`Cannot index string with string` hatasını her gördüğünüzde, bu `jq`'ya var olmayan veya yanlış türde olan bir alanı çıkarmasını söylediğiniz anlamına gelir.
Alanın sonuna bir `?` ekleyerek bu hatalardan kurtulabilirsiniz.
Bu, `jq`'ya hataları yok saymasını söyler.

Örnek: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

Şimdi, belirli kriterlere göre filtreledikten sonra, ilgilendiğimiz belirli alanları seçmek için `jq` sorgusu içinde bir `|` kullanabiliriz.

Örneğin, hedef kullanıcı adı `TgtUser`'ı ve kaynak IP adresi `SrcIP`'yi çıkaralım:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

Yine, çıktı vermek için birden fazla alan seçmek amacıyla `jq`'ya `-j` (join) seçeneğini ekliyoruz.
Ardından, belirli bir IP adresinin tür 3 ağ oturum açması yoluyla bir kullanıcıya kaç kez oturum açtığını öğrenmek için önceki örneklerdeki gibi `sort`, `uniq -c` vb. çalıştırabilirsiniz.

## 4. Çıktıyı CSV Biçiminde Kaydetme

Ne yazık ki, Windows olay günlüklerindeki alanlar olay türüne göre tamamen farklılık gösterecektir, bu nedenle yüzlerce sütun olmadan alanlara göre virgülle ayrılmış zaman çizelgeleri oluşturmak kolayca mümkün değildir.
Ancak, tek tür olaylar için alanlarla ayrılmış zaman çizelgeleri oluşturmak mümkündür.
İki yaygın örnek, yanal hareketi ve parola tahmini/püskürtmesini kontrol etmek için Security `4624` (Başarılı Oturum Açmalar) ve `4625` (Başarısız Oturum Açmalar)'dır.

Bu örnekte, yalnızca Security 4624 günlüklerini çıkarıyor ve zaman damgasını, bilgisayar adını ve tüm `Details` bilgilerini veriyoruz.
Bunu `| @csv` kullanarak bir CSV dosyasına kaydediyoruz, ancak verileri bir dizi olarak geçirmemiz gerekiyor.
Bunu, daha önce yaptığımız gibi çıktı vermek istediğimiz alanları seçerek ve bunları bir diziye dönüştürmek için `[ ]` köşeli parantezlerle çevreleyerek yapabiliriz.

Örnek: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

Notlar:
  * `Details` nesnesindeki tüm alanları seçmek için `[]` ekleriz.
  * `Details`'in bir dizi değil de bir dizgi olduğu ve `Cannot iterate over string` hataları vereceği durumlar vardır, bu nedenle bir `?` eklemeniz gerekir.
  * Çift tırnakları ters eğik çizgi ile kaçırmamak için `jq`'ya `-r` (Ham çıktı) seçeneğini ekleriz.

Sonuçlar:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

Yalnızca kimlerin başarılı oturum açmaları olduğunu kontrol ediyorsak, son `LID` (Oturum Açma Kimliği) alanına ihtiyacımız olmayabilir.
İhtiyaç duyulmayan herhangi bir sütunu `del` işleviyle silebilirsiniz.

Örnek: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

Dizi `0`'dan saymaya başlar, bu nedenle 7. alanı kaldırmak için `6` kullanırız.

Artık `> 4624-logs.csv` ekleyerek CSV dosyasını kaydedebilir ve ardından daha fazla analiz için Excel veya Timeline Explorer'a aktarabilirsiniz.

Filtreleme yapmak için bir başlık eklemeniz gerekeceğini unutmayın.
`jq` sorgusu içinde bir başlık eklemek mümkün olsa da, genellikle dosyayı kaydettikten sonra üst satırı manuel olarak eklemek en kolayıdır.

## 5. En Çok Uyarıya Sahip Tarihleri Bulma

Hayabusa varsayılan olarak, önem düzeylerine göre en çok uyarıya sahip tarihleri size söyleyecektir.
Ancak, en çok uyarıya sahip ikinci, üçüncü vb. tarihleri de bulmak isteyebilirsiniz.
Bunu, ihtiyaçlarınıza bağlı olarak yıl, ay veya tarihe göre gruplamak için zaman damgasını dizgi dilimleme ile yapabiliriz.

Örnek: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]`, `jq`'ya `Timestamp`'ten yalnızca ilk 10 baytı çıkarmasını söyler.

Bu bize en çok olaya sahip tarihleri verecektir:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

En çok olaya sahip ayı öğrenmek isterseniz, ilk 7 baytı çıkarmak için `.[:10]`'u `.[:7]` olarak değiştirebilirsiniz.

En çok `high` uyarıya sahip tarihleri listelemek isterseniz, bunu şöyle yapabilirsiniz:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

İhtiyaçlarınıza bağlı olarak bilgisayar adına, olay kimliğine vb. göre `select` işlevine filtre koşulları eklemeye devam edebilirsiniz.

## 6. PowerShell Günlüklerini Yeniden Oluşturma

PowerShell günlüklerinin talihsiz bir yanı, günlüklerin genellikle birden fazla günlüğe bölünerek okunmalarını zorlaştırmasıdır.
Yalnızca saldırganın çalıştırdığı komutları çıkararak günlükleri çok daha kolay okunur hale getirebiliriz.

Örneğin, EID `4104` ScriptBlock günlükleriniz varsa, kolay okunur bir zaman çizelgesi oluşturmak için yalnızca o alanı çıkarabilirsiniz.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

Bu, aşağıdaki gibi bir zaman çizelgesiyle sonuçlanacaktır:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. Şüpheli Ağ Bağlantılarını Bulma

Önce aşağıdaki komutla tüm hedef IP adreslerinin bir listesini alabilirsiniz:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

Tehdit istihbaratınız varsa, IP adreslerinden herhangi birinin kötü amaçlı olduğunun bilinip bilinmediğini kontrol edebilirsiniz.

Belirli bir hedef IP adresine kaç kez bağlanıldığını aşağıdaki ile sayabilirsiniz:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

`TgtIP`'yi `SrcIP` olarak değiştirerek, kaynak IP adreslerine göre kötü amaçlı IP adresleri için aynı tehdit istihbaratı kontrolünü yapabilirsiniz.

Diyelim ki ortamınızdan bağlanılan `93.184.220.29` kötü amaçlı IP adresini bulduğunuzu varsayalım.
Bu olaylarla ilgili ayrıntıları aşağıdaki sorgu ile alabilirsiniz:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

Bu size şuna benzer JSON sonuçları verecektir:
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

Bağlantı kurulan etki alanlarını listelemek isterseniz, aşağıdaki komutu kullanabilirsiniz:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> Not: NETBIOS ana bilgisayar adlarını kaldırmak için `.` için bir grep filtresi ekledim.

## 8. Yürütülebilir İkili Dosya Hash Değerlerini Çıkarma

Sysmon EID `1` Süreç Oluşturma günlüklerinde, sysmon ikili dosyanın hash değerlerini hesaplamak üzere yapılandırılabilir.
Güvenlik analistleri bu hash değerlerini tehdit istihbaratı ile bilinen kötü amaçlı hash değerleriyle karşılaştırabilir.
`Hashes` alanını aşağıdaki ile çıkarabilirsiniz:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

Bu size şuna benzer bir hash listesi verecektir:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon genellikle `MD5`, `SHA1` ve `IMPHASH` gibi birden fazla hash hesaplar.
Bu hash değerlerini `jq`'da düzenli ifadelerle çıkarabilir veya daha iyi performans için sadece dizgi dilimleme kullanabilirsiniz.

Örneğin, MD5 hash değerlerini çıkarabilir ve yinelenenleri aşağıdaki ile kaldırabilirsiniz:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. PowerShell Günlüklerini Çıkarma

PowerShell Scriptblock günlükleri (EID: 4104) genellikle birçok günlüğe bölünür ve CSV biçimine çıktı verirken Hayabusa, çıktıyı daha öz hale getirmek için sekmeleri ve satır başı karakterlerini siler.
Ancak, powershell günlüklerini orijinal sekme ve satır başı karakteri biçimlendirmesiyle ve günlükleri bir araya getirerek analiz etmek en kolayıdır.
İşte VSCode vb. ile açıp analiz etmek amacıyla `COMPUTER-A`'dan PowerShell EID 4104 günlüklerini çıkarıp bir `.ps1` dosyasına kaydetmenin bir örneği.
ScriptBlock alanını çıkardıktan sonra, `\r\n` ve `\n`'yi satır başı karakterleriyle ve `\t`'yi sekmelerle değiştirmek için `awk` kullanırız.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

Analist günlükleri kötü amaçlı PowerShell komutları için analiz ettikten sonra, genellikle bu komutların ne zaman çalıştırıldığını araması gerekir.
İşte bir komutun çalıştırıldığı zamanı aramak amacıyla Zaman Damgasını ve PowerShell günlüklerini bir CSV dosyasına çıkarmanın bir örneği:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

Not: Kullanılan dizgi sınırlayıcı `¦`'dir çünkü tek ve çift tırnaklar PowerShell günlüklerinde sıklıkla bulunur ve CSV çıktısını bozar.
CSV dosyasını içe aktardığınızda, uygulamaya `¦` dizgi sınırlayıcısını belirtmeniz gerekir.
