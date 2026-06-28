# Hayabusa Sonuçlarını Timeline Explorer ile Analiz Etme

## Hakkında

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md), DFIR amaçlarıyla CSV dosyalarını analiz ederken Excel'in yerini almak için tasarlanmış ücretsiz ancak kapalı kaynak kodlu bir araçtır.
C# ile yazılmış, yalnızca Windows üzerinde çalışan bir GUI aracıdır.
Bu araç, tek bir analist tarafından yürütülen küçük soruşturmalar ve DFIR analizini yeni öğrenmeye başlayan kişiler için harikadır; ancak arayüz ilk başta anlaşılması zor olabilir, bu nedenle farklı özellikleri anlamak için lütfen bu kılavuzu kullanın.

## Kurulum ve Çalıştırma

Uygulamayı kurmaya gerek yoktur.
Yalnızca en son sürümü [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) adresinden indirin, sıkıştırılmış dosyayı açın ve `TimelineExplorer.exe` dosyasını çalıştırın.
Uygun .NET çalışma zamanına sahip değilseniz, onu kurmanız gerektiğini bildiren bir mesaj görünecektir.
Bu yazının yazıldığı tarih itibarıyla (2025/2/14), en son sürüm `9` sürümlü .NET üzerinde çalışan `2.1.0` sürümüdür.

## Bir CSV dosyası yükleme

Bir CSV dosyası yüklemek için menüden `File` -> `Open` öğesine tıklamanız yeterlidir.

Şuna benzer bir şey göreceksiniz:

![İlk Başlatma](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

En altta dosya adını, `Total lines` ve `Visible lines` değerlerini görebilirsiniz.

CSV dosyasında bulunan sütunların yanı sıra, sol tarafta Timeline Explorer tarafından eklenen iki sütun vardır: `Line` ve `Tag`.
`Line`, satır numarasını gösterir ancak genellikle soruşturmalar için kullanışlı değildir, bu nedenle bu sütunu gizlemek isteyebilirsiniz.
`Tag`, daha sonra ileri analiz için not almak istediğiniz olaylara bir işaret koymanıza olanak tanır vb...
Maalesef, CSV dosyası verilerin üzerine yazılmasını önlemek için salt okunur modda açıldığından, olaylara özel etiketler eklemenin veya olaylar hakkında yorum yazmanın bir yolu yoktur.

## Veri Filtreleme

Farenizi bir başlığın sağ üst kısmına getirirseniz, siyah bir filtre simgesinin belirdiğini görürsünüz.

![Temel Veri Filtreleme](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

Önce `high` ve `crit` (`critical`) uyarılarına öncelik vermek için önem derecesine işaret koyabilirsiniz.
Bu filtreleme, ayrıca `Rule Title` altındaki her şeyi işaretleyip ardından gürültülü kuralların işaretini kaldırarak gürültülü uyarıları filtrelemek için de çok kullanışlıdır.

Aşağıda gösterildiği gibi, `Text Filters` öğesine tıklarsanız daha gelişmiş filtreler oluşturabilirsiniz:

![Gelişmiş Veri Filtreleme](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

Ancak burada filtre oluşturmak yerine, genellikle başlığın altındaki `ABC` simgesine tıklayıp filtreleri burada uygulamak daha kolaydır:

![ABC Filtreleme](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

Maalesef, bu iki yer biraz farklı filtreleme seçenekleri sunar, bu nedenle veriler üzerinde filtreleme yapmak için her iki yerin de farkında olmalısınız.

Örneğin, filtrelemek istediğiniz çok fazla `Proc Exec` olayınız varsa, bu olayları yok saymak için `Does not contain` seçeneğini seçip `Proc Exec` yazabilirsiniz:

![Kural Filtreleme](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

Aşağıya doğru baktığınızda, filtre kuralını farklı renklerde görebilirsiniz.
Filtreyi geçici olarak devre dışı bırakmak isterseniz, işaretini kaldırmanız yeterlidir.
Tüm filtreleri temizlemek isterseniz, `X` düğmesine tıklayın.

Başka bir gürültülü kuralı yok saymak isterseniz, sağ alt köşedeki `Edit Filter` öğesine tıklayarak `Filter Editor` açmalısınız:

![Filtre Düzenleyici](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

`Not Contains([Rule Title], 'Proc Exec')` metnini kopyalayın, `and` ekleyin, aynı filtreyi yapıştırın ve `Proc Exec` ifadesini `Possible LOLBIN` olarak değiştirin; artık bu iki kuralı yok sayabilirsiniz:

![Çoklu Filtreler](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

Birden fazla filtreyi birleştirmenin en kolay yolu, önce `ABC` simgesinden filtre söz dizimini oluşturmak, ardından bu metni kopyalayıp yapıştırarak düzenlemek ve filtreleri `and`, `or` ve `not` ile birleştirmektir.

Filtrelerinizi düzenlemek için olası seçeneklerin yer aldığı bir açılır kutu elde etmek üzere herhangi bir renkli metne de tıklayabilirsiniz:

![Açılır menüyle düzenleme](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Başlık Seçenekleri

Başlıklardan herhangi birine sağ tıklarsanız, aşağıdaki seçenekleri elde edersiniz:

![Başlık Seçenekleri](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

Bu seçeneklerin çoğu açıklamayı gerektirmez.

* Bir sütunu gizledikten sonra, `Column Chooser` öğesini açıp sütun adına sağ tıklayarak ve `Show Column` öğesine tıklayarak onu tekrar gösterebilirsiniz.
* `Group By This Column`, bir sütun başlığını yukarıya sürükleyerek gruplama yapmakla aynı etkiye sahiptir. (Daha sonra ayrıntılı olarak açıklanmıştır.)
* `Hide Group By Box`, yalnızca `Drag a column header here to group by that column` metnini gizler ve arama çubuğunu kenara taşır.

### Koşullu Biçimlendirme

`Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...` öğelerine tıklayarak metni renk, kalın yazı tipi vb. ile biçimlendirebilirsiniz:

![Koşullu Biçimlendirme](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

Örneğin, `critical` uyarılarını `Red Fill` ile göstermek isterseniz, yalnızca `crit` yazın ve seçeneklerden `Red Fill` öğesini seçin, `Apply formatting to an entire row` öğesini işaretleyin ve `OK` düğmesine basın.

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

Artık `critical` uyarıları aşağıda gösterildiği gibi kırmızı renkte görünecektir:

![Kırmızı dolgu](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

Bunu `low`, `medium` ve `high` uyarıları için de renk ekleyerek sürdürebilirsiniz.

## Arama

Varsayılan olarak, arama çubuğuna bir metin yazdığınızda filtreleme yapar ve yalnızca satırın bir yerinde o metni içeren sonuçları gösterir.
Alttaki `Visible lines` alanını kontrol ederek kaç isabetiniz olduğunu görebilirsiniz.

Bu davranışı en sağ alttaki `Search options` öğesine tıklayarak değiştirebilirsiniz.
Bu, aşağıdakileri gösterecektir:

![Arama Seçenekleri](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

`Behavior` ayarını `Filter` yerine `Search` olarak değiştirirseniz, metni normal şekilde arayabilirsiniz.

> Not: Davranışı değiştirmek genellikle zaman alır ve Timeline Explorer bir süre takılır, bu yüzden tıkladıktan sonra sabırlı olun.

Varsayılan `Match criteria` değeri `Mixed`'dir ancak `Or`, `And` veya `Exact` olarak değiştirilebilir.
`Mixed` dışında herhangi bir değere değiştirirseniz, `Condition` değerini `Contains` yerine `Starts with`, `Like` veya `Equals` olarak ayarlayabilirsiniz.

`Mixed` `Match criteria` değeri karmaşıktır çünkü bazen `AND` mantığını, bazen de `OR` mantığını kullanır ancak öğrenildikten sonra çok esnek olabilir.
Şu şekilde çalışır:

* Kelimeleri boşluklarla ayırırsanız, `OR` mantığı olarak değerlendirilir.
* Aramanıza boşluk eklemek isterseniz, tırnak işareti eklemeniz gerekir.
* Bir koşulun önüne `+` koyarak `AND` mantığı uygulayın.
* Bir koşulun önüne `-` koyarak sonuçları hariç tutun.
* `ColumnName:FilterString` biçimiyle belirli bir sütun üzerinde filtreleyin.
* Belirli bir sütun üzerinde filtreleyip ayrıca ayrı bir anahtar kelime de eklerseniz, `AND` mantığı olur.

Örnekler:
| Arama Ölçütü                  | Açıklama                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Herhangi bir arama sütununda `mimikatz` dizesini içeren kayıtları seçer.                                                                        |
| one two three                    | Herhangi bir arama sütununda `one` VEYA `two` VEYA `three` içeren kayıtları seçer.                                                             |
| "hoge hoge"                      | Herhangi bir arama sütununda `hoge hoge` içeren kayıtları seçer.                                                                                  |
| mimikatz +"Bad Guy"              | Herhangi bir arama sütununda hem `mimikatz` HEM DE `Bad Guy` içeren kayıtları seçer.                                                                |
| EventID:4624 kali                | `EventID` ile başlayan sütunda `4624` içeren VE herhangi bir arama sütununda `kali` içeren kayıtları seçer.                          |
| data +entry -mark                | Herhangi bir arama sütununda hem `data` HEM DE `entry` içeren, `mark` içeren kayıtları hariç tutan kayıtları seçer.                               |
| manu mask -file                  | `menu` VEYA `mask` içeren, `file` içeren kayıtları hariç tutan kayıtları seçer.                                                           |
| From:Roller Subj:"currency mask" | `From` ile başlayan sütunda `Roller` içeren VE `Subj` ile başlayan sütunda `currency mask` içeren kayıtları seçer. |
| import -From:Steve               | Herhangi bir arama sütununda `import` içeren, `From` ile başlayan sütunda `Steve` içeren kayıtları hariç tutan kayıtları seçer.       |

## Sütunları dondurma

Bir arama seçeneği olmasa da, `Search options` menüsü altında `First scrollable column` değerini yapılandırabilirsiniz.
Çoğu analist, belirli olayların ne zaman gerçekleştiğini her zaman görebilmek için bunu `Timestamp` olarak ayarlar.

## Gruplamak için sütun başlıklarını sürükleme

Bir sütun başlığını `Drag a column header here to group by that column` alanına sürüklerseniz, Timeline Explorer o sütuna göre gruplama yapar.
Uyarıları önem derecesine göre önceliklendirebilmek için `Level` değerine göre gruplama yapmak yaygındır:

![Gruplama](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

Sonuçlarınızda birden fazla bilgisayar varsa, her bilgisayar için farklı önem derecelerine göre önceliklendirme yapmak üzere `Computer` değerine göre daha ileri gruplama yapabilirsiniz.

## Alanları kontrol etme

Varsayılan olarak, Hayabusa alan verilerini kırık dikey çubuk sembolüyle ayırır: `¦`.
Alan verileri yatay bir satırda olduğunda, bu karakter günlüklerde sık bulunmadığından, birden fazla alanı ayırt etmeyi çok kolaylaştırır:

![Alan Bilgisi](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

Ancak bazen günlükte çok fazla alan bilgisi olur ve her şey tek bir ekrana sığmaz.
Bu durumda, tüm alan bilgisini gösteren bir açılır pencere elde etmek için hücreye çift tıklayabilirsiniz:

![Hücre İçeriği](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

Sorun şu ki, Timeline Explorer alan verilerini yalnızca yeni satır karakterleriyle (`CRLF`, `CR`, `LF`), virgüllerle ve sekmelerle biçimlendirmenize izin verir.

`-M, --multiline` seçeneğini kullanırsanız, alanları bir yeni satır karakteriyle ayırabilirsiniz ve bir hücrenin içeriğini açmak için çift tıkladığınızda doğru şekilde biçimlendirilir:

![Çok satırlı biçimlendirme](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

Sorun şu ki, artık zaman çizelgesinde yalnızca ilk alan gösterilecektir, bu nedenle diğer alan verilerini her kontrol etmek istediğinizde çift tıklayıp yeni bir pencere açmanız gerekir:

![Çok satırlı tek alan](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

Maalesef, Timeline Explorer zaman çizelgesi görünümünde birden fazla satırı desteklemez.

Bunu aşmak için, Hayabusa `v3.1.0` sürümünden itibaren alanları sekmelerle ayırabilirsiniz:

![Sekme ile ayırma](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

Bir alanın nerede bitip diğerinin nerede başladığını ayırt etmek biraz daha zordur.
Ayrıca, çift tıklayıp hücrenin içeriğini açtığınızda alanlar otomatik olarak biçimlendirilmez:

![Sekme ile ayırma biçimlendirilmemiş](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

Ancak, alttaki `Tab` öğesine ve ardından `Format` öğesine tıklarsanız, alanları okunması kolay bir görünüme biçimlendirebilirsiniz:

![Sekme ile ayırma biçimlendirilmiş](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Temalar

Karanlık modu vb. tercih ederseniz, renk temasını `Tools` -> `Skins` öğelerinden değiştirebilirsiniz...

## Oturumlar

Sütunları, görünümü özelleştirir, filtreler eklerseniz vb. ve bu ayarları daha sonrası için kaydetmek isterseniz, oturumunuzu `File` -> `Session` -> `Save` öğelerinden kaydettiğinizden emin olun.
