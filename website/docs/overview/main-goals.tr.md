# Ana Hedefler

## Tehdit Avı ve Kurumsal Çapta DFIR

Hayabusa şu anda 4000'den fazla Sigma kuralına ve 170'ten fazla Hayabusa yerleşik tespit kuralına sahiptir ve düzenli olarak daha fazla kural eklenmektedir.
[Velociraptor](https://docs.velociraptor.app/)'un [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/)'ı ile kurumsal çapta proaktif tehdit avı için olduğu kadar DFIR (Dijital Adli Bilişim ve Olay Müdahalesi) için de ücretsiz olarak kullanılabilir.
Bu iki açık kaynaklı aracı birleştirerek, ortamda kurulu bir SIEM olmadığında esasen geriye dönük olarak bir SIEM'i yeniden oluşturabilirsiniz.
Bunun nasıl yapılacağını [Eric Capuano](https://twitter.com/eric_capuano)'nun Velociraptor adım adım anlatımını [buradan](https://www.youtube.com/watch?v=Q1IoGX--814) izleyerek öğrenebilirsiniz.

## Hızlı Adli Bilişim Zaman Çizelgesi Oluşturma

Windows olay günlüğü analizi geleneksel olarak çok uzun ve sıkıcı bir süreç olmuştur, çünkü Windows olay günlükleri 1) analiz edilmesi zor bir veri formatındadır ve 2) verilerin çoğu gürültüdür ve soruşturmalar için yararlı değildir.
Hayabusa'nın hedefi yalnızca yararlı verileri çıkarmak ve bunları yalnızca profesyonel olarak eğitilmiş analistler tarafından değil, herhangi bir Windows sistem yöneticisi tarafından da kullanılabilecek, mümkün olduğunca özlü ve okunması kolay bir formatta sunmaktır.
Hayabusa, analistlerin geleneksel Windows olay günlüğü analiziyle karşılaştırıldığında işlerinin %80'ini sürenin %20'sinde tamamlamalarını sağlamayı umuyor.

![DFIR Zaman Çizelgesi](../assets/doc/DFIR-TimelineCreation-EN.png)
