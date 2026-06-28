# Çıktı Görüntüleme ve Özet

## İlerleme Çubuğu

İlerleme çubuğu yalnızca birden fazla evtx dosyasıyla çalışır.
Analiz etmeyi tamamladığı evtx dosyalarının sayısını ve yüzdesini gerçek zamanlı olarak görüntüler.

## Renkli Çıktı

Uyarılar, uyarı `level` değerine göre renkli olarak çıktılanır.
Varsayılan renkleri `./config/level_color.txt` konumundaki yapılandırma dosyasında `level,(RGB 6-digit ColorHex)` biçiminde değiştirebilirsiniz.
Renkli çıktıyı devre dışı bırakmak isterseniz, `-K, --no-color` seçeneğini kullanabilirsiniz.

## Sonuç Özeti

Toplam olaylar, isabet alan olayların sayısı, veri azaltma ölçümleri, toplam ve benzersiz tespitler, en çok tespit içeren tarihler, en çok tespit içeren bilgisayarlar ve en üst uyarılar her taramadan sonra görüntülenir.

### Tespit Sıklığı Zaman Çizelgesi

`-T, --visualize-timeline` seçeneğini eklerseniz, Olay Sıklığı Zaman Çizelgesi özelliği tespit edilen olayların ışıltı çizgisi (sparkline) sıklık zaman çizelgesini görüntüler.
Not: 5'ten fazla olay olması gerekir. Ayrıca, karakterler varsayılan Komut İstemi veya PowerShell İstemi üzerinde doğru şekilde işlenmez, bu nedenle lütfen Windows Terminal, iTerm2 vb. gibi bir terminal kullanın...
