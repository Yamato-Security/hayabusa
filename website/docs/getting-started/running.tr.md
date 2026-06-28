# Hayabusa'yı Çalıştırma

## Dikkat: Anti-Virüs/EDR Uyarıları ve Yavaş Çalışma Süreleri

Hayabusa'yı çalıştırmaya çalışırken, hatta yalnızca `.yml` kurallarını indirirken bile anti-virüs veya EDR ürünlerinden bir uyarı alabilirsiniz; çünkü tespit imzasında `mimikatz` ve şüpheli PowerShell komutları gibi anahtar kelimeler bulunur.
Bunlar yanlış pozitiflerdir, bu yüzden hayabusa'nın çalışmasına izin vermek için güvenlik ürünlerinizde istisnalar yapılandırmanız gerekecektir.
Kötü amaçlı yazılım veya tedarik zinciri saldırıları konusunda endişeliyseniz, lütfen hayabusa kaynak kodunu kontrol edin ve ikili dosyaları kendiniz derleyin.

Özellikle yeniden başlatma sonrası ilk çalıştırmada, Windows Defender'ın gerçek zamanlı korumasından dolayı yavaş çalışma süresi yaşayabilirsiniz.
Gerçek zamanlı korumayı geçici olarak kapatarak veya hayabusa çalışma dizinine bir istisna ekleyerek bunu önleyebilirsiniz.
(Bunları yapmadan önce lütfen güvenlik risklerini göz önünde bulundurun.)

## Windows

Bir Command/PowerShell Prompt veya Windows Terminal içinde, uygun 32-bit veya 64-bit Windows ikili dosyasını çalıştırmanız yeterlidir.

### Yolda boşluk bulunan bir dosya veya dizini taramaya çalışırken oluşan hata

Windows'ta yerleşik Command veya PowerShell istemini kullanırken, dosya veya dizin yolunuzda boşluk varsa Hayabusa'nın herhangi bir .evtx dosyası yükleyemediğine dair bir hata alabilirsiniz.
.evtx dosyalarını düzgün şekilde yüklemek için aşağıdakileri yaptığınızdan emin olun:
1. Dosya veya dizin yolunu çift tırnak içine alın.
2. Bir dizin yoluysa, son karakter olarak ters eğik çizgi (backslash) eklemediğinizden emin olun.

### Karakterlerin doğru görüntülenmemesi

Windows'taki varsayılan `Lucida Console` yazı tipiyle, logoda ve tablolarda kullanılan çeşitli karakterler düzgün görüntülenmeyecektir.
Bunu düzeltmek için yazı tipini `Consalas` olarak değiştirmelisiniz.

Bu, kapanış mesajlarındaki Japonca karakterlerin görüntülenmesi dışında metin işlemenin çoğunu düzeltecektir:

![Mojibake](../assets/screenshots/Mojibake.png)

Bunu düzeltmek için dört seçeneğiniz var:
1. Command veya PowerShell istemi yerine [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) kullanın. (Önerilen)
2. `MS Gothic` yazı tipini kullanın. Ters eğik çizgilerin Yen sembollerine dönüşeceğini unutmayın.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. [HackGen](https://github.com/yuru7/HackGen/releases) yazı tiplerini yükleyin ve `HackGen Console NF` kullanın.
4. Japonca içeren kapanış mesajlarını görüntülememek için `-q, --quiet` kullanın.

## Linux

Önce ikili dosyayı çalıştırılabilir yapmanız gerekir.

```bash
chmod +x ./hayabusa
```

Ardından Hayabusa kök dizininden çalıştırın:

```bash
./hayabusa
```

## macOS

Terminal veya iTerm2'den önce ikili dosyayı çalıştırılabilir yapmanız gerekir.

```bash
chmod +x ./hayabusa
```

Ardından, Hayabusa kök dizininden çalıştırmayı deneyin:

```bash
./hayabusa
```

macOS'un en son sürümünde, çalıştırmaya çalıştığınızda aşağıdaki güvenlik hatasını alabilirsiniz:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

"Cancel" düğmesine tıklayın ve ardından System Preferences'tan "Security & Privacy"yi açın ve General sekmesinden "Allow Anyway"e tıklayın.

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

Bundan sonra, tekrar çalıştırmayı deneyin.

```bash
./hayabusa
```

Aşağıdaki uyarı belirecektir, bu yüzden lütfen "Open"a tıklayın.

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

Artık hayabusa'yı çalıştırabilmeniz gerekir.
