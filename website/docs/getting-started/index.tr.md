# İndirmeler

Lütfen Hayabusa'nın derlenmiş ikili dosyalara sahip en son kararlı sürümünü indirin veya kaynak kodunu [Releases](https://github.com/Yamato-Security/hayabusa/releases) sayfasından derleyin.

Aşağıdaki mimariler için ikili dosyalar sağlıyoruz:

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [Bazı nedenlerden dolayı Linux ARM MUSL ikili dosyası düzgün çalışmadığı için](https://github.com/Yamato-Security/hayabusa/issues/1332) bu ikili dosyayı sağlamıyoruz. Bu bizim kontrolümüz dışında olduğundan, sorun giderildiğinde gelecekte sağlamayı planlıyoruz.

## Windows canlı yanıt paketleri

v2.18.0 itibarıyla, tek bir dosyada sağlanan XOR ile kodlanmış kuralları ve tüm yapılandırma dosyalarının tek bir dosyada birleştirildiği özel Windows paketleri sağlıyoruz ([hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules) üzerinde barındırılmaktadır).
Sadece adında `live-response` bulunan zip paketlerini indirin.
Zip dosyaları yalnızca üç dosya içerir: Hayabusa ikili dosyası, XOR ile kodlanmış kurallar dosyası ve yapılandırma dosyası.
Bu canlı yanıt paketlerinin amacı, Hayabusa'yı istemci uç noktalarında çalıştırırken, Windows Defender gibi antivirüs tarayıcılarının `.yml` kural dosyalarında yanlış pozitif vermediğinden emin olmaktır.
Ayrıca, USN Journal gibi adli bilişim eserlerinin üzerine yazılmaması için sisteme yazılan dosya miktarını en aza indirmek istiyoruz.
