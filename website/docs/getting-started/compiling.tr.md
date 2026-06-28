# İleri Düzey: Kaynaktan Derleme (İsteğe Bağlı)

Rust kuruluysa, aşağıdaki komutla kaynaktan derleyebilirsiniz:

Not: Derlemek için genellikle Rust'ın en son sürümüne ihtiyacınız vardır.

```bash
cargo build --release
```

En son kararsız sürümü main dalından veya en son kararlı sürümü [Releases](https://github.com/Yamato-Security/hayabusa/releases) sayfasından indirebilirsiniz.

Rust'ı düzenli olarak şu komutla güncellediğinizden emin olun:

```bash
rustup update stable
```

Derlenen ikili dosya `./target/release` klasörüne çıktılanacaktır.

## Rust Paketlerinin Güncellenmesi

Derlemeden önce en son Rust crate'lerine güncelleyebilirsiniz:

```bash
cargo update
```

> Güncelleme sonrasında bir şey bozulursa lütfen bize bildirin.

## 32-bit Windows İkili Dosyalarını Çapraz Derleme

64-bit Windows sistemlerinde aşağıdakilerle 32-bit ikili dosyalar oluşturabilirsiniz:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Uyarı: `rustup update stable` çapraz derleme için derleyiciyi güncellemeyeceğinden ve derleme hataları alabileceğinizden, Rust'ın yeni bir kararlı sürümü çıktığında her seferinde `rustup install stable-i686-pc-windows-msvc` komutunu çalıştırdığınızdan emin olun.**

## macOS Derleme Notları

openssl ile ilgili derleme hataları alırsanız, [Homebrew](https://brew.sh/) kurmanız ve ardından aşağıdaki paketleri kurmanız gerekir:

```bash
brew install pkg-config
brew install openssl
```

## Linux Derleme Notları

Aşağıdaki derleme bağımlılıkları gereklidir:

* openssl-devel (Fedora tabanlı) / libssl-dev (Ubuntu tabanlı) 
* perl
* musl-gcc

## Linux MUSL İkili Dosyalarını Çapraz Derleme

Bir Linux işletim sisteminde, önce hedefi kurun.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Şununla derleyin:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Uyarı: `rustup update stable` çapraz derleme için derleyiciyi güncellemeyeceğinden ve derleme hataları alabileceğinizden, Rust'ın yeni bir kararlı sürümü çıktığında her seferinde `rustup install stable-x86_64-unknown-linux-musl` komutunu çalıştırdığınızdan emin olun.**

MUSL ikili dosyası `./target/x86_64-unknown-linux-musl/release/` dizininde oluşturulacaktır.
MUSL ikili dosyaları GNU ikili dosyalarından yaklaşık %15 daha yavaştır, ancak farklı linux sürümleri ve dağıtımları arasında daha taşınabilirdir.
