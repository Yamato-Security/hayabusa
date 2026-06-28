# Розширено: Компіляція з вихідного коду (необов'язково)

Якщо у вас встановлено Rust, ви можете скомпілювати з вихідного коду за допомогою наступної команди:

Примітка: Для компіляції зазвичай потрібна остання версія Rust.

```bash
cargo build --release
```

Ви можете завантажити останню нестабільну версію з гілки main або останню стабільну версію зі сторінки [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Не забувайте періодично оновлювати Rust за допомогою:

```bash
rustup update stable
```

Скомпільований двійковий файл буде виведено в теку `./target/release`.

## Оновлення пакетів Rust

Ви можете оновитися до останніх крейтів Rust перед компіляцією:

```bash
cargo update
```

> Будь ласка, повідомте нам, якщо щось зламається після оновлення.

## Крос-компіляція 32-бітних двійкових файлів Windows

Ви можете створювати 32-бітні двійкові файли на 64-бітних системах Windows за допомогою наступного:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Попередження: Обов'язково запускайте `rustup install stable-i686-pc-windows-msvc` щоразу, коли з'являється нова стабільна версія Rust, оскільки `rustup update stable` не оновлює компілятор для крос-компіляції, і ви можете отримати помилки збірки.**

## Примітки щодо компіляції на macOS

Якщо ви отримуєте помилки компіляції щодо openssl, вам потрібно встановити [Homebrew](https://brew.sh/), а потім встановити наступні пакети:

```bash
brew install pkg-config
brew install openssl
```

## Примітки щодо компіляції на Linux

Потрібні наступні залежності для збірки:
* openssl-devel (на основі Fedora) / libssl-dev (на основі Ubuntu) 
* perl
* musl-gcc

## Крос-компіляція двійкових файлів Linux MUSL

В ОС Linux спочатку встановіть ціль.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Скомпілюйте за допомогою:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Попередження: Обов'язково запускайте `rustup install stable-x86_64-unknown-linux-musl` щоразу, коли з'являється нова стабільна версія Rust, оскільки `rustup update stable` не оновлює компілятор для крос-компіляції, і ви можете отримати помилки збірки.**

Двійковий файл MUSL буде створено в каталозі `./target/x86_64-unknown-linux-musl/release/`.
Двійкові файли MUSL приблизно на 15% повільніші за двійкові файли GNU, проте вони більш портативні між різними версіями та дистрибутивами linux.
