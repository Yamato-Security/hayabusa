# Fortgeschritten: Kompilieren aus dem Quellcode (Optional)

Wenn Rust installiert ist, können Sie mit dem folgenden Befehl aus dem Quellcode kompilieren:

Hinweis: Zum Kompilieren benötigen Sie normalerweise die neueste Version von Rust.

```bash
cargo build --release
```

Sie können die neueste instabile Version vom main-Branch oder die neueste stabile Version von der [Releases](https://github.com/Yamato-Security/hayabusa/releases)-Seite herunterladen.

Stellen Sie sicher, dass Sie Rust regelmäßig aktualisieren mit:

```bash
rustup update stable
```

Die kompilierte Binärdatei wird im Ordner `./target/release` ausgegeben.

## Rust-Pakete aktualisieren

Sie können vor dem Kompilieren auf die neuesten Rust-Crates aktualisieren:

```bash
cargo update
```

> Bitte teilen Sie uns mit, falls nach dem Update etwas nicht mehr funktioniert.

## Cross-Kompilieren von 32-Bit-Windows-Binärdateien

Sie können auf 64-Bit-Windows-Systemen mit dem folgenden Befehl 32-Bit-Binärdateien erstellen:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Warnung: Stellen Sie sicher, dass Sie `rustup install stable-i686-pc-windows-msvc` immer dann ausführen, wenn es eine neue stabile Version von Rust gibt, da `rustup update stable` den Compiler für das Cross-Kompilieren nicht aktualisiert und Sie möglicherweise Build-Fehler erhalten.**

## Hinweise zum Kompilieren unter macOS

Wenn Sie Kompilierungsfehler bezüglich openssl erhalten, müssen Sie [Homebrew](https://brew.sh/) installieren und anschließend die folgenden Pakete installieren:

```bash
brew install pkg-config
brew install openssl
```

## Hinweise zum Kompilieren unter Linux

Die folgenden Build-Abhängigkeiten sind erforderlich:

* openssl-devel (Fedora-basiert) / libssl-dev (Ubuntu-basiert) 
* perl
* musl-gcc

## Cross-Kompilieren von Linux-MUSL-Binärdateien

Installieren Sie auf einem Linux-Betriebssystem zunächst das Target.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Kompilieren Sie mit:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Warnung: Stellen Sie sicher, dass Sie `rustup install stable-x86_64-unknown-linux-musl` immer dann ausführen, wenn es eine neue stabile Version von Rust gibt, da `rustup update stable` den Compiler für das Cross-Kompilieren nicht aktualisiert und Sie möglicherweise Build-Fehler erhalten.**

Die MUSL-Binärdatei wird im Verzeichnis `./target/x86_64-unknown-linux-musl/release/` erstellt.
MUSL-Binärdateien sind etwa 15 % langsamer als die GNU-Binärdateien, sie sind jedoch portabler über verschiedene Versionen und Distributionen von Linux hinweg.
