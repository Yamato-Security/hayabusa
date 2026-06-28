# Lanjutan: Mengompilasi Dari Kode Sumber (Opsional)

Jika Anda telah menginstal Rust, Anda dapat mengompilasi dari kode sumber dengan perintah berikut:

Catatan: Untuk mengompilasi, Anda biasanya memerlukan versi Rust terbaru.

```bash
cargo build --release
```

Anda dapat mengunduh versi unstable terbaru dari branch main atau versi stabil terbaru dari halaman [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Pastikan untuk memperbarui Rust secara berkala dengan:

```bash
rustup update stable
```

Biner yang telah dikompilasi akan dihasilkan di dalam folder `./target/release`.

## Memperbarui Paket Rust

Anda dapat memperbarui ke crate Rust terbaru sebelum mengompilasi:

```bash
cargo update
```

> Beri tahu kami jika ada yang rusak setelah Anda memperbarui.

## Cross-compiling Biner Windows 32-bit

Anda dapat membuat biner 32-bit pada sistem Windows 64-bit dengan cara berikut:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Peringatan: Pastikan untuk menjalankan `rustup install stable-i686-pc-windows-msvc` setiap kali ada versi stabil baru dari Rust karena `rustup update stable` tidak akan memperbarui kompiler untuk cross compiling dan Anda mungkin menerima kesalahan build.**

## Catatan Kompilasi macOS

Jika Anda menerima kesalahan kompilasi tentang openssl, Anda perlu menginstal [Homebrew](https://brew.sh/) dan kemudian menginstal paket-paket berikut:

```bash
brew install pkg-config
brew install openssl
```

## Catatan Kompilasi Linux

Dependensi build berikut diperlukan:

* openssl-devel (berbasis Fedora) / libssl-dev (berbasis Ubuntu) 
* perl
* musl-gcc

## Cross-compiling Biner Linux MUSL

Pada OS Linux, instal terlebih dahulu target-nya.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Kompilasi dengan:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Peringatan: Pastikan untuk menjalankan `rustup install stable-x86_64-unknown-linux-musl` setiap kali ada versi stabil baru dari Rust karena `rustup update stable` tidak akan memperbarui kompiler untuk cross compiling dan Anda mungkin menerima kesalahan build.**

Biner MUSL akan dibuat di dalam direktori `./target/x86_64-unknown-linux-musl/release/`.
Biner MUSL sekitar 15% lebih lambat dibandingkan biner GNU, namun, biner tersebut lebih portabel di berbagai versi dan distribusi linux.
