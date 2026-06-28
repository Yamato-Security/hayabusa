# 進階：從原始碼編譯（選用）

如果您已安裝 Rust，可以使用以下指令從原始碼編譯：

注意：要進行編譯，您通常需要最新版本的 Rust。

```bash
cargo build --release
```

您可以從 main 分支下載最新的不穩定版本，或從 [Releases](https://github.com/Yamato-Security/hayabusa/releases) 頁面下載最新的穩定版本。

請務必定期更新 Rust，使用以下指令：

```bash
rustup update stable
```

編譯後的二進位檔將輸出到 `./target/release` 資料夾中。

## 更新 Rust 套件

您可以在編譯前更新到最新的 Rust crates：

```bash
cargo update
```

> 如果更新後有任何功能異常，請告知我們。

## 交叉編譯 32 位元 Windows 二進位檔

您可以在 64 位元的 Windows 系統上使用以下指令建立 32 位元二進位檔：

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **警告：每當有新的 Rust 穩定版本時，請務必執行 `rustup install stable-i686-pc-windows-msvc`，因為 `rustup update stable` 不會更新用於交叉編譯的編譯器，否則您可能會收到建置錯誤。**

## macOS 編譯注意事項

如果您收到關於 openssl 的編譯錯誤，您需要安裝 [Homebrew](https://brew.sh/)，然後安裝以下套件：

```bash
brew install pkg-config
brew install openssl
```

## Linux 編譯注意事項

需要以下建置相依套件：
* openssl-devel（Fedora 系列）/ libssl-dev（Ubuntu 系列） 
* perl
* musl-gcc

## 交叉編譯 Linux MUSL 二進位檔

在 Linux 作業系統上，請先安裝目標平台。

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

使用以下指令編譯：

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **警告：每當有新的 Rust 穩定版本時，請務必執行 `rustup install stable-x86_64-unknown-linux-musl`，因為 `rustup update stable` 不會更新用於交叉編譯的編譯器，否則您可能會收到建置錯誤。**

MUSL 二進位檔將建立在 `./target/x86_64-unknown-linux-musl/release/` 目錄中。
MUSL 二進位檔比 GNU 二進位檔約慢 15%，但它們在不同版本與發行版的 linux 之間更具可攜性。
