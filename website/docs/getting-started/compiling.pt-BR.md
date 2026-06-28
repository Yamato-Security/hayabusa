# Avançado: Compilando a Partir do Código-Fonte (Opcional)

Se você tiver o Rust instalado, pode compilar a partir do código-fonte com o seguinte comando:

Nota: Para compilar, você normalmente precisa da versão mais recente do Rust.

```bash
cargo build --release
```

Você pode baixar a versão instável mais recente a partir da branch main ou a versão estável mais recente na página de [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Certifique-se de atualizar periodicamente o Rust com:

```bash
rustup update stable
```

O binário compilado será gerado na pasta `./target/release`.

## Atualizando os Pacotes do Rust

Você pode atualizar para os crates mais recentes do Rust antes de compilar:

```bash
cargo update
```

> Por favor, avise-nos se algo quebrar após a atualização.

## Cross-compilando Binários de 32 bits para Windows

Você pode criar binários de 32 bits em sistemas Windows de 64 bits com o seguinte:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Aviso: Certifique-se de executar `rustup install stable-i686-pc-windows-msvc` sempre que houver uma nova versão estável do Rust, pois `rustup update stable` não atualizará o compilador para cross-compilação e você poderá receber erros de build.**

## Notas de Compilação no macOS

Se você receber erros de compilação sobre openssl, será necessário instalar o [Homebrew](https://brew.sh/) e, em seguida, instalar os seguintes pacotes:

```bash
brew install pkg-config
brew install openssl
```

## Notas de Compilação no Linux

As seguintes dependências de build são necessárias:
* openssl-devel (baseado em Fedora) / libssl-dev (baseado em Ubuntu) 
* perl
* musl-gcc

## Cross-compilando Binários Linux MUSL

Em um sistema operacional Linux, primeiro instale o target.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Compile com:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Aviso: Certifique-se de executar `rustup install stable-x86_64-unknown-linux-musl` sempre que houver uma nova versão estável do Rust, pois `rustup update stable` não atualizará o compilador para cross-compilação e você poderá receber erros de build.**

O binário MUSL será criado no diretório `./target/x86_64-unknown-linux-musl/release/`.
Binários MUSL são cerca de 15% mais lentos que os binários GNU, porém são mais portáveis entre diferentes versões e distribuições de linux.
