# 고급: 소스에서 컴파일하기 (선택 사항)

Rust가 설치되어 있다면 다음 명령으로 소스에서 컴파일할 수 있습니다:

참고: 컴파일하려면 일반적으로 최신 버전의 Rust가 필요합니다.

```bash
cargo build --release
```

main 브랜치에서 최신 불안정 버전을 다운로드하거나 [Releases](https://github.com/Yamato-Security/hayabusa/releases) 페이지에서 최신 안정 버전을 다운로드할 수 있습니다.

다음 명령으로 Rust를 주기적으로 업데이트하세요:

```bash
rustup update stable
```

컴파일된 바이너리는 `./target/release` 폴더에 출력됩니다.

## Rust 패키지 업데이트

컴파일하기 전에 최신 Rust crate로 업데이트할 수 있습니다:

```bash
cargo update
```

> 업데이트 후 문제가 발생하면 알려주세요.

## 32비트 Windows 바이너리 크로스 컴파일

다음 명령으로 64비트 Windows 시스템에서 32비트 바이너리를 만들 수 있습니다:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **경고: `rustup update stable`은 크로스 컴파일용 컴파일러를 업데이트하지 않으며 빌드 오류가 발생할 수 있으므로, Rust의 새로운 안정 버전이 나올 때마다 반드시 `rustup install stable-i686-pc-windows-msvc`를 실행하세요.**

## macOS 컴파일 참고 사항

openssl 관련 컴파일 오류가 발생하면 [Homebrew](https://brew.sh/)를 설치한 다음 아래 패키지들을 설치해야 합니다:

```bash
brew install pkg-config
brew install openssl
```

## Linux 컴파일 참고 사항

다음 빌드 의존성이 필요합니다:

* openssl-devel (Fedora 기반) / libssl-dev (Ubuntu 기반) 
* perl
* musl-gcc

## Linux MUSL 바이너리 크로스 컴파일

Linux OS에서는 먼저 타겟을 설치합니다.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

다음 명령으로 컴파일합니다:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **경고: `rustup update stable`은 크로스 컴파일용 컴파일러를 업데이트하지 않으며 빌드 오류가 발생할 수 있으므로, Rust의 새로운 안정 버전이 나올 때마다 반드시 `rustup install stable-x86_64-unknown-linux-musl`를 실행하세요.**

MUSL 바이너리는 `./target/x86_64-unknown-linux-musl/release/` 디렉터리에 생성됩니다.
MUSL 바이너리는 GNU 바이너리보다 약 15% 느리지만, 다양한 버전과 배포판의 linux에서 더 이식성이 높습니다.
