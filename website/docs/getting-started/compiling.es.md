# Avanzado: Compilación desde el código fuente (Opcional)

Si tienes Rust instalado, puedes compilar desde el código fuente con el siguiente comando:

Nota: Para compilar, normalmente necesitas la última versión de Rust.

```bash
cargo build --release
```

Puedes descargar la última versión inestable desde la rama principal o la última versión estable desde la página de [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Asegúrate de actualizar Rust periódicamente con:

```bash
rustup update stable
```

El binario compilado se generará en la carpeta `./target/release`.

## Actualización de los paquetes de Rust

Puedes actualizar a las últimas crates de Rust antes de compilar:

```bash
cargo update
```

> Por favor, avísanos si algo deja de funcionar después de actualizar.

## Compilación cruzada de binarios de Windows de 32 bits

Puedes crear binarios de 32 bits en sistemas Windows de 64 bits con lo siguiente:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Advertencia: Asegúrate de ejecutar `rustup install stable-i686-pc-windows-msvc` cada vez que haya una nueva versión estable de Rust, ya que `rustup update stable` no actualizará el compilador para la compilación cruzada y podrías recibir errores de compilación.**

## Notas de compilación en macOS

Si recibes errores de compilación relacionados con openssl, deberás instalar [Homebrew](https://brew.sh/) y luego instalar los siguientes paquetes:

```bash
brew install pkg-config
brew install openssl
```

## Notas de compilación en Linux

Se requieren las siguientes dependencias de compilación:
* openssl-devel (basado en Fedora) / libssl-dev (basado en Ubuntu) 
* perl
* musl-gcc

## Compilación cruzada de binarios MUSL de Linux

En un sistema operativo Linux, primero instala el target.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Compila con:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Advertencia: Asegúrate de ejecutar `rustup install stable-x86_64-unknown-linux-musl` cada vez que haya una nueva versión estable de Rust, ya que `rustup update stable` no actualizará el compilador para la compilación cruzada y podrías recibir errores de compilación.**

El binario MUSL se creará en el directorio `./target/x86_64-unknown-linux-musl/release/`.
Los binarios MUSL son aproximadamente un 15% más lentos que los binarios GNU; sin embargo, son más portables entre diferentes versiones y distribuciones de Linux.
