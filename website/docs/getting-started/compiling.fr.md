# Avancé : Compilation depuis les sources (Optionnel)

Si Rust est installé, vous pouvez compiler depuis les sources avec la commande suivante :

Note : Pour compiler, vous avez généralement besoin de la dernière version de Rust.

```bash
cargo build --release
```

Vous pouvez télécharger la dernière version instable depuis la branche main ou la dernière version stable depuis la page [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Veillez à mettre à jour Rust périodiquement avec :

```bash
rustup update stable
```

Le binaire compilé sera généré dans le dossier `./target/release`.

## Mise à jour des paquets Rust

Vous pouvez mettre à jour vers les dernières crates Rust avant de compiler :

```bash
cargo update
```

> Veuillez nous faire savoir si quelque chose se casse après votre mise à jour.

## Compilation croisée de binaires Windows 32 bits

Vous pouvez créer des binaires 32 bits sur des systèmes Windows 64 bits avec ce qui suit :

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **Avertissement : Veillez à exécuter `rustup install stable-i686-pc-windows-msvc` à chaque nouvelle version stable de Rust, car `rustup update stable` ne mettra pas à jour le compilateur pour la compilation croisée et vous pourriez recevoir des erreurs de compilation.**

## Notes de compilation macOS

Si vous recevez des erreurs de compilation concernant openssl, vous devrez installer [Homebrew](https://brew.sh/) puis installer les paquets suivants :

```bash
brew install pkg-config
brew install openssl
```

## Notes de compilation Linux

Les dépendances de compilation suivantes sont requises :
* openssl-devel (basé sur Fedora) / libssl-dev (basé sur Ubuntu) 
* perl
* musl-gcc

## Compilation croisée de binaires Linux MUSL

Sur un système d'exploitation Linux, installez d'abord la cible.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Compilez avec :

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **Avertissement : Veillez à exécuter `rustup install stable-x86_64-unknown-linux-musl` à chaque nouvelle version stable de Rust, car `rustup update stable` ne mettra pas à jour le compilateur pour la compilation croisée et vous pourriez recevoir des erreurs de compilation.**

Le binaire MUSL sera créé dans le répertoire `./target/x86_64-unknown-linux-musl/release/`.
Les binaires MUSL sont environ 15 % plus lents que les binaires GNU, cependant, ils sont plus portables entre les différentes versions et distributions de Linux.
