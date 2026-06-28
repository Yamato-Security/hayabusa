# متقدم: التجميع من المصدر (اختياري)

إذا كان لديك Rust مثبتًا، يمكنك التجميع من المصدر باستخدام الأمر التالي:

ملاحظة: للتجميع، تحتاج عادةً إلى أحدث إصدار من Rust.

```bash
cargo build --release
```

يمكنك تنزيل أحدث إصدار غير مستقر من الفرع الرئيسي أو أحدث إصدار مستقر من صفحة [الإصدارات](https://github.com/Yamato-Security/hayabusa/releases).

تأكد من تحديث Rust بشكل دوري باستخدام:

```bash
rustup update stable
```

سيتم إخراج الملف الثنائي المُجمَّع في المجلد `./target/release`.

## تحديث حزم Rust

يمكنك التحديث إلى أحدث حزم Rust (crates) قبل التجميع:

```bash
cargo update
```

> يرجى إعلامنا إذا تعطّل أي شيء بعد التحديث.

## التجميع المتقاطع للملفات الثنائية لنظام Windows 32-بت

يمكنك إنشاء ملفات ثنائية 32-بت على أنظمة Windows 64-بت باستخدام ما يلي:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **تحذير: تأكد من تشغيل `rustup install stable-i686-pc-windows-msvc` كلما توفر إصدار مستقر جديد من Rust لأن `rustup update stable` لن يقوم بتحديث المُجمِّع للتجميع المتقاطع وقد تتلقى أخطاء في البناء.**

## ملاحظات حول التجميع على macOS

إذا تلقيت أخطاء تجميع متعلقة بـ openssl، فستحتاج إلى تثبيت [Homebrew](https://brew.sh/) ثم تثبيت الحزم التالية:

```bash
brew install pkg-config
brew install openssl
```

## ملاحظات حول التجميع على Linux

تتطلب تبعيات البناء التالية:
* openssl-devel (Fedora-based) / libssl-dev (Ubuntu-based) 
* perl
* musl-gcc

## التجميع المتقاطع للملفات الثنائية Linux MUSL

على نظام تشغيل Linux، قم أولًا بتثبيت الهدف.

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

قم بالتجميع باستخدام:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **تحذير: تأكد من تشغيل `rustup install stable-x86_64-unknown-linux-musl` كلما توفر إصدار مستقر جديد من Rust لأن `rustup update stable` لن يقوم بتحديث المُجمِّع للتجميع المتقاطع وقد تتلقى أخطاء في البناء.**

سيتم إنشاء الملف الثنائي MUSL في الدليل `./target/x86_64-unknown-linux-musl/release/`.
ملفات MUSL الثنائية أبطأ بحوالي 15% من ملفات GNU الثنائية، ومع ذلك، فهي أكثر قابلية للنقل عبر إصدارات وتوزيعات Linux المختلفة.
