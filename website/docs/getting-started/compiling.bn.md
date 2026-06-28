# উন্নত: সোর্স থেকে কম্পাইল করা (ঐচ্ছিক)

আপনার যদি Rust ইনস্টল করা থাকে, তাহলে আপনি নিম্নলিখিত কমান্ড দিয়ে সোর্স থেকে কম্পাইল করতে পারেন:

দ্রষ্টব্য: কম্পাইল করতে, আপনার সাধারণত Rust-এর সর্বশেষ সংস্করণ প্রয়োজন।

```bash
cargo build --release
```

আপনি main শাখা থেকে সর্বশেষ অস্থিতিশীল সংস্করণ অথবা [Releases](https://github.com/Yamato-Security/hayabusa/releases) পৃষ্ঠা থেকে সর্বশেষ স্থিতিশীল সংস্করণ ডাউনলোড করতে পারেন।

নিয়মিতভাবে Rust আপডেট করতে ভুলবেন না:

```bash
rustup update stable
```

কম্পাইল করা বাইনারিটি `./target/release` ফোল্ডারে আউটপুট হবে।

## Rust প্যাকেজ আপডেট করা

কম্পাইল করার আগে আপনি সর্বশেষ Rust crate-এ আপডেট করতে পারেন:

```bash
cargo update
```

> আপডেট করার পরে যদি কিছু ভেঙে যায় তবে অনুগ্রহ করে আমাদের জানান।

## 32-বিট Windows বাইনারি ক্রস-কম্পাইল করা

আপনি নিম্নলিখিতভাবে 64-বিট Windows সিস্টেমে 32-বিট বাইনারি তৈরি করতে পারেন:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **সতর্কতা: যখনই Rust-এর একটি নতুন স্থিতিশীল সংস্করণ আসে তখনই `rustup install stable-i686-pc-windows-msvc` চালাতে ভুলবেন না, কারণ `rustup update stable` ক্রস কম্পাইলিংয়ের জন্য কম্পাইলারটি আপডেট করবে না এবং আপনি বিল্ড ত্রুটি পেতে পারেন।**

## macOS কম্পাইলিং নোট

আপনি যদি openssl সম্পর্কে কম্পাইল ত্রুটি পান, তাহলে আপনাকে [Homebrew](https://brew.sh/) ইনস্টল করতে হবে এবং তারপর নিম্নলিখিত প্যাকেজগুলি ইনস্টল করতে হবে:

```bash
brew install pkg-config
brew install openssl
```

## Linux কম্পাইলিং নোট

নিম্নলিখিত বিল্ড নির্ভরতাগুলি প্রয়োজন:
* openssl-devel (Fedora-ভিত্তিক) / libssl-dev (Ubuntu-ভিত্তিক) 
* perl
* musl-gcc

## Linux MUSL বাইনারি ক্রস-কম্পাইল করা

একটি Linux OS-এ, প্রথমে target ইনস্টল করুন।

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

এর সাথে কম্পাইল করুন:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **সতর্কতা: যখনই Rust-এর একটি নতুন স্থিতিশীল সংস্করণ আসে তখনই `rustup install stable-x86_64-unknown-linux-musl` চালাতে ভুলবেন না, কারণ `rustup update stable` ক্রস কম্পাইলিংয়ের জন্য কম্পাইলারটি আপডেট করবে না এবং আপনি বিল্ড ত্রুটি পেতে পারেন।**

MUSL বাইনারিটি `./target/x86_64-unknown-linux-musl/release/` ডিরেক্টরিতে তৈরি হবে।
MUSL বাইনারিগুলি GNU বাইনারিগুলির চেয়ে প্রায় ১৫% ধীর, তবে এগুলি linux-এর বিভিন্ন সংস্করণ এবং ডিস্ট্রিবিউশন জুড়ে আরও বহনযোগ্য।
