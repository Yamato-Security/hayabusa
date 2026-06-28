# အဆင့်မြင့်- Source မှ Compile ပြုလုပ်ခြင်း (ရွေးချယ်နိုင်သည်)

Rust ကို install ထားပါက အောက်ပါ command ဖြင့် source မှ compile ပြုလုပ်နိုင်သည်-

မှတ်ချက်- Compile ပြုလုပ်ရန် သာမန်အားဖြင့် Rust ၏ နောက်ဆုံးဗားရှင်းကို လိုအပ်သည်။

```bash
cargo build --release
```

နောက်ဆုံး မတည်ငြိမ်သေးသော ဗားရှင်းကို main branch မှ သို့မဟုတ် နောက်ဆုံး တည်ငြိမ်သော ဗားရှင်းကို [Releases](https://github.com/Yamato-Security/hayabusa/releases) စာမျက်နှာမှ download လုပ်နိုင်သည်။

Rust ကို အောက်ပါအတိုင်း အခါအားလျော်စွာ update ပြုလုပ်ရန် သေချာပါစေ-

```bash
rustup update stable
```

Compile ပြုလုပ်ပြီးသော binary ကို `./target/release` folder တွင် ထုတ်ပေးမည်ဖြစ်သည်။

## Rust Packages များကို Update ပြုလုပ်ခြင်း

Compile မပြုလုပ်မီ နောက်ဆုံး Rust crates များသို့ update ပြုလုပ်နိုင်သည်-

```bash
cargo update
```

> Update ပြုလုပ်ပြီးနောက် တစ်စုံတစ်ရာ ပျက်စီးသွားပါက ကျွန်ုပ်တို့ကို အကြောင်းကြားပေးပါ။

## 32-bit Windows Binaries များ Cross-compile ပြုလုပ်ခြင်း

64-bit Windows systems များတွင် အောက်ပါအတိုင်း 32-bit binaries များ ဖန်တီးနိုင်သည်-

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **သတိ- `rustup update stable` သည် cross compiling အတွက် compiler ကို update မပြုလုပ်သောကြောင့်၊ Rust ၏ stable ဗားရှင်းအသစ် ထွက်ရှိသည့်အခါတိုင်း `rustup install stable-i686-pc-windows-msvc` ကို run ရန် သေချာပါစေ။ မဟုတ်ပါက build errors များ ရရှိနိုင်သည်။**

## macOS Compiling မှတ်ချက်များ

openssl နှင့်ပတ်သက်သော compile errors များ ရရှိပါက [Homebrew](https://brew.sh/) ကို install ပြုလုပ်ပြီးနောက် အောက်ပါ packages များကို install ပြုလုပ်ရန် လိုအပ်မည်ဖြစ်သည်-

```bash
brew install pkg-config
brew install openssl
```

## Linux Compiling မှတ်ချက်များ

အောက်ပါ build dependencies များ လိုအပ်သည်-
* openssl-devel (Fedora-based) / libssl-dev (Ubuntu-based) 
* perl
* musl-gcc

## Linux MUSL Binaries များ Cross-compile ပြုလုပ်ခြင်း

Linux OS တွင် target ကို ဦးစွာ install ပြုလုပ်ပါ။

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

အောက်ပါအတိုင်း compile ပြုလုပ်ပါ-

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **သတိ- `rustup update stable` သည် cross compiling အတွက် compiler ကို update မပြုလုပ်သောကြောင့်၊ Rust ၏ stable ဗားရှင်းအသစ် ထွက်ရှိသည့်အခါတိုင်း `rustup install stable-x86_64-unknown-linux-musl` ကို run ရန် သေချာပါစေ။ မဟုတ်ပါက build errors များ ရရှိနိုင်သည်။**

MUSL binary ကို `./target/x86_64-unknown-linux-musl/release/` directory တွင် ဖန်တီးမည်ဖြစ်သည်။
MUSL binaries များသည် GNU binaries များထက် ၁၅% ခန့် နှေးကွေးသော်လည်း၊ linux ၏ မတူညီသော ဗားရှင်းများနှင့် distributions များတွင် ပိုမို portable ဖြစ်သည်။
