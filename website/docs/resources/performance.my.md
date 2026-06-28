# Hayabusa Developer များအတွက် Rust Performance လမ်းညွှန်

# စာရေးသူ
Fukusuke Takahashi

# အင်္ဂလိပ်ဘာသာပြန်ဆိုမှု
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# ဤစာတမ်းအကြောင်း
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (အင်္ဂလိပ်: "peregrine falcon") သည် ဂျပန်နိုင်ငံရှိ [Yamato Security](https://yamatosecurity.connpass.com/) အဖွဲ့မှ တီထွင်ထားသော လျင်မြန်သည့် forensics ခွဲခြမ်းစိတ်ဖြာရေး tool တစ်ခုဖြစ်သည်။ peregrine falcon ကဲ့သို့ လျင်မြန်စွာ (ခြိမ်းခြောက်မှု) hunt ပြုလုပ်နိုင်ရန်အတွက် [Rust](https://www.rust-lang.org/) ဖြင့် တီထွင်ထားခြင်းဖြစ်သည်။ Rust သည် သူ့ဘာသာသူ လျင်မြန်သော ဘာသာစကားတစ်ခုဖြစ်သော်လည်း နှေးကွေးမှုနှင့် memory အသုံးပြုမှု မြင့်မားလာစေသည့် ထောင်ချောက်များစွာ ရှိပါသည်။ ဤစာတမ်းကို Hayabusa တွင် တကယ်ဖြစ်ပျက်ခဲ့သော performance တိုးတက်မှုများအပေါ် အခြေခံ၍ ဖန်တီးထားသည် ([changelog ကို ဤနေရာတွင်](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md) ကြည့်ပါ)၊ သို့သော် ဤနည်းပညာများကို အခြား Rust program များတွင်လည်း အသုံးပြုနိုင်သင့်ပါသည်။ ကျွန်ုပ်တို့၏ စမ်းသပ်မှုနှင့် အမှားပြုပြင်မှုများမှ ရရှိခဲ့သော အသိပညာများမှ သင် အကျိုးကျေးဇူး ရရှိနိုင်မည်ဟု မျှော်လင့်ပါသည်။

# အမြန်နှုန်း တိုးတက်စေခြင်း
## Memory allocator ကို ပြောင်းလဲခြင်း
default memory allocator ကို ရိုးရှင်းစွာ ပြောင်းလဲခြင်းဖြင့် အမြန်နှုန်း သိသိသာသာ တိုးတက်လာနိုင်ပါသည်။
ဥပမာအားဖြင့် ဤ [benchmarks](https://github.com/rust-lang/rust-analyzer/issues/1441) များအရ အောက်ပါ memory allocator နှစ်ခုဖြစ်သော

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

တို့သည် default memory allocator ထက် များစွာ ပိုမြန်ပါသည်။ ကျွန်ုပ်တို့သည် memory allocator ကို jemalloc မှ mimalloc သို့ ပြောင်းလဲခြင်းဖြင့် အမြန်နှုန်း သိသိသာသာ တိုးတက်မှုကို အတည်ပြုနိုင်ခဲ့သဖြင့် version 1.8.0 မှစ၍ mimalloc ကို default အဖြစ် ပြုလုပ်ခဲ့ပါသည်။ (mimalloc သည် jemalloc ထက် memory အနည်းငယ် ပိုသုံးသော်လည်းပါပဲ။)

### မပြောင်းမီ  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
global [memory allocator](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) ကို ပြောင်းလဲရန် အောက်ပါ အဆင့် ၂ ဆင့်သာ ပြုလုပ်ရန် လိုအပ်ပါသည်:

1. [mimalloc crate](https://crates.io/crates/mimalloc) ကို `Cargo.toml` ဖိုင်၏ [[dependencies] section](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) တွင် ထည့်ပါ:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. program အတွင်း တစ်နေရာရာတွင် [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) အောက်တွင် mimalloc ကို အသုံးပြုလိုကြောင်း သတ်မှတ်ပါ:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
memory allocator ကို ပြောင်းလဲရန် ဤမျှသာ ပြုလုပ်ရန် လိုအပ်ပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）  <!-- omit in toc -->
အမြန်နှုန်း မည်မျှ တိုးတက်မည်ဆိုသည်မှာ program ပေါ်တွင် မူတည်သော်လည်း အောက်ပါ ဥပမာတွင်
- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

memory allocator ကို [mimalloc](https://github.com/microsoft/mimalloc) သို့ ပြောင်းလဲခြင်းသည် Intel CPU များတွင် performance 20-30% တိုးတက်မှု ဖြစ်ပေါ်စေခဲ့ပါသည်။ 
(အကြောင်းတစ်ခုခုကြောင့် ARM အခြေခံ macOS device များတွင်မူ performance တိုးတက်မှု သိသိသာသာ မရှိခဲ့ပါ။)

## Loop များတွင် IO processing ကို လျှော့ချခြင်း
Disk IO processing သည် memory တွင် processing ပြုလုပ်ခြင်းထက် များစွာ နှေးပါသည်။ ထို့ကြောင့် အထူးသဖြင့် loop များတွင် IO processing ကို တတ်နိုင်သမျှ ရှောင်ရှားရန် သင့်လျော်ပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် loop အတွင်း file open ခြင်းကို တစ်သန်းကြိမ် ဖြစ်ပေါ်နေပုံကို ပြသထားသည်:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
အောက်ပါအတိုင်း file ကို loop ၏ ပြင်ပတွင် open ခြင်းဖြင့်
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
အမြန်နှုန်း ၁၀၀၀ ဆ ခန့် တိုးတက်လာပါမည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် detection result တစ်ခုစီကို ကိုင်တွယ်စဉ်က IO processing ကို loop ၏ ပြင်ပတွင် ပြုလုပ်နိုင်ခဲ့သည်:
- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

ဤသည်က အမြန်နှုန်း 20% ခန့် တိုးတက်မှု ဖြစ်ပေါ်စေခဲ့သည်။

## Loop များတွင် regular expression compilation ကို ရှောင်ရှားခြင်း
Regular expression compilation သည် regular expression matching နှင့် နှိုင်းယှဉ်ပါက အလွန် ကုန်ကျစရိတ်များသော လုပ်ငန်းစဉ်တစ်ခု ဖြစ်ပါသည်။ ထို့ကြောင့် အထူးသဖြင့် loop များတွင် regular expression compilation ကို တတ်နိုင်သမျှ ရှောင်ရှားရန် အကြံပြုပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် အောက်ပါ လုပ်ငန်းစဉ်သည် loop အတွင်း regular expression matching ၁၀၀,၀၀၀ ကြိမ် ဖန်တီးပါသည်:
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    for _ in 0..100000 {
        if Regex::new(match_str).unwrap().is_match(text){ // Regular expression compilation in a loop
            println!("matched!");
        }
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
အောက်တွင် ပြထားသည့်အတိုင်း regular expression compilation ကို loop ၏ ပြင်ပတွင် ပြုလုပ်ခြင်းဖြင့်
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap(); // Compile the regular expression outside the loop
    for _ in 0..100000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
ပြင်ဆင်ထားသော code သည် ၁၀၀ ဆ ခန့် ပိုမြန်ပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် regular expression compilation ကို loop ၏ ပြင်ပတွင် ပြုလုပ်ပြီး cache လုပ်ထားပါသည်။
- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

ဤသည်က အမြန်နှုန်း သိသိသာသာ တိုးတက်မှု ဖြစ်ပေါ်စေခဲ့သည်။

## Buffer IO ကို အသုံးပြုခြင်း
Buffer IO မပါဘဲ file IO သည် နှေးပါသည်။ buffer IO ဖြင့်ဆိုလျှင် IO operation များကို memory အတွင်းရှိ buffer များမှတစ်ဆင့် ပြုလုပ်သဖြင့် system call အရေအတွက် လျော့နည်းကာ အမြန်နှုန်း တိုးတက်လာပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် အောက်ပါ လုပ်ငန်းစဉ်တွင် [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) သည် ၁,၀၀၀,၀၀၀ ကြိမ် ဖြစ်ပေါ်ပါသည်။
```Rust
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let mut f = File::create("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.write(b"hello world!");
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
အောက်ပါအတိုင်း [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) ကို အသုံးပြုခြင်းဖြင့်
```Rust
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let mut f = File::create("sample.txt").unwrap();
    let mut writer = BufWriter::new(f);
    for _ in 0..1000000 {
        writer.write(b"some text");
    }
    writer.flush().unwrap();
}
```
အမြန်နှုန်း ၅၀ ဆ ခန့် တိုးတက်မှု ရှိပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အထက်တွင် ဖော်ပြထားသော method ကို ဤနေရာတွင် အကောင်အထည်ဖော်ခဲ့ပြီး
- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

output processing တွင် အမြန်နှုန်း သိသိသာသာ တိုးတက်မှု ဖြစ်ပေါ်စေခဲ့သည်။

## Regular expression များအစား standard String method များကို အသုံးပြုခြင်း
Regular expression များသည် ရှုပ်ထွေးသော matching pattern များကို လွှမ်းခြုံနိုင်သော်လည်း [standard String method](https://doc.rust-lang.org/std/string/struct.String.html) များထက် နှေးပါသည်။ ထို့ကြောင့် အောက်ပါကဲ့သို့ ရိုးရှင်းသော string matching များအတွက် standard String method များ အသုံးပြုခြင်းသည် ပိုမြန်ပါသည်။

- Starts-with matching（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Ends-with matching（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Contains matching（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် အောက်ပါ code သည် regular expression ဖြင့် ends-with matching ကို တစ်သန်းကြိမ် ပြုလုပ်ပါသည်။
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = ".*abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
အောက်ပါအတိုင်း [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) ကို အသုံးပြုခြင်းဖြင့်
```Rust
fn main() {
    let text = "1234567890";
    let match_str = "abc";
    for _ in 0..1000000 {
        if text.ends_with(match_str) {
            println!("matched!");
        }
    }
}
```
processing သည် ၁၀ ဆ ပိုမြန်ပါမည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
Hayabusa သည် case-insensitive string နှိုင်းယှဉ်မှု လိုအပ်သဖြင့် [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) ကို အသုံးပြုပြီးနောက် အထက်ပါ method ကို သက်ရောက်စေပါသည်။ ထိုသို့ ပြုလုပ်သော်လည်း အောက်ပါ ဥပမာများတွင်
- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

ယခင်နှင့် နှိုင်းယှဉ်ပါက အမြန်နှုန်း 15% ခန့် တိုးတက်ခဲ့သည်။

## String အရှည်ဖြင့် filter လုပ်ခြင်း
ကိုင်တွယ်နေသော string များ၏ လက္ခဏာများပေါ်တွင် မူတည်၍ ရိုးရှင်းသော filter တစ်ခု ထည့်သွင်းခြင်းဖြင့် string matching ကြိုးပမ်းမှု အရေအတွက်ကို လျှော့ချနိုင်ပြီး လုပ်ငန်းစဉ်ကို မြန်ဆန်စေနိုင်ပါသည်။ string အရှည် ပုံသေမဟုတ်ဘဲ မကိုက်ညီသော string များကို မကြာခဏ နှိုင်းယှဉ်ပါက string အရှည်ကို အဓိက filter အဖြစ် အသုံးပြုခြင်းဖြင့် လုပ်ငန်းစဉ်ကို မြန်ဆန်စေနိုင်ပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် အောက်ပါ code သည် regular expression matching ကို တစ်သန်းကြိမ် ကြိုးပမ်းပါသည်။
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
အောက်တွင် ပြထားသည့်အတိုင်း [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) ကို အဓိက filter အဖြစ် အသုံးပြုခြင်းဖြင့်
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if text.len() == match_str.len() { // Primary filter by string length
            if r.is_match(text) {
                println!("matched!");
            }
        }
    }
}
```
အမြန်နှုန်း ၂၀ ဆ ခန့် တိုးတက်ပါမည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် အထက်ပါ method ကို အသုံးပြုထားသည်။
- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

ဤသည်က အမြန်နှုန်း 15% ခန့် တိုးတက်စေခဲ့သည်။

## codegen-units=1 ဖြင့် compile မလုပ်ပါနှင့်
Rust ဖြင့် performance optimization နှင့်ပတ်သက်သော ဆောင်းပါးများစွာတွင် `[profile.release]` section အောက်တွင် `codegen-units = 1` ကို ထည့်ရန် အကြံပြုထားကြသည်။
ဤသည်က default အနေဖြင့် parallel ဖြင့် compile လုပ်နေသဖြင့် compile အချိန်ကို နှေးကွေးစေမည်ဖြစ်သော်လည်း သီအိုရီအရ ပိုမို optimize ဖြစ်ပြီး ပိုမြန်သော code ဖြစ်ပေါ်စေသင့်သည်။
သို့သော် ကျွန်ုပ်တို့၏ စမ်းသပ်မှုတွင် Hayabusa သည် ဤ option ကို ဖွင့်ထားသည့်အခါ တကယ်တမ်း ပိုနှေးကာ compile လုပ်ချိန်လည်း ပိုကြာသဖြင့် ၎င်းကို ပိတ်ထားပါသည်။
executable ၏ binary size သည် ၁၀၀kb ခန့် ပိုသေးငယ်သဖြင့် hard disk space အကန့်အသတ်ရှိသော embedded system များအတွက် ဤသည်က သင့်လျော်ပေမည်။

# Memory အသုံးပြုမှု လျှော့ချခြင်း

## clone(), to_string(), နှင့် to_owned() တို့ကို မလိုအပ်ဘဲ အသုံးပြုခြင်းကို ရှောင်ရှားခြင်း
[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) သို့မဟုတ် [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) ကို အသုံးပြုခြင်းသည် [ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) နှင့် ဆက်စပ်သော compilation error များကို ဖြေရှင်းရန် လွယ်ကူသော နည်းလမ်းများ ဖြစ်ပါသည်။ သို့သော် ၎င်းတို့သည် များသောအားဖြင့် memory ကို မြင့်မားစွာ အသုံးပြုစေသဖြင့် ရှောင်ရှားသင့်ပါသည်။ ၎င်းတို့ကို ကုန်ကျစရိတ်နည်းသော [reference](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) များဖြင့် အစားထိုးနိုင်မလားဆိုသည်ကို အရင်ဆုံး ကြည့်ရှုခြင်းသည် အမြဲ အကောင်းဆုံး ဖြစ်ပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် တူညီသော `Vec` ကို အကြိမ်များစွာ iterate လုပ်လိုပါက [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) ကို အသုံးပြု၍ compilation error များကို ဖယ်ရှားနိုင်သည်။
```Rust
fn main() {
    let lst = vec![1, 2, 3];
    for x in lst.clone() { // In order to eliminate compile errors
        println!("{x}");
    }

    for x in lst {
        println!("{x}");
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
သို့သော် အောက်တွင် ပြထားသည့်အတိုင်း [reference](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) များကို အသုံးပြုခြင်းဖြင့် [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) အသုံးပြုရန် လိုအပ်မှုကို ဖယ်ရှားနိုင်ပါသည်။
```Rust
fn main() {
    let lst = vec![1, 2, 3];
    for x in &lst { // Eliminate compile errors with a reference
        println!("{x}");
    }

    for x in lst {
        println!("{x}");
    }
}
```
clone() အသုံးပြုမှုကို ဖယ်ရှားခြင်းဖြင့် memory အသုံးပြုမှု 50% အထိ လျော့နည်းပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် မလိုအပ်သော [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html), နှင့် [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html) အသုံးပြုမှုများကို အစားထိုးခြင်းဖြင့်
- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

memory အသုံးပြုမှုကို သိသိသာသာ လျှော့ချနိုင်ခဲ့ပါသည်။

## Vec အစား Iterator ကို အသုံးပြုခြင်း
[Vec](https://doc.rust-lang.org/std/vec/) သည် element အားလုံးကို memory တွင် သိမ်းဆည်းထားသဖြင့် element အရေအတွက်နှင့် အချိုးကျ memory များစွာ အသုံးပြုပါသည်။ element တစ်ခုစီ ကိုင်တွယ်ခြင်းဖြင့် လုံလောက်ပါက ၎င်းအစား [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) ကို အသုံးပြုခြင်းသည် memory များစွာ ပိုနည်းနည်း အသုံးပြုပါမည်။

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် အောက်ပါ `return_lines()` function သည် ၁ GB ခန့်ရှိသော file ကို ဖတ်ပြီး [Vec](https://doc.rust-lang.org/std/vec/) ကို ပြန်ပေးပါသည်:
```Rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn return_lines() -> Vec<String> {
    let f = File::open("sample.txt").unwrap();
    let buf = BufReader::new(f);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn main() {
    let lines = return_lines();
    for line in lines {
        println!("{}", line)
    }
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
ထိုအစား အောက်ပါအတိုင်း [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) ကို ပြန်ပေးသင့်ပါသည်:
```Rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn return_lines() -> impl Iterator<Item=String> {
    let f = File::open("sample.txt").unwrap();
    let buf = BufReader::new(f);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        // ここでcollect()せずに、Iteratorを戻り値として返す
}

fn main() {
    let lines = return_lines();
    for line in lines {
        println!("{}", line)
    }
}
```
သို့မဟုတ် မည်သည့် branch ကို ယူသည်ပေါ်မူတည်၍ type ကွဲပြားပါက အောက်ပါအတိုင်း `Box<dyn Iterator<Item = T>>` ကို ပြန်ပေးနိုင်ပါသည်:
```Rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn return_lines(need_filter:bool) -> Box<dyn Iterator<Item = String>> {
    let f = File::open("sample.txt").unwrap();
    let buf = BufReader::new(f);
    if need_filter {
        let result= buf.lines()
            .filter_map(|l| l.ok())
            .map(|l| l.replace("A", "B"));
        return Box::new(result)
    }
    let result= buf.lines()
        .map(|l| l.expect("Could not parse line"));
    Box::new(result)
}

fn main() {
    let lines = return_lines(true);
    for line in lines {
        println!("{}", line)
    }
}
```
Memory အသုံးပြုမှုသည် ၁ GB မှ ၃ MB သာ သို့ သိသိသာသာ ကျဆင်းပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် အထက်ဖော်ပြပါ method ကို အသုံးပြုထားသည်:
- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

1.7GB JSON file တွင် စမ်းသပ်သောအခါ memory 75% လျော့ကျသွားခဲ့သည်။

## String တိုများ ကိုင်တွယ်သည့်အခါ compact_str crate ကို အသုံးပြုခြင်း
24 byte အောက် string တိုများ အများအပြားကို ကိုင်တွယ်သည့်အခါ [compact_str crate](https://docs.rs/crate/compact_str/latest) ကို အသုံးပြု၍ memory အသုံးပြုမှု လျှော့ချနိုင်ပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် Vec သည် string ၁၀ သန်း သိမ်းဆည်းထားသည်။
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
၎င်းတို့ကို [CompactString](https://docs.rs/compact_str/latest/compact_str/) ဖြင့် အစားထိုးခြင်းသည် ပိုကောင်းပါသည်:
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
ဤသို့ ပြုလုပ်ခြင်းဖြင့် memory အသုံးပြုမှု 50% ခန့် လျော့နည်းပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် string တိုများကို [CompactString](https://docs.rs/compact_str/latest/compact_str/) ဖြင့် ကိုင်တွယ်ထားသည်:
- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

ဤသည်က memory အသုံးပြုမှု 20% ခန့် လျှော့ချမှု ပေးခဲ့သည်။

## Long-lived structure များတွင် မလိုအပ်သော field များကို ဖျက်ခြင်း
process startup အတွင်း memory တွင် ဆက်လက် သိမ်းဆည်းထားသော structure များသည် overall memory အသုံးပြုမှုကို သက်ရောက်စေနိုင်ပါသည်။ Hayabusa တွင် အောက်ပါ structure များ (version 2.2.2 အရ) ကို အထူးသဖြင့် အရေအတွက်များစွာ သိမ်းဆည်းထားပါသည်။
- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

အထက်ပါ structure များနှင့် ဆက်စပ်သော field များကို ဖယ်ရှားခြင်းသည် overall memory အသုံးပြုမှု လျှော့ချရာတွင် အကျိုးသက်ရောက်မှု အနည်းငယ် ရှိခဲ့ပါသည်။

### မပြောင်းမီ  <!-- omit in toc -->
ဥပမာအားဖြင့် `DetectInfo` field သည် version 1.8.1 အထိ အောက်ပါအတိုင်း ဖြစ်ခဲ့သည်:
```Rust
#[derive(Debug, Clone)]
pub struct DetectInfo {
    pub rulepath: CompactString,
    pub ruletitle: CompactString,
    pub level: CompactString,
    pub computername: CompactString,
    pub eventid: CompactString,
    pub detail: CompactString,
    pub record_information: CompactString,
    pub ext_field: Vec<(CompactString, Profile)>,
    pub is_condition: bool,
}
```
### ပြောင်းပြီးနောက်  <!-- omit in toc -->
အောက်ပါအတိုင်း `record_information` field ကို ဖျက်ခြင်းဖြင့်
```Rust
#[derive(Debug, Clone)]
pub struct DetectInfo {
    pub rulepath: CompactString,
    pub ruletitle: CompactString,
    pub level: CompactString,
    pub computername: CompactString,
    pub eventid: CompactString,
    pub detail: CompactString,
    // remove record_information field
    pub ext_field: Vec<(CompactString, Profile)>,
    pub is_condition: bool,
}
```
detection result record တစ်ခုလျှင် memory အသုံးပြုမှု byte အနည်းငယ်စီ လျှော့ချမှု ရရှိခဲ့ပါသည်။

### ထိရောက်မှု（Pull Request မှ တကယ့်ဥပမာ）   <!-- omit in toc -->
အောက်ပါ ဥပမာတွင် detection result record အရေအတွက် ၁.၅ သန်းခန့်ရှိသော data ကို စမ်းသပ်သောအခါ
- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

memory အသုံးပြုမှု 300MB ခန့် လျှော့ချနိုင်ခဲ့ပါသည်။

# Benchmarking
## Memory allocator ၏ statistics function ကို အသုံးပြုခြင်း
memory allocator အချို့သည် ၎င်းတို့၏ ကိုယ်ပိုင် memory အသုံးပြုမှု statistics ကို ထိန်းသိမ်းထားပါသည်။ ဥပမာအားဖြင့် [mimalloc](https://github.com/microsoft/mimalloc) တွင် [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) function ကို ခေါ်၍ memory အသုံးပြုမှုကို ရယူနိုင်ပါသည်။

### statistics ရယူနည်း  <!-- omit in toc -->
လိုအပ်ချက်များ: [Memory allocator ကို ပြောင်းလဲခြင်း](#change-the-memory-allocator) အပိုင်းတွင် ရှင်းပြထားသည့်အတိုင်း mimalloc ကို အသုံးပြုနေရန် လိုအပ်ပါသည်။

1.  `Cargo.toml` ၏ [dependencies section](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) တွင် [libmimalloc-sys crate](https://crates.io/crates/libmimalloc-sys) ကို ထည့်ပါ:
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. memory အသုံးပြုမှု statistics ကို print ထုတ်လိုသည့်အခါတိုင်း အောက်ပါ code ကို ရေးပြီး `unsafe` block အတွင်း [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) ကို ခေါ်ပါ။ memory အသုံးပြုမှု statistics ကို standard out သို့ ထုတ်ပေးပါမည်။
    ```Rust
    use libmimalloc_sys::mi_stats_print_out;
    use std::ptr::null_mut;
    
    fn main() {
      
      // Write the following code where you want to measure memory usage
      unsafe {
            mi_stats_print_out(None, null_mut());
      }
    }
    ```
3. ဘယ်ဘက်အပေါ်ထောင့်ရှိ `peak/reserved` value သည် အမြင့်ဆုံး memory အသုံးပြုမှု ဖြစ်ပါသည်။ 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### ဥပမာ   <!-- omit in toc -->
အထက်ပါ အကောင်အထည်ဖော်မှုကို အောက်ပါတွင် သက်ရောက်စေခဲ့သည်:
- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

Hayabusa တွင် `--debug` option ကို ထည့်ပါက memory အသုံးပြုမှု statistics ကို အဆုံးတွင် ထုတ်ပေးပါမည်။

## Windows ၏ performance counter ကို အသုံးပြုခြင်း
OS ဘက်တွင် ရယူနိုင်သော statistics မှ resource အသုံးပြုမှု အမျိုးမျိုးကို စစ်ဆေးနိုင်ပါသည်။ ဤကိစ္စတွင် အောက်ပါ အချက်နှစ်ချက်ကို သတိပြုသင့်ပါသည်။

- anti-virus software (Windows Defender) မှ သက်ရောက်မှု
  - ပထမအကြိမ် run ခြင်းသာ scan ၏ သက်ရောက်မှုခံရပြီး ပိုနှေးသဖြင့် build ပြီးနောက် ဒုတိယအကြိမ်နှင့် နောက်ဆက်တွဲ အကြိမ်များ၏ ရလဒ်များသည် နှိုင်းယှဉ်ရန် သင့်လျော်ပါသည်။ (သို့မဟုတ် ပိုတိကျသော ရလဒ်များအတွက် သင့် anti-virus ကို disable လုပ်နိုင်ပါသည်။)
- file caching မှ သက်ရောက်မှု
  - OS startup ပြီးနောက် ဒုတိယအကြိမ်နှင့် နောက်ဆက်တွဲ အကြိမ်များ၏ ရလဒ်များသည် evtx နှင့် အခြား file IO များကို memory အတွင်းရှိ file cache မှ ဖတ်သဖြင့် ပထမအကြိမ်ထက် ပိုမြန်ပါသည်၊ ထို့ကြောင့် OS boot ပြီးနောက် ပထမအကြိမ်၏ ရလဒ်များသည် benchmark ယူရန် ပိုသင့်လျော်ပါသည်။

### ရယူနည်း  <!-- omit in toc -->
လိုအပ်ချက်များ：အောက်ပါ လုပ်ထုံးလုပ်နည်းသည် Windows တွင် `PowerShell 7` ကို တပ်ဆင်ပြီးသား environment များတွင်သာ မှန်ကန်ပါသည်။

1. OS ကို restart လုပ်ပါ
2. performance counter ကို တစ်စက္ကန့်လျှင်တစ်ကြိမ် CSV file သို့ ဆက်တိုက် မှတ်တမ်းတင်မည့် `PowerShell 7` ၏ [Get-Counter command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) ကို run ပါ။ (အောက်ဖော်ပြပါမှ မဟုတ်သော အခြား resource များကို တိုင်းတာလိုပါက [ဤဆောင်းပါး](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) သည် ကောင်းသော အကိုးအကား ဖြစ်ပါသည်။)
    ```PowerShell
    Get-Counter -Counter "\Memory\Available MBytes",  "\Processor(_Total)\% Processor Time" -Continuous | ForEach {
         $_.CounterSamples | ForEach {
             [pscustomobject]@{
                 TimeStamp = $_.TimeStamp
                 Path = $_.Path
                 Value = $_.CookedValue
             }
         }
     } | Export-Csv -Path PerfMonCounters.csv -NoTypeInformation
    ```
3. တိုင်းတာလိုသော process ကို execute လုပ်ပါ။

### ဥပမာ  <!-- omit in toc -->
အောက်ပါတွင် Hayabusa ဖြင့် performance တိုင်းတာရန် ဥပမာ လုပ်ထုံးလုပ်နည်း ပါဝင်ပါသည်။
- [Windows performance counter များ ရယူခြင်း ဥပမာ](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## heaptrack ကို အသုံးပြုခြင်း
[heaptrack](https://github.com/KDE/heaptrack) သည် Linux နှင့် macOS အတွက် ရရှိနိုင်သော ခေတ်မီသော memory profiler တစ်ခုဖြစ်သည်။ heaptrack ကို အသုံးပြုခြင်းဖြင့် bottleneck များကို သေချာစွာ စုံစမ်းနိုင်ပါသည်။

### ရယူနည်း  <!-- omit in toc -->
လိုအပ်ချက်များ: အောက်တွင် Ubuntu 22.04 အတွက် လုပ်ထုံးလုပ်နည်း ဖြစ်သည်။ heaptrack ကို Windows တွင် အသုံးမပြုနိုင်ပါ။

1. heaptrack ကို အောက်ပါ command နှစ်ခုဖြင့် install လုပ်ပါ။
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Hayabusa မှ အောက်ပါ mimalloc code ကို ဖယ်ရှားပါ။ (heaptrack ၏ memory profiler ကို mimalloc ဖြင့် အသုံးမပြုနိုင်ပါ။
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Hayabusa ၏ `Cargo.toml` file ရှိ [[profile.release] section](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) ကို ဖျက်ပြီး အောက်ပါအတိုင်း ပြောင်းပါ:
     ```
     [profile.release]
     debug = true
     ```

4. release build တစ်ခု build လုပ်ပါ: `cargo build --release`
5. `heaptrack hayabusa csv-timeline -d sample -o out.csv` ကို run ပါ

ယခု Hayabusa run ပြီးသွားသောအခါ heaptrack ၏ ရလဒ်များသည် GUI application တစ်ခုတွင် အလိုအလျောက် ပွင့်လာပါမည်။

### ဥပမာများ  <!-- omit in toc -->
heaptrack ၏ ရလဒ်များ ဥပမာကို အောက်တွင် ပြထားသည်။ `Flame Graph` နှင့် `Top-Down` tab များသည် memory အသုံးပြုမှု မြင့်မားသော function များကို မြင်သာစွာ စစ်ဆေးနိုင်စေပါသည်။

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# အကိုးအကားများ

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# ပံ့ပိုးကူညီမှုများ

ဤစာတမ်းသည် [Hayabusa](https://github.com/Yamato-Security/hayabusa) တွင် တကယ့် တိုးတက်မှု ဖြစ်ရပ်များမှ ရရှိသော တွေ့ရှိချက်များအပေါ် အခြေခံထားသည်။ အမှားများ သို့မဟုတ် performance တိုးတက်စေနိုင်သော နည်းပညာများ တွေ့ရှိပါက ကျွန်ုပ်တို့ထံ issue သို့မဟုတ် pull request တစ်ခု ပေးပို့ပါ။
