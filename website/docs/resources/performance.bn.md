# Hayabusa ডেভেলপারদের জন্য Rust পারফরম্যান্স গাইড

# লেখক
Fukusuke Takahashi

# ইংরেজি অনুবাদ
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# এই নথি সম্পর্কে
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (ইংরেজিতে: "peregrine falcon") হল জাপানের [Yamato Security](https://yamatosecurity.connpass.com/) গ্রুপ দ্বারা তৈরি একটি দ্রুত ফরেনসিক বিশ্লেষণ টুল। এটি একটি peregrine falcon-এর মতো দ্রুত (হুমকি) শিকার করার জন্য [Rust](https://www.rust-lang.org/)-এ তৈরি করা হয়েছে। Rust নিজেই একটি দ্রুত ভাষা, তবে এমন অনেক ফাঁদ আছে যা ধীর গতি এবং উচ্চ মেমরি ব্যবহারের কারণ হতে পারে। আমরা Hayabusa-এর প্রকৃত পারফরম্যান্স উন্নতির ভিত্তিতে এই নথিটি তৈরি করেছি ([এখানে changelog দেখুন](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), তবে এই কৌশলগুলি অন্যান্য Rust প্রোগ্রামেও প্রযোজ্য হওয়া উচিত। আমরা আশা করি আমাদের পরীক্ষা-নিরীক্ষার মাধ্যমে অর্জিত জ্ঞান থেকে আপনি উপকৃত হতে পারবেন।

# গতি উন্নতি
## মেমরি অ্যালোকেটর পরিবর্তন করুন
শুধুমাত্র ডিফল্ট মেমরি অ্যালোকেটর পরিবর্তন করলেই গতি উল্লেখযোগ্যভাবে উন্নত হতে পারে।
উদাহরণস্বরূপ, এই [benchmarks](https://github.com/rust-lang/rust-analyzer/issues/1441) অনুযায়ী, নিম্নলিখিত দুটি মেমরি অ্যালোকেটর

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

ডিফল্ট মেমরি অ্যালোকেটরের চেয়ে অনেক দ্রুত। আমরা আমাদের মেমরি অ্যালোকেটর jemalloc থেকে mimalloc-এ পরিবর্তন করে একটি উল্লেখযোগ্য গতি উন্নতি নিশ্চিত করতে পেরেছি, তাই আমরা সংস্করণ 1.8.0 থেকে mimalloc-কে ডিফল্ট করেছি। (যদিও mimalloc jemalloc-এর চেয়ে সামান্য বেশি মেমরি ব্যবহার করে।)

### Before  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### After  <!-- omit in toc -->
গ্লোবাল [memory allocator](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) পরিবর্তন করতে আপনাকে কেবল নিম্নলিখিত ২টি ধাপ সম্পন্ন করতে হবে:

1. [mimalloc crate](https://crates.io/crates/mimalloc)-কে `Cargo.toml` ফাইলের [[dependencies] section](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency)-এ যোগ করুন:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. প্রোগ্রামের কোথাও [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute)-এর অধীনে আপনি mimalloc ব্যবহার করতে চান তা সংজ্ঞায়িত করুন:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
মেমরি অ্যালোকেটর পরিবর্তন করতে আপনাকে শুধু এতটুকুই করতে হবে।

### Effectiveness（Real example from a Pull Request）  <!-- omit in toc -->
গতি কতটা উন্নত হবে তা প্রোগ্রামের উপর নির্ভর করবে, তবে নিম্নলিখিত উদাহরণে

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

মেমরি অ্যালোকেটরকে [mimalloc](https://github.com/microsoft/mimalloc)-এ পরিবর্তন করার ফলে Intel CPU-তে ২০-৩০% পারফরম্যান্স বৃদ্ধি হয়েছে। 
(কোনো কারণে, ARM ভিত্তিক macOS ডিভাইসে এতটা উল্লেখযোগ্য পারফরম্যান্স বৃদ্ধি হয়নি।)

## লুপে IO প্রক্রিয়াকরণ হ্রাস করুন
ডিস্ক IO প্রক্রিয়াকরণ মেমরিতে প্রক্রিয়াকরণের চেয়ে অনেক ধীর। তাই, যতটা সম্ভব IO প্রক্রিয়াকরণ এড়ানো বাঞ্ছনীয়, বিশেষ করে লুপে।

### Before  <!-- omit in toc -->
নিচের উদাহরণটি একটি লুপে দশ লক্ষ বার একটি ফাইল খোলা দেখায়:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### After  <!-- omit in toc -->
নিম্নরূপে লুপের বাইরে ফাইলটি খুলে
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
প্রায় ১০০০ গুণ গতি বৃদ্ধি হবে।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে, একবারে একটি করে সনাক্তকরণ ফলাফল পরিচালনা করার সময় IO প্রক্রিয়াকরণ লুপের বাইরে সম্পন্ন করা সম্ভব হয়েছিল:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

এর ফলে প্রায় ২০% গতি উন্নতি হয়েছে।

## লুপে রেগুলার এক্সপ্রেশন কম্পাইলেশন এড়িয়ে চলুন
রেগুলার এক্সপ্রেশন কম্পাইলেশন রেগুলার এক্সপ্রেশন ম্যাচিংয়ের তুলনায় একটি অত্যন্ত ব্যয়বহুল প্রক্রিয়া। তাই, যতটা সম্ভব রেগুলার এক্সপ্রেশন কম্পাইলেশন এড়ানো বাঞ্ছনীয়, বিশেষ করে লুপে।

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, নিম্নলিখিত প্রক্রিয়াটি একটি লুপে একটি রেগুলার এক্সপ্রেশন ম্যাচ করার ১,০০,০০০ বার চেষ্টা তৈরি করে:
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
### After  <!-- omit in toc -->
নিচে দেখানো হিসাবে লুপের বাইরে একটি রেগুলার এক্সপ্রেশন কম্পাইলেশন করে
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
আপডেট করা কোডটি প্রায় ১০০ গুণ দ্রুত।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে, রেগুলার এক্সপ্রেশন কম্পাইলেশন লুপের বাইরে সম্পন্ন এবং ক্যাশ করা হয়।

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

এর ফলে উল্লেখযোগ্য গতি উন্নতি হয়েছে।

## বাফার IO ব্যবহার করুন
বাফার IO ছাড়া, ফাইল IO ধীর হয়। বাফার IO দিয়ে, IO অপারেশনগুলি মেমরির বাফারের মাধ্যমে সম্পন্ন হয়, যা সিস্টেম কলের সংখ্যা হ্রাস করে এবং গতি উন্নত করে।

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, নিম্নলিখিত প্রক্রিয়ায়, [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) ১,০০০,০০০ বার ঘটে।
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
### After  <!-- omit in toc -->
নিম্নরূপে [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) ব্যবহার করে
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
প্রায় ৫০ গুণ গতি উন্নতি হয়।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
উপরে বর্ণিত পদ্ধতিটি এখানে বাস্তবায়িত হয়েছিল

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

এবং আউটপুট প্রক্রিয়াকরণে উল্লেখযোগ্য গতি উন্নতি হয়েছে।

## রেগুলার এক্সপ্রেশনের পরিবর্তে স্ট্যান্ডার্ড String মেথড ব্যবহার করুন
রেগুলার এক্সপ্রেশন জটিল ম্যাচিং প্যাটার্ন কভার করতে পারলেও, এগুলি [স্ট্যান্ডার্ড String মেথড](https://doc.rust-lang.org/std/string/struct.String.html)-এর চেয়ে ধীর। তাই, নিম্নলিখিত মতো সরল স্ট্রিং ম্যাচিংয়ের জন্য স্ট্যান্ডার্ড String মেথড ব্যবহার করা দ্রুততর।

- Starts-with ম্যাচিং（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Ends-with ম্যাচিং（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Contains ম্যাচিং（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, নিম্নলিখিত কোডটি একটি রেগুলার এক্সপ্রেশনে দশ লক্ষ বার ends-with ম্যাচিং সম্পন্ন করে।
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
### After  <!-- omit in toc -->
নিম্নরূপে [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) ব্যবহার করে
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
প্রক্রিয়াকরণ ১০ গুণ দ্রুত হবে।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
যেহেতু Hayabusa-এর কেস-ইনসেনসিটিভ স্ট্রিং তুলনার প্রয়োজন, আমরা [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) ব্যবহার করি এবং তারপর উপরের পদ্ধতিটি প্রয়োগ করি। তা সত্ত্বেও, নিম্নলিখিত উদাহরণগুলিতে

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

আগের তুলনায় গতি প্রায় ১৫% উন্নত হয়েছে।

## স্ট্রিং দৈর্ঘ্য অনুসারে ফিল্টার করুন
পরিচালিত স্ট্রিংগুলির বৈশিষ্ট্যের উপর নির্ভর করে, একটি সরল ফিল্টার যোগ করলে স্ট্রিং ম্যাচিং প্রচেষ্টার সংখ্যা হ্রাস পেতে পারে এবং প্রক্রিয়াটি দ্রুততর হতে পারে। আপনি যদি প্রায়শই অ-নির্দিষ্ট এবং অমিল স্ট্রিং দৈর্ঘ্যের স্ট্রিং তুলনা করেন, তবে স্ট্রিং দৈর্ঘ্যকে প্রাথমিক ফিল্টার হিসাবে ব্যবহার করে আপনি প্রক্রিয়াটিকে দ্রুততর করতে পারেন।

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, নিম্নলিখিত কোডটি দশ লক্ষ রেগুলার এক্সপ্রেশন ম্যাচ চেষ্টা করে।
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
### After  <!-- omit in toc -->
নিচে দেখানো হিসাবে [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len)-কে প্রাথমিক ফিল্টার হিসাবে ব্যবহার করে
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
গতি প্রায় ২০ গুণ উন্নত হবে।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে, উপরের পদ্ধতিটি ব্যবহার করা হয়েছে।

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

এটি গতি প্রায় ১৫% উন্নত করেছে।

## codegen-units=1 দিয়ে কম্পাইল করবেন না
Rust দিয়ে পারফরম্যান্স অপ্টিমাইজেশন সম্পর্কিত অনেক নিবন্ধে `[profile.release]` সেকশনের অধীনে `codegen-units = 1` যোগ করার পরামর্শ দেওয়া হয়।
এর ফলে কম্পাইলেশন সময় ধীর হবে কারণ ডিফল্ট হল সমান্তরালে কম্পাইল করা কিন্তু তাত্ত্বিকভাবে এটি আরও অপ্টিমাইজড এবং দ্রুততর কোডে পরিণত হওয়া উচিত।
তবে, আমাদের পরীক্ষায়, এই অপশনটি চালু থাকলে Hayabusa আসলে ধীর গতিতে চলে এবং কম্পাইলেশন বেশি সময় নেয় তাই আমরা এটি বন্ধ রাখি।
এক্সিকিউটেবলের বাইনারি আকার প্রায় ১০০kb ছোট হয় তাই এটি এমবেডেড সিস্টেমের জন্য আদর্শ হতে পারে যেখানে হার্ড ডিস্কের স্থান সীমিত।

# মেমরি ব্যবহার হ্রাস করা

## clone(), to_string() এবং to_owned()-এর অপ্রয়োজনীয় ব্যবহার এড়িয়ে চলুন
[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) বা [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) ব্যবহার করা হল [ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) সম্পর্কিত কম্পাইলেশন ত্রুটি সমাধানের সহজ উপায়। তবে, এগুলি সাধারণত উচ্চ মেমরি ব্যবহারের কারণ হবে এবং এড়ানো উচিত। প্রথমে দেখা সর্বদা সর্বোত্তম যে আপনি এগুলিকে কম খরচের [references](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) দিয়ে প্রতিস্থাপন করতে পারেন কিনা।

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, আপনি যদি একই `Vec`-কে একাধিকবার iterate করতে চান, তবে আপনি কম্পাইলেশন ত্রুটি দূর করতে [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) ব্যবহার করতে পারেন।
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
### After  <!-- omit in toc -->
তবে, নিচে দেখানো হিসাবে [references](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) ব্যবহার করে, আপনি [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) ব্যবহারের প্রয়োজন দূর করতে পারেন।
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
clone() ব্যবহার অপসারণ করে, মেমরি ব্যবহার ৫০% পর্যন্ত হ্রাস পায়।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে, অপ্রয়োজনীয় [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) এবং [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html) ব্যবহার প্রতিস্থাপন করে,

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

আমরা মেমরি ব্যবহার উল্লেখযোগ্যভাবে হ্রাস করতে পেরেছি।

## Vec-এর পরিবর্তে Iterator ব্যবহার করুন
[Vec](https://doc.rust-lang.org/std/vec/) সমস্ত উপাদান মেমরিতে রাখে, তাই এটি উপাদানের সংখ্যার অনুপাতে প্রচুর মেমরি ব্যবহার করে। একবারে একটি করে উপাদান প্রক্রিয়াকরণ যথেষ্ট হলে, পরিবর্তে একটি [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) ব্যবহার করলে অনেক কম মেমরি ব্যবহার হবে।

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, নিম্নলিখিত `return_lines()` ফাংশনটি প্রায় ১ GB-এর একটি ফাইল পড়ে এবং একটি [Vec](https://doc.rust-lang.org/std/vec/) ফেরত দেয়:
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
### After  <!-- omit in toc -->
পরিবর্তে আপনার নিম্নরূপে একটি [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) ফেরত দেওয়া উচিত:
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
অথবা কোন শাখা নেওয়া হয় তার উপর নির্ভর করে টাইপ ভিন্ন হলে, আপনি নিম্নরূপে একটি `Box<dyn Iterator<Item = T>>` ফেরত দিতে পারেন:
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
মেমরি ব্যবহার ১ GB থেকে কেবল ৩ MB-তে উল্লেখযোগ্যভাবে হ্রাস পায়।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে উপরে বর্ণিত পদ্ধতিটি ব্যবহার করা হয়:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

একটি 1.7GB JSON ফাইলে পরীক্ষা করার সময়, মেমরি ৭৫% হ্রাস পেয়েছে।

## ছোট স্ট্রিং পরিচালনার সময় compact_str crate ব্যবহার করুন
২৪ বাইটের কম অনেকগুলো ছোট স্ট্রিং নিয়ে কাজ করার সময়, মেমরি ব্যবহার হ্রাস করতে [compact_str crate](https://docs.rs/crate/compact_str/latest) ব্যবহার করা যেতে পারে।

### Before  <!-- omit in toc -->
নিচের উদাহরণে, Vec ১ কোটি স্ট্রিং ধারণ করে।
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### After  <!-- omit in toc -->
এগুলিকে একটি [CompactString](https://docs.rs/compact_str/latest/compact_str/) দিয়ে প্রতিস্থাপন করা ভালো:
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
এটি করার মাধ্যমে, মেমরি ব্যবহার প্রায় ৫০% হ্রাস পায়।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে, ছোট স্ট্রিংগুলি [CompactString](https://docs.rs/compact_str/latest/compact_str/) দিয়ে পরিচালনা করা হয়:

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

এটি প্রায় ২০% মেমরি ব্যবহার হ্রাস দিয়েছে।

## দীর্ঘস্থায়ী স্ট্রাকচারে অপ্রয়োজনীয় ফিল্ড মুছে ফেলুন
প্রসেস স্টার্টআপের সময় মেমরিতে ধরে রাখা স্ট্রাকচারগুলি সামগ্রিক মেমরি ব্যবহারকে প্রভাবিত করতে পারে। Hayabusa-তে, নিম্নলিখিত স্ট্রাকচারগুলি (সংস্করণ 2.2.2 অনুযায়ী), বিশেষ করে, প্রচুর সংখ্যায় ধরে রাখা হয়।

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

উপরের স্ট্রাকচারগুলির সাথে সম্পর্কিত ফিল্ড অপসারণ সামগ্রিক মেমরি ব্যবহার হ্রাসে কিছুটা প্রভাব ফেলেছে।

### Before  <!-- omit in toc -->
উদাহরণস্বরূপ, `DetectInfo` ফিল্ডটি, সংস্করণ 1.8.1 পর্যন্ত, নিম্নরূপ ছিল:
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
### After  <!-- omit in toc -->
নিম্নরূপে `record_information` ফিল্ডটি মুছে ফেলে
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
প্রতি সনাক্তকরণ ফলাফল রেকর্ড পিছু কয়েক বাইট মেমরি ব্যবহার হ্রাস অর্জিত হয়েছিল।

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
নিম্নলিখিত উদাহরণে, যেখানে সনাক্তকরণ ফলাফল রেকর্ডের সংখ্যা প্রায় ১৫ লক্ষ ছিল এমন ডেটার বিরুদ্ধে পরীক্ষা করা হয়েছিল,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

আমরা প্রায় 300MB মেমরি ব্যবহার হ্রাস অর্জন করতে পেরেছি।

# বেঞ্চমার্কিং
## মেমরি অ্যালোকেটরের পরিসংখ্যান ফাংশন ব্যবহার করুন।
কিছু মেমরি অ্যালোকেটর তাদের নিজস্ব মেমরি ব্যবহারের পরিসংখ্যান বজায় রাখে। উদাহরণস্বরূপ, [mimalloc](https://github.com/microsoft/mimalloc)-এ, মেমরি ব্যবহার পেতে [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) ফাংশনটি কল করা যেতে পারে।

### পরিসংখ্যান কীভাবে পাবেন  <!-- omit in toc -->
পূর্বশর্ত: আপনাকে [মেমরি অ্যালোকেটর পরিবর্তন করুন](#change-the-memory-allocator) সেকশনে ব্যাখ্যা করা হিসাবে mimalloc ব্যবহার করতে হবে।

1.  `Cargo.toml`-এর [dependencies section](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency)-এ, [libmimalloc-sys crate](https://crates.io/crates/libmimalloc-sys) যোগ করুন:
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. যখনই আপনি মেমরি ব্যবহারের পরিসংখ্যান প্রিন্ট করতে চান, নিম্নলিখিত কোডটি লিখুন এবং একটি `unsafe` ব্লকের ভিতরে, [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) কল করুন। মেমরি ব্যবহারের পরিসংখ্যান স্ট্যান্ডার্ড আউটে আউটপুট হবে।
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
3. উপরের বাম `peak/reserved` মান হল সর্বোচ্চ মেমরি ব্যবহার। 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### উদাহরণ   <!-- omit in toc -->
উপরের বাস্তবায়নটি নিম্নলিখিতে প্রয়োগ করা হয়েছিল:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

Hayabusa-তে, আপনি যদি `--debug` অপশন যোগ করেন, তবে শেষে মেমরি ব্যবহারের পরিসংখ্যান আউটপুট হবে।

## Windows-এর পারফরম্যান্স কাউন্টার ব্যবহার করুন
OS-এর দিকে পাওয়া যায় এমন পরিসংখ্যান থেকে বিভিন্ন রিসোর্স ব্যবহার পরীক্ষা করা যেতে পারে। এই ক্ষেত্রে, নিম্নলিখিত দুটি বিষয় লক্ষ্য করা উচিত।

- অ্যান্টি-ভাইরাস সফটওয়্যার (Windows Defender) থেকে প্রভাব
  - শুধুমাত্র প্রথম রানটি স্ক্যান দ্বারা প্রভাবিত হয় এবং ধীর হয়, তাই বিল্ডের পর দ্বিতীয় এবং পরবর্তী রানগুলির ফলাফল তুলনার জন্য উপযুক্ত। (অথবা আপনি আরও সঠিক ফলাফলের জন্য আপনার অ্যান্টি-ভাইরাস নিষ্ক্রিয় করতে পারেন।)
- ফাইল ক্যাশিং থেকে প্রভাব
  - OS স্টার্টআপের পর দ্বিতীয় এবং পরবর্তী বারের ফলাফল প্রথমবারের চেয়ে দ্রুত কারণ evtx এবং অন্যান্য ফাইল IO মেমরিতে ফাইল ক্যাশ থেকে পড়া হয়, তাই OS বুট হওয়ার পর প্রথমবারের ফলাফল বেঞ্চমার্ক নেওয়ার জন্য আরও আদর্শ।

### কীভাবে পাবেন  <!-- omit in toc -->
পূর্বশর্ত：নিম্নলিখিত পদ্ধতিটি শুধুমাত্র সেই পরিবেশের জন্য বৈধ যেখানে Windows-এ `PowerShell 7` ইতিমধ্যে ইনস্টল করা আছে।

1. OS পুনরায় চালু করুন
2. `PowerShell 7`-এর [Get-Counter command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) চালান যা প্রতি সেকেন্ডে একটি CSV ফাইলে পারফরম্যান্স কাউন্টার ক্রমাগত রেকর্ড করবে। (আপনি যদি নিচে তালিকাভুক্ত ছাড়া অন্য রিসোর্স পরিমাপ করতে চান, [এই নিবন্ধটি](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) একটি ভালো রেফারেন্স।)
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
3. আপনি যে প্রক্রিয়াটি পরিমাপ করতে চান তা এক্সিকিউট করুন।

### উদাহরণ  <!-- omit in toc -->
নিম্নলিখিতে Hayabusa দিয়ে পারফরম্যান্স পরিমাপের একটি উদাহরণ পদ্ধতি রয়েছে।

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## heaptrack ব্যবহার করুন
[heaptrack](https://github.com/KDE/heaptrack) হল Linux এবং macOS-এর জন্য উপলব্ধ একটি অত্যাধুনিক মেমরি প্রোফাইলার। heaptrack ব্যবহার করে, আপনি বটলনেকগুলি পুঙ্খানুপুঙ্খভাবে তদন্ত করতে পারেন।

### কীভাবে পাবেন  <!-- omit in toc -->
পূর্বশর্ত: নিচে Ubuntu 22.04-এর জন্য পদ্ধতি দেওয়া হল। আপনি Windows-এ heaptrack ব্যবহার করতে পারবেন না।

1. নিম্নলিখিত দুটি কমান্ড দিয়ে heaptrack ইনস্টল করুন।
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Hayabusa থেকে নিম্নলিখিত mimalloc কোড সরিয়ে ফেলুন। (আপনি mimalloc দিয়ে heaptrack-এর মেমরি প্রোফাইলার ব্যবহার করতে পারবেন না।
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Hayabusa-এর `Cargo.toml` ফাইলে [[profile.release] section](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) মুছে ফেলুন এবং এটি নিম্নরূপে পরিবর্তন করুন:
     ```
     [profile.release]
     debug = true
     ```

4. একটি রিলিজ বিল্ড তৈরি করুন: `cargo build --release`
5. `heaptrack hayabusa csv-timeline -d sample -o out.csv` চালান

এখন Hayabusa চালানো শেষ হলে, heaptrack-এর ফলাফল স্বয়ংক্রিয়ভাবে একটি GUI অ্যাপ্লিকেশনে খুলবে।

### উদাহরণ  <!-- omit in toc -->
heaptrack-এর ফলাফলের একটি উদাহরণ নিচে দেখানো হয়েছে। `Flame Graph` এবং `Top-Down` ট্যাবগুলি আপনাকে উচ্চ মেমরি ব্যবহার সহ ফাংশনগুলি ভিজ্যুয়ালি পরীক্ষা করতে দেয়।

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# রেফারেন্স

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# অবদান

এই নথিটি [Hayabusa](https://github.com/Yamato-Security/hayabusa)-এর প্রকৃত উন্নতির ক্ষেত্রের অনুসন্ধানের উপর ভিত্তি করে তৈরি। আপনি যদি কোনো ত্রুটি বা পারফরম্যান্স উন্নত করতে পারে এমন কৌশল খুঁজে পান, তবে অনুগ্রহ করে আমাদের একটি issue বা pull request পাঠান।
