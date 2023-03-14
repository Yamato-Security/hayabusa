# Hayabusa開発者向けRustパフォーマンスガイド

# 目次

- [Hayabusa開発者向けRustパフォーマンスガイド](#hayabusa開発者向けrustパフォーマンスガイド)
- [目次](#目次)
- [著者](#著者)
- [この文書について](#この文書について)
- [速度の改善](#速度の改善)
  - [メモリアロケーターを変更する](#メモリアロケーターを変更する)
  - [ループの中で、IO処理を避ける](#ループの中でio処理を避ける)
  - [ループの中で、正規表現コンパイルを避ける](#ループの中で正規表現コンパイルを避ける)
  - [バッファーIOを使う](#バッファーioを使う)
  - [正規表現の代わりにString標準メソッドを使う](#正規表現の代わりにstring標準メソッドを使う)
  - [文字列長比較により、フィルターする](#文字列長比較によりフィルターする)
  - [コンパイル時にcodegen-units=1を使用しない](#コンパイル時にcodegen-units1を使用しない)
- [メモリ使用量の削減](#メモリ使用量の削減)
  - [不要なclone()、to\_string()、to\_owned()の使用を避ける](#不要なcloneto_stringto_ownedの使用を避ける)
  - [Vecの代わりにIteratorを使う](#vecの代わりにiteratorを使う)
  - [短い文字列に、compact\_strクレートを使う](#短い文字列にcompact_strクレートを使う)
  - [寿命の長い構造体の不要なフィールドを削除する](#寿命の長い構造体の不要なフィールドを削除する)
- [ベンチマーク情報の取得](#ベンチマーク情報の取得)
  - [メモリアロケーターの統計機能を利用する](#メモリアロケーターの統計機能を利用する)
  - [Windowsパフォーマンスカウンターを利用する](#windowsパフォーマンスカウンターを利用する)
  - [heaptrackを利用する](#heaptrackを利用する)
- [参考リンク](#参考リンク)
- [貢献](#貢献)

# 著者

Fukusuke Takahashi

# この文書について
[Hayabusa](https://github.com/Yamato-Security/hayabusa)は、日本の[Yamato Security](https://yamatosecurity.connpass.com/)グループにより開発されたファストフォレンジックツールです。[隼](https://ja.wikipedia.org/wiki/%E3%83%8F%E3%83%A4%E3%83%96%E3%82%B5)のように高速に脅威ハンティングできることを目指し、[Rust](https://www.rust-lang.org/) で開発されています。[Rust](https://www.rust-lang.org/) はそれ自体が高速な言語ですが、その特徴を十分に活かすためのポイントがあります。この文書は、[Hayabusa開発史](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)の中の改善事例をもとに、ハイパフォーマンスな[Rust](https://www.rust-lang.org/) プログラムを開発するためのテクニックを説明し、今後の開発に役立てることを目的としています。

# 速度の改善
## メモリアロケーターを変更する
既定のメモリアロケーターを変更するだけで、大幅に速度改善をできる場合があります。
たとえば[こちらのベンチマーク](https://github.com/rust-lang/rust-analyzer/issues/1441)によると、以下2つのメモリアロケーターは、

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

既定のメモリアロケーターより、高速という結果です。[Hayabusa](https://github.com/Yamato-Security/hayabusa)でも[mimalloc](https://microsoft.github.io/mimalloc/)を採用することで、大幅な速度改善を確認できたため、バージョン1.8.0から[mimalloc](https://microsoft.github.io/mimalloc/)を利用しています。

### 変更前  <!-- omit in toc -->
```
# とくになし（規定でメモリアロケータ宣言は不要）
```
### 変更後  <!-- omit in toc -->
[メモリアロケーター](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html)の変更手順は、以下の2ステップのみです。

1. [mimallocクレート](https://crates.io/crates/mimalloc)を`Cargo.toml`の[[dependencies]セクション](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency)で指定する
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. プログラム中のどこかで、[#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute)で[mimalloc](https://github.com/microsoft/mimalloc)利用を明示する
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
以上で、メモリアロケーターが[mimalloc](https://github.com/microsoft/mimalloc)に変更されます。

### 効果（Pull Request事例）  <!-- omit in toc -->
改善効果はプログラムの特性に依りますが、以下の事例では、
- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

上記手順でメモリアロケーターを[mimalloc](https://github.com/microsoft/mimalloc)に変更することで、Intel系OSで20-30%速度を改善しました。

## ループの中で、IO処理を避ける
ディスクIO処理はメモリ上で完結する処理と比較して、非常に低速です。そのため、とくにループの中でのIO処理は極力避けることが望ましいです。

### 変更前  <!-- omit in toc -->
たとえば、ループの中でファイルオープンが100万回発生する以下の処理は、
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### 変更後  <!-- omit in toc -->
以下のように、ループの外でファイルオープンさせることで、
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
変更前と比較して1000倍ほど速くなります。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、検知結果を1件ずつ扱うときのIO処理をループ外にだすことで、
- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

20%ほどの速度改善を実現しました。

## ループの中で、正規表現コンパイルを避ける
正規表現のコンパイルは、正規表現のマッチングと比較して、非常にコストがかかる処理です。そのため、とくにループ中での正規表現コンパイルは極力避けることが望ましいです。

### 変更前  <!-- omit in toc -->
たとえば、ループの中で正規表現マッチを10万回試行する以下の処理は、
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    for _ in 0..100000 {
        if Regex::new(match_str).unwrap().is_match(text){ // ループの中で正規表現コンパイル
            println!("matched!");
        }
    }
}
```
### 変更後  <!-- omit in toc -->
以下のように、ループの外で正規表現コンパイルをすることで、
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap(); // ループの外で正規表現コンパイル
    for _ in 0..100000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
変更前と比較して100倍ほど速くなります。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、正規表現コンパイルをループ外で実施し、キャッシュすることで
- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

大幅な速度改善を実現しました。

## バッファーIOを使う
バッファーIOを使わない場合のファイルIOは、低速です。バッファーIOを使うとメモリ上のバッファーを介して、IO処理が行われ、システムコール回数を削減でき、速度を改善できます。

### 変更前  <!-- omit in toc -->
たとえば、[write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write)が100万回発生する以下の処理は、
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
### 変更後  <!-- omit in toc -->
以下のように、[BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html)を使うことで、
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
変更前と比較して50倍ほど速くなります。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、上記手法により、
- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

出力処理の大幅な速度改善を実現しました。

## 正規表現の代わりにString標準メソッドを使う
正規表現は複雑なマッチングパターンを網羅できる一方、[String標準のメソッド](https://doc.rust-lang.org/std/string/struct.String.html)と比較すると低速です。そのため、以下のような単純な文字列マッチングには、[String標準のメソッド](https://doc.rust-lang.org/std/string/struct.String.html)を使ったほうが高速です。

- 前方一致（正規表現では、`foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- 後方一致（正規表現では、`.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- 部分一致（正規表現では、`.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### 変更前  <!-- omit in toc -->
たとえば、100万回正規表現で後方一致マッチを試行する以下の処理は、
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
### 変更後  <!-- omit in toc -->
以下のように、[String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)を使うことで、
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
変更前と比較して10倍ほど速くなります。

### 効果（Pull Request事例）   <!-- omit in toc -->
[Hayabusa](https://github.com/Yamato-Security/hayabusa)では、大文字小文字を区別しない文字列比較をする必要があるため、[to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase)を実施したうえで、上記手法を適用しています。その場合でも以下の事例では、
- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

正規表現を使った場合と比較して、15%ほどの速度改善を実現しました。

## 文字列長比較により、フィルターする
扱う文字列の特性に依っては、簡単なフィルターを加えることで、文字列マッチング試行回数を減らし、高速化できる場合があります。
文字列長が非固定長かつ不一致の文字列を比較することが多い場合、文字列長を一次フィルターに使うことで処理を高速化できます。

### 変更前  <!-- omit in toc -->
たとえば、100万回正規表現マッチを試行する以下の処理は、
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
### 変更後  <!-- omit in toc -->
以下のように、[String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len)を一次フィルターに使うことで、
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if text.len() == match_str.len() { //文字列長で1次フィルター
            if r.is_match(text) {
                println!("matched!");
            }
        }
    }
}
```
変更前と比較して20倍ほど速くなります。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、上記手法により、
- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

15%ほどの速度改善を実現しました。

## コンパイル時にcodegen-units=1を使用しない
Rustのパフォーマンス最適化に関する多くの記事では、`[profile.release]`セクションに `codegen-units = 1` を追加することが推奨されています。
デフォルトでは並列にコンパイルされるため、コンパイルにかかる時間は遅くなりますが、理論的にはより最適化された高速なコードが得られるはずです。
しかし、この設定を有効にした場合、Hayabusaの動作が遅くなり、コンパイルに時間がかかるため、無効のままにしています。
実行ファイルのバイナリサイズが100kb程度小さくなるので、ハードディスクの容量が限られている組み込みシステムには最適かもしれません。

# メモリ使用量の削減

## 不要なclone()、to_string()、to_owned()の使用を避ける
[所有権](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html)に関連するコンパイルエラーの解消手段として、[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html)や[to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html)を安易に使うと、保持するデータ量や頻度に依り、ボトルネックになる可能性があります。
低コストで動作する[参照](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html)で代替できるかを先に検討することが望ましいです。

### 変更前  <!-- omit in toc -->
たとえば、同一の`Vec`を複数回イテレーションしたい場合、[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html)でコンパイルエラーを解消することもできますが
```Rust
fn main() {
    let lst = vec![1, 2, 3];
    for x in lst.clone() { // コンパイルエラー解消のために
        println!("{x}");
    }

    for x in lst {
        println!("{x}");
    }
}
```
### 変更後  <!-- omit in toc -->
以下のように、[参照](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html)を利用することで[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html)による不要なコピーをなくすことができます。
```Rust
fn main() {
    let lst = vec![1, 2, 3];
    for x in &lst { // 参照でコンパイルエラー解消
        println!("{x}");
    }

    for x in lst {
        println!("{x}");
    }
}
```
変更前と比較して最大メモリ使用量が50%ほど削減されます。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、不要な[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html)、[to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html)、[to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html)を置き換えることで、
- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

大幅なメモリ使用量削減を実現しました。

## Vecの代わりにIteratorを使う
[Vec](https://doc.rust-lang.org/std/vec/)は全要素をメモリ上に保持するため、要素数に比例して多くのメモリを使います。一要素ずつの処理で事足りる場合は、代わりに[Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html)を使用することで、メモリ使用量を大幅に削減できます。

### 変更前  <!-- omit in toc -->
たとえば、1GBほどのファイルを読み出し、[Vec](https://doc.rust-lang.org/std/vec/)を返す以下の`return_lines()`関数は、
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
### 変更後  <!-- omit in toc -->
以下のように、[Iteratorトレイト](https://doc.rust-lang.org/std/iter/trait.Iterator.html)を返す、
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
また処理の分岐により、型が異なる場合は、以下のように`Box<dyn Iterator<Item = T>>`を返すことで
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
変更前のメモリ使用量は1GBほどでしたが、3MBほどのメモリ使用量になり、大幅に削減できます。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では上記手法により、
- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

1.7GBのJSONファイルの処理時のメモリ使用量を75%削減しています。

## 短い文字列に、compact_strクレートを使う
24byte未満の短い文字列を大量に扱う場合は、[compact_strクレート](https://docs.rs/crate/compact_str/latest)を利用することで、メモリ使用量の削減効果があります。

### 変更前  <!-- omit in toc -->
たとえば、1000万個のStringを持つ以下のVecは、
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // なにか処理
}
```
### 変更後  <!-- omit in toc -->
以下のように、[CompactString](https://docs.rs/compact_str/latest/compact_str/)に置き換えることで、
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // なにか処理
}
```
変更前と比較してメモリ使用量が50%ほど削減されます。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、短い文字列に対して、[CompactString](https://docs.rs/compact_str/latest/compact_str/)を利用することで、
- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

20%ほどのメモリ使用量削減を実現しました。

## 寿命の長い構造体の不要なフィールドを削除する
プロセス起動中、メモリ上に保持し続ける構造体は、全体のメモリ使用量に影響を及ぼしている可能性があります。[Hayabusa](https://github.com/Yamato-Security/hayabusa)では、とくに以下の構造体（バージョン2.2.2時点）は保持数が多いため、
- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

上記構造体に関連するフィールドの削除は、全体のメモリ使用量削減に一定の効果がありました。

### 変更前  <!-- omit in toc -->
たとえば、`DetectInfo`のフィールドはバージョン1.8.1までは、以下でしたが、
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
### 変更後  <!-- omit in toc -->
以下のように、`record_information`フィールドを削除することで、
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
検知結果レコード1件あたり、数バイトのメモリ使用量削減が見込めます。

### 効果（Pull Request事例）   <!-- omit in toc -->
以下の事例では、検知結果レコード件数が150万件ほどのデータに対して、
- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

それぞれどちらも、300MB程度メモリ使用量を削減しています。


# ベンチマーク情報の取得
## メモリアロケーターの統計機能を利用する
メモリアロケーターの中には、自身のメモリ使用統計情報を保持するものがあります。たとえば[mimalloc](https://github.com/microsoft/mimalloc)では、[mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79)関数を呼び出すことで、メモリ使用量が取得できます。

### 取得方法  <!-- omit in toc -->
前提： [メモリアロケーターを変更する](#メモリアロケーターを変更する)で[mimalloc](https://github.com/microsoft/mimalloc)を設定している場合の手順です。

1.  `Cargo.toml`の[dependenciesセクション](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency)で[libmimalloc-sysクレート](https://crates.io/crates/libmimalloc-sys)指定する
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. メモリ使用量を測定したい箇所で、以下コードを書き、`unsafe`ブロックで[mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79)を呼び出すと標準出力にメモリ使用統計情報が出力されます
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
3. [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79)の出力結果が以下の通り得られます。左上の`peak/reserved`の値が最大メモリ使用量です。

    ![mimalloc_stats_print_out](01_mi_stats_print_out.png)

### 事例   <!-- omit in toc -->
以下で上記実装を適用し、
- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

[Hayabusa](https://github.com/Yamato-Security/hayabusa)では、`--debug`オプションつきで実行した場合、メモリ使用量を確認できるようにしています。

## Windowsパフォーマンスカウンターを利用する
OS側で取得できる統計情報から各種リソース使用状況を確認できます。この場合は、以下の2点に注意が必要です。

- アンチウイルスソフトの影響
  - 初回実行のみスキャンの影響を受けて、遅くなるため、ビルド後2回目以降の測定結果が比較に適します。
- ファイルキャッシュの影響
  - OS起動後、2回目以降の測定結果は、evtxなどのファイルIOがメモリ上のファイルキャッシュから読み出される分、1回目より速くなるため、OS起動後初回の測定結果が比較に適します。

### 取得方法  <!-- omit in toc -->
前提：以下はWindowsで`PowerShell7`がインストール済みの環境でのみ有効な手順です。

1. OSを再起動する
2. `PowerShell7`の[Get-Counterコマンド](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter)を実行し、パフォーマンスカウンター(下記以外のリソースを計測したい場合は、[こちらの記事](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/)が参考になります)を1秒間隔で取得し続け、CSVに記録します
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
3. 計測したい処理を実行する

### 事例  <!-- omit in toc -->
以下は、[Hayabusa](https://github.com/Yamato-Security/hayabusa)で、パフォーマンスを計測する際の手順例です。
- [Windowsのパフォーマンスカウンタ取得例](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## heaptrackを利用する
[heaptrack](https://github.com/KDE/heaptrack)は、LinuxおよびmacOSで利用可能な高機能なメモリプロファイラーです。[heaptrack](https://github.com/KDE/heaptrack)を使うことで、詳細にボトルネックを調査できます。

### 取得方法  <!-- omit in toc -->
前提： 以下はUbuntu 22.04の場合の手順です。[heaptrack](https://github.com/KDE/heaptrack)はWindowsでは使えません。

1. 以下の2コマンドで、[heaptrack](https://github.com/KDE/heaptrack)をインストール
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. [Hayabusa](https://github.com/Yamato-Security/hayabusa)のコードから、[mimalloc](https://github.com/microsoft/mimalloc)関連の以下箇所のコードを削除する（[mimalloc](https://github.com/microsoft/mimalloc)では[heaptrack](https://github.com/KDE/heaptrack)によるメモリプロファイルが取得できないため）
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. [Hayabusa](https://github.com/Yamato-Security/hayabusa)の`Cargo.toml`の[[profile.release]セクション](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67)を削除し、以下に変更する
     ```
     [profile.release]
     debug = true
     ```

4. `cargo build --release` でリリースビルドをする
5. `heaptrack hayabusa csv-timeline -d sample -o out.csv` を実行する

以上で、[Hayabusa](https://github.com/Yamato-Security/hayabusa)の実行が完了すると、自動で[heaptrack](https://github.com/KDE/heaptrack)解析結果のGUIが立ち上がります。

### 事例  <!-- omit in toc -->
[heaptrack](https://github.com/KDE/heaptrack)解析結果の例は以下です。`Flame Graph`タブや`Top-Down`タブで視覚的にメモリ使用量の多い処理を確認することができます。

![heaptrack01](02-heaptrack.png)

![heaptrack02](03-heaptrack.png)

# 参考リンク

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# 貢献

この文書は、[Hayabusa](https://github.com/Yamato-Security/hayabusa)の実際の改善事例から得た知見をもとに作成していますが、誤りやよりパフォーマンスを出せるテクニックがありましたら、issueやプルリクエストを頂けると幸いです！