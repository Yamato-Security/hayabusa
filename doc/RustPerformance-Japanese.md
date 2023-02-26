# Hayabusa開発者向けRustパフォーマンスガイド

# 目次

- [Hayabusa開発者向けRustパフォーマンスガイド](#hayabusa開発者向けrustパフォーマンスガイド)
- [目次](#目次)
- [この文書について](#この文書について)
- [メモリ使用量の削減](#メモリ使用量の削減)
  - [メモリアロケーターを変更する](#メモリアロケーターを変更する)
  - [不要なclone()、to\_string()、to\_owned()の使用を避ける](#不要なcloneto_stringto_ownedの使用を避ける)
  - [Vecの代わりにIteratorを使う](#vecの代わりにiteratorを使う)
  - [短い文字列に、compact\_strクレートを使う](#短い文字列にcompact_strクレートを使う)
  - [寿命の長い構造体の不要なフィールドを削除する](#寿命の長い構造体の不要なフィールドを削除する)
- [速度の改善](#速度の改善)
  - [ループの中で、IO処理を避ける](#ループの中でio処理を避ける)
  - [ループの中で、正規表現コンパイルを避ける](#ループの中で正規表現コンパイルを避ける)
  - [文字列長比較により、フィルターする](#文字列長比較によりフィルターする)
  - [正規表現の代わりにString標準メソッドを使う](#正規表現の代わりにstring標準メソッドを使う)
  - [バッファーIOを使う](#バッファーioを使う)
- [ベンチマークの取得](#ベンチマークの取得)
  - [メモリアロケーターの統計機能の利用（mimalloc）](#メモリアロケーターの統計機能の利用mimalloc)
  - [Windowsパフォーマンスカウンターの利用](#windowsパフォーマンスカウンターの利用)
  - [heaptrackによるメモリ使用量の取得](#heaptrackによるメモリ使用量の取得)
- [参考リンク](#参考リンク)
- [貢献](#貢献)

# この文書について
[Hayabusa](https://github.com/Yamato-Security/hayabusa)は、日本の[Yamato Security](https://yamatosecurity.connpass.com/)グループにより開発されたファストフォレンジックツールです。[隼](https://ja.wikipedia.org/wiki/%E3%83%8F%E3%83%A4%E3%83%96%E3%82%B5)のように高速で脅威ハンティングできることを目指し、[Rust](https://www.rust-lang.org/) で開発されています。[Rust](https://www.rust-lang.org/) はそれ自体が高速な言語ですが、その特徴を十分に活かすためのポイントがあります。この文書では、[Hayabusa開発史](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)の中の改善事例をもとに、ハイパフォーマンスな[Rust](https://www.rust-lang.org/) プログラムを開発するためのテクニックを紹介し、今後の開発に役立てることを目的としています。


# メモリ使用量の削減
## メモリアロケーターを変更する
規定のメモリアロケーターを変更するだけで、大幅に速度改善をできる場合があります。
たとえば[こちらのベンチマーク](https://github.com/rust-lang/rust-analyzer/issues/1441)によると、以下2つのメモリアロケーターは、

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

規定のメモリアロケーターより、高速という結果です。[Hayabusa](https://github.com/Yamato-Security/hayabusa)でも[mimalloc](https://microsoft.github.io/mimalloc/)を採用することで、大幅な速度改善が確認され、バージョン1.8.0から[mimalloc](https://microsoft.github.io/mimalloc/)を利用しています。

### 変更前  <!-- omit in toc -->
```
# とくになし（規定でメモリアロケータ宣言は不要）
```
### 変更後  <!-- omit in toc -->
Rustの[メモリアロケーター](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html)の変更手順は、以下の2ステップのみです。

1. [mimallocクレート](https://crates.io/crates/mimalloc)を`Cargo.toml`の[dependenciesセクション](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency)で指定する
```Toml
[dependencies]
mimalloc = { version = "*", default-features = false }
```
2. [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute)で[mimalloc](https://github.com/microsoft/mimalloc)利用を明示する
```Rust
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
```
以上で、[mimalloc](https://github.com/microsoft/mimalloc)をメモリアロケーターとして動作させることができます。

### 効果（Pull Reuest事例）  <!-- omit in toc -->
改善効果はプログラムの特性に依りますが、以下PRの事例では、
- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

上記手順でメモリアロケーターを[mimalloc](https://github.com/microsoft/mimalloc)に変更することで、Intel系OSで20-30%速度を改善しています。

## 不要なclone()、to_string()、to_owned()の使用を避ける
ひとこと
### 変更前  <!-- omit in toc -->
```Rust
```
### 変更後  <!-- omit in toc -->
```Rust
```
### 効果（Pull Reuest事例）   <!-- omit in toc -->
- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

## Vecの代わりにIteratorを使う
[Vec](https://doc.rust-lang.org/std/vec/)は全要素をメモリで保持するため、要素数が多いケースでは大量のメモリを使用します。一要素ずつの処理で事足りるケースでは、代わりに[Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html)を使用することで、メモリ使用量を大幅に削減できます。

### 変更前  <!-- omit in toc -->
```Rust
```
### 変更後  <!-- omit in toc -->
```Rust
```
### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、
- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

1.7GBのJSONファイルの処理時のメモリ使用量を75%削減しています。

## 短い文字列に、compact_strクレートを使う
短い文字列を

### 変更前  <!-- omit in toc -->
```Rust
```
### 変更後  <!-- omit in toc -->
```Rust
```
### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、
- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

〇〇できました。

## 寿命の長い構造体の不要なフィールドを削除する
プロセス起動中、メモリ上に保持し続ける必要がある構造体は、全体のメモリ使用量に影響を及ぼしている可能性があります。[Hayabusa](https://github.com/Yamato-Security/hayabusa)では、とくに以下の構造体（バージョン2.2.2時点）は保持数が多いため、
- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

上記構造体に関連するフィールドの削除は、全体のメモリ使用量削減に一定の効果がありました。

### 変更前  <!-- omit in toc -->
```Rust
```
### 変更後  <!-- omit in toc -->
```Rust
```
### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、
- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

〇〇できました。

# 速度の改善

## ループの中で、IO処理を避ける
ディスクIO処理はメモリ上で完結する処理と比較して、非常に低速です。そのため、とくにループ中でのIO処理は極力避けることが望ましいです。

### 変更前  <!-- omit in toc -->
```Rust
```
### 変更後  <!-- omit in toc -->
```Rust
```
### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、検知結果1件ずつを処理するループ中でのIO処理をループ外にだすことで、
- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

20%ほどの速度改善を実現しました。

## ループの中で、正規表現コンパイルを避ける
正規表現マッチングは一定の速度がでる一方で、正規表現コンパイルは非常に低速です。そのため、とくにループ中での正規表現コンパイルは極力避けることが望ましいです。

### 変更前  <!-- omit in toc -->
たとえば、10万回正規表現マッチを試行させる以下の処理は、
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
    let r = Regex::new(match_str).unwrap(); // ループの中で正規表現コンパイル
    for _ in 0..100000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
上記の例では、変更前と比較して100倍ほど速くなります。

### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、
- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

〇〇できました。


## 文字列長比較により、フィルターする
扱う文字列の特性に依っては、簡単なフィルターを加えることで、文字列マッチング試行回数を減らし、高速化できる場合があります。
たとえば、文字列長が非固定長かつ不一致の文字列を比較することが多い場合、文字列長を1次フィルターに使うことで処理を高速化できます。

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
上記の例では、変更前と比較して20倍ほど速くなります。

### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、上記手法により、
- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

15%ほどの速度改善を実現しました。

## 正規表現の代わりにString標準メソッドを使う
正規表現は複雑なマッチングパターンを網羅できる一方、String標準のメソッドと比較すると低速です。そのため、以下のような単純な文字列マッチングには、String標準メソッドを使ったほうが高速です。

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
上記の例では、変更前と比較して10倍ほど速くなります。

### 効果（Pull Reuest事例）   <!-- omit in toc -->
[Hayabusa](https://github.com/Yamato-Security/hayabusa)では、大文字小文字を区別しない文字列比較をする必要があるため、[to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase)を実施したうえで、上記手法を適用しました。その場合でも以下PRの事例では、
- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

正規表現を使った場合と比較して、15%ほどの速度改善を実現しました。

## バッファーIOを使う
ひとこと
### 変更前  <!-- omit in toc -->
```Rust
```
### 変更後  <!-- omit in toc -->
```Rust
```
### 効果（Pull Reuest事例）   <!-- omit in toc -->
以下PRの事例では、
- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

大幅な速度改善を実現しました。

# ベンチマークの取得
## メモリアロケーターの統計機能の利用（mimalloc）
メモリアロケーターの中には、自身のメモリ使用統計情報を保持するものがあります。[mimalloc](https://github.com/microsoft/mimalloc)では、[mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79)関数を呼び出すことで、メモリ統計情報が取得できます。

### 取得方法  <!-- omit in toc -->
前提： [メモリアロケーターを変更する](#メモリアロケーターを変更する)で[mimalloc](https://github.com/microsoft/mimalloc)を設定している場合の手順です。

1.  `Cargo.toml`の[dependenciesセクション](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency)で[libmimalloc-sysクレート](https://crates.io/crates/libmimalloc-sys)指定する
```Toml
[dependencies]
libmimalloc-sys = { version = "*",  features = ["extended"] }
```
2. メモリ使用量を測定したい箇所で、以下コードを書きます。
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
### 事例   <!-- omit in toc -->
以下PRで、
- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

[Hayabusa](https://github.com/Yamato-Security/hayabusa)では、`--debug`オプションつきで実行した場合、メモリ使用量を確認できるようにしています。

## Windowsパフォーマンスカウンターの利用
OS側で取得できる統計情報から各種リソース使用状況を確認できます。この場合は、以下の点に注意が必要です。

- アンチウイルスソフトの影響
  - Hayabusaでは初回実行のみスキャン影響を受けて、遅くなるため、ビルド後2回目以降の結果が比較に適します。
- ファイルキャッシュの影響
  - OS起動後、2回目以降の測定結果は、ファイルIOがメモリ上のファイルキャッシュから読み出される分、1回目より速くなり不正確な比較になりがちです。

### 取得方法  <!-- omit in toc -->
前提：以下はWindowsで`PowerShell7`がインストール済みの環境でのみ有効な手順です。

1. OSを再起動する
2. `PowerShell7`の[Get-Counterコマンド](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter)を実行し、パフォーマンスカウンター（以下の例ではCPU/Memory使用率を取得）を1秒間隔で取得する
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

## heaptrackによるメモリ使用量の取得
ひとこと
### 取得方法  <!-- omit in toc -->
```
```
### 事例  <!-- omit in toc -->
- TODO
- TODO

# 参考リンク

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)

# 貢献

この文書は、[Hayabusa](https://github.com/Yamato-Security/hayabusa)の実際の改善事例から得た知見をもとに作成していますが、誤りやよりパフォーマンスを出せるテクニックがありましたら、issueやプルリクエストを頂けると幸いです！