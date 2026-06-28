# Hayabusa Geliştiricileri için Rust Performans Kılavuzu

# Yazar
Fukusuke Takahashi

# İngilizce çeviri
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# Bu belge hakkında
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (Türkçe: "gökdoğan"), Japonya'daki [Yamato Security](https://yamatosecurity.connpass.com/) grubu tarafından geliştirilen hızlı bir adli analiz aracıdır. Bir gökdoğan kadar hızlı (tehdit) avlamak amacıyla [Rust](https://www.rust-lang.org/) ile geliştirilmiştir. Rust kendi başına hızlı bir dildir, ancak yavaş hızlara ve yüksek bellek kullanımına yol açabilecek birçok tuzak vardır. Bu belgeyi Hayabusa'daki gerçek performans iyileştirmelerine dayanarak oluşturduk (bkz. [buradaki değişiklik günlüğü](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), ancak bu teknikler diğer Rust programlarına da uygulanabilir olmalıdır. Deneme yanılma yoluyla edindiğimiz bilgilerden yararlanabileceğinizi umuyoruz.

# Hız iyileştirmesi
## Bellek ayırıcıyı değiştirin
Varsayılan bellek ayırıcıyı değiştirmek tek başına hızı önemli ölçüde artırabilir.
Örneğin, bu [karşılaştırmalara](https://github.com/rust-lang/rust-analyzer/issues/1441) göre, aşağıdaki iki bellek ayırıcı

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

varsayılan bellek ayırıcıdan çok daha hızlıdır. Bellek ayırıcımızı jemalloc'tan mimalloc'a değiştirerek önemli bir hız iyileştirmesi doğrulayabildik, bu yüzden 1.8.0 sürümünden itibaren mimalloc'u varsayılan yaptık. (Her ne kadar mimalloc, jemalloc'tan biraz daha fazla bellek kullansa da.)

### Before  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### After  <!-- omit in toc -->
Global [bellek ayırıcıyı](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) değiştirmek için yalnızca aşağıdaki 2 adımı gerçekleştirmeniz gerekir:

1. [mimalloc crate'ini](https://crates.io/crates/mimalloc) `Cargo.toml` dosyasının [[dependencies] bölümüne](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) ekleyin:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. Programın bir yerinde [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) altında mimalloc kullanmak istediğinizi tanımlayın:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
Bellek ayırıcıyı değiştirmek için yapmanız gereken tek şey budur.

### Effectiveness（Real example from a Pull Request）  <!-- omit in toc -->
Hızın ne kadar iyileşeceği programa bağlı olacaktır, ancak aşağıdaki örnekte

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

bellek ayırıcıyı [mimalloc](https://github.com/microsoft/mimalloc) olarak değiştirmek, Intel CPU'larda %20-30'luk bir performans artışıyla sonuçlandı. 
(Nedense, ARM tabanlı macOS cihazlarında bu kadar önemli bir performans artışı olmadı.)

## Döngülerdeki IO işlemlerini azaltın
Disk IO işlemleri, bellekteki işlemlerden çok daha yavaştır. Bu nedenle, özellikle döngülerde, IO işlemlerinden mümkün olduğunca kaçınmak arzu edilir.

### Before  <!-- omit in toc -->
Aşağıdaki örnek, bir döngüde bir milyon kez gerçekleşen bir dosya açma işlemini göstermektedir:
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
Dosyayı aşağıdaki gibi döngünün dışında açarak
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
yaklaşık 1000 kat hız artışı olacaktır.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnekte, her seferinde bir algılama sonucu işlenirken yapılan IO işlemi, döngünün dışında gerçekleştirilebildi:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

Bu, yaklaşık %20'lik bir hız iyileştirmesiyle sonuçlandı.

## Döngülerde düzenli ifade derlemesinden kaçının
Düzenli ifade derlemesi, düzenli ifade eşleştirmesine kıyasla çok maliyetli bir işlemdir. Bu nedenle, özellikle döngülerde, düzenli ifade derlemesinden mümkün olduğunca kaçınmak tavsiye edilir.

### Before  <!-- omit in toc -->
Örneğin, aşağıdaki işlem bir döngüde bir düzenli ifadeyi eşleştirmek için 100.000 deneme oluşturur:
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
Aşağıda gösterildiği gibi düzenli ifade derlemesini döngünün dışında yaparak
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
güncellenmiş kod yaklaşık 100 kat daha hızlıdır.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnekte, düzenli ifade derlemesi döngünün dışında gerçekleştirilir ve önbelleğe alınır.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

Bu, önemli hız iyileştirmeleriyle sonuçlandı.

## Tampon IO kullanın
Tampon IO olmadan, dosya IO'su yavaştır. Tampon IO ile, IO işlemleri bellekteki tamponlar aracılığıyla gerçekleştirilir, bu da sistem çağrılarının sayısını azaltır ve hızı artırır.

### Before  <!-- omit in toc -->
Örneğin, aşağıdaki işlemde [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) 1.000.000 kez gerçekleşir.
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
[BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) kullanarak aşağıdaki gibi
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
yaklaşık 50 kat hız iyileştirmesi olur.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Yukarıda açıklanan yöntem burada uygulandı

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

ve çıktı işlemede önemli hız iyileştirmeleriyle sonuçlandı.

## Düzenli ifadeler yerine standart String yöntemlerini kullanın
Düzenli ifadeler karmaşık eşleştirme desenlerini kapsayabilse de, [standart String yöntemlerinden](https://doc.rust-lang.org/std/string/struct.String.html) daha yavaştırlar. Bu nedenle, aşağıdaki gibi basit dize eşleştirmesi için standart String yöntemlerini kullanmak daha hızlıdır.

- Başlangıç eşleştirmesi（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Bitiş eşleştirmesi（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- İçerme eşleştirmesi（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### Before  <!-- omit in toc -->
Örneğin, aşağıdaki kod bir düzenli ifadede bir milyon kez bitiş eşleştirmesi gerçekleştirir.
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
[String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) kullanarak aşağıdaki gibi
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
işlem 10 kat daha hızlı olacaktır.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Hayabusa, büyük/küçük harfe duyarsız dize karşılaştırması gerektirdiğinden, [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) kullanır ve ardından yukarıdaki yöntemi uygularız. O zaman bile, aşağıdaki örneklerde

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

hız öncesine kıyasla yaklaşık %15 iyileşti.

## Dize uzunluğuna göre filtreleyin
İşlenen dizelerin özelliklerine bağlı olarak, basit bir filtre eklemek dize eşleştirme denemelerinin sayısını azaltabilir ve işlemi hızlandırabilir. Sabit olmayan ve eşleşmeyen dize uzunluklarına sahip dizeleri sık sık karşılaştırıyorsanız, dize uzunluğunu birincil filtre olarak kullanarak işlemi hızlandırabilirsiniz.

### Before  <!-- omit in toc -->
Örneğin, aşağıdaki kod bir milyon düzenli ifade eşleştirmesi dener.
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
Aşağıda gösterildiği gibi [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) kullanarak birincil filtre olarak
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
hız yaklaşık 20 kat iyileşecektir.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnekte yukarıdaki yöntem kullanılmaktadır.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

Bu, hızı yaklaşık %15 iyileştirdi.

## codegen-units=1 ile derlemeyin
Rust ile performans optimizasyonu hakkındaki birçok makale, `[profile.release]` bölümü altına `codegen-units = 1` eklemeyi tavsiye eder.
Varsayılan olarak paralel derleme yapıldığından bu, daha yavaş derleme sürelerine neden olur, ancak teorik olarak daha optimize ve daha hızlı kodla sonuçlanmalıdır.
Ancak, testlerimizde Hayabusa aslında bu seçenek açıkken daha yavaş çalışır ve derleme daha uzun sürer, bu yüzden bunu kapalı tutuyoruz.
Yürütülebilir dosyanın ikili boyutu yaklaşık 100kb daha küçüktür, bu yüzden bu, sabit disk alanının sınırlı olduğu gömülü sistemler için ideal olabilir.

# Bellek kullanımını azaltma

## clone(), to_string() ve to_owned() öğelerinin gereksiz kullanımından kaçının
[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) veya [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) kullanmak, [sahiplik](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) ile ilgili derleme hatalarını çözmenin kolay yollarıdır. Ancak, genellikle yüksek bellek kullanımına neden olurlar ve bunlardan kaçınılmalıdır. Önce onları düşük maliyetli [referanslarla](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) değiştirip değiştiremeyeceğinizi görmek her zaman en iyisidir.

### Before  <!-- omit in toc -->
Örneğin, aynı `Vec` üzerinde birden çok kez yineleme yapmak istiyorsanız, derleme hatalarını ortadan kaldırmak için [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) kullanabilirsiniz.
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
Ancak, aşağıda gösterildiği gibi [referanslar](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) kullanarak, [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) kullanma ihtiyacını ortadan kaldırabilirsiniz.
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
clone() kullanımını kaldırarak, bellek kullanımı %50'ye kadar azaltılır.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnekte, gereksiz [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) ve [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html) kullanımını değiştirerek,

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

bellek kullanımını önemli ölçüde azaltabildik.

## Vec yerine Iterator kullanın
[Vec](https://doc.rust-lang.org/std/vec/) tüm öğeleri bellekte tutar, bu yüzden öğe sayısıyla orantılı olarak çok fazla bellek kullanır. Bir seferde bir öğeyi işlemek yeterliyse, bunun yerine bir [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) kullanmak çok daha az bellek kullanacaktır.

### Before  <!-- omit in toc -->
Örneğin, aşağıdaki `return_lines()` fonksiyonu yaklaşık 1 GB'lık bir dosyayı okur ve bir [Vec](https://doc.rust-lang.org/std/vec/) döndürür:
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
Bunun yerine aşağıdaki gibi bir [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) döndürmelisiniz:
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
Veya hangi dalın alındığına bağlı olarak tür farklıysa, aşağıdaki gibi bir `Box<dyn Iterator<Item = T>>` döndürebilirsiniz:
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
Bellek kullanımı 1 GB'tan yalnızca 3 MB'a önemli ölçüde düşer.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnek yukarıda açıklanan yöntemi kullanır:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

1.7GB'lık bir JSON dosyası üzerinde test edildiğinde, bellek %75 azaldı.

## Kısa dizeleri işlerken compact_str crate'ini kullanın
24 bayttan az olan çok sayıda kısa dizeyle uğraşırken, bellek kullanımını azaltmak için [compact_str crate'i](https://docs.rs/crate/compact_str/latest) kullanılabilir.

### Before  <!-- omit in toc -->
Aşağıdaki örnekte, Vec 10 milyon dize tutar.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### After  <!-- omit in toc -->
Onları bir [CompactString](https://docs.rs/compact_str/latest/compact_str/) ile değiştirmek daha iyidir:
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
Bunu yaparak, bellek kullanımı yaklaşık %50 azaltılır.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnekte, kısa dizeler [CompactString](https://docs.rs/compact_str/latest/compact_str/) ile işlenir:

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

Bu, bellek kullanımında yaklaşık %20'lik bir azalma sağladı.

## Uzun ömürlü yapılarda gereksiz alanları silin
İşlem başlatma sırasında bellekte tutulmaya devam eden yapılar, genel bellek kullanımını etkileyebilir. Hayabusa'da, özellikle aşağıdaki yapılar (2.2.2 sürümü itibarıyla) çok sayıda tutulur.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

Yukarıdaki yapılarla ilişkili alanların kaldırılması, genel bellek kullanımını azaltmada bir miktar etkili oldu.

### Before  <!-- omit in toc -->
Örneğin, `DetectInfo` alanı, 1.8.1 sürümüne kadar şöyleydi:
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
`record_information` alanını aşağıdaki gibi silerek
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
algılama sonucu kaydı başına birkaç baytlık bir bellek kullanımı azalması sağlandı.

### Effectiveness（Real example from a Pull Request）   <!-- omit in toc -->
Aşağıdaki örnekte, algılama sonucu kayıtlarının sayısının yaklaşık 1,5 milyon olduğu veriler üzerinde test edildiğinde,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

bellek kullanımında yaklaşık 300MB'lık bir azalma elde edebildik.

# Karşılaştırmalı değerlendirme (Benchmarking)
## Bellek ayırıcının istatistik fonksiyonunu kullanın.
Bazı bellek ayırıcılar kendi bellek kullanım istatistiklerini tutar. Örneğin, [mimalloc](https://github.com/microsoft/mimalloc) içinde, bellek kullanımını elde etmek için [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) fonksiyonu çağrılabilir.

### İstatistikler nasıl elde edilir  <!-- omit in toc -->
Önkoşullar: [Bellek ayırıcıyı değiştirin](#change-the-memory-allocator) bölümünde açıklandığı gibi mimalloc kullanıyor olmanız gerekir.

1.  `Cargo.toml`'un [dependencies bölümünde](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency), [libmimalloc-sys crate'ini](https://crates.io/crates/libmimalloc-sys) ekleyin:
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. Bellek kullanım istatistiklerini yazdırmak istediğiniz her yerde, aşağıdaki kodu yazın ve bir `unsafe` bloğu içinde [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) öğesini çağırın. Bellek kullanım istatistikleri standart çıktıya gönderilecektir.
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
3. Sol üstteki `peak/reserved` değeri maksimum bellek kullanımıdır. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### Örnek   <!-- omit in toc -->
Yukarıdaki uygulama aşağıdakinde uygulandı:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

Hayabusa'da, `--debug` seçeneğini eklerseniz, bellek kullanım istatistikleri sonunda gönderilecektir.

## Windows'un performans sayacını kullanın
İşletim sistemi tarafında elde edilebilen istatistiklerden çeşitli kaynak kullanımları kontrol edilebilir. Bu durumda, aşağıdaki iki noktaya dikkat edilmelidir.

- Anti-virüs yazılımının (Windows Defender) etkisi
  - Yalnızca ilk çalıştırma taramadan etkilenir ve daha yavaştır, bu yüzden derlemeden sonraki ikinci ve sonraki çalıştırmaların sonuçları karşılaştırma için uygundur. (Veya daha doğru sonuçlar için anti-virüsünüzü devre dışı bırakabilirsiniz.)
- Dosya önbelleğinin etkisi
  - İşletim sistemi başlatıldıktan sonraki ikinci ve sonraki zamanların sonuçları, evtx ve diğer dosya IO'ları bellekteki dosya önbelleğinden okunduğundan ilk seferden daha hızlıdır, bu yüzden işletim sistemi başlatıldıktan sonraki ilk seferin sonuçları karşılaştırmalı değerlendirme yapmak için daha idealdir.

### Nasıl elde edilir  <!-- omit in toc -->
Önkoşullar：Aşağıdaki prosedür yalnızca Windows'ta `PowerShell 7`'nin zaten kurulu olduğu ortamlar için geçerlidir.

1. İşletim sistemini yeniden başlatın
2. Performans sayacını her saniye sürekli olarak bir CSV dosyasına kaydedecek olan `PowerShell 7`'nin [Get-Counter komutunu](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) çalıştırın. (Aşağıda listelenenlerin dışındaki kaynakları ölçmek isterseniz, [bu makale](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) iyi bir referanstır.)
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
3. Ölçmek istediğiniz işlemi yürütün.

### Örnek  <!-- omit in toc -->
Aşağıda, Hayabusa ile performans ölçümü yapmak için örnek bir prosedür yer almaktadır.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## heaptrack kullanın
[heaptrack](https://github.com/KDE/heaptrack), Linux ve macOS için kullanılabilen gelişmiş bir bellek profil oluşturucudur. heaptrack kullanarak, darboğazları kapsamlı bir şekilde araştırabilirsiniz.

### Nasıl elde edilir  <!-- omit in toc -->
Önkoşullar: Aşağıda Ubuntu 22.04 için prosedür yer almaktadır. heaptrack'i Windows'ta kullanamazsınız.

1. heaptrack'i aşağıdaki iki komutla kurun.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Hayabusa'dan aşağıdaki mimalloc kodunu kaldırın. (heaptrack'in bellek profil oluşturucusunu mimalloc ile kullanamazsınız.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Hayabusa'nın `Cargo.toml` dosyasındaki [[profile.release] bölümünü](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) silin ve aşağıdaki gibi değiştirin:
     ```
     [profile.release]
     debug = true
     ```

4. Bir release derlemesi oluşturun: `cargo build --release`
5. `heaptrack hayabusa csv-timeline -d sample -o out.csv` çalıştırın

Artık Hayabusa çalışmayı bitirdiğinde, heaptrack'in sonuçları otomatik olarak bir GUI uygulamasında açılacaktır.

### Örnekler  <!-- omit in toc -->
heaptrack'in sonuçlarına bir örnek aşağıda gösterilmiştir. `Flame Graph` ve `Top-Down` sekmeleri, yüksek bellek kullanımına sahip fonksiyonları görsel olarak kontrol etmenize olanak tanır.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# Referanslar

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# Katkılar

Bu belge, [Hayabusa](https://github.com/Yamato-Security/hayabusa)'daki gerçek iyileştirme vakalarından elde edilen bulgulara dayanmaktadır. Herhangi bir hata veya performansı iyileştirebilecek teknikler bulursanız, lütfen bize bir issue veya pull request gönderin.
