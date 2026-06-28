# Посібник з продуктивності Rust для розробників Hayabusa

# Автор
Fukusuke Takahashi

# Англійський переклад
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# Про цей документ
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (англійською: "peregrine falcon", сапсан) — це швидкий інструмент для криміналістичного аналізу, розроблений групою [Yamato Security](https://yamatosecurity.connpass.com/) в Японії. Він розроблений на [Rust](https://www.rust-lang.org/), щоб полювати (на загрози) так само швидко, як сапсан. Rust сам по собі є швидкою мовою, проте існує багато підводних каменів, які можуть призвести до низької швидкості та високого споживання пам'яті. Ми створили цей документ на основі реальних покращень продуктивності в Hayabusa (див. [журнал змін тут](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), але ці прийоми мають бути застосовними і до інших програм на Rust. Сподіваємося, що ви зможете скористатися знаннями, які ми здобули методом проб і помилок.

# Покращення швидкості
## Змініть розподільник пам'яті
Просто зміна стандартного розподільника пам'яті може значно покращити швидкість.
Наприклад, згідно з цими [бенчмарками](https://github.com/rust-lang/rust-analyzer/issues/1441), наступні два розподільники пам'яті

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

є набагато швидшими за стандартний розподільник пам'яті. Нам вдалося підтвердити значне покращення швидкості, змінивши наш розподільник пам'яті з jemalloc на mimalloc, тому ми зробили mimalloc стандартним починаючи з версії 1.8.0. (Хоча mimalloc дійсно використовує трохи більше пам'яті, ніж jemalloc.)

### До  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### Після  <!-- omit in toc -->
Вам потрібно виконати лише наступні 2 кроки, щоб змінити глобальний [розподільник пам'яті](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html):

1. Додайте [крейт mimalloc](https://crates.io/crates/mimalloc) до [секції [dependencies]](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) файлу `Cargo.toml`:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. Визначте, що ви хочете використовувати mimalloc під [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) десь у програмі:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
Це все, що потрібно зробити, щоб змінити розподільник пам'яті.

### Ефективність（Реальний приклад з Pull Request）  <!-- omit in toc -->
Наскільки покращиться швидкість, залежить від програми, але в наступному прикладі

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

зміна розподільника пам'яті на [mimalloc](https://github.com/microsoft/mimalloc) призвела до покращення продуктивності на 20-30% на процесорах Intel. 
(З якоїсь причини не було такого значного приросту продуктивності на пристроях macOS на базі ARM.)

## Зменшіть IO-обробку в циклах
Дискова IO-обробка набагато повільніша за обробку в пам'яті. Тому бажано уникати IO-обробки настільки, наскільки це можливо, особливо в циклах.

### До  <!-- omit in toc -->
Наведений нижче приклад показує відкриття файлу мільйон разів у циклі:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### Після  <!-- omit in toc -->
Відкривши файл за межами циклу, як показано нижче
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
буде приблизно 1000-кратне збільшення швидкості.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
У наступному прикладі IO-обробку, що виконувалася при обробці одного результату виявлення за раз, вдалося винести за межі циклу:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

Це призвело до покращення швидкості приблизно на 20%.

## Уникайте компіляції регулярних виразів у циклах
Компіляція регулярних виразів є дуже витратним процесом порівняно зі співставленням регулярних виразів. Тому доцільно уникати компіляції регулярних виразів настільки, наскільки це можливо, особливо в циклах.

### До  <!-- omit in toc -->
Наприклад, наступний процес створює 100 000 спроб співставлення регулярного виразу в циклі:
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
### Після  <!-- omit in toc -->
Виконавши компіляцію регулярного виразу за межами циклу, як показано нижче
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
оновлений код приблизно в 100 разів швидший.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
У наступному прикладі компіляція регулярного виразу виконується за межами циклу та кешується.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

Це призвело до значних покращень швидкості.

## Використовуйте буферизований IO
Без буферизованого IO файловий IO повільний. З буферизованим IO операції IO виконуються через буфери в пам'яті, зменшуючи кількість системних викликів та покращуючи швидкість.

### До  <!-- omit in toc -->
Наприклад, у наступному процесі [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) відбувається 1 000 000 разів.
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
### Після  <!-- omit in toc -->
Використовуючи [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html), як показано нижче
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
буде приблизно 50-кратне покращення швидкості.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
Описаний вище метод був реалізований тут

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

і призвів до значних покращень швидкості в обробці виведення.

## Використовуйте стандартні методи String замість регулярних виразів
Хоча регулярні вирази можуть охоплювати складні шаблони співставлення, вони повільніші за [стандартні методи String](https://doc.rust-lang.org/std/string/struct.String.html). Тому швидше використовувати стандартні методи String для простого співставлення рядків, як, наприклад, наступне.

- Співставлення за початком（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Співставлення за закінченням（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Співставлення за входженням（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### До  <!-- omit in toc -->
Наприклад, наступний код виконує співставлення за закінченням у регулярному виразі мільйон разів.
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
### Після  <!-- omit in toc -->
Використовуючи [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with), як показано нижче
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
обробка буде в 10 разів швидшою.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
Оскільки Hayabusa потребує порівняння рядків без урахування регістру, ми використовуємо [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase), а потім застосовуємо вищезгаданий метод. Навіть тоді, у наступних прикладах

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

швидкість покращилася приблизно на 15% порівняно з попередньою.

## Фільтруйте за довжиною рядка
Залежно від характеристик рядків, що обробляються, додавання простого фільтра може зменшити кількість спроб співставлення рядків та прискорити процес. Якщо ви часто порівнюєте рядки нефіксованої та неспівпадаючої довжини, ви можете прискорити процес, використовуючи довжину рядка як первинний фільтр.

### До  <!-- omit in toc -->
Наприклад, наступний код намагається виконати мільйон співставлень регулярних виразів.
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
### Після  <!-- omit in toc -->
Використовуючи [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) як первинний фільтр, як показано нижче
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
швидкість покращиться приблизно в 20 разів.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
У наступному прикладі використовується вищезгаданий метод.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

Це покращило швидкість приблизно на 15%.

## Не компілюйте з codegen-units=1
Багато статей про оптимізацію продуктивності з Rust радять додати `codegen-units = 1` під секцією `[profile.release]`.
Це призведе до повільнішого часу компіляції, оскільки за замовчуванням компіляція відбувається паралельно, але теоретично має призвести до більш оптимізованого та швидшого коду.
Однак у наших тестах Hayabusa насправді працює повільніше з увімкненою цією опцією, і компіляція займає більше часу, тому ми тримаємо це вимкненим.
Розмір бінарного файлу виконуваного файлу приблизно на 100kb менший, тому це може бути ідеальним для вбудованих систем, де простір на жорсткому диску обмежений.

# Зменшення споживання пам'яті

## Уникайте непотрібного використання clone(), to_string() та to_owned()
Використання [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) або [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) — це прості способи вирішення помилок компіляції, пов'язаних із [володінням](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html). Однак вони зазвичай призводять до високого споживання пам'яті, і їх слід уникати. Завжди найкраще спочатку перевірити, чи можете ви замінити їх на низьковитратні [посилання](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html).

### До  <!-- omit in toc -->
Наприклад, якщо ви хочете ітерувати один і той самий `Vec` кілька разів, ви можете використати [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), щоб усунути помилки компіляції.
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
### Після  <!-- omit in toc -->
Однак, використовуючи [посилання](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html), як показано нижче, ви можете усунути потребу у використанні [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html).
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
Усунувши використання clone(), споживання пам'яті зменшується до 50%.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
У наступному прикладі, замінивши непотрібне використання [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) та [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html),

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

нам вдалося значно зменшити споживання пам'яті.

## Використовуйте Iterator замість Vec
[Vec](https://doc.rust-lang.org/std/vec/) зберігає всі елементи в пам'яті, тому він використовує багато пам'яті пропорційно до кількості елементів. Якщо достатньо обробляти один елемент за раз, то використання [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) замість нього використовуватиме набагато менше пам'яті.

### До  <!-- omit in toc -->
Наприклад, наступна функція `return_lines()` читає файл розміром близько 1 ГБ і повертає [Vec](https://doc.rust-lang.org/std/vec/):
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
### Після  <!-- omit in toc -->
Замість цього ви повинні повертати [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html), як показано нижче:
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
Або якщо тип відрізняється залежно від того, яка гілка обрана, ви можете повернути `Box<dyn Iterator<Item = T>>`, як показано нижче:
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
Споживання пам'яті значно знижується з 1 ГБ до лише 3 МБ.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
Наступний приклад використовує описаний вище метод:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

Під час тестування на JSON-файлі розміром 1.7ГБ пам'ять зменшилася на 75%.

## Використовуйте крейт compact_str при обробці коротких рядків
При роботі з великою кількістю коротких рядків розміром менше 24 байтів можна використовувати [крейт compact_str](https://docs.rs/crate/compact_str/latest), щоб зменшити споживання пам'яті.

### До  <!-- omit in toc -->
У наведеному нижче прикладі Vec містить 10 мільйонів рядків.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### Після  <!-- omit in toc -->
Краще замінити їх на [CompactString](https://docs.rs/compact_str/latest/compact_str/):
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
Зробивши це, споживання пам'яті зменшується приблизно на 50%.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
У наступному прикладі короткі рядки обробляються за допомогою [CompactString](https://docs.rs/compact_str/latest/compact_str/):

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

Це дало зменшення споживання пам'яті приблизно на 20%.

## Видаляйте непотрібні поля в довгоживучих структурах
Структури, які продовжують зберігатися в пам'яті під час запуску процесу, можуть впливати на загальне споживання пам'яті. У Hayabusa наступні структури (станом на версію 2.2.2), зокрема, зберігаються у великій кількості.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

Видалення полів, пов'язаних із вищезгаданими структурами, мало певний ефект на зменшення загального споживання пам'яті.

### До  <!-- omit in toc -->
Наприклад, поле `DetectInfo` було, до версії 1.8.1, наступним:
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
### Після  <!-- omit in toc -->
Видаливши поле `record_information`, як показано нижче
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
було досягнуто зменшення споживання пам'яті на кілька байтів на кожен запис результату виявлення.

### Ефективність（Реальний приклад з Pull Request）   <!-- omit in toc -->
У наступному прикладі, при тестуванні на даних, де кількість записів результатів виявлення становила близько 1,5 мільйона,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

нам вдалося досягти зменшення споживання пам'яті приблизно на 300МБ.

# Бенчмаркінг
## Використовуйте функцію статистики розподільника пам'яті.
Деякі розподільники пам'яті ведуть власну статистику споживання пам'яті. Наприклад, у [mimalloc](https://github.com/microsoft/mimalloc) функцію [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) можна викликати для отримання споживання пам'яті.

### Як отримати статистику  <!-- omit in toc -->
Передумови: Вам потрібно використовувати mimalloc, як пояснено в розділі [Змініть розподільник пам'яті](#change-the-memory-allocator).

1.  У [секції dependencies](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) файлу `Cargo.toml` додайте [крейт libmimalloc-sys](https://crates.io/crates/libmimalloc-sys):
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. Щоразу, коли ви хочете вивести статистику споживання пам'яті, напишіть наступний код і всередині блоку `unsafe` викличте [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79). Статистика споживання пам'яті буде виведена на стандартний вивід.
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
3. Значення `peak/reserved` у верхньому лівому куті — це максимальне споживання пам'яті. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### Приклад   <!-- omit in toc -->
Вищезгадана реалізація була застосована в наступному:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

У Hayabusa, якщо ви додасте опцію `--debug`, статистика споживання пам'яті буде виведена в кінці.

## Використовуйте лічильник продуктивності Windows
Різне використання ресурсів можна перевірити за статистикою, яку можна отримати на боці ОС. У цьому випадку слід звернути увагу на наступні два моменти.

- Вплив антивірусного програмного забезпечення (Windows Defender)
  - Лише перший запуск зазнає впливу сканування і є повільнішим, тому результати другого та наступних запусків після збірки придатні для порівняння. (Або ви можете вимкнути антивірус для більш точних результатів.)
- Вплив кешування файлів
  - Результати другого та наступних разів після запуску ОС швидші за перший раз, оскільки evtx та інші файлові IO читаються з кешу файлів у пам'яті, тому результати першого разу після завантаження ОС більш ідеальні для проведення бенчмарків.

### Як отримати  <!-- omit in toc -->
Передумови：Наступна процедура дійсна лише для середовищ, де `PowerShell 7` вже встановлений на Windows.

1. Перезавантажте ОС
2. Запустіть [команду Get-Counter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) у `PowerShell 7`, яка буде безперервно записувати лічильник продуктивності щосекунди у CSV-файл. (Якщо ви хочете виміряти ресурси, відмінні від наведених нижче, [ця стаття](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) є хорошим орієнтиром.)
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
3. Виконайте процес, який ви хочете виміряти.

### Приклад  <!-- omit in toc -->
Нижче наведено приклад процедури вимірювання продуктивності з Hayabusa.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## Використовуйте heaptrack
[heaptrack](https://github.com/KDE/heaptrack) — це досконалий профайлер пам'яті, доступний для Linux та macOS. Використовуючи heaptrack, ви можете ретельно дослідити вузькі місця.

### Як отримати  <!-- omit in toc -->
Передумови: Нижче наведено процедуру для Ubuntu 22.04. Ви не можете використовувати heaptrack на Windows.

1. Встановіть heaptrack за допомогою наступних двох команд.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Видаліть наступний код mimalloc з Hayabusa. (Ви не можете використовувати профайлер пам'яті heaptrack з mimalloc.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Видаліть [секцію [profile.release]](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) у файлі `Cargo.toml` Hayabusa та змініть її на наступне:
     ```
     [profile.release]
     debug = true
     ```

4. Зберіть реліз-збірку: `cargo build --release`
5. Запустіть `heaptrack hayabusa csv-timeline -d sample -o out.csv`

Тепер, коли Hayabusa завершить роботу, результати heaptrack автоматично відкриються у GUI-застосунку.

### Приклади  <!-- omit in toc -->
Приклад результатів heaptrack показано нижче. Вкладки `Flame Graph` та `Top-Down` дозволяють візуально перевірити функції з високим споживанням пам'яті.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# Посилання

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# Внески

Цей документ ґрунтується на висновках з реальних випадків покращення в [Hayabusa](https://github.com/Yamato-Security/hayabusa). Якщо ви знайдете будь-які помилки або прийоми, які можуть покращити продуктивність, будь ласка, надішліть нам issue або pull request.
