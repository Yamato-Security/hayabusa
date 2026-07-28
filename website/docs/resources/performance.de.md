# Rust-Performance-Leitfaden für Hayabusa-Entwickler

# Autor
Fukusuke Takahashi

# Englische Übersetzung
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# Über dieses Dokument
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (Englisch: "peregrine falcon", deutsch: "Wanderfalke") ist ein schnelles Forensik-Analysewerkzeug, das von der Gruppe [Yamato Security](https://yamatosecurity.connpass.com/) in Japan entwickelt wird. Es wird in [Rust](https://www.rust-lang.org/) entwickelt, um (Bedrohungen) so schnell wie ein Wanderfalke aufzuspüren. Rust ist an sich eine schnelle Sprache, doch es gibt viele Fallstricke, die zu langsamer Geschwindigkeit und hohem Speicherverbrauch führen können. Wir haben dieses Dokument auf Grundlage tatsächlicher Performance-Verbesserungen in Hayabusa erstellt (siehe das [Changelog hier](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), aber diese Techniken sollten auch auf andere Rust-Programme anwendbar sein. Wir hoffen, dass Sie von dem Wissen profitieren können, das wir durch unsere Versuche und Fehler gewonnen haben.

# Geschwindigkeitsverbesserung
## Den Speicher-Allocator ändern
Allein das Ändern des standardmäßigen Speicher-Allocators kann die Geschwindigkeit erheblich verbessern.
Laut diesen [Benchmarks](https://github.com/rust-lang/rust-analyzer/issues/1441) sind beispielsweise die folgenden beiden Speicher-Allocatoren

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

deutlich schneller als der standardmäßige Speicher-Allocator. Wir konnten eine erhebliche Geschwindigkeitsverbesserung feststellen, indem wir unseren Speicher-Allocator von jemalloc auf mimalloc umgestellt haben, daher haben wir mimalloc seit Version 1.8.0 zum Standard gemacht. (Allerdings verbraucht mimalloc etwas mehr Speicher als jemalloc.)

### Vorher  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### Nachher  <!-- omit in toc -->
Sie müssen nur die folgenden 2 Schritte ausführen, um den globalen [Speicher-Allocator](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) zu ändern:

1. Fügen Sie das [mimalloc-Crate](https://crates.io/crates/mimalloc) zum [[dependencies]-Abschnitt](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) der Datei `Cargo.toml` hinzu:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. Legen Sie unter [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) irgendwo im Programm fest, dass Sie mimalloc verwenden möchten:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
Mehr müssen Sie nicht tun, um den Speicher-Allocator zu ändern.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）  <!-- omit in toc -->
Wie stark sich die Geschwindigkeit verbessert, hängt vom Programm ab, aber im folgenden Beispiel

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

führte das Ändern des Speicher-Allocators auf [mimalloc](https://github.com/microsoft/mimalloc) zu einer Performance-Steigerung von 20-30 % auf Intel-CPUs. 
(Aus irgendeinem Grund gab es auf ARM-basierten macOS-Geräten keine so deutliche Performance-Steigerung.)

## IO-Verarbeitung in Schleifen reduzieren
Festplatten-IO-Verarbeitung ist viel langsamer als Verarbeitung im Speicher. Daher ist es wünschenswert, IO-Verarbeitung so weit wie möglich zu vermeiden, insbesondere in Schleifen.

### Vorher  <!-- omit in toc -->
Das Beispiel unten zeigt, wie ein Datei-Öffnen eine Million Mal in einer Schleife auftritt:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### Nachher  <!-- omit in toc -->
Indem die Datei wie folgt außerhalb der Schleife geöffnet wird
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
ergibt sich eine etwa 1000-fache Geschwindigkeitssteigerung.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Im folgenden Beispiel konnte die IO-Verarbeitung bei der Behandlung eines Erkennungsergebnisses nach dem anderen außerhalb der Schleife durchgeführt werden:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

Dies führte zu einer Geschwindigkeitsverbesserung von etwa 20 %.

## Kompilierung regulärer Ausdrücke in Schleifen vermeiden
Die Kompilierung regulärer Ausdrücke ist im Vergleich zum Abgleich regulärer Ausdrücke ein sehr kostspieliger Vorgang. Daher ist es ratsam, die Kompilierung regulärer Ausdrücke so weit wie möglich zu vermeiden, insbesondere in Schleifen.

### Vorher  <!-- omit in toc -->
Der folgende Vorgang erzeugt zum Beispiel 100.000 Versuche, einen regulären Ausdruck in einer Schleife abzugleichen:
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
### Nachher  <!-- omit in toc -->
Indem die Kompilierung des regulären Ausdrucks außerhalb der Schleife durchgeführt wird, wie unten gezeigt
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
ist der aktualisierte Code etwa 100-mal schneller.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Im folgenden Beispiel wird die Kompilierung des regulären Ausdrucks außerhalb der Schleife durchgeführt und zwischengespeichert.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

Dies führte zu erheblichen Geschwindigkeitsverbesserungen.

## Buffer-IO verwenden
Ohne Buffer-IO ist Datei-IO langsam. Mit Buffer-IO werden IO-Operationen über Puffer im Speicher durchgeführt, wodurch die Anzahl der Systemaufrufe reduziert und die Geschwindigkeit verbessert wird.

### Vorher  <!-- omit in toc -->
Im folgenden Vorgang tritt zum Beispiel [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) 1.000.000 Mal auf.
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
### Nachher  <!-- omit in toc -->
Durch die Verwendung von [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) wie folgt
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
ergibt sich eine etwa 50-fache Geschwindigkeitsverbesserung.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Die oben beschriebene Methode wurde hier implementiert

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

und hat zu erheblichen Geschwindigkeitsverbesserungen bei der Ausgabeverarbeitung geführt.

## Standard-String-Methoden anstelle von regulären Ausdrücken verwenden
Während reguläre Ausdrücke komplexe Abgleichsmuster abdecken können, sind sie langsamer als [Standard-String-Methoden](https://doc.rust-lang.org/std/string/struct.String.html). Daher ist es schneller, für einfache String-Abgleiche wie die folgenden Standard-String-Methoden zu verwenden.

- Starts-with-Abgleich（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Ends-with-Abgleich（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Contains-Abgleich（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### Vorher  <!-- omit in toc -->
Der folgende Code führt zum Beispiel eine Million Mal einen Ends-with-Abgleich mit einem regulären Ausdruck durch.
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
### Nachher  <!-- omit in toc -->
Durch die Verwendung von [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) wie folgt
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
wird die Verarbeitung 10-mal schneller.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Da Hayabusa einen Groß-/Kleinschreibung-unabhängigen String-Vergleich benötigt, verwenden wir [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) und wenden dann die obige Methode an. Selbst dann hat sich in den folgenden Beispielen

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

die Geschwindigkeit im Vergleich zu vorher um etwa 15 % verbessert.

## Nach String-Länge filtern
Je nach den Eigenschaften der verarbeiteten Strings kann das Hinzufügen eines einfachen Filters die Anzahl der String-Abgleichsversuche reduzieren und den Vorgang beschleunigen. Wenn Sie häufig Strings mit nicht festgelegter und nicht übereinstimmender String-Länge vergleichen, können Sie den Vorgang beschleunigen, indem Sie die String-Länge als primären Filter verwenden.

### Vorher  <!-- omit in toc -->
Der folgende Code versucht zum Beispiel eine Million Abgleiche regulärer Ausdrücke.
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
### Nachher  <!-- omit in toc -->
Durch die Verwendung von [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) als primären Filter, wie unten gezeigt
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
wird sich die Geschwindigkeit um etwa das 20-Fache verbessern.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Im folgenden Beispiel wird die obige Methode verwendet.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

Dies verbesserte die Geschwindigkeit um etwa 15 %.

## Nicht mit codegen-units=1 kompilieren
Viele Artikel über Performance-Optimierung mit Rust raten dazu, `codegen-units = 1` unter dem Abschnitt `[profile.release]` hinzuzufügen.
Dies führt zu langsameren Kompilierungszeiten, da standardmäßig parallel kompiliert wird, sollte aber theoretisch zu optimierterem und schnellerem Code führen.
In unseren Tests läuft Hayabusa mit dieser aktivierten Option jedoch tatsächlich langsamer und die Kompilierung dauert länger, daher lassen wir dies deaktiviert.
Die Binärgröße der ausführbaren Datei ist etwa 100 kb kleiner, daher kann dies für eingebettete Systeme ideal sein, bei denen der Festplattenspeicher begrenzt ist.

# Speicherverbrauch reduzieren

## Unnötige Verwendung von clone(), to_string() und to_owned() vermeiden
Die Verwendung von [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) oder [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) ist eine einfache Möglichkeit, Kompilierungsfehler im Zusammenhang mit [Ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) zu beheben. Sie führen jedoch in der Regel zu hohem Speicherverbrauch und sollten vermieden werden. Es ist immer am besten, zuerst zu prüfen, ob Sie sie durch kostengünstige [Referenzen](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) ersetzen können.

### Vorher  <!-- omit in toc -->
Wenn Sie zum Beispiel über denselben `Vec` mehrmals iterieren möchten, können Sie [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) verwenden, um Kompilierungsfehler zu beseitigen.
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
### Nachher  <!-- omit in toc -->
Durch die Verwendung von [Referenzen](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html), wie unten gezeigt, können Sie jedoch die Notwendigkeit beseitigen, [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) zu verwenden.
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
Durch das Entfernen der clone()-Verwendung wird der Speicherverbrauch um bis zu 50 % reduziert.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Im folgenden Beispiel konnten wir durch das Ersetzen der unnötigen Verwendung von [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) und [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html),

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

den Speicherverbrauch erheblich reduzieren.

## Iterator anstelle von Vec verwenden
[Vec](https://doc.rust-lang.org/std/vec/) hält alle Elemente im Speicher, daher verbraucht es viel Speicher proportional zur Anzahl der Elemente. Wenn die Verarbeitung eines Elements nach dem anderen ausreicht, verbraucht die Verwendung eines [Iterators](https://doc.rust-lang.org/std/iter/trait.Iterator.html) stattdessen viel weniger Speicher.

### Vorher  <!-- omit in toc -->
Die folgende Funktion `return_lines()` liest zum Beispiel eine Datei von etwa 1 GB und gibt einen [Vec](https://doc.rust-lang.org/std/vec/) zurück:
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
### Nachher  <!-- omit in toc -->
Stattdessen sollten Sie wie folgt einen [Iterator-Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) zurückgeben:
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
Oder wenn der Typ je nachdem, welcher Zweig genommen wird, unterschiedlich ist, können Sie wie folgt einen `Box<dyn Iterator<Item = T>>` zurückgeben:
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
Der Speicherverbrauch sinkt erheblich von 1 GB auf nur 3 MB.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Das folgende Beispiel verwendet die oben beschriebene Methode:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

Beim Test mit einer 1,7 GB großen JSON-Datei verringerte sich der Speicher um 75 %.

## Das compact_str-Crate beim Umgang mit kurzen Strings verwenden
Beim Umgang mit einer großen Anzahl kurzer Strings von weniger als 24 Byte kann das [compact_str-Crate](https://docs.rs/crate/compact_str/latest) verwendet werden, um den Speicherverbrauch zu reduzieren.

### Vorher  <!-- omit in toc -->
Im Beispiel unten enthält der Vec 10 Millionen Strings.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### Nachher  <!-- omit in toc -->
Es ist besser, sie durch einen [CompactString](https://docs.rs/compact_str/latest/compact_str/) zu ersetzen:
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
Dadurch wird der Speicherverbrauch um etwa 50 % reduziert.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Im folgenden Beispiel werden kurze Strings mit [CompactString](https://docs.rs/compact_str/latest/compact_str/) behandelt:

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

Dies ergab eine Reduzierung des Speicherverbrauchs um etwa 20 %.

## Unnötige Felder in langlebigen Strukturen löschen
Strukturen, die während des Prozessstarts weiterhin im Speicher gehalten werden, können den gesamten Speicherverbrauch beeinflussen. In Hayabusa werden insbesondere die folgenden Strukturen (Stand Version 2.2.2) in großer Zahl gehalten.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

Das Entfernen von Feldern, die mit den obigen Strukturen verbunden sind, hatte einen gewissen Effekt auf die Reduzierung des gesamten Speicherverbrauchs.

### Vorher  <!-- omit in toc -->
Das Feld `DetectInfo` war zum Beispiel bis Version 1.8.1 wie folgt:
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
### Nachher  <!-- omit in toc -->
Durch das Löschen des Feldes `record_information` wie folgt
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
wurde eine Reduzierung des Speicherverbrauchs von mehreren Byte pro Erkennungsergebnis-Datensatz erreicht.

### Wirksamkeit（Reales Beispiel aus einem Pull Request）   <!-- omit in toc -->
Im folgenden Beispiel konnten wir beim Test gegen Daten, bei denen die Anzahl der Erkennungsergebnis-Datensätze etwa 1,5 Millionen betrug,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

eine Reduzierung des Speicherverbrauchs um etwa 300 MB erreichen.

# Benchmarking
## Die Statistikfunktion des Speicher-Allocators verwenden.
Einige Speicher-Allocatoren führen ihre eigenen Speicherverbrauchsstatistiken. In [mimalloc](https://github.com/microsoft/mimalloc) kann zum Beispiel die Funktion [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) aufgerufen werden, um den Speicherverbrauch zu erhalten.

### So erhalten Sie Statistiken  <!-- omit in toc -->
Voraussetzungen: Sie müssen mimalloc verwenden, wie im Abschnitt [Den Speicher-Allocator ändern](#change-the-memory-allocator) erklärt.

1.  Fügen Sie im [dependencies-Abschnitt](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) von `Cargo.toml` das [libmimalloc-sys-Crate](https://crates.io/crates/libmimalloc-sys) hinzu:
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. Wann immer Sie die Speicherverbrauchsstatistiken ausgeben möchten, schreiben Sie den folgenden Code und rufen Sie innerhalb eines `unsafe`-Blocks [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) auf. Die Speicherverbrauchsstatistiken werden auf die Standardausgabe ausgegeben.
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
3. Der Wert `peak/reserved` oben links ist der maximale Speicherverbrauch. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### Beispiel   <!-- omit in toc -->
Die obige Implementierung wurde im Folgenden angewendet:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

Wenn Sie in Hayabusa die Option `--debug` hinzufügen, werden am Ende Speicherverbrauchsstatistiken ausgegeben.

## Den Performance-Counter von Windows verwenden
Verschiedene Ressourcennutzungen können aus Statistiken überprüft werden, die auf der Betriebssystemseite erhalten werden können. In diesem Fall sind die folgenden zwei Punkte zu beachten.

- Einfluss durch Antivirensoftware (Windows Defender)
  - Nur der erste Durchlauf wird vom Scan beeinflusst und ist langsamer, daher eignen sich Ergebnisse vom zweiten und folgenden Durchläufen nach dem Build für den Vergleich. (Oder Sie können Ihr Antivirenprogramm deaktivieren, um genauere Ergebnisse zu erhalten.)
- Einfluss durch Datei-Caching
  - Die Ergebnisse vom zweiten und folgenden Mal nach dem Betriebssystemstart sind schneller als beim ersten Mal, weil evtx und andere Datei-IOs aus dem Datei-Cache im Speicher gelesen werden, daher sind die Ergebnisse vom ersten Mal nach dem Booten des Betriebssystems idealer für die Durchführung von Benchmarks.

### So erhalten Sie ihn  <!-- omit in toc -->
Voraussetzungen：Das folgende Verfahren ist nur für Umgebungen gültig, in denen `PowerShell 7` bereits auf Windows installiert ist.

1. Starten Sie das Betriebssystem neu
2. Führen Sie den [Get-Counter-Befehl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) von `PowerShell 7` aus, der den Performance-Counter kontinuierlich jede Sekunde in eine CSV-Datei aufzeichnet. (Wenn Sie andere Ressourcen als die unten aufgeführten messen möchten, ist [dieser Artikel](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) eine gute Referenz.)
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
3. Führen Sie den Prozess aus, den Sie messen möchten.

### Beispiel  <!-- omit in toc -->
Das Folgende enthält ein Beispielverfahren zum Messen der Performance mit Hayabusa.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## heaptrack verwenden
[heaptrack](https://github.com/KDE/heaptrack) ist ein ausgefeilter Speicher-Profiler, der für Linux und macOS verfügbar ist. Durch die Verwendung von heaptrack können Sie Engpässe gründlich untersuchen.

### So erhalten Sie ihn  <!-- omit in toc -->
Voraussetzungen: Unten ist das Verfahren für Ubuntu 22.04. Sie können heaptrack nicht auf Windows verwenden.

1. Installieren Sie heaptrack mit den folgenden zwei Befehlen.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Entfernen Sie den folgenden mimalloc-Code aus Hayabusa. (Sie können den Speicher-Profiler von heaptrack nicht mit mimalloc verwenden.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Löschen Sie den [[profile.release]-Abschnitt](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) in der Datei `Cargo.toml` von Hayabusa und ändern Sie ihn wie folgt:
     ```
     [profile.release]
     debug = true
     ```

4. Erstellen Sie einen Release-Build: `cargo build --release`
5. Führen Sie `heaptrack hayabusa dfir-timeline -d sample -o out.csv` aus

Wenn Hayabusa nun mit der Ausführung fertig ist, werden die Ergebnisse von heaptrack automatisch in einer GUI-Anwendung geöffnet.

### Beispiele  <!-- omit in toc -->
Ein Beispiel für die Ergebnisse von heaptrack wird unten gezeigt. Die Tabs `Flame Graph` und `Top-Down` ermöglichen es Ihnen, Funktionen mit hohem Speicherverbrauch visuell zu überprüfen.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# Referenzen

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# Beiträge

Dieses Dokument basiert auf Erkenntnissen aus tatsächlichen Verbesserungsfällen in [Hayabusa](https://github.com/Yamato-Security/hayabusa). Wenn Sie Fehler oder Techniken finden, die die Performance verbessern können, senden Sie uns bitte ein Issue oder einen Pull Request.
