# Panduan Performa Rust untuk Pengembang Hayabusa

# Penulis
Fukusuke Takahashi

# Terjemahan bahasa Inggris
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# Tentang dokumen ini
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (bahasa Inggris: "peregrine falcon") adalah alat analisis forensik cepat yang dikembangkan oleh kelompok [Yamato Security](https://yamatosecurity.connpass.com/) di Jepang. Alat ini dikembangkan dengan [Rust](https://www.rust-lang.org/) agar dapat melakukan (threat) hunting secepat seekor elang peregrine. Rust sendiri adalah bahasa yang cepat, namun ada banyak jebakan yang dapat mengakibatkan kecepatan lambat dan penggunaan memori tinggi. Kami membuat dokumen ini berdasarkan peningkatan performa nyata di Hayabusa (lihat [changelog di sini](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), tetapi teknik-teknik ini seharusnya juga dapat diterapkan pada program Rust lainnya. Kami berharap Anda dapat memperoleh manfaat dari pengetahuan yang kami peroleh melalui proses coba-coba.

# Peningkatan kecepatan
## Ganti memory allocator
Hanya dengan mengganti memory allocator bawaan dapat meningkatkan kecepatan secara signifikan.
Sebagai contoh, menurut [benchmark](https://github.com/rust-lang/rust-analyzer/issues/1441) ini, dua memory allocator berikut

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

jauh lebih cepat daripada memory allocator bawaan. Kami dapat memastikan peningkatan kecepatan yang signifikan dengan mengganti memory allocator kami dari jemalloc ke mimalloc, sehingga kami menjadikan mimalloc sebagai bawaan sejak versi 1.8.0. (Meskipun mimalloc memang menggunakan memori sedikit lebih banyak daripada jemalloc.)

### Sebelum  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### Sesudah  <!-- omit in toc -->
Anda hanya perlu melakukan 2 langkah berikut untuk mengganti [memory allocator](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) global:

1. Tambahkan [crate mimalloc](https://crates.io/crates/mimalloc) ke [bagian [dependencies]](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) pada file `Cargo.toml`:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. Definisikan bahwa Anda ingin menggunakan mimalloc di bawah [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) di suatu tempat dalam program:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
Hanya itu yang perlu Anda lakukan untuk mengganti memory allocator.

### Efektivitas（Contoh nyata dari sebuah Pull Request）  <!-- omit in toc -->
Seberapa besar kecepatan meningkat akan bergantung pada program, tetapi pada contoh berikut

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

mengganti memory allocator menjadi [mimalloc](https://github.com/microsoft/mimalloc) menghasilkan peningkatan performa 20-30% pada CPU Intel. 
(Entah mengapa, tidak ada peningkatan performa yang sesignifikan itu pada perangkat macOS berbasis ARM.)

## Kurangi pemrosesan IO di dalam loop
Pemrosesan IO disk jauh lebih lambat daripada pemrosesan di memori. Oleh karena itu, sebaiknya hindari pemrosesan IO sebanyak mungkin, terutama di dalam loop.

### Sebelum  <!-- omit in toc -->
Contoh di bawah ini menunjukkan pembukaan file yang terjadi satu juta kali di dalam loop:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### Sesudah  <!-- omit in toc -->
Dengan membuka file di luar loop seperti berikut
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
akan ada peningkatan kecepatan sekitar 1000 kali.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Pada contoh berikut, pemrosesan IO saat menangani satu hasil deteksi pada satu waktu berhasil dilakukan di luar loop:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

Ini menghasilkan peningkatan kecepatan sekitar 20%.

## Hindari kompilasi ekspresi reguler di dalam loop
Kompilasi ekspresi reguler adalah proses yang sangat mahal dibandingkan dengan pencocokan ekspresi reguler. Oleh karena itu, disarankan untuk menghindari kompilasi ekspresi reguler sebanyak mungkin, terutama di dalam loop.

### Sebelum  <!-- omit in toc -->
Sebagai contoh, proses berikut membuat 100.000 percobaan untuk mencocokkan ekspresi reguler di dalam loop:
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
### Sesudah  <!-- omit in toc -->
Dengan melakukan kompilasi ekspresi reguler di luar loop, seperti yang ditunjukkan di bawah ini
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
kode yang diperbarui menjadi sekitar 100 kali lebih cepat.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Pada contoh berikut, kompilasi ekspresi reguler dilakukan di luar loop dan di-cache.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

Ini menghasilkan peningkatan kecepatan yang signifikan.

## Gunakan buffer IO
Tanpa buffer IO, IO file menjadi lambat. Dengan buffer IO, operasi IO dilakukan melalui buffer di memori, mengurangi jumlah system call dan meningkatkan kecepatan.

### Sebelum  <!-- omit in toc -->
Sebagai contoh, pada proses berikut, [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) terjadi 1.000.000 kali.
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
### Sesudah  <!-- omit in toc -->
Dengan menggunakan [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) seperti berikut
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
ada peningkatan kecepatan sekitar 50 kali.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Metode yang dijelaskan di atas diimplementasikan di sini

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

dan telah menghasilkan peningkatan kecepatan yang signifikan dalam pemrosesan output.

## Gunakan metode String standar alih-alih ekspresi reguler
Meskipun ekspresi reguler dapat mencakup pola pencocokan yang kompleks, ekspresi tersebut lebih lambat daripada [metode String standar](https://doc.rust-lang.org/std/string/struct.String.html). Oleh karena itu, lebih cepat menggunakan metode String standar untuk pencocokan string sederhana seperti berikut.

- Pencocokan starts-with（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Pencocokan ends-with（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Pencocokan contains（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### Sebelum  <!-- omit in toc -->
Sebagai contoh, kode berikut melakukan pencocokan ends-with dalam ekspresi reguler satu juta kali.
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
### Sesudah  <!-- omit in toc -->
Dengan menggunakan [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) seperti berikut
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
pemrosesan akan menjadi 10 kali lebih cepat.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Karena Hayabusa memerlukan perbandingan string yang tidak peka huruf besar/kecil, kami menggunakan [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) lalu menerapkan metode di atas. Bahkan dengan begitu, pada contoh-contoh berikut

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

kecepatan meningkat sekitar 15% dibandingkan sebelumnya.

## Filter berdasarkan panjang string
Tergantung pada karakteristik string yang ditangani, menambahkan filter sederhana dapat mengurangi jumlah percobaan pencocokan string dan mempercepat proses. Jika Anda sering membandingkan string dengan panjang yang tidak tetap dan tidak cocok, Anda dapat mempercepat proses dengan menggunakan panjang string sebagai filter utama.

### Sebelum  <!-- omit in toc -->
Sebagai contoh, kode berikut mencoba satu juta pencocokan ekspresi reguler.
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
### Sesudah  <!-- omit in toc -->
Dengan menggunakan [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) sebagai filter utama, seperti yang ditunjukkan di bawah ini
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
kecepatan akan meningkat sekitar 20 kali.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Pada contoh berikut, metode di atas digunakan.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

Ini meningkatkan kecepatan sekitar 15%.

## Jangan kompilasi dengan codegen-units=1
Banyak artikel tentang optimasi performa dengan Rust menyarankan untuk menambahkan `codegen-units = 1` di bawah bagian `[profile.release]`.
Ini akan menyebabkan waktu kompilasi yang lebih lambat karena defaultnya adalah mengompilasi secara paralel, tetapi secara teori seharusnya menghasilkan kode yang lebih teroptimasi dan lebih cepat.
Namun, dalam pengujian kami, Hayabusa justru berjalan lebih lambat dengan opsi ini diaktifkan dan kompilasi memakan waktu lebih lama sehingga kami menonaktifkannya.
Ukuran biner dari executable sekitar 100kb lebih kecil sehingga ini mungkin ideal untuk sistem tertanam (embedded) yang ruang hard disk-nya terbatas.

# Mengurangi penggunaan memori

## Hindari penggunaan clone(), to_string(), dan to_owned() yang tidak perlu
Menggunakan [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) atau [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) adalah cara mudah untuk menyelesaikan error kompilasi terkait [ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html). Namun, biasanya hal tersebut akan menghasilkan penggunaan memori yang tinggi dan sebaiknya dihindari. Selalu lebih baik untuk pertama-tama melihat apakah Anda dapat menggantinya dengan [referensi](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) berbiaya rendah.

### Sebelum  <!-- omit in toc -->
Sebagai contoh, jika Anda ingin melakukan iterasi pada `Vec` yang sama beberapa kali, Anda dapat menggunakan [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) untuk menghilangkan error kompilasi.
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
### Sesudah  <!-- omit in toc -->
Namun, dengan menggunakan [referensi](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) seperti yang ditunjukkan di bawah ini, Anda dapat menghilangkan kebutuhan untuk menggunakan [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html).
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
Dengan menghilangkan penggunaan clone(), penggunaan memori berkurang hingga 50%.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Pada contoh berikut, dengan mengganti penggunaan [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html), dan [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html) yang tidak perlu,

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

kami berhasil mengurangi penggunaan memori secara signifikan.

## Gunakan Iterator alih-alih Vec
[Vec](https://doc.rust-lang.org/std/vec/) menyimpan semua elemen di memori, sehingga menggunakan banyak memori sebanding dengan jumlah elemen. Jika memproses satu elemen pada satu waktu sudah cukup, maka menggunakan [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) sebagai gantinya akan menggunakan memori yang jauh lebih sedikit.

### Sebelum  <!-- omit in toc -->
Sebagai contoh, fungsi `return_lines()` berikut membaca file sekitar 1 GB dan mengembalikan sebuah [Vec](https://doc.rust-lang.org/std/vec/):
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
### Sesudah  <!-- omit in toc -->
Sebagai gantinya Anda harus mengembalikan sebuah [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) seperti berikut:
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
Atau jika tipenya berbeda tergantung cabang mana yang diambil, Anda dapat mengembalikan sebuah `Box<dyn Iterator<Item = T>>` seperti berikut:
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
Penggunaan memori turun secara signifikan dari 1 GB menjadi hanya 3 MB.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Contoh berikut menggunakan metode yang dijelaskan di atas:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

Ketika diuji pada file JSON berukuran 1,7GB, memori berkurang 75%.

## Gunakan crate compact_str saat menangani string pendek
Saat menangani sejumlah besar string pendek yang kurang dari 24 byte, [crate compact_str](https://docs.rs/crate/compact_str/latest) dapat digunakan untuk mengurangi penggunaan memori.

### Sebelum  <!-- omit in toc -->
Pada contoh di bawah ini, Vec menyimpan 10 juta string.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### Sesudah  <!-- omit in toc -->
Lebih baik menggantinya dengan sebuah [CompactString](https://docs.rs/compact_str/latest/compact_str/):
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
Dengan melakukan ini, penggunaan memori berkurang sekitar 50%.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Pada contoh berikut, string pendek ditangani dengan [CompactString](https://docs.rs/compact_str/latest/compact_str/):

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

Ini memberikan pengurangan penggunaan memori sekitar 20%.

## Hapus field yang tidak perlu dalam struktur yang berumur panjang
Struktur yang terus dipertahankan di memori selama proses berjalan dapat memengaruhi keseluruhan penggunaan memori. Di Hayabusa, struktur berikut (per versi 2.2.2), khususnya, dipertahankan dalam jumlah besar.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

Penghapusan field yang terkait dengan struktur di atas memberikan efek dalam mengurangi keseluruhan penggunaan memori.

### Sebelum  <!-- omit in toc -->
Sebagai contoh, field `DetectInfo` adalah, hingga versi 1.8.1, sebagai berikut:
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
### Sesudah  <!-- omit in toc -->
Dengan menghapus field `record_information` seperti berikut
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
pengurangan penggunaan memori sebesar beberapa byte per record hasil deteksi tercapai.

### Efektivitas（Contoh nyata dari sebuah Pull Request）   <!-- omit in toc -->
Pada contoh berikut, ketika diuji terhadap data dengan jumlah record hasil deteksi sekitar 1,5 juta,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

kami berhasil mencapai pengurangan penggunaan memori sekitar 300MB.

# Benchmarking
## Gunakan fungsi statistik dari memory allocator.
Beberapa memory allocator menyimpan statistik penggunaan memori mereka sendiri. Sebagai contoh, di [mimalloc](https://github.com/microsoft/mimalloc), fungsi [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) dapat dipanggil untuk memperoleh penggunaan memori.

### Cara memperoleh statistik  <!-- omit in toc -->
Prasyarat: Anda perlu menggunakan mimalloc seperti yang dijelaskan di bagian [Ganti memory allocator](#change-the-memory-allocator).

1.  Di [bagian dependencies](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) pada `Cargo.toml`, tambahkan [crate libmimalloc-sys](https://crates.io/crates/libmimalloc-sys):
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. Kapan pun Anda ingin mencetak statistik penggunaan memori, tulis kode berikut dan di dalam blok `unsafe`, panggil [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79). Statistik penggunaan memori akan dikeluarkan ke standard out.
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
3. Nilai `peak/reserved` di kiri atas adalah penggunaan memori maksimum. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### Contoh   <!-- omit in toc -->
Implementasi di atas diterapkan pada berikut:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

Di Hayabusa, jika Anda menambahkan opsi `--debug`, statistik penggunaan memori akan dikeluarkan di akhir.

## Gunakan performance counter Windows
Berbagai penggunaan sumber daya dapat diperiksa dari statistik yang dapat diperoleh dari sisi OS. Dalam hal ini, dua hal berikut perlu diperhatikan.

- Pengaruh dari perangkat lunak anti-virus (Windows Defender)
  - Hanya proses pertama yang dipengaruhi oleh pemindaian dan lebih lambat, sehingga hasil dari proses kedua dan selanjutnya setelah build cocok untuk perbandingan. (Atau Anda dapat menonaktifkan anti-virus Anda untuk hasil yang lebih akurat.)
- Pengaruh dari caching file
  - Hasil dari kali kedua dan selanjutnya setelah OS dinyalakan lebih cepat daripada kali pertama karena evtx dan IO file lainnya dibaca dari cache file di memori, sehingga hasil dari kali pertama setelah OS booting lebih ideal untuk mengambil benchmark.

### Cara memperoleh  <!-- omit in toc -->
Prasyarat：Prosedur berikut hanya valid untuk lingkungan di mana `PowerShell 7` sudah terpasang di Windows.

1. Restart OS
2. Jalankan [perintah Get-Counter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) dari `PowerShell 7` yang akan terus merekam performance counter setiap detik ke file CSV. (Jika Anda ingin mengukur sumber daya selain yang tercantum di bawah ini, [artikel ini](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) adalah referensi yang baik.)
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
3. Eksekusi proses yang ingin Anda ukur.

### Contoh  <!-- omit in toc -->
Berikut ini berisi contoh prosedur untuk mengukur performa dengan Hayabusa.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## Gunakan heaptrack
[heaptrack](https://github.com/KDE/heaptrack) adalah memory profiler canggih yang tersedia untuk Linux dan macOS. Dengan menggunakan heaptrack, Anda dapat menyelidiki bottleneck secara menyeluruh.

### Cara memperoleh  <!-- omit in toc -->
Prasyarat: Berikut adalah prosedur untuk Ubuntu 22.04. Anda tidak dapat menggunakan heaptrack di Windows.

1. Pasang heaptrack dengan dua perintah berikut.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Hapus kode mimalloc berikut dari Hayabusa. (Anda tidak dapat menggunakan memory profiler heaptrack dengan mimalloc.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Hapus [bagian [profile.release]](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) di file `Cargo.toml` Hayabusa dan ubah menjadi berikut:
     ```
     [profile.release]
     debug = true
     ```

4. Build sebuah release build: `cargo build --release`
5. Jalankan `heaptrack hayabusa dfir-timeline -d sample -o out.csv`

Sekarang ketika Hayabusa selesai berjalan, hasil heaptrack akan otomatis terbuka di aplikasi GUI.

### Contoh  <!-- omit in toc -->
Contoh hasil heaptrack ditunjukkan di bawah ini. Tab `Flame Graph` dan `Top-Down` memungkinkan Anda memeriksa secara visual fungsi-fungsi dengan penggunaan memori yang tinggi.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# Referensi

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# Kontribusi

Dokumen ini didasarkan pada temuan dari kasus perbaikan nyata di [Hayabusa](https://github.com/Yamato-Security/hayabusa). Jika Anda menemukan kesalahan atau teknik yang dapat meningkatkan performa, silakan kirimkan issue atau pull request kepada kami.
