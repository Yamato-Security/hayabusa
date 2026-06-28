# คู่มือประสิทธิภาพ Rust สำหรับนักพัฒนา Hayabusa

# ผู้เขียน
Fukusuke Takahashi

# การแปลภาษาอังกฤษ
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# เกี่ยวกับเอกสารนี้
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (ภาษาอังกฤษ: "peregrine falcon" หรือเหยี่ยวเพเรกริน) เป็นเครื่องมือวิเคราะห์ทางนิติวิทยาศาสตร์ที่รวดเร็วซึ่งพัฒนาโดยกลุ่ม [Yamato Security](https://yamatosecurity.connpass.com/) ในประเทศญี่ปุ่น มันถูกพัฒนาด้วย [Rust](https://www.rust-lang.org/) เพื่อให้สามารถ (ภัยคุกคาม) ล่าได้รวดเร็วเทียบเท่าเหยี่ยวเพเรกริน Rust เป็นภาษาที่รวดเร็วในตัวมันเองอยู่แล้ว อย่างไรก็ตาม มีจุดที่อาจพลาดได้หลายจุดซึ่งอาจส่งผลให้ความเร็วช้าลงและการใช้หน่วยความจำสูงขึ้น เราสร้างเอกสารนี้ขึ้นจากการปรับปรุงประสิทธิภาพจริงใน Hayabusa (ดู [บันทึกการเปลี่ยนแปลงได้ที่นี่](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)) แต่เทคนิคเหล่านี้น่าจะนำไปใช้ได้กับโปรแกรม Rust อื่น ๆ ได้เช่นกัน เราหวังว่าคุณจะได้รับประโยชน์จากความรู้ที่เราได้รับผ่านการลองผิดลองถูกของเรา

# การปรับปรุงความเร็ว
## เปลี่ยน memory allocator
เพียงแค่เปลี่ยน memory allocator เริ่มต้นก็อาจช่วยปรับปรุงความเร็วได้อย่างมาก
ตัวอย่างเช่น ตาม [benchmarks](https://github.com/rust-lang/rust-analyzer/issues/1441) เหล่านี้ memory allocator สองตัวต่อไปนี้

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

เร็วกว่า memory allocator เริ่มต้นมาก เราสามารถยืนยันการปรับปรุงความเร็วได้อย่างมีนัยสำคัญด้วยการเปลี่ยน memory allocator ของเราจาก jemalloc เป็น mimalloc ดังนั้นเราจึงทำให้ mimalloc เป็นค่าเริ่มต้นตั้งแต่เวอร์ชัน 1.8.0 (แม้ว่า mimalloc จะใช้หน่วยความจำมากกว่า jemalloc เล็กน้อยก็ตาม)

### ก่อน  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### หลัง  <!-- omit in toc -->
คุณเพียงแค่ต้องทำ 2 ขั้นตอนต่อไปนี้เพื่อเปลี่ยน global [memory allocator](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html):

1. เพิ่ม [mimalloc crate](https://crates.io/crates/mimalloc) ลงในไฟล์ `Cargo.toml` ที่ [[dependencies] section](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency):
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. กำหนดว่าคุณต้องการใช้ mimalloc ภายใต้ [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) ที่ใดที่หนึ่งในโปรแกรม:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
นั่นคือทั้งหมดที่คุณต้องทำเพื่อเปลี่ยน memory allocator

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）  <!-- omit in toc -->
ความเร็วจะปรับปรุงได้มากเพียงใดขึ้นอยู่กับโปรแกรม แต่ในตัวอย่างต่อไปนี้
- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

การเปลี่ยน memory allocator เป็น [mimalloc](https://github.com/microsoft/mimalloc) ส่งผลให้ประสิทธิภาพเพิ่มขึ้น 20-30% บน Intel CPU
(ด้วยเหตุผลบางอย่าง ประสิทธิภาพไม่ได้เพิ่มขึ้นอย่างมีนัยสำคัญบนอุปกรณ์ macOS ที่ใช้ ARM)

## ลดการประมวลผล IO ในลูป
การประมวลผล Disk IO ช้ากว่าการประมวลผลในหน่วยความจำมาก ดังนั้นจึงควรหลีกเลี่ยงการประมวลผล IO ให้มากที่สุดเท่าที่จะเป็นไปได้ โดยเฉพาะอย่างยิ่งในลูป

### ก่อน  <!-- omit in toc -->
ตัวอย่างด้านล่างแสดงการเปิดไฟล์เกิดขึ้นหนึ่งล้านครั้งในลูป:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### หลัง  <!-- omit in toc -->
ด้วยการเปิดไฟล์นอกลูปดังต่อไปนี้
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
จะมีความเร็วเพิ่มขึ้นประมาณ 1000 เท่า

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ในตัวอย่างต่อไปนี้ การประมวลผล IO เมื่อจัดการผลการตรวจจับทีละรายการสามารถทำได้นอกลูป:
- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

ส่งผลให้ความเร็วปรับปรุงได้ประมาณ 20%

## หลีกเลี่ยงการคอมไพล์ regular expression ในลูป
การคอมไพล์ regular expression เป็นกระบวนการที่มีต้นทุนสูงมากเมื่อเทียบกับการจับคู่ regular expression ดังนั้นจึงควรหลีกเลี่ยงการคอมไพล์ regular expression ให้มากที่สุดเท่าที่จะเป็นไปได้ โดยเฉพาะอย่างยิ่งในลูป

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น กระบวนการต่อไปนี้สร้างความพยายามจับคู่ regular expression 100,000 ครั้งในลูป:
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
### หลัง  <!-- omit in toc -->
ด้วยการคอมไพล์ regular expression นอกลูปดังที่แสดงด้านล่าง
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
โค้ดที่อัปเดตจะเร็วขึ้นประมาณ 100 เท่า

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ในตัวอย่างต่อไปนี้ การคอมไพล์ regular expression ทำนอกลูปและถูกแคชไว้
- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

ส่งผลให้ความเร็วปรับปรุงได้อย่างมีนัยสำคัญ

## ใช้ buffer IO
หากไม่มี buffer IO การทำ file IO จะช้า ด้วย buffer IO การดำเนินการ IO จะทำผ่านบัฟเฟอร์ในหน่วยความจำ ลดจำนวน system call และปรับปรุงความเร็ว

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น ในกระบวนการต่อไปนี้ [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) เกิดขึ้น 1,000,000 ครั้ง
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
### หลัง  <!-- omit in toc -->
ด้วยการใช้ [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) ดังต่อไปนี้
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
จะมีความเร็วเพิ่มขึ้นประมาณ 50 เท่า

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
วิธีที่อธิบายข้างต้นถูกนำมาใช้ที่นี่
- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

และส่งผลให้ความเร็วปรับปรุงได้อย่างมีนัยสำคัญในการประมวลผลเอาต์พุต

## ใช้เมธอด String มาตรฐานแทน regular expression
แม้ว่า regular expression จะสามารถครอบคลุมรูปแบบการจับคู่ที่ซับซ้อนได้ แต่ก็ช้ากว่า [เมธอด String มาตรฐาน](https://doc.rust-lang.org/std/string/struct.String.html) ดังนั้นการใช้เมธอด String มาตรฐานสำหรับการจับคู่สตริงแบบง่าย ๆ เช่นต่อไปนี้จึงเร็วกว่า

- การจับคู่แบบ Starts-with（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- การจับคู่แบบ Ends-with（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- การจับคู่แบบ Contains（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น โค้ดต่อไปนี้ทำการจับคู่แบบ ends-with ใน regular expression หนึ่งล้านครั้ง
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
### หลัง  <!-- omit in toc -->
ด้วยการใช้ [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) ดังต่อไปนี้
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
การประมวลผลจะเร็วขึ้น 10 เท่า

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
เนื่องจาก Hayabusa ต้องการการเปรียบเทียบสตริงแบบไม่สนใจตัวพิมพ์เล็กพิมพ์ใหญ่ เราจึงใช้ [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) แล้วจึงใช้วิธีข้างต้น แม้กระนั้น ในตัวอย่างต่อไปนี้
- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

ความเร็วปรับปรุงได้ประมาณ 15% เมื่อเทียบกับก่อนหน้า

## กรองตามความยาวสตริง
ขึ้นอยู่กับลักษณะของสตริงที่กำลังจัดการ การเพิ่มตัวกรองแบบง่าย ๆ อาจช่วยลดจำนวนความพยายามจับคู่สตริงและเร่งความเร็วของกระบวนการ หากคุณมักเปรียบเทียบสตริงที่มีความยาวไม่คงที่และไม่ตรงกัน คุณสามารถเร่งความเร็วของกระบวนการได้ด้วยการใช้ความยาวสตริงเป็นตัวกรองหลัก

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น โค้ดต่อไปนี้พยายามจับคู่ regular expression หนึ่งล้านครั้ง
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
### หลัง  <!-- omit in toc -->
ด้วยการใช้ [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) เป็นตัวกรองหลัก ดังที่แสดงด้านล่าง
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
ความเร็วจะปรับปรุงได้ประมาณ 20 เท่า

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ในตัวอย่างต่อไปนี้ มีการใช้วิธีข้างต้น
- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

ซึ่งปรับปรุงความเร็วได้ประมาณ 15%

## อย่าคอมไพล์ด้วย codegen-units=1
บทความจำนวนมากเกี่ยวกับการปรับแต่งประสิทธิภาพด้วย Rust แนะนำให้เพิ่ม `codegen-units = 1` ภายใต้ส่วน `[profile.release]`
สิ่งนี้จะทำให้เวลาในการคอมไพล์ช้าลงเนื่องจากค่าเริ่มต้นคือการคอมไพล์แบบขนาน แต่ในทางทฤษฎีควรส่งผลให้โค้ดได้รับการปรับแต่งมากขึ้นและเร็วขึ้น
อย่างไรก็ตาม ในการทดสอบของเรา Hayabusa ทำงานช้าลงจริง ๆ เมื่อเปิดตัวเลือกนี้และการคอมไพล์ใช้เวลานานขึ้น ดังนั้นเราจึงปิดไว้
ขนาดไบนารีของไฟล์ปฏิบัติการเล็กลงประมาณ 100kb ดังนั้นสิ่งนี้อาจเหมาะสำหรับระบบฝังตัวที่พื้นที่ฮาร์ดดิสก์มีจำกัด

# การลดการใช้หน่วยความจำ

## หลีกเลี่ยงการใช้ clone(), to_string() และ to_owned() ที่ไม่จำเป็น
การใช้ [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) หรือ [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) เป็นวิธีง่าย ๆ ในการแก้ไขข้อผิดพลาดในการคอมไพล์ที่เกี่ยวข้องกับ [ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) อย่างไรก็ตาม มักจะส่งผลให้มีการใช้หน่วยความจำสูงและควรหลีกเลี่ยง ทางที่ดีที่สุดคือดูก่อนเสมอว่าคุณสามารถแทนที่ด้วย [references](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) ที่มีต้นทุนต่ำได้หรือไม่

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น หากคุณต้องการวนซ้ำ `Vec` เดียวกันหลายครั้ง คุณสามารถใช้ [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) เพื่อกำจัดข้อผิดพลาดในการคอมไพล์
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
### หลัง  <!-- omit in toc -->
อย่างไรก็ตาม ด้วยการใช้ [references](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) ดังที่แสดงด้านล่าง คุณสามารถลบความจำเป็นในการใช้ [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) ได้
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
ด้วยการลบการใช้ clone() การใช้หน่วยความจำจะลดลงได้มากถึง 50%

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ในตัวอย่างต่อไปนี้ ด้วยการแทนที่การใช้ [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) และ [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html) ที่ไม่จำเป็น
- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

เราสามารถลดการใช้หน่วยความจำได้อย่างมีนัยสำคัญ

## ใช้ Iterator แทน Vec
[Vec](https://doc.rust-lang.org/std/vec/) เก็บองค์ประกอบทั้งหมดไว้ในหน่วยความจำ ดังนั้นจึงใช้หน่วยความจำมากตามสัดส่วนของจำนวนองค์ประกอบ หากการประมวลผลทีละองค์ประกอบเพียงพอ การใช้ [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) แทนจะใช้หน่วยความจำน้อยกว่ามาก

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น ฟังก์ชัน `return_lines()` ต่อไปนี้อ่านไฟล์ขนาดประมาณ 1 GB และคืนค่า [Vec](https://doc.rust-lang.org/std/vec/):
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
### หลัง  <!-- omit in toc -->
แทนที่ คุณควรคืนค่า [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) ดังต่อไปนี้:
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
หรือหากชนิดข้อมูลแตกต่างกันขึ้นอยู่กับว่าเลือกใช้สาขาใด คุณสามารถคืนค่า `Box<dyn Iterator<Item = T>>` ดังต่อไปนี้:
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
การใช้หน่วยความจำลดลงอย่างมีนัยสำคัญจาก 1 GB เหลือเพียง 3 MB

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ตัวอย่างต่อไปนี้ใช้วิธีที่อธิบายข้างต้น:
- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

เมื่อทดสอบกับไฟล์ JSON ขนาด 1.7GB หน่วยความจำลดลง 75%

## ใช้ compact_str crate เมื่อจัดการสตริงสั้น
เมื่อจัดการกับสตริงสั้นจำนวนมากที่มีขนาดน้อยกว่า 24 ไบต์ สามารถใช้ [compact_str crate](https://docs.rs/crate/compact_str/latest) เพื่อลดการใช้หน่วยความจำได้

### ก่อน  <!-- omit in toc -->
ในตัวอย่างด้านล่าง Vec เก็บสตริง 10 ล้านตัว
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### หลัง  <!-- omit in toc -->
ทางที่ดีกว่าคือแทนที่ด้วย [CompactString](https://docs.rs/compact_str/latest/compact_str/):
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
ด้วยการทำเช่นนี้ การใช้หน่วยความจำจะลดลงประมาณ 50%

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ในตัวอย่างต่อไปนี้ สตริงสั้นถูกจัดการด้วย [CompactString](https://docs.rs/compact_str/latest/compact_str/):
- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

สิ่งนี้ทำให้การใช้หน่วยความจำลดลงประมาณ 20%

## ลบฟิลด์ที่ไม่จำเป็นในโครงสร้างที่มีอายุยาว
โครงสร้างที่ยังคงถูกเก็บไว้ในหน่วยความจำระหว่างการเริ่มต้นกระบวนการอาจส่งผลต่อการใช้หน่วยความจำโดยรวม ใน Hayabusa โครงสร้างต่อไปนี้ (ณ เวอร์ชัน 2.2.2) โดยเฉพาะอย่างยิ่ง ถูกเก็บไว้เป็นจำนวนมาก
- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

การลบฟิลด์ที่เกี่ยวข้องกับโครงสร้างข้างต้นมีผลบางส่วนในการลดการใช้หน่วยความจำโดยรวม

### ก่อน  <!-- omit in toc -->
ตัวอย่างเช่น ฟิลด์ `DetectInfo` จนถึงเวอร์ชัน 1.8.1 เป็นดังต่อไปนี้:
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
### หลัง  <!-- omit in toc -->
ด้วยการลบฟิลด์ `record_information` ดังต่อไปนี้
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
การลดการใช้หน่วยความจำลงหลายไบต์ต่อเรกคอร์ดผลการตรวจจับหนึ่งรายการสามารถทำได้สำเร็จ

### ประสิทธิผล（ตัวอย่างจริงจาก Pull Request）   <!-- omit in toc -->
ในตัวอย่างต่อไปนี้ เมื่อทดสอบกับข้อมูลที่มีจำนวนเรกคอร์ดผลการตรวจจับประมาณ 1.5 ล้านรายการ
- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

เราสามารถลดการใช้หน่วยความจำได้ประมาณ 300MB

# การวัดประสิทธิภาพ (Benchmarking)
## ใช้ฟังก์ชันสถิติของ memory allocator
memory allocator บางตัวเก็บสถิติการใช้หน่วยความจำของตนเอง ตัวอย่างเช่น ใน [mimalloc](https://github.com/microsoft/mimalloc) สามารถเรียกฟังก์ชัน [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) เพื่อรับการใช้หน่วยความจำได้

### วิธีการรับสถิติ  <!-- omit in toc -->
ข้อกำหนดเบื้องต้น: คุณต้องใช้ mimalloc ตามที่อธิบายในส่วน [เปลี่ยน memory allocator](#change-the-memory-allocator)

1.  ใน `Cargo.toml` ที่ [dependencies section](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) ให้เพิ่ม [libmimalloc-sys crate](https://crates.io/crates/libmimalloc-sys):
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. เมื่อใดก็ตามที่คุณต้องการพิมพ์สถิติการใช้หน่วยความจำ ให้เขียนโค้ดต่อไปนี้และภายในบล็อก `unsafe` ให้เรียก [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) สถิติการใช้หน่วยความจำจะถูกส่งออกไปยัง standard out
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
3. ค่า `peak/reserved` ที่มุมซ้ายบนคือการใช้หน่วยความจำสูงสุด

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### ตัวอย่าง   <!-- omit in toc -->
การนำไปใช้ข้างต้นถูกนำมาใช้ในส่วนต่อไปนี้:
- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

ใน Hayabusa หากคุณเพิ่มตัวเลือก `--debug` สถิติการใช้หน่วยความจำจะถูกส่งออกในตอนท้าย

## ใช้ performance counter ของ Windows
สามารถตรวจสอบการใช้ทรัพยากรต่าง ๆ ได้จากสถิติที่ได้รับจากฝั่ง OS ในกรณีนี้ ควรสังเกตสองจุดต่อไปนี้

- อิทธิพลจากซอฟต์แวร์แอนตี้ไวรัส (Windows Defender)
  - มีเพียงการรันครั้งแรกเท่านั้นที่ได้รับผลกระทบจากการสแกนและช้าลง ดังนั้นผลลัพธ์จากการรันครั้งที่สองและครั้งต่อ ๆ ไปหลังจากบิลด์จึงเหมาะสำหรับการเปรียบเทียบ (หรือคุณสามารถปิดใช้งานแอนตี้ไวรัสของคุณเพื่อผลลัพธ์ที่แม่นยำยิ่งขึ้น)
- อิทธิพลจากการแคชไฟล์
  - ผลลัพธ์จากครั้งที่สองและครั้งต่อ ๆ ไปหลังจากเริ่มต้น OS จะเร็วกว่าครั้งแรกเนื่องจาก evtx และ file IO อื่น ๆ ถูกอ่านจากแคชไฟล์ในหน่วยความจำ ดังนั้นผลลัพธ์จากครั้งแรกหลังจาก OS บูตจึงเหมาะสมกว่าสำหรับการวัดประสิทธิภาพ

### วิธีการรับ  <!-- omit in toc -->
ข้อกำหนดเบื้องต้น：ขั้นตอนต่อไปนี้ใช้ได้เฉพาะกับสภาพแวดล้อมที่ติดตั้ง `PowerShell 7` บน Windows อยู่แล้วเท่านั้น

1. รีสตาร์ท OS
2. รัน [Get-Counter command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) ของ `PowerShell 7` ซึ่งจะบันทึก performance counter อย่างต่อเนื่องทุกวินาทีลงในไฟล์ CSV (หากคุณต้องการวัดทรัพยากรอื่นนอกเหนือจากที่ระบุไว้ด้านล่าง [บทความนี้](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) เป็นข้อมูลอ้างอิงที่ดี)
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
3. รันกระบวนการที่คุณต้องการวัด

### ตัวอย่าง  <!-- omit in toc -->
ส่วนต่อไปนี้มีตัวอย่างขั้นตอนการวัดประสิทธิภาพด้วย Hayabusa
- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## ใช้ heaptrack
[heaptrack](https://github.com/KDE/heaptrack) เป็น memory profiler ที่ซับซ้อนซึ่งมีให้ใช้สำหรับ Linux และ macOS ด้วยการใช้ heaptrack คุณสามารถตรวจสอบคอขวดได้อย่างละเอียด

### วิธีการรับ  <!-- omit in toc -->
ข้อกำหนดเบื้องต้น: ด้านล่างเป็นขั้นตอนสำหรับ Ubuntu 22.04 คุณไม่สามารถใช้ heaptrack บน Windows ได้

1. ติดตั้ง heaptrack ด้วยสองคำสั่งต่อไปนี้
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. ลบโค้ด mimalloc ต่อไปนี้ออกจาก Hayabusa (คุณไม่สามารถใช้ memory profiler ของ heaptrack กับ mimalloc ได้
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. ลบ [[profile.release] section](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) ในไฟล์ `Cargo.toml` ของ Hayabusa และเปลี่ยนเป็นดังต่อไปนี้:
     ```
     [profile.release]
     debug = true
     ```

4. สร้าง release build: `cargo build --release`
5. รัน `heaptrack hayabusa csv-timeline -d sample -o out.csv`

ตอนนี้เมื่อ Hayabusa รันเสร็จ ผลลัพธ์ของ heaptrack จะเปิดในแอปพลิเคชัน GUI โดยอัตโนมัติ

### ตัวอย่าง  <!-- omit in toc -->
ตัวอย่างผลลัพธ์ของ heaptrack แสดงไว้ด้านล่าง แท็บ `Flame Graph` และ `Top-Down` ช่วยให้คุณตรวจสอบฟังก์ชันที่ใช้หน่วยความจำสูงได้ด้วยสายตา

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# เอกสารอ้างอิง

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# การมีส่วนร่วม

เอกสารนี้อ้างอิงจากข้อค้นพบจากกรณีการปรับปรุงจริงใน [Hayabusa](https://github.com/Yamato-Security/hayabusa) หากคุณพบข้อผิดพลาดหรือเทคนิคใด ๆ ที่สามารถปรับปรุงประสิทธิภาพได้ โปรดส่ง issue หรือ pull request มาให้เรา
