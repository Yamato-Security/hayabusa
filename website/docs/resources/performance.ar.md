# دليل أداء Rust لمطوري Hayabusa

# المؤلف
Fukusuke Takahashi

# الترجمة الإنجليزية
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# حول هذا المستند
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (بالإنجليزية: "صقر الشاهين") هي أداة سريعة للتحليل الجنائي طورتها مجموعة [Yamato Security](https://yamatosecurity.connpass.com/) في اليابان. وهي مطورة بلغة [Rust](https://www.rust-lang.org/) من أجل (تتبع) التهديدات بسرعة صقر الشاهين. إن Rust لغة سريعة في حد ذاتها، ومع ذلك هناك العديد من المزالق التي يمكن أن تؤدي إلى بطء السرعة وارتفاع استخدام الذاكرة. لقد أنشأنا هذا المستند بناءً على تحسينات أداء فعلية في Hayabusa (انظر [سجل التغييرات هنا](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md))، لكن هذه التقنيات ينبغي أن تكون قابلة للتطبيق على برامج Rust الأخرى أيضًا. نأمل أن تستفيد من المعرفة التي اكتسبناها من خلال تجربتنا وأخطائنا.

# تحسين السرعة
## تغيير مُخصِّص الذاكرة
قد يؤدي مجرد تغيير مُخصِّص الذاكرة الافتراضي إلى تحسين السرعة بشكل كبير.
على سبيل المثال، وفقًا لهذه [القياسات المرجعية](https://github.com/rust-lang/rust-analyzer/issues/1441)، فإن مُخصِّصَيْ الذاكرة التاليَيْن

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

أسرع بكثير من مُخصِّص الذاكرة الافتراضي. لقد تمكنا من تأكيد تحسن كبير في السرعة عند تغيير مُخصِّص الذاكرة لدينا من jemalloc إلى mimalloc، لذا جعلنا mimalloc الخيار الافتراضي منذ الإصدار 1.8.0. (مع أن mimalloc يستخدم ذاكرة أكثر قليلًا من jemalloc.)

### قبل  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### بعد  <!-- omit in toc -->
كل ما تحتاج إليه هو تنفيذ الخطوتين التاليتين لتغيير [مُخصِّص الذاكرة](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) العام:

1. أضف [حزمة mimalloc](https://crates.io/crates/mimalloc) إلى [قسم [dependencies]](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) في ملف `Cargo.toml`:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. عرّف أنك تريد استخدام mimalloc تحت [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) في مكان ما من البرنامج:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
هذا كل ما تحتاج إلى فعله لتغيير مُخصِّص الذاكرة.

### الفعالية（مثال واقعي من طلب سحب）  <!-- omit in toc -->
يعتمد مدى تحسن السرعة على البرنامج، لكن في المثال التالي

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

أدى تغيير مُخصِّص الذاكرة إلى [mimalloc](https://github.com/microsoft/mimalloc) إلى زيادة في الأداء بنسبة 20-30٪ على معالجات Intel. 
(لسبب ما، لم تكن هناك زيادة في الأداء بنفس القدر على أجهزة macOS المعتمدة على ARM.)

## تقليل معالجة الإدخال/الإخراج داخل الحلقات
معالجة الإدخال/الإخراج للقرص أبطأ بكثير من المعالجة في الذاكرة. لذلك، من المستحسن تجنب معالجة الإدخال/الإخراج قدر الإمكان، خاصة داخل الحلقات.

### قبل  <!-- omit in toc -->
يوضح المثال أدناه فتح ملف يحدث مليون مرة داخل حلقة:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### بعد  <!-- omit in toc -->
بفتح الملف خارج الحلقة كما يلي
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
ستكون هناك زيادة في السرعة بحوالي 1000 مرة.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
في المثال التالي، أمكن تنفيذ معالجة الإدخال/الإخراج عند التعامل مع نتيجة كشف واحدة في كل مرة خارج الحلقة:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

أدى هذا إلى تحسن في السرعة بحوالي 20٪.

## تجنّب تجميع التعبيرات النمطية داخل الحلقات
يُعد تجميع التعبيرات النمطية عملية مكلفة جدًا مقارنة بمطابقة التعبيرات النمطية. لذلك، يُنصح بتجنب تجميع التعبيرات النمطية قدر الإمكان، خاصة داخل الحلقات.

### قبل  <!-- omit in toc -->
على سبيل المثال، تنشئ العملية التالية 100,000 محاولة لمطابقة تعبير نمطي داخل حلقة:
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
### بعد  <!-- omit in toc -->
بإجراء تجميع التعبير النمطي خارج الحلقة، كما هو موضح أدناه
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
يكون الكود المُحدَّث أسرع بحوالي 100 مرة.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
في المثال التالي، يُجرى تجميع التعبير النمطي خارج الحلقة ويُخزَّن مؤقتًا.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

أدى هذا إلى تحسينات كبيرة في السرعة.

## استخدام الإدخال/الإخراج المُخزَّن مؤقتًا (buffer IO)
بدون الإدخال/الإخراج المُخزَّن مؤقتًا، يكون إدخال/إخراج الملفات بطيئًا. مع الإدخال/الإخراج المُخزَّن مؤقتًا، تُجرى عمليات الإدخال/الإخراج عبر مخازن مؤقتة في الذاكرة، مما يقلل عدد استدعاءات النظام ويحسن السرعة.

### قبل  <!-- omit in toc -->
على سبيل المثال، في العملية التالية، تحدث [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) مليون مرة.
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
### بعد  <!-- omit in toc -->
باستخدام [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) كما يلي
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
يحدث تحسن في السرعة بحوالي 50 مرة.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
الطريقة الموضحة أعلاه نُفِّذت هنا

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

وأدت إلى تحسينات كبيرة في السرعة في معالجة الإخراج.

## استخدام طرق String القياسية بدلًا من التعبيرات النمطية
بينما يمكن للتعبيرات النمطية تغطية أنماط مطابقة معقدة، فإنها أبطأ من [طرق String القياسية](https://doc.rust-lang.org/std/string/struct.String.html). لذلك، يكون استخدام طرق String القياسية أسرع لمطابقة السلاسل النصية البسيطة مثل التالي.

- مطابقة البداية（التعبير النمطي: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- مطابقة النهاية（التعبير النمطي: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- مطابقة الاحتواء（التعبير النمطي: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### قبل  <!-- omit in toc -->
على سبيل المثال، يُجري الكود التالي مطابقة النهاية بتعبير نمطي مليون مرة.
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
### بعد  <!-- omit in toc -->
باستخدام [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) كما يلي
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
ستكون المعالجة أسرع بمقدار 10 مرات.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
بما أن Hayabusa تتطلب مقارنة سلاسل نصية غير حساسة لحالة الأحرف، فإننا نستخدم [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) ثم نطبق الطريقة أعلاه. حتى مع ذلك، في الأمثلة التالية

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

تحسنت السرعة بحوالي 15٪ مقارنة بما كانت عليه سابقًا.

## التصفية حسب طول السلسلة النصية
اعتمادًا على خصائص السلاسل النصية التي يجري التعامل معها، قد تؤدي إضافة مرشِّح بسيط إلى تقليل عدد محاولات مطابقة السلاسل النصية وتسريع العملية. إذا كنت غالبًا ما تقارن سلاسل نصية ذات أطوال غير ثابتة وغير متطابقة، فيمكنك تسريع العملية باستخدام طول السلسلة النصية كمرشِّح أولي.

### قبل  <!-- omit in toc -->
على سبيل المثال، يحاول الكود التالي مليون مطابقة لتعبير نمطي.
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
### بعد  <!-- omit in toc -->
باستخدام [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) كمرشِّح أولي، كما هو موضح أدناه
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
ستتحسن السرعة بحوالي 20 مرة.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
في المثال التالي، تُستخدم الطريقة أعلاه.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

أدى هذا إلى تحسين السرعة بحوالي 15٪.

## لا تُجرِ التجميع باستخدام codegen-units=1
تنصح العديد من المقالات حول تحسين الأداء مع Rust بإضافة `codegen-units = 1` تحت قسم `[profile.release]`.
سيؤدي هذا إلى أوقات تجميع أبطأ لأن الافتراضي هو التجميع بالتوازي، لكنه نظريًا ينبغي أن يؤدي إلى كود أكثر تحسينًا وأسرع.
ومع ذلك، في اختباراتنا، تعمل Hayabusa في الواقع بشكل أبطأ مع تشغيل هذا الخيار، ويستغرق التجميع وقتًا أطول، لذا نُبقيه معطلًا.
حجم البرنامج التنفيذي الثنائي أصغر بحوالي 100 كيلوبايت، لذا قد يكون هذا مثاليًا للأنظمة المضمَّنة حيث تكون مساحة القرص الصلب محدودة.

# تقليل استخدام الذاكرة

## تجنّب الاستخدام غير الضروري لـ clone() و to_string() و to_owned()
يُعد استخدام [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) أو [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) طريقة سهلة لحل أخطاء التجميع المتعلقة بـ[الملكية](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html). ومع ذلك، فإنها عادة ما تؤدي إلى استخدام مرتفع للذاكرة وينبغي تجنبها. من الأفضل دائمًا أن ترى أولًا ما إذا كان بإمكانك استبدالها بـ[مراجع](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) منخفضة التكلفة.

### قبل  <!-- omit in toc -->
على سبيل المثال، إذا كنت تريد التكرار على نفس `Vec` عدة مرات، فيمكنك استخدام [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) للتخلص من أخطاء التجميع.
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
### بعد  <!-- omit in toc -->
ومع ذلك، باستخدام [المراجع](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) كما هو موضح أدناه، يمكنك إزالة الحاجة إلى استخدام [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html).
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
بإزالة استخدام clone()، يُقلَّل استخدام الذاكرة بنسبة تصل إلى 50٪.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
في المثال التالي، باستبدال الاستخدام غير الضروري لـ[clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) و[to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) و[to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html)،

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

تمكنا من تقليل استخدام الذاكرة بشكل كبير.

## استخدام Iterator بدلًا من Vec
يحتفظ [Vec](https://doc.rust-lang.org/std/vec/) بجميع العناصر في الذاكرة، لذا فإنه يستخدم قدرًا كبيرًا من الذاكرة بما يتناسب مع عدد العناصر. إذا كانت معالجة عنصر واحد في كل مرة كافية، فإن استخدام [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) بدلًا من ذلك سيستخدم ذاكرة أقل بكثير.

### قبل  <!-- omit in toc -->
على سبيل المثال، تقرأ الدالة `return_lines()` التالية ملفًا بحجم حوالي 1 جيجابايت وتُرجع [Vec](https://doc.rust-lang.org/std/vec/):
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
### بعد  <!-- omit in toc -->
بدلًا من ذلك ينبغي أن تُرجع [سمة Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) كما يلي:
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
أو إذا كان النوع مختلفًا اعتمادًا على الفرع الذي يُتَّخذ، فيمكنك إرجاع `Box<dyn Iterator<Item = T>>` كما يلي:
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
ينخفض استخدام الذاكرة بشكل كبير من 1 جيجابايت إلى 3 ميجابايت فقط.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
يستخدم المثال التالي الطريقة الموضحة أعلاه:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

عند الاختبار على ملف JSON بحجم 1.7 جيجابايت، انخفضت الذاكرة بنسبة 75٪.

## استخدام حزمة compact_str عند التعامل مع السلاسل النصية القصيرة
عند التعامل مع عدد كبير من السلاسل النصية القصيرة الأقل من 24 بايت، يمكن استخدام [حزمة compact_str](https://docs.rs/crate/compact_str/latest) لتقليل استخدام الذاكرة.

### قبل  <!-- omit in toc -->
في المثال أدناه، يحتفظ Vec بعشرة ملايين سلسلة نصية.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### بعد  <!-- omit in toc -->
من الأفضل استبدالها بـ[CompactString](https://docs.rs/compact_str/latest/compact_str/):
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
بفعل هذا، يُقلَّل استخدام الذاكرة بحوالي 50٪.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
في المثال التالي، يُتعامل مع السلاسل النصية القصيرة باستخدام [CompactString](https://docs.rs/compact_str/latest/compact_str/):

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

أعطى هذا تقليلًا في استخدام الذاكرة بحوالي 20٪.

## حذف الحقول غير الضرورية في البُنى طويلة العمر
قد تؤثر البُنى التي تستمر في الاحتفاظ بها في الذاكرة أثناء بدء تشغيل العملية على إجمالي استخدام الذاكرة. في Hayabusa، يُحتفظ بالبُنى التالية (اعتبارًا من الإصدار 2.2.2) بأعداد كبيرة على وجه الخصوص.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

كان لإزالة الحقول المرتبطة بالبُنى أعلاه بعض التأثير في تقليل إجمالي استخدام الذاكرة.

### قبل  <!-- omit in toc -->
على سبيل المثال، كان حقل `DetectInfo`، حتى الإصدار 1.8.1، على النحو التالي:
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
### بعد  <!-- omit in toc -->
بحذف حقل `record_information` كما يلي
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
تحقق تقليل في استخدام الذاكرة بمقدار عدة بايتات لكل سجل نتيجة كشف.

### الفعالية（مثال واقعي من طلب سحب）   <!-- omit in toc -->
في المثال التالي، عند الاختبار على بيانات كان فيها عدد سجلات نتائج الكشف حوالي 1.5 مليون،

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

تمكنا من تحقيق تقليل في استخدام الذاكرة بحوالي 300 ميجابايت.

# القياس المرجعي
## استخدام دالة الإحصائيات الخاصة بمُخصِّص الذاكرة.
تحتفظ بعض مُخصِّصات الذاكرة بإحصائيات استخدام الذاكرة الخاصة بها. على سبيل المثال، في [mimalloc](https://github.com/microsoft/mimalloc)، يمكن استدعاء الدالة [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) للحصول على استخدام الذاكرة.

### كيفية الحصول على الإحصائيات  <!-- omit in toc -->
المتطلبات الأساسية: يجب أن تكون مستخدمًا لـ mimalloc كما هو موضح في قسم [تغيير مُخصِّص الذاكرة](#change-the-memory-allocator).

1.  في [قسم dependencies](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) من `Cargo.toml`، أضف [حزمة libmimalloc-sys](https://crates.io/crates/libmimalloc-sys):
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. كلما أردت طباعة إحصائيات استخدام الذاكرة، اكتب الكود التالي، وداخل كتلة `unsafe`، استدعِ [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79). ستُخرَج إحصائيات استخدام الذاكرة إلى الإخراج القياسي.
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
3. قيمة `peak/reserved` في أعلى اليسار هي الحد الأقصى لاستخدام الذاكرة. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### مثال   <!-- omit in toc -->
طُبِّق التنفيذ أعلاه في ما يلي:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

في Hayabusa، إذا أضفت الخيار `--debug`، فسيتم إخراج إحصائيات استخدام الذاكرة في النهاية.

## استخدام عداد الأداء في Windows
يمكن التحقق من استخدامات الموارد المختلفة من الإحصائيات التي يمكن الحصول عليها من جانب نظام التشغيل. في هذه الحالة، ينبغي ملاحظة النقطتين التاليتين.

- التأثير من برامج مكافحة الفيروسات (Windows Defender)
  - يتأثر التشغيل الأول فقط بالفحص ويكون أبطأ، لذا فإن النتائج من التشغيل الثاني وما بعده بعد البناء مناسبة للمقارنة. (أو يمكنك تعطيل برنامج مكافحة الفيروسات للحصول على نتائج أكثر دقة.)
- التأثير من التخزين المؤقت للملفات
  - تكون النتائج من المرة الثانية وما بعدها بعد بدء تشغيل نظام التشغيل أسرع من المرة الأولى لأن evtx وعمليات الإدخال/الإخراج الأخرى للملفات تُقرأ من ذاكرة التخزين المؤقت للملفات في الذاكرة، لذا فإن النتائج من المرة الأولى بعد إقلاع نظام التشغيل أكثر مثالية لأخذ القياسات المرجعية.

### كيفية الحصول عليها  <!-- omit in toc -->
المتطلبات الأساسية：الإجراء التالي صالح فقط للبيئات التي يكون فيها `PowerShell 7` مثبتًا بالفعل على Windows.

1. أعد تشغيل نظام التشغيل
2. شغّل [أمر Get-Counter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) الخاص بـ `PowerShell 7` والذي سيسجل باستمرار عداد الأداء كل ثانية إلى ملف CSV. (إذا كنت ترغب في قياس موارد غير المذكورة أدناه، فإن [هذه المقالة](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) مرجع جيد.)
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
3. نفّذ العملية التي تريد قياسها.

### مثال  <!-- omit in toc -->
يحتوي ما يلي على مثال لإجراء قياس الأداء باستخدام Hayabusa.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## استخدام heaptrack
[heaptrack](https://github.com/KDE/heaptrack) هو محلل ذاكرة متطور متاح لنظامي Linux وmacOS. باستخدام heaptrack، يمكنك التحقيق بدقة في الاختناقات.

### كيفية الحصول عليها  <!-- omit in toc -->
المتطلبات الأساسية: فيما يلي الإجراء لنظام Ubuntu 22.04. لا يمكنك استخدام heaptrack على Windows.

1. ثبّت heaptrack باستخدام الأمرين التاليين.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. أزل كود mimalloc التالي من Hayabusa. (لا يمكنك استخدام محلل ذاكرة heaptrack مع mimalloc.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. احذف [قسم [profile.release]](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) في ملف `Cargo.toml` الخاص بـ Hayabusa وغيّره إلى ما يلي:
     ```
     [profile.release]
     debug = true
     ```

4. ابنِ بناءً للإصدار: `cargo build --release`
5. شغّل `heaptrack hayabusa csv-timeline -d sample -o out.csv`

الآن عندما تنتهي Hayabusa من العمل، ستُفتح نتائج heaptrack تلقائيًا في تطبيق ذي واجهة رسومية.

### أمثلة  <!-- omit in toc -->
يُعرض مثال على نتائج heaptrack أدناه. تتيح لك علامتا التبويب `Flame Graph` و`Top-Down` التحقق بصريًا من الدوال ذات استخدام الذاكرة المرتفع.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# المراجع

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# المساهمات

يستند هذا المستند إلى نتائج من حالات تحسين فعلية في [Hayabusa](https://github.com/Yamato-Security/hayabusa). إذا وجدت أي أخطاء أو تقنيات يمكن أن تحسن الأداء، يرجى إرسال مشكلة أو طلب سحب إلينا.
