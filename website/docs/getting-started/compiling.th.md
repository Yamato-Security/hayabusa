# ขั้นสูง: การคอมไพล์จากซอร์ส (ทางเลือก)

หากคุณติดตั้ง Rust ไว้แล้ว คุณสามารถคอมไพล์จากซอร์สได้ด้วยคำสั่งต่อไปนี้:

หมายเหตุ: ในการคอมไพล์ โดยปกติคุณจำเป็นต้องใช้ Rust เวอร์ชันล่าสุด

```bash
cargo build --release
```

คุณสามารถดาวน์โหลดเวอร์ชันที่ยังไม่เสถียรล่าสุดได้จากเบรนช์ main หรือเวอร์ชันเสถียรล่าสุดได้จากหน้า [Releases](https://github.com/Yamato-Security/hayabusa/releases)

อย่าลืมอัปเดต Rust เป็นระยะด้วย:

```bash
rustup update stable
```

ไบนารีที่คอมไพล์แล้วจะถูกสร้างออกมาในโฟลเดอร์ `./target/release`

## การอัปเดตแพ็กเกจ Rust

คุณสามารถอัปเดตเป็น Rust crates ล่าสุดได้ก่อนการคอมไพล์:

```bash
cargo update
```

> โปรดแจ้งให้เราทราบหากมีสิ่งใดเสียหายหลังจากที่คุณอัปเดต

## การครอสคอมไพล์ไบนารี Windows แบบ 32 บิต

คุณสามารถสร้างไบนารีแบบ 32 บิตบนระบบ Windows แบบ 64 บิตได้ด้วยวิธีต่อไปนี้:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **คำเตือน: อย่าลืมรัน `rustup install stable-i686-pc-windows-msvc` ทุกครั้งที่มี Rust เวอร์ชันเสถียรใหม่ เนื่องจาก `rustup update stable` จะไม่อัปเดตคอมไพเลอร์สำหรับการครอสคอมไพล์ และคุณอาจได้รับข้อผิดพลาดในการบิลด์**

## หมายเหตุการคอมไพล์บน macOS

หากคุณได้รับข้อผิดพลาดในการคอมไพล์เกี่ยวกับ openssl คุณจะต้องติดตั้ง [Homebrew](https://brew.sh/) จากนั้นติดตั้งแพ็กเกจต่อไปนี้:

```bash
brew install pkg-config
brew install openssl
```

## หมายเหตุการคอมไพล์บน Linux

จำเป็นต้องมี build dependencies ต่อไปนี้:

* openssl-devel (Fedora-based) / libssl-dev (Ubuntu-based) 
* perl
* musl-gcc

## การครอสคอมไพล์ไบนารี Linux MUSL

บนระบบปฏิบัติการ Linux ให้ติดตั้ง target ก่อน

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

คอมไพล์ด้วย:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **คำเตือน: อย่าลืมรัน `rustup install stable-x86_64-unknown-linux-musl` ทุกครั้งที่มี Rust เวอร์ชันเสถียรใหม่ เนื่องจาก `rustup update stable` จะไม่อัปเดตคอมไพเลอร์สำหรับการครอสคอมไพล์ และคุณอาจได้รับข้อผิดพลาดในการบิลด์**

ไบนารี MUSL จะถูกสร้างขึ้นในไดเรกทอรี `./target/x86_64-unknown-linux-musl/release/`
ไบนารี MUSL ช้ากว่าไบนารี GNU ประมาณ 15% อย่างไรก็ตาม มันสามารถพกพาข้ามเวอร์ชันและดิสทริบิวชันต่าง ๆ ของ linux ได้ดีกว่า
