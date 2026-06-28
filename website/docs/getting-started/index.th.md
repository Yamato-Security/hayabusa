# การดาวน์โหลด

โปรดดาวน์โหลด Hayabusa เวอร์ชันเสถียรล่าสุดพร้อมไบนารีที่คอมไพล์แล้ว หรือคอมไพล์ซอร์สโค้ดจากหน้า [Releases](https://github.com/Yamato-Security/hayabusa/releases)

เราจัดเตรียมไบนารีสำหรับสถาปัตยกรรมต่อไปนี้:

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [ด้วยเหตุผลบางประการ ไบนารี Linux ARM MUSL ไม่ทำงานอย่างถูกต้อง](https://github.com/Yamato-Security/hayabusa/issues/1332) ดังนั้นเราจึงไม่จัดเตรียมไบนารีนั้น เรื่องนี้อยู่นอกเหนือการควบคุมของเรา เราจึงวางแผนที่จะจัดเตรียมไบนารีนั้นในอนาคตเมื่อได้รับการแก้ไขแล้ว

## แพ็กเกจ live response สำหรับ Windows

ตั้งแต่ v2.18.0 เป็นต้นไป เราจัดเตรียมแพ็กเกจ Windows พิเศษที่ใช้กฎซึ่งเข้ารหัสแบบ XOR ที่ให้มาในไฟล์เดียว รวมถึงไฟล์คอนฟิกทั้งหมดที่รวมเข้าไว้ในไฟล์เดียว (โฮสต์อยู่ที่ [hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules))
เพียงดาวน์โหลดแพ็กเกจ zip ที่มีคำว่า `live-response` อยู่ในชื่อ
ไฟล์ zip มีเพียงสามไฟล์เท่านั้น: ไบนารี Hayabusa, ไฟล์กฎที่เข้ารหัสแบบ XOR และไฟล์คอนฟิก
จุดประสงค์ของแพ็กเกจ live response เหล่านี้คือเมื่อรัน Hayabusa บนเอนด์พอยต์ของไคลเอนต์ เราต้องการให้แน่ใจว่าโปรแกรมสแกนไวรัสอย่าง Windows Defender จะไม่แจ้งเตือนผลบวกลวง (false positive) กับไฟล์กฎ `.yml`
นอกจากนี้ เราต้องการลดจำนวนไฟล์ที่ถูกเขียนลงในระบบให้น้อยที่สุด เพื่อไม่ให้อาร์ติแฟกต์ทางนิติวิทยาศาสตร์อย่าง USN Journal ถูกเขียนทับ
