# กฎ Hayabusa

กฎการตรวจจับของ Hayabusa เขียนในรูปแบบ YML ที่คล้ายกับ sigma และอยู่ในโฟลเดอร์ `rules`
กฎเหล่านี้ถูกจัดเก็บไว้ที่ [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) ดังนั้นโปรดส่ง issue และ pull request ใด ๆ เกี่ยวกับกฎไปที่นั่นแทนที่จะเป็น repository หลักของ Hayabusa

ดู [การสร้างไฟล์กฎ](creating-rules.md), [ฟิลด์การตรวจจับ](detection-fields.md) และ [Sigma Correlations](correlations.md) ในส่วนนี้เพื่อทำความเข้าใจรูปแบบของกฎและวิธีการสร้างกฎ (แหล่งที่มา: [hayabusa-rules repository](https://github.com/Yamato-Security/hayabusa-rules))

กฎทั้งหมดจาก hayabusa-rules repository ควรถูกวางไว้ในโฟลเดอร์ `rules`
กฎระดับ `informational` ถือเป็น `events` ในขณะที่อะไรก็ตามที่มี `level` เป็น `low` ขึ้นไปถือเป็น `alerts`

โครงสร้างไดเรกทอรีของกฎ hayabusa แบ่งออกเป็น 2 ไดเรกทอรี:

* `builtin`: ล็อกที่สามารถสร้างขึ้นได้โดยฟังก์ชันการทำงานในตัวของ Windows
* `sysmon`: ล็อกที่สร้างขึ้นโดย [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

กฎจะถูกแยกออกเป็นไดเรกทอรีเพิ่มเติมตามประเภทของล็อก (ตัวอย่าง: Security, System ฯลฯ) และตั้งชื่อในรูปแบบต่อไปนี้:

โปรดดูกฎปัจจุบันเพื่อใช้เป็นเทมเพลตในการสร้างกฎใหม่หรือสำหรับการตรวจสอบตรรกะการตรวจจับ

## Sigma v.s. Hayabusa (Built-in Sigma Compatible) Rules

Hayabusa รองรับกฎ Sigma โดยตรง ยกเว้นเพียงอย่างเดียวคือการจัดการฟิลด์ `logsource` ภายใน
เพื่อลดผลบวกลวง (false positive) กฎ Sigma ควรถูกประมวลผลผ่าน convertor ของเราที่อธิบายไว้ [ที่นี่](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md)
สิ่งนี้จะเพิ่ม `Channel` และ `EventID` ที่ถูกต้อง และดำเนินการแมปฟิลด์สำหรับบางหมวดหมู่เช่น `process_creation`

กฎ Hayabusa เกือบทั้งหมดเข้ากันได้กับรูปแบบ Sigma ดังนั้นคุณจึงสามารถใช้กฎเหล่านี้เหมือนกับกฎ Sigma เพื่อแปลงเป็นรูปแบบ SIEM อื่น ๆ ได้
กฎ Hayabusa ออกแบบมาเพื่อการวิเคราะห์ Windows event log โดยเฉพาะ และมีประโยชน์ดังต่อไปนี้:

1. ฟิลด์ `details` เพิ่มเติมเพื่อแสดงข้อมูลเพิ่มเติมที่นำมาจากเฉพาะฟิลด์ที่มีประโยชน์ในล็อก
2. กฎทั้งหมดได้รับการทดสอบกับล็อกตัวอย่างและทราบว่าทำงานได้
3. aggregator เพิ่มเติมที่ไม่พบใน sigma เช่น `|equalsfield` และ `|endswithfield`

เท่าที่เราทราบ hayabusa ให้การรองรับกฎ sigma โดยตรงได้ดีที่สุดในบรรดาเครื่องมือวิเคราะห์ Windows event log แบบโอเพนซอร์สทั้งหมด
