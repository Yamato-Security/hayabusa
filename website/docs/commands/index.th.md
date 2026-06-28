# รายการคำสั่ง

## คำสั่งวิเคราะห์:
* `computer-metrics`: แสดงจำนวนเหตุการณ์ตามชื่อคอมพิวเตอร์
* `eid-metrics`: แสดงจำนวนและเปอร์เซ็นต์ของเหตุการณ์ตาม Event ID
* `expand-list`: ดึง `expand` placeholders จากโฟลเดอร์ `rules`
* `extract-base64`: ดึงและถอดรหัสสตริง base64 จากเหตุการณ์
* `log-metrics`: แสดงเมตริกของไฟล์ล็อก
* `logon-summary`: แสดงสรุปของเหตุการณ์การล็อกออน
* `pivot-keywords-list`: แสดงรายการคำสำคัญที่น่าสงสัยเพื่อใช้ในการ pivot
* `search`: ค้นหาเหตุการณ์ทั้งหมดด้วยคำสำคัญหรือนิพจน์ทั่วไป (regular expressions)

## คำสั่งกำหนดค่า:
* `config-critical-systems`: ค้นหาระบบสำคัญ เช่น โดเมนคอนโทรลเลอร์และไฟล์เซิร์ฟเวอร์

## คำสั่งไทม์ไลน์ DFIR:
* `csv-timeline`: บันทึกไทม์ไลน์ในรูปแบบ CSV
* `json-timeline`: บันทึกไทม์ไลน์ในรูปแบบ JSON/JSONL
* `level-tuning`: ปรับแต่ง `level` ของการแจ้งเตือนแบบกำหนดเอง
* `list-profiles`: แสดงรายการโปรไฟล์เอาต์พุตที่มีอยู่
* `set-default-profile`: เปลี่ยนโปรไฟล์เริ่มต้น
* `update-rules`: ซิงค์กฎให้เป็นกฎล่าสุดในที่เก็บ GitHub [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)

## คำสั่งทั่วไป:
* `help`: แสดงข้อความนี้หรือความช่วยเหลือของคำสั่งย่อยที่ระบุ
* `list-contributors`: แสดงรายชื่อผู้มีส่วนร่วม
