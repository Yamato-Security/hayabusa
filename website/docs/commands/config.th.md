# คำสั่ง Config

## คำสั่ง `config-critical-systems`

คำสั่งนี้จะพยายามค้นหาระบบสำคัญอย่างเช่นโดเมนคอนโทรลเลอร์และไฟล์เซิร์ฟเวอร์โดยอัตโนมัติ และเพิ่มเข้าไปในไฟล์ตั้งค่า `./config/critical_systems.txt` เพื่อให้การแจ้งเตือนทั้งหมดถูกเพิ่มระดับขึ้นหนึ่งระดับ
คำสั่งจะค้นหาเหตุการณ์ Security 4768 (Kerberos TGT requested) เพื่อพิจารณาว่าเป็นโดเมนคอนโทรลเลอร์หรือไม่
คำสั่งจะค้นหาเหตุการณ์ Security 5145 (Network Share File Access) เพื่อพิจารณาว่าเป็นไฟล์เซิร์ฟเวอร์หรือไม่
ชื่อโฮสต์ใดก็ตามที่ถูกเพิ่มเข้าไปในไฟล์ `critical_systems.txt` จะมีการแจ้งเตือนทั้งหมดที่อยู่เหนือระดับ low ถูกเพิ่มขึ้นหนึ่งระดับ โดยมีระดับสูงสุดคือระดับ `emergency`

```
Usage:
  hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  ไดเรกทอรีของไฟล์ .evtx หลายไฟล์ (or images with --vhdx/--e01)
  -f, --file <FILE>      พาธไฟล์ของไฟล์ .evtx หนึ่งไฟล์ (or an image with --vhdx/--e01)
      --vhdx             Scan VHDX images read-only; -d searches up to three subdirectory levels
      --e01              Scan E01/Ex01 images read-only without extraction; -d searches three subdirectory levels

Display Settings:
  -K, --no-color  ปิดใช้งานการแสดงผลแบบสี
  -q, --quiet     โหมดเงียบ: ไม่แสดงแบนเนอร์เมื่อเริ่มโปรแกรม

General Options:
  -h, --help  แสดงเมนูช่วยเหลือ
```

### ตัวอย่างคำสั่ง `config-critical-systems`

* ค้นหาในไดเรกทอรี `../hayabusa-sample-evtx` เพื่อหาโดเมนคอนโทรลเลอร์และไฟล์เซิร์ฟเวอร์:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
