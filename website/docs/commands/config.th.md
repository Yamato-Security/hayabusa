# คำสั่ง Config

## คำสั่ง `config-critical-systems`

คำสั่งนี้จะพยายามค้นหาระบบสำคัญอย่างเช่นโดเมนคอนโทรลเลอร์และไฟล์เซิร์ฟเวอร์โดยอัตโนมัติ และเพิ่มเข้าไปในไฟล์ตั้งค่า `./config/critical_systems.txt` เพื่อให้การแจ้งเตือนทั้งหมดถูกเพิ่มระดับขึ้นหนึ่งระดับ
คำสั่งจะค้นหาเหตุการณ์ Security 4768 (Kerberos TGT requested) เพื่อพิจารณาว่าเป็นโดเมนคอนโทรลเลอร์หรือไม่
คำสั่งจะค้นหาเหตุการณ์ Security 5145 (Network Share File Access) เพื่อพิจารณาว่าเป็นไฟล์เซิร์ฟเวอร์หรือไม่
ชื่อโฮสต์ใดก็ตามที่ถูกเพิ่มเข้าไปในไฟล์ `critical_systems.txt` จะมีการแจ้งเตือนทั้งหมดที่อยู่เหนือระดับ low ถูกเพิ่มขึ้นหนึ่งระดับ โดยมีระดับสูงสุดคือระดับ `emergency`

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### ตัวอย่างคำสั่ง `config-critical-systems`

* ค้นหาในไดเรกทอรี `../hayabusa-sample-evtx` เพื่อหาโดเมนคอนโทรลเลอร์และไฟล์เซิร์ฟเวอร์:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
