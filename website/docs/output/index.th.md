# การแสดงผลไทม์ไลน์

## โปรไฟล์การแสดงผล (Output Profiles)

Hayabusa มีโปรไฟล์การแสดงผลที่กำหนดไว้ล่วงหน้า 5 แบบให้ใช้งานใน `config/profiles.yaml`:

1. `minimal`
2. `standard` (ค่าเริ่มต้น)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

คุณสามารถปรับแต่งหรือเพิ่มโปรไฟล์ของคุณเองได้อย่างง่ายดายโดยการแก้ไขไฟล์นี้
คุณยังสามารถเปลี่ยนโปรไฟล์เริ่มต้นได้อย่างง่ายดายด้วย `set-default-profile --profile <profile>`
ใช้คำสั่ง `list-profiles` เพื่อแสดงโปรไฟล์ที่มีอยู่และข้อมูลฟิลด์ของโปรไฟล์เหล่านั้น

### 1. การแสดงผลของโปรไฟล์ `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. การแสดงผลของโปรไฟล์ `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. การแสดงผลของโปรไฟล์ `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. การแสดงผลของโปรไฟล์ `all-field-info`

แทนที่จะแสดงข้อมูล `details` แบบย่อ ข้อมูลฟิลด์ทั้งหมดในส่วน `EventData` และ `UserData` จะถูกแสดงผลพร้อมกับชื่อฟิลด์ดั้งเดิมของมัน

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. การแสดงผลของโปรไฟล์ `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. การแสดงผลของโปรไฟล์ `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. การแสดงผลของโปรไฟล์ `timesketch-minimal`

แสดงผลในรูปแบบที่เข้ากันได้กับการนำเข้าสู่ [Timesketch](https://timesketch.org/)

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. การแสดงผลของโปรไฟล์ `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### การเปรียบเทียบโปรไฟล์

การทดสอบประสิทธิภาพต่อไปนี้ดำเนินการบนเครื่อง Lenovo P51 ปี 2018 (CPU Xeon 4 Core / RAM 64GB) ด้วยข้อมูล evtx ขนาด 3GB และเปิดใช้งานกฎ 3891 รายการ (2023/06/01)

| โปรไฟล์ | เวลาในการประมวลผล | ขนาดไฟล์ที่แสดงผล | การเพิ่มขึ้นของขนาดไฟล์ |
| :---: | :---: | :---: | :---: |
| minimal | 8 นาที 50 วินาที | 770 MB | -30% |
| standard (ค่าเริ่มต้น) | 9 นาที 00 วินาที | 1.1 GB | ไม่มี |
| verbose | 9 นาที 10 วินาที | 1.3 GB | +20% |
| all-field-info | 9 นาที 3 วินาที | 1.2 GB | +10% |
| all-field-info-verbose | 9 นาที 10 วินาที | 1.3 GB | +20% |
| super-verbose | 9 นาที 12 วินาที | 1.5 GB | +35% |

### นามแฝงของฟิลด์ในโปรไฟล์ (Profile Field Aliases)

ข้อมูลต่อไปนี้สามารถแสดงผลได้ด้วยโปรไฟล์การแสดงผลที่มีอยู่ในตัว:

| ชื่อนามแฝง | ข้อมูลที่ Hayabusa แสดงผล|
| :--- | :--- |
|%AllFieldInfo% | ข้อมูลฟิลด์ทั้งหมด |
|%Channel% | ชื่อของบันทึก ฟิลด์ `<Event><System><Channel>` |
|%Computer% | ฟิลด์ `<Event><System><Computer>` |
|%Details% | ฟิลด์ `details` ในกฎตรวจจับ YML อย่างไรก็ตาม มีเฉพาะกฎของ hayabusa เท่านั้นที่มีฟิลด์นี้ ฟิลด์นี้ให้ข้อมูลเพิ่มเติมเกี่ยวกับการแจ้งเตือนหรือเหตุการณ์ และสามารถดึงข้อมูลที่เป็นประโยชน์จากฟิลด์ในบันทึกเหตุการณ์ได้ ตัวอย่างเช่น ชื่อผู้ใช้ ข้อมูลบรรทัดคำสั่ง ข้อมูลโพรเซส เป็นต้น เมื่อ placeholder ชี้ไปยังฟิลด์ที่ไม่มีอยู่ หรือมีการแมปนามแฝงที่ไม่ถูกต้อง มันจะถูกแสดงผลเป็น `n/a` (ไม่พร้อมใช้งาน) หากไม่ได้ระบุฟิลด์ `details` (เช่น กฎ sigma) ข้อความ `details` เริ่มต้นในการดึงฟิลด์ที่กำหนดไว้ใน `./rules/config/default_details.txt` จะถูกแสดงผล คุณสามารถเพิ่มข้อความ `details` เริ่มต้นได้มากขึ้นโดยการเพิ่ม `Provider Name`, `EventID` และข้อความ `details` ที่คุณต้องการแสดงผลใน `default_details.txt` เมื่อไม่มีการกำหนดฟิลด์ `details` ในกฎหรือใน `default_details.txt` ฟิลด์ทั้งหมดจะถูกแสดงผลในคอลัมน์ `details` |
|%ExtraFieldInfo% | แสดงข้อมูลฟิลด์ที่ไม่ได้ถูกแสดงผลใน %Details% |
|%EventID% | ฟิลด์ `<Event><System><EventID>` |
|%EvtxFile% | ชื่อไฟล์ evtx ที่ทำให้เกิดการแจ้งเตือนหรือเหตุการณ์ |
|%Level% | ฟิลด์ `level` ในกฎตรวจจับ YML (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [tactics](https://attack.mitre.org/tactics/enterprise/) (ตัวอย่าง: Initial Access, Lateral Movement, เป็นต้น) |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID และ Software ID |
|%OtherTags% | คำสำคัญใดๆ ในฟิลด์ `tags` ในกฎตรวจจับ YML ที่ไม่รวมอยู่ใน `MitreTactics` หรือ `MitreTags` |
|%Provider% | แอตทริบิวต์ `Name` ในฟิลด์ `<Event><System><Provider>` |
|%RecordID% | Event Record ID จากฟิลด์ `<Event><System><EventRecordID>` |
|%RuleAuthor% | ฟิลด์ `author` ในกฎตรวจจับ YML |
|%RuleCreationDate% | ฟิลด์ `date` ในกฎตรวจจับ YML |
|%RuleFile% | ชื่อไฟล์ของกฎตรวจจับที่สร้างการแจ้งเตือนหรือเหตุการณ์ |
|%RuleID% | ฟิลด์ `id` ในกฎตรวจจับ YML |
|%RuleModifiedDate% | ฟิลด์ `modified` ในกฎตรวจจับ YML |
|%RuleTitle% | ฟิลด์ `title` ในกฎตรวจจับ YML |
|%Status% | ฟิลด์ `status` ในกฎตรวจจับ YML |
|%Timestamp% | ค่าเริ่มต้นคือรูปแบบ `YYYY-MM-DD HH:mm:ss.sss +hh:mm` ฟิลด์ `<Event><System><TimeCreated SystemTime>` ในบันทึกเหตุการณ์ เขตเวลาเริ่มต้นจะเป็นเขตเวลาท้องถิ่น แต่คุณสามารถเปลี่ยนเขตเวลาเป็น UTC ได้ด้วยตัวเลือก `--utc` |

#### นามแฝงของฟิลด์โปรไฟล์เพิ่มเติม

คุณยังสามารถเพิ่มนามแฝงเพิ่มเติมเหล่านี้ลงในโปรไฟล์การแสดงผลของคุณได้หากคุณต้องการ:

| ชื่อนามแฝง | ข้อมูลที่ Hayabusa แสดงผล|
| :--- | :--- |
|%RenderedMessage% | ฟิลด์ `<Event><RenderingInfo><Message>` ในบันทึกที่ส่งต่อจาก WEC |

หมายเหตุ: นามแฝงนี้**ไม่ได้**รวมอยู่ในโปรไฟล์ที่มีในตัวใดๆ ดังนั้นคุณจะต้องแก้ไขไฟล์ `config/default_profile.yaml` ด้วยตนเองและเพิ่มบรรทัดต่อไปนี้:

```
Message: "%RenderedMessage%"
```

คุณยังสามารถกำหนด [event key aliases](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) เพื่อแสดงผลฟิลด์อื่นๆ ได้
