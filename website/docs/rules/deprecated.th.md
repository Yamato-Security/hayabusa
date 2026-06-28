# คุณสมบัติที่เลิกใช้งานแล้ว

คีย์เวิร์ดพิเศษที่เลิกใช้งานแล้วและการรวมข้อมูล `count` ยังคงรองรับใน Hayabusa แต่จะไม่ถูกใช้ภายในกฎในอนาคต

## คีย์เวิร์ดพิเศษที่เลิกใช้งานแล้ว

ในปัจจุบัน สามารถระบุคีย์เวิร์ดพิเศษต่อไปนี้ได้:
- `value`: จับคู่ด้วยสตริง (สามารถระบุไวลด์การ์ดและไปป์ได้เช่นกัน)
- `min_length`: จับคู่เมื่อจำนวนอักขระมากกว่าหรือเท่ากับจำนวนที่ระบุ
- `regexes`: จับคู่หากหนึ่งในนิพจน์ปกติในไฟล์ที่คุณระบุในฟิลด์นี้ตรงกัน
- `allowlist`: กฎจะถูกข้ามหากพบการจับคู่ใด ๆ ในรายการนิพจน์ปกติในไฟล์ที่คุณระบุในฟิลด์นี้

ในตัวอย่างด้านล่าง กฎจะจับคู่หากเงื่อนไขต่อไปนี้เป็นจริง:
- `ServiceName` ถูกเรียกว่า `malicious-service` หรือมีนิพจน์ปกติใน `./rules/config/regex/detectlist_suspicous_services.txt`
- `ImagePath` มีอักขระอย่างน้อย 1000 ตัว
- `ImagePath` ไม่มีการจับคู่ใด ๆ ใน `allowlist`

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### ไฟล์ตัวอย่างคีย์เวิร์ด regexes และ allowlist

Hayabusa มีไฟล์นิพจน์ปกติในตัวสองไฟล์ที่ใช้สำหรับไฟล์ `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml`:
- `./rules/config/regex/detectlist_suspicous_services.txt`: เพื่อตรวจจับชื่อบริการที่น่าสงสัย
- `./rules/config/regex/allowlist_legitimate_services.txt`: เพื่ออนุญาตบริการที่ถูกต้องตามกฎหมาย

ไฟล์ที่กำหนดใน `regexes` และ `allowlist` สามารถแก้ไขเพื่อเปลี่ยนพฤติกรรมของกฎทั้งหมดที่อ้างอิงถึงไฟล์เหล่านั้นได้ โดยไม่ต้องเปลี่ยนไฟล์กฎใด ๆ เลย

คุณยังสามารถใช้ไฟล์ข้อความ detectlist และ allowlist อื่น ๆ ที่คุณสร้างขึ้นได้

## เงื่อนไขการรวมข้อมูลที่เลิกใช้งานแล้ว (กฎ `count`)

ฟีเจอร์นี้ยังคงรองรับใน Hayabusa แต่จะถูกแทนที่ด้วยกฎความสัมพันธ์ของ Sigma ในอนาคต

### พื้นฐาน

คีย์เวิร์ด `condition` ที่อธิบายไว้ข้างต้นไม่เพียงแต่ใช้ตรรกะ `AND` และ `OR` เท่านั้น แต่ยังสามารถนับหรือ "รวมข้อมูล" เหตุการณ์ได้อีกด้วย
ฟังก์ชันนี้เรียกว่า "เงื่อนไขการรวมข้อมูล" และระบุโดยการเชื่อมต่อเงื่อนไขด้วยไปป์
ในตัวอย่างการตรวจจับการพ่นรหัสผ่าน (password spray) ด้านล่างนี้ มีการใช้นิพจน์เงื่อนไขเพื่อตรวจสอบว่ามีค่า `TargetUserName` ตั้งแต่ 5 ค่าขึ้นไปจาก `IpAddress` ต้นทางเดียวกันภายในกรอบเวลา 5 นาทีหรือไม่

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

เงื่อนไขการรวมข้อมูลสามารถกำหนดได้ในรูปแบบต่อไปนี้:
- `count() {operator} {number}`: สำหรับเหตุการณ์ log ที่ตรงกับเงื่อนไขแรกก่อนไปป์ เงื่อนไขจะจับคู่หากจำนวน log ที่จับคู่ได้เป็นไปตามนิพจน์เงื่อนไขที่ระบุโดย `{operator}` และ `{number}`

`{operator}` สามารถเป็นหนึ่งในค่าต่อไปนี้:
- `==`: หากค่าเท่ากับค่าที่ระบุ จะถือว่าตรงกับเงื่อนไข
- `>=`: หากค่ามากกว่าหรือเท่ากับค่าที่ระบุ จะถือว่าเป็นไปตามเงื่อนไข
- `>`: หากค่ามากกว่าค่าที่ระบุ จะถือว่าเป็นไปตามเงื่อนไข
- `<=`: หากค่าน้อยกว่าหรือเท่ากับค่าที่ระบุ จะถือว่าเป็นไปตามเงื่อนไข
- `<`: หากค่าน้อยกว่าค่าที่ระบุ จะถือว่าเป็นไปตามเงื่อนไข

`{number}` ต้องเป็นตัวเลข

`timeframe` สามารถกำหนดได้ดังต่อไปนี้:
- `15s`: 15 วินาที
- `30m`: 30 นาที
- `12h`: 12 ชั่วโมง
- `7d`: 7 วัน
- `3M`: 3 เดือน

### สี่รูปแบบสำหรับเงื่อนไขการรวมข้อมูล

1. ไม่มีอาร์กิวเมนต์ count หรือคีย์เวิร์ด `by` ตัวอย่าง: `selection | count() > 10`
   > หาก `selection` จับคู่มากกว่า 10 ครั้งภายในกรอบเวลา เงื่อนไขจะจับคู่
   > รูปแบบเหล่านี้จะถูกแทนที่ด้วยกฎความสัมพันธ์แบบ Event Count ที่ไม่ใช้ฟิลด์ `group-by`
2. ไม่มีอาร์กิวเมนต์ count แต่มีคีย์เวิร์ด `by` ตัวอย่าง: `selection | count() by IpAddress > 10`
   > `selection` จะต้องเป็นจริงมากกว่า 10 ครั้งสำหรับ `IpAddress` **เดียวกัน**
   > กฎ #2 เหล่านี้พบได้บ่อยกว่ากฎ #1
   > คุณยังสามารถระบุหลายฟิลด์เพื่อจัดกลุ่มได้ ตัวอย่างเช่น: `by IpAddress, Computer`
   > รูปแบบเหล่านี้จะถูกแทนที่ด้วยกฎความสัมพันธ์แบบ Event Count ที่ใช้ฟิลด์ `group-by`
3. มีอาร์กิวเมนต์ count แต่ไม่มีคีย์เวิร์ด `by` ตัวอย่าง: `selection | count(TargetUserName) > 10`
   > หาก `selection` จับคู่และ `TargetUserName` **แตกต่างกัน** มากกว่า 10 ครั้งภายในกรอบเวลา เงื่อนไขจะจับคู่
   > รูปแบบเหล่านี้จะถูกแทนที่ด้วยกฎความสัมพันธ์แบบ Value Count ที่ไม่ใช้ฟิลด์ `group-by`
4. มีทั้งอาร์กิวเมนต์ count และคีย์เวิร์ด `by` ตัวอย่าง: `selection | count(Users) by IpAddress > 10`
   > สำหรับ `IpAddress` **เดียวกัน** จะต้องมี `TargetUserName` ที่ **แตกต่างกัน** มากกว่า 10 ค่าเพื่อให้เงื่อนไขจับคู่
   > กฎ #4 เหล่านี้พบได้บ่อยกว่ากฎ #3
   > รูปแบบเหล่านี้จะถูกแทนที่ด้วยกฎความสัมพันธ์แบบ Value Count ที่ใช้ฟิลด์ `group-by`

### ตัวอย่างรูปแบบที่ 1

นี่คือรูปแบบพื้นฐานที่สุด: `count() {operator} {number}` กฎด้านล่างจะจับคู่หาก `selection` เกิดขึ้น 3 ครั้งขึ้นไป

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### ตัวอย่างรูปแบบที่ 2

`count() by {eventkey} {operator} {number}`: เหตุการณ์ log ที่ตรงกับ `condition` ก่อนไปป์จะถูกจัดกลุ่มตาม `{eventkey}` **เดียวกัน** หากจำนวนเหตุการณ์ที่จับคู่ได้สำหรับแต่ละกลุ่มเป็นไปตามเงื่อนไขที่ระบุโดย `{operator}` และ `{number}` เงื่อนไขจะจับคู่

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### ตัวอย่างรูปแบบที่ 3

`count({eventkey}) {operator} {number}`: นับว่ามีค่า `{eventkey}` ที่ **แตกต่างกัน** กี่ค่าอยู่ในเหตุการณ์ log ที่ตรงกับเงื่อนไขก่อนไปป์เงื่อนไข หากจำนวนเป็นไปตามนิพจน์เงื่อนไขที่ระบุใน `{operator}` และ `{number}` จะถือว่าเป็นไปตามเงื่อนไข

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### ตัวอย่างรูปแบบที่ 4

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: log ที่ตรงกับเงื่อนไขก่อนไปป์เงื่อนไขจะถูกจัดกลุ่มตาม `{eventkey_2}` **เดียวกัน** และนับจำนวนค่า `{eventkey_1}` ที่ **แตกต่างกัน** ในแต่ละกลุ่ม หากค่าที่นับได้สำหรับแต่ละกลุ่มเป็นไปตามนิพจน์เงื่อนไขที่ระบุโดย `{operator}` และ `{number}` เงื่อนไขจะจับคู่

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### ผลลัพธ์ของกฎ count

รายละเอียดผลลัพธ์สำหรับกฎ count นั้นคงที่ และจะพิมพ์เงื่อนไข count ดั้งเดิมใน `[condition]` ตามด้วย eventkey ที่บันทึกไว้ใน `[result]`

ในตัวอย่างด้านล่าง รายการชื่อผู้ใช้ `TargetUserName` ที่ถูกโจมตีแบบ bruteforce ตามด้วย `IpAddress` ต้นทาง:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

ไทม์สแตมป์ของการแจ้งเตือนจะเป็นเวลาจากเหตุการณ์แรกที่ตรวจพบ
