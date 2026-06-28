## กฎ Event Count

กฎเหล่านี้เป็นกฎที่นับเหตุการณ์บางอย่างและแจ้งเตือนหากเหตุการณ์เหล่านี้เกิดขึ้นมากเกินไปหรือไม่เพียงพอภายในกรอบเวลาหนึ่ง
ตัวอย่างทั่วไปของการตรวจจับเหตุการณ์จำนวนมากภายในช่วงเวลาหนึ่งคือการตรวจจับการโจมตีแบบเดารหัสผ่าน การโจมตีแบบ password spray และการโจมตีแบบ denial of service
คุณยังสามารถใช้กฎเหล่านี้เพื่อตรวจจับปัญหาความน่าเชื่อถือของแหล่งล็อก เช่น เมื่อเหตุการณ์บางอย่างต่ำกว่าเกณฑ์ที่กำหนด

### ตัวอย่างกฎ Event Count:

ตัวอย่างต่อไปนี้ใช้สองกฎเพื่อตรวจจับการโจมตีแบบเดารหัสผ่าน
จะมีการแจ้งเตือนเมื่อกฎที่ถูกอ้างอิงตรงกัน 5 ครั้งขึ้นไปภายใน 5 นาทีและฟิลด์ `IpAddress` เป็นค่าเดียวกันสำหรับเหตุการณ์เหล่านั้น

> โปรดทราบว่าเราได้รวมเฉพาะฟิลด์ที่จำเป็นเพื่อให้เข้าใจแนวคิดเท่านั้น
> กฎฉบับเต็มที่ตัวอย่างนี้อ้างอิงอยู่ที่ [here](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) เพื่อการอ้างอิงของคุณ

### กฎ correlation แบบ Event Count:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### กฎ Failed Logon - Incorrect Password:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### ตัวอย่างกฎ `count` ที่เลิกใช้แล้ว:

กฎ correlation และกฎที่ถูกอ้างอิงข้างต้นให้ผลลัพธ์เหมือนกันกับกฎต่อไปนี้ที่ใช้ตัวปรับแต่ง `count` แบบเก่า:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### ผลลัพธ์ของกฎ Event Count:

กฎข้างต้นจะสร้างผลลัพธ์ต่อไปนี้:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## กฎ Value Count

กฎเหล่านี้นับเหตุการณ์เดียวกันภายในกรอบเวลาหนึ่งที่มีค่า **แตกต่างกัน** ของฟิลด์ที่กำหนด

ตัวอย่าง:
- การสแกนเครือข่ายที่ที่อยู่ IP ต้นทางเดียวพยายามเชื่อมต่อไปยังที่อยู่ IP ปลายทางและ/หรือพอร์ตจำนวนมากที่แตกต่างกัน
- การโจมตีแบบ password spraying ที่ต้นทางเดียวล้มเหลวในการยืนยันตัวตนกับผู้ใช้จำนวนมากที่แตกต่างกัน
- ตรวจจับเครื่องมืออย่าง BloodHound ที่แจกแจงกลุ่ม AD ที่มีสิทธิ์สูงจำนวนมากภายในกรอบเวลาสั้นๆ

### ตัวอย่างกฎ Value Count:

กฎต่อไปนี้ตรวจจับเมื่อผู้โจมตีพยายามเดาชื่อผู้ใช้
นั่นคือ เมื่อที่อยู่ IP ต้นทาง (`IpAddress`) **เดียวกัน** ล้มเหลวในการเข้าสู่ระบบด้วยชื่อผู้ใช้ (`TargetUserName`) ที่ **แตกต่างกัน** มากกว่า 3 รายการภายใน 5 นาที

> โปรดทราบว่าเราได้รวมเฉพาะฟิลด์ที่จำเป็นเพื่อให้เข้าใจแนวคิดเท่านั้น
> กฎฉบับเต็มที่ตัวอย่างนี้อ้างอิงอยู่ที่ [here](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) เพื่อการอ้างอิงของคุณ

### กฎ correlation แบบ Value Count:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### กฎ Value Count Logon Failure (Non-existant User):

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### กฎตัวปรับแต่ง `count` ที่เลิกใช้แล้ว:

กฎ correlation และกฎที่ถูกอ้างอิงข้างต้นให้ผลลัพธ์เหมือนกันกับกฎต่อไปนี้ที่ใช้ตัวปรับแต่ง `count` แบบเก่า:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### ผลลัพธ์ของกฎ Value Count:

กฎข้างต้นจะสร้างผลลัพธ์ต่อไปนี้:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## กฎ Temporal Proximity

เหตุการณ์ทั้งหมดที่กำหนดโดยกฎที่ถูกอ้างอิงในฟิลด์ rule ต้องเกิดขึ้นภายในกรอบเวลาที่กำหนดโดย timespan
ค่าของฟิลด์ที่กำหนดใน `group-by` ต้องมีค่าเหมือนกันทั้งหมด (เช่น โฮสต์เดียวกัน ผู้ใช้เดียวกัน เป็นต้น)

### ตัวอย่างกฎ Temporal Proximity:

ตัวอย่าง: คำสั่ง Reconnaissance ที่กำหนดในสามกฎ Sigma ถูกเรียกใช้ในลำดับใดก็ได้ภายใน 5 นาทีบนระบบโดยผู้ใช้คนเดียวกัน

### กฎ correlation แบบ Temporal Proximity:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## กฎ Ordered Temporal Proximity

ประเภท correlation แบบ `temporal_ordered` มีพฤติกรรมเหมือน `temporal` และเพิ่มเติมว่าเหตุการณ์ต้องปรากฏตามลำดับที่ระบุไว้ในแอตทริบิวต์ `rules`

### ตัวอย่างกฎ Ordered Temporal Proximity:

ตัวอย่าง: การเข้าสู่ระบบที่ล้มเหลวจำนวนมากตามที่กำหนดข้างต้น ตามด้วยการเข้าสู่ระบบสำเร็จโดยบัญชีผู้ใช้เดียวกันภายใน 1 ชั่วโมง:

### กฎ correlation แบบ Ordered Temporal Proximity:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## หมายเหตุเกี่ยวกับกฎ correlation

1. คุณควรรวมกฎ correlation และกฎที่ถูกอ้างอิงทั้งหมดไว้ในไฟล์เดียวและแยกกันด้วยตัวคั่น YAML คือ `---`

2. โดยค่าเริ่มต้น กฎ correlation ที่ถูกอ้างอิงจะไม่ถูกแสดงผล หากคุณต้องการดูผลลัพธ์ของกฎที่ถูกอ้างอิง คุณต้องเพิ่ม `generate: true` ภายใต้ `correlation` ซึ่งมีประโยชน์มากในการเปิดและตรวจสอบเมื่อสร้างกฎ correlation

    ตัวอย่าง:
    ```
    correlation:
        generate: true
    ```
3. คุณสามารถใช้ชื่อ alias แทน rule ID เมื่ออ้างอิงกฎเพื่อให้เข้าใจสิ่งต่างๆ ได้ง่ายขึ้น

4. คุณสามารถอ้างอิงกฎได้หลายกฎ

5. คุณสามารถใช้หลายฟิลด์ใน `group-by` ได้ หากคุณทำเช่นนั้น ค่าทั้งหมดในฟิลด์เหล่านั้นต้องเหมือนกัน มิฉะนั้นคุณจะไม่ได้รับการแจ้งเตือน โดยส่วนใหญ่ คุณจะเขียนกฎที่กรองในฟิลด์บางอย่างด้วย `group-by` เพื่อลด false positive อย่างไรก็ตาม สามารถละเว้น `group-by` เพื่อสร้างกฎที่ทั่วไปมากขึ้นได้

6. timestamp ของกฎ correlation จะเป็นจุดเริ่มต้นของการโจมตี ดังนั้นคุณควรตรวจสอบเหตุการณ์หลังจากนั้นเพื่อยืนยันว่าเป็น false positive หรือไม่
