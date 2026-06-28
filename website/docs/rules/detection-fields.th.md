# ฟิลด์การตรวจจับ (Detection field)

## พื้นฐานของ Selection

ก่อนอื่น จะอธิบายพื้นฐานของวิธีการสร้างกฎ selection

### วิธีเขียนตรรกะ AND และ OR

ในการเขียนตรรกะ AND เราจะใช้ dictionary แบบซ้อนกัน
กฎการตรวจจับด้านล่างกำหนดว่า **ทั้งสองเงื่อนไข** ต้องเป็นจริงจึงจะทำให้กฎตรงกัน
- EventID ต้องเท่ากับ `7040` พอดี
- **AND**
- Channel ต้องเท่ากับ `System` พอดี

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

ในการเขียนตรรกะ OR เราจะใช้ list (dictionary ที่ขึ้นต้นด้วย `-`)
ในกฎการตรวจจับด้านล่าง **เงื่อนไขใดเงื่อนไขหนึ่ง** จะทำให้กฎถูกกระตุ้น
- EventID ต้องเท่ากับ `7040` พอดี
- **OR**
- Channel ต้องเท่ากับ `System` พอดี

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

เรายังสามารถรวมตรรกะ `AND` และ `OR` เข้าด้วยกันได้ดังที่แสดงด้านล่าง
ในกรณีนี้ กฎจะตรงกันเมื่อเงื่อนไขสองข้อต่อไปนี้เป็นจริงทั้งคู่
- EventID เท่ากับ `7040` **OR** `7041` พอดี
- **AND**
- Channel เท่ากับ `System` พอดี

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

ต่อไปนี้เป็นข้อความคัดลอกบางส่วนของ Windows event log ที่จัดรูปแบบในรูปแบบ XML ดั้งเดิม
ฟิลด์ `Event.System.Channel` ในตัวอย่างไฟล์กฎด้านบนอ้างอิงถึงแท็ก XML ดั้งเดิม: `<Event><System><Channel>System<Channel><System></Event>`
แท็ก XML ที่ซ้อนกันจะถูกแทนที่ด้วยชื่อแท็กที่คั่นด้วยจุด (`.`)
ในกฎของ hayabusa สตริงฟิลด์เหล่านี้ที่เชื่อมต่อกันด้วยจุดจะเรียกว่า `eventkeys`

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### นามแฝงของ Eventkey (Eventkey Aliases)

eventkey ที่ยาวซึ่งมีการคั่นด้วย `.` หลายตัวเป็นเรื่องปกติ ดังนั้น hayabusa จะใช้นามแฝงเพื่อให้ทำงานกับมันได้ง่ายขึ้น นามแฝงถูกกำหนดไว้ในไฟล์ `rules/config/eventkey_alias.txt` ไฟล์นี้เป็นไฟล์ CSV ที่ประกอบด้วยการจับคู่ระหว่าง `alias` และ `event_key` คุณสามารถเขียนกฎด้านบนใหม่ได้ดังที่แสดงด้านล่างด้วยนามแฝงซึ่งทำให้กฎอ่านง่ายขึ้น

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### ข้อควรระวัง: นามแฝง Eventkey ที่ยังไม่ได้กำหนด

ไม่ใช่นามแฝง eventkey ทั้งหมดที่ถูกกำหนดไว้ใน `rules/config/eventkey_alias.txt` หากคุณไม่ได้รับข้อมูลที่ถูกต้องในข้อความ `details` (`Alert details`) และกลับได้รับ `n/a` (not available) แทน หรือหาก selection ในตรรกะการตรวจจับของคุณทำงานไม่ถูกต้อง คุณอาจจำเป็นต้องอัปเดต `rules/config/eventkey_alias.txt` ด้วยนามแฝงใหม่

### วิธีใช้แอตทริบิวต์ XML ในเงื่อนไข

อิลิเมนต์ XML อาจมีแอตทริบิวต์ที่กำหนดโดยการเพิ่มช่องว่างให้กับอิลิเมนต์ ตัวอย่างเช่น `Name` ใน `Provider Name` ด้านล่างเป็นแอตทริบิวต์ XML ของอิลิเมนต์ `Provider`

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

ในการระบุแอตทริบิวต์ XML ใน eventkey ให้ใช้รูปแบบ `{eventkey}_attributes.{attribute_name}` ตัวอย่างเช่น ในการระบุแอตทริบิวต์ `Name` ของอิลิเมนต์ `Provider` ในไฟล์กฎ จะมีลักษณะดังนี้:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### การค้นหาแบบ grep

Hayabusa สามารถทำการค้นหาแบบ grep ในไฟล์ Windows event log ได้โดยไม่ต้องระบุ eventkey ใด ๆ

ในการทำการค้นหาแบบ grep ให้ระบุการตรวจจับดังที่แสดงด้านล่าง ในกรณีนี้ หากสตริง `mimikatz` หรือ `metasploit` รวมอยู่ใน Windows Event log มันจะตรงกัน นอกจากนี้ยังสามารถระบุ wildcard ได้อีกด้วย

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> หมายเหตุ: Hayabusa จะแปลงข้อมูล Windows event log เป็นรูปแบบ JSON ภายในก่อนการประมวลผลข้อมูล ดังนั้นจึงไม่สามารถจับคู่กับแท็ก XML ได้

### EventData

Windows event log แบ่งออกเป็นสองส่วน: ส่วน `System` ที่มีการเขียนข้อมูลพื้นฐาน (Event ID, Timestamp, Record ID, ชื่อ Log (Channel)) และส่วน `EventData` หรือ `UserData` ที่มีการเขียนข้อมูลตามต้องการขึ้นอยู่กับ Event ID
ปัญหาหนึ่งที่เกิดขึ้นบ่อยคือ ชื่อของฟิลด์ที่ซ้อนอยู่ใน `EventData` ทั้งหมดถูกเรียกว่า `Data` ดังนั้น eventkey ที่อธิบายไว้จนถึงตอนนี้จึงไม่สามารถแยกแยะระหว่าง `SubjectUserSid` และ `SubjectUserName` ได้

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

ในการจัดการกับปัญหานี้ คุณสามารถระบุค่าที่กำหนดไว้ใน `Data Name` ได้ ตัวอย่างเช่น หากคุณต้องการใช้ `SubjectUserName` และ `SubjectDomainName` ใน EventData เป็นเงื่อนไขของกฎ คุณสามารถเขียนได้ดังนี้:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### รูปแบบที่ผิดปกติใน EventData

แท็กบางตัวที่ซ้อนอยู่ใน `EventData` ไม่มีแอตทริบิวต์ `Name`

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

ในการตรวจจับ event log เช่นที่อยู่ด้านบน คุณสามารถระบุ eventkey ชื่อ `Data` ได้
ในกรณีนี้ เงื่อนไขจะตรงกันตราบเท่าที่แท็ก `Data` ที่ซ้อนกันตัวใดตัวหนึ่งเท่ากับ `None`

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### การส่งออกข้อมูลฟิลด์จากชื่อฟิลด์หลายตัวที่มีชื่อเดียวกัน

บาง event จะบันทึกข้อมูลของตนไปยังชื่อฟิลด์ที่เรียกว่า `Data` ทั้งหมดเหมือนในตัวอย่างก่อนหน้านี้
หากคุณระบุ `%Data%` ใน `details:` ข้อมูลทั้งหมดจะถูกส่งออกในรูปแบบอาร์เรย์

ตัวอย่างเช่น:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

หากคุณต้องการพิมพ์เฉพาะข้อมูลฟิลด์ `Data` ตัวแรก คุณสามารถระบุ `%Data[1]%` ในสตริงการแจ้งเตือน `details:` ของคุณ และจะมีเพียง `rundll32.exe` เท่านั้นที่ถูกส่งออก

## ตัวปรับแต่งฟิลด์ (Field Modifiers)

สามารถใช้อักขระ pipe กับ eventkey ได้ดังที่แสดงด้านล่างสำหรับการจับคู่สตริง
เงื่อนไขทั้งหมดที่เราได้อธิบายไว้จนถึงตอนนี้ใช้การจับคู่แบบตรงทุกตัวอักษร แต่ด้วยการใช้ตัวปรับแต่งฟิลด์ คุณสามารถอธิบายกฎการตรวจจับที่ยืดหยุ่นมากขึ้นได้
ในตัวอย่างต่อไปนี้ หากค่าของ `Data` มีสตริง `EngineVersion=2` มันจะตรงกับเงื่อนไข

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

การจับคู่สตริงไม่คำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่ อย่างไรก็ตาม จะคำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่ทุกครั้งที่ใช้ `|re` หรือ `|equalsfield`

### ตัวปรับแต่งฟิลด์ของ Sigma ที่รองรับ

ปัจจุบัน Hayabusa เป็นเครื่องมือโอเพนซอร์สเพียงตัวเดียวที่รองรับข้อกำหนดของ Sigma ทั้งหมดอย่างสมบูรณ์

คุณสามารถตรวจสอบสถานะปัจจุบันของตัวปรับแต่งฟิลด์ที่รองรับทั้งหมด รวมถึงจำนวนครั้งที่ตัวปรับแต่งเหล่านี้ถูกใช้ในกฎของ Sigma และ Hayabusa ได้ที่ https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md
เอกสารนี้ได้รับการอัปเดตแบบไดนามิกทุกครั้งที่มีการอัปเดตกฎของ Sigma หรือ Hayabusa

- `'|all':`: ตัวปรับแต่งฟิลด์นี้แตกต่างจากตัวอื่น ๆ ด้านบน เพราะมันไม่ได้ถูกนำไปใช้กับฟิลด์ใดฟิลด์หนึ่ง แต่กับทุกฟิลด์

    ในตัวอย่างนี้ สตริงทั้ง `Keyword-1` และ `Keyword-2` ต้องมีอยู่ แต่สามารถอยู่ที่ใดก็ได้ในฟิลด์ใดก็ได้:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: ข้อมูลจะถูกเข้ารหัสเป็น base64 ในสามวิธีที่แตกต่างกันขึ้นอยู่กับตำแหน่งในสตริงที่เข้ารหัส ตัวปรับแต่งนี้จะเข้ารหัสสตริงเป็นทั้งสามรูปแบบและตรวจสอบว่าสตริงถูกเข้ารหัสอยู่ที่ใดที่หนึ่งในสตริง base64 หรือไม่
- `|cased`: ทำให้การค้นหาคำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่
- `|cidr`: ตรวจสอบว่าค่าฟิลด์ตรงกับสัญกรณ์ CIDR ของ IPv4 หรือ IPv6 หรือไม่ (ตัวอย่าง: `192.0.2.0/24`)
- `|contains`: ตรวจสอบว่าค่าฟิลด์มีสตริงที่กำหนดหรือไม่
- `|contains|all`: ตรวจสอบว่ามีหลายคำอยู่ในข้อมูลหรือไม่
- `|contains|all|windash`: เหมือนกับ `|contains|windash` แต่คีย์เวิร์ดทั้งหมดต้องมีอยู่
- `|contains|cased`: ตรวจสอบว่าค่าฟิลด์มีสตริงที่กำหนดซึ่งคำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่หรือไม่
- `|contains|expand`: ตรวจสอบว่าค่าฟิลด์มีสตริงในไฟล์ config `expand` ภายใน `/config/expand/` หรือไม่
- `|contains|windash`: จะตรวจสอบสตริงตามที่เป็นอยู่ รวมถึงแปลงอักขระ `-` ตัวแรกเป็นรูปแบบผสมของอักขระ `/`, `–` (en dash), `—` (em dash) และ `―` (horizontal bar)
- `|endswith`: ตรวจสอบว่าค่าฟิลด์ลงท้ายด้วยสตริงที่กำหนดหรือไม่
- `|endswith|cased`: ตรวจสอบว่าค่าฟิลด์ลงท้ายด้วยสตริงที่กำหนดซึ่งคำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่หรือไม่
- `|endswith|windash`: ตรวจสอบส่วนท้ายของสตริงและดำเนินการสร้างรูปแบบต่าง ๆ สำหรับ dash
- `|exists`: ตรวจสอบว่าฟิลด์มีอยู่หรือไม่
- `|expand`: ตรวจสอบว่าค่าฟิลด์เท่ากับสตริงในไฟล์ config `expand` ภายใน `/config/expand/` หรือไม่
- `|fieldref`: ตรวจสอบว่าค่าในสองฟิลด์เหมือนกันหรือไม่ คุณสามารถใช้ `not` ใน `condition` ได้หากต้องการตรวจสอบว่าสองฟิลด์แตกต่างกันหรือไม่
- `|fieldref|contains`: ตรวจสอบว่าค่าของฟิลด์หนึ่งมีอยู่ในอีกฟิลด์หนึ่งหรือไม่
- `|fieldref|endswith`: ตรวจสอบว่าฟิลด์ทางซ้ายลงท้ายด้วยสตริงของฟิลด์ทางขวาหรือไม่ คุณสามารถใช้ `not` ใน `condition` เพื่อตรวจสอบว่าทั้งสองแตกต่างกันหรือไม่
- `|fieldref|startswith`: ตรวจสอบว่าฟิลด์ทางซ้ายขึ้นต้นด้วยสตริงของฟิลด์ทางขวาหรือไม่ คุณสามารถใช้ `not` ใน `condition` เพื่อตรวจสอบว่าทั้งสองแตกต่างกันหรือไม่
- `|gt`: ตรวจสอบว่าค่าฟิลด์มากกว่าตัวเลขที่กำหนดหรือไม่
- `|gte`: ตรวจสอบว่าค่าฟิลด์มากกว่าหรือเท่ากับตัวเลขที่กำหนดหรือไม่
- `|lt`: ตรวจสอบว่าค่าฟิลด์น้อยกว่าตัวเลขที่กำหนดหรือไม่
- `|lte`: ตรวจสอบว่าค่าฟิลด์น้อยกว่าหรือเท่ากับตัวเลขที่กำหนดหรือไม่
- `|re`: ใช้นิพจน์ทั่วไป (regular expression) ที่คำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่ (เราใช้ regex crate ดังนั้นโปรดดูเอกสารที่ <https://docs.rs/regex/latest/regex/#syntax> เพื่อเรียนรู้วิธีเขียนนิพจน์ทั่วไปที่รองรับ)
    > ข้อควรระวัง: [ไวยากรณ์นิพจน์ทั่วไปในกฎ Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) ใช้ PCRE โดยมี metacharacter บางตัวสำหรับ character class, lookbehind, atomic grouping ฯลฯ ที่ไม่รองรับ Rust regex crate ควรจะสามารถใช้นิพจน์ทั่วไปทั้งหมดในกฎ Sigma ได้ แต่มีความเป็นไปได้ที่จะเกิดความไม่เข้ากัน
- `|re|i`: (Insensitive) ใช้นิพจน์ทั่วไปที่ไม่คำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่
- `|re|m`: (Multi-line) จับคู่ข้ามหลายบรรทัด `^` / `$` จับคู่จุดเริ่มต้น/สิ้นสุดของบรรทัด
- `|re|s`: (Single-line) จุด (`.`) จับคู่อักขระทั้งหมด รวมถึงอักขระขึ้นบรรทัดใหม่
- `|startswith`: ตรวจสอบว่าค่าฟิลด์ขึ้นต้นด้วยสตริงที่กำหนดหรือไม่
- `|startswith|cased`: ตรวจสอบว่าค่าฟิลด์ขึ้นต้นด้วยสตริงที่กำหนดซึ่งคำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่หรือไม่
- `|utf16|base64offset|contains`: ตรวจสอบว่าสตริง UTF-16 ที่กำหนดถูกเข้ารหัสอยู่ภายในสตริง base64 หรือไม่
- `|utf16be|base64offset|contains`: ตรวจสอบว่าสตริง UTF-16 แบบ big-endian ที่กำหนดถูกเข้ารหัสอยู่ภายในสตริง base64 หรือไม่
- `|utf16le|base64offset|contains`: ตรวจสอบว่าสตริง UTF-16 แบบ little-endian ที่กำหนดถูกเข้ารหัสอยู่ภายในสตริง base64 หรือไม่
- `|wide|base64offset|contains`: นามแฝงสำหรับ `utf16le|base64offset|contains` ตรวจสอบสตริง UTF-16 แบบ little-endian

### ตัวปรับแต่งฟิลด์ที่เลิกใช้แล้ว

ตัวปรับแต่งต่อไปนี้ตอนนี้เลิกใช้แล้วและถูกแทนที่ด้วยตัวปรับแต่งที่ยึดตามข้อกำหนดของ sigma มากขึ้น

- `|equalsfield`: ตอนนี้ถูกแทนที่ด้วย `|fieldref`
- `|endswithfield`: ตอนนี้ถูกแทนที่ด้วย `|fieldref|endswith`

### ตัวปรับแต่งฟิลด์ Expand

ตัวปรับแต่งฟิลด์ `expand` มีลักษณะเฉพาะตรงที่เป็นตัวปรับแต่งฟิลด์เพียงตัวเดียวที่ต้องมีการกำหนดค่าล่วงหน้าก่อนใช้งาน
ตัวอย่างเช่น มันใช้ตัวยึดตำแหน่ง (placeholder) เช่น `%DC-MACHINE-NAME%` และต้องการไฟล์ config ชื่อ `/config/expand/DC-MACHINE-NAME.txt` ที่มีชื่อเครื่อง DC ที่เป็นไปได้ทั้งหมด

วิธีกำหนดค่านี้อธิบายไว้โดยละเอียดมากขึ้น[ที่นี่](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command)

## Wildcards

สามารถใช้ wildcard ใน eventkey ได้ ในตัวอย่างด้านล่าง หาก `ProcessCommandLine` ขึ้นต้นด้วยสตริง "malware" กฎจะตรงกัน
ข้อกำหนดนี้พื้นฐานเหมือนกับ wildcard ของกฎ sigma ดังนั้นจึงไม่คำนึงถึงตัวพิมพ์เล็กพิมพ์ใหญ่

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

สามารถใช้ wildcard สองตัวต่อไปนี้ได้
- `*`: จับคู่สตริงใด ๆ ที่มีอักขระศูนย์ตัวหรือมากกว่า (ภายในจะถูกแปลงเป็นนิพจน์ทั่วไป `.*`)
- `?`: จับคู่อักขระเดี่ยวใด ๆ (ภายในจะถูกแปลงเป็นนิพจน์ทั่วไป `.`)

เกี่ยวกับการ escape wildcard:
- wildcard (`*` และ `?`) สามารถ escape ได้โดยใช้ backslash: `\*`, `\?`
- หากคุณต้องการใช้ backslash ก่อนหน้า wildcard ทันที ให้เขียน `\\*` หรือ `\\?`
- ไม่จำเป็นต้อง escape หากคุณใช้ backslash เพียงตัวเดียว

## คีย์เวิร์ด null

คีย์เวิร์ด `null` สามารถใช้เพื่อตรวจสอบว่าฟิลด์ไม่มีอยู่หรือไม่

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

หมายเหตุ: สิ่งนี้แตกต่างจาก `ProcessCommandLine: ''` ซึ่งตรวจสอบว่าค่าของฟิลด์ว่างเปล่าหรือไม่

## condition

ด้วยสัญกรณ์ที่เราอธิบายไว้ด้านบน คุณสามารถแสดงตรรกะ `AND` และ `OR` ได้ แต่มันจะสับสนหากคุณพยายามกำหนดตรรกะที่ซับซ้อน
เมื่อคุณต้องการสร้างกฎที่ซับซ้อนมากขึ้น คุณควรใช้คีย์เวิร์ด `condition` ดังที่แสดงด้านล่าง

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

นิพจน์ต่อไปนี้สามารถใช้สำหรับ `condition` ได้
- `{expression1} and {expression2}`: ต้องการทั้ง {expression1} AND {expression2}
- `{expression1} or {expression2}`: ต้องการ {expression1} OR {expression2} อย่างใดอย่างหนึ่ง
- `not {expression}`: กลับตรรกะของ {expression}
- `( {expression} )`: กำหนดลำดับความสำคัญของ {expression} โดยเป็นไปตามตรรกะลำดับความสำคัญเดียวกับในคณิตศาสตร์

ในตัวอย่างด้านบน ชื่อ selection เช่น `SELECTION_1`, `SELECTION_2` ฯลฯ ถูกนำมาใช้ แต่สามารถตั้งชื่อเป็นอะไรก็ได้ตราบเท่าที่มีเพียงอักขระต่อไปนี้: `a-z A-Z 0-9 _`
> อย่างไรก็ตาม โปรดใช้แบบแผนมาตรฐานของ `selection_1`, `selection_2`, `filter_1`, `filter_2` ฯลฯ เพื่อให้อ่านง่ายเมื่อเป็นไปได้

## ตรรกะ not

กฎหลายข้อจะส่งผลให้เกิด false positive ดังนั้นจึงเป็นเรื่องปกติมากที่จะมี selection สำหรับลายเซ็นที่ต้องการค้นหา แต่ก็มี filter selection เพื่อไม่ให้แจ้งเตือนเกี่ยวกับ false positive ด้วย
ตัวอย่างเช่น:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma correlations

เราได้ใช้งาน Sigma เวอร์ชัน 2.0.0 correlation ทั้งหมดตามที่กำหนดไว้[ที่นี่](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md)

correlation ที่รองรับ:
- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

กฎ correlation แบบ "metrics" ใหม่ (`value_sum`, `value_avg`, `value_percentile`) ที่เปิดตัวเมื่อวันที่ 12 กันยายน 2025 ใน Sigma เวอร์ชัน 2.1.0 ปัจจุบันยังไม่รองรับ
