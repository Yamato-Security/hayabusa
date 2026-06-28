# คำแนะนำในการสร้างกฎ

## คำแนะนำในการสร้างกฎ

1. **เมื่อเป็นไปได้ ให้ระบุชื่อ `Channel` หรือ `ProviderName` และหมายเลข `EventID` เสมอ** โดยค่าเริ่มต้น จะมีการสแกนเฉพาะ event ID ที่ระบุไว้ใน `./rules/config/target_event_IDs.txt` เท่านั้น ดังนั้นคุณอาจต้องเพิ่มหมายเลข `EventID` ใหม่ลงในไฟล์นี้หาก EID นั้นยังไม่มีอยู่ในนั้น

2. **โปรดอย่าใช้ฟิลด์ `selection` หรือ `filter` หลายฟิลด์และการจัดกลุ่มที่มากเกินไปเมื่อไม่จำเป็น** ตัวอย่างเช่น:

#### แทนที่จะเป็นแบบนี้

```yaml
detection:
    SELECTION_1:
        Channnel: Security
    SELECTION_2:
        EventID: 4625
    SELECTION_3:
        LogonType: 3
    FILTER_1:
        SubStatus: "0xc0000064"   #Non-existent user
    FILTER_2:
        SubStatus: "0xc000006a"   #Wrong password
    condition: SELECTION_1 and SELECTION_2 and SELECTION_3 and not (FILTER_1 or FILTER_2)
```

#### โปรดทำแบบนี้

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        - SubStatus: "0xc0000064"   #Non-existent user
        - SubStatus: "0xc000006a"   #Wrong password
    condition: selection and not filter
```

3. **เมื่อคุณต้องการหลายส่วน (section) โปรดตั้งชื่อส่วนแรกด้วยข้อมูล channel และ event ID ในส่วน `section_basic` และตั้งชื่อ selection อื่น ๆ ด้วยชื่อที่มีความหมายตามหลัง `section_` และ `filter_` นอกจากนี้ โปรดเขียนคอมเมนต์เพื่ออธิบายสิ่งใดก็ตามที่เข้าใจได้ยาก** ตัวอย่างเช่น:

#### แทนที่จะเป็นแบบนี้

```yaml
detection:
    Takoyaki:
        Channel: Security
        EventID: 4648
    Naruto:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    Sushi:
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    Godzilla:
        SubjectUserName|endswith: "$"
    Ninja:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$"
        IpAddress: "-"
    Daisuki:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: Takoyaki and Daisuki and not (Naruto and not Godzilla) and not Ninja and not Sushi
```

#### โปรดทำแบบนี้

```yaml
detection:
    selection_basic:
        Channel: Security
        EventID: 4648
    selection_TargetUserIsComputerAccount:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    filter_UsersAndTargetServerAreComputerAccounts:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_SubjectUserIsComputerAccount:
        SubjectUserName|endswith: "$"
    filter_SystemAccounts:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_SuspiciousProcess:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_basic and selection_SuspiciousProcess and not (selection_TargetUserIsComputerAccount
               and not filter_SubjectUserIsComputerAccount) and not filter_SystemAccounts and not filter_UsersAndTargetServerAreComputerAccounts
```

## การแปลงกฎ Sigma เป็นรูปแบบ Hayabusa

เราได้สร้าง backend สำหรับแปลงกฎจาก Sigma เป็นรูปแบบที่เข้ากันได้กับ Hayabusa [ที่นี่](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)
