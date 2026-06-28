# การสร้างไฟล์กฎ (Creating Rule Files)

## เกี่ยวกับ Hayabusa-Rules

นี่คือ repository ที่บรรจุ sigma rules ที่ได้รับการคัดสรรมาเพื่อตรวจจับการโจมตีใน Windows event logs
ส่วนใหญ่ใช้สำหรับกฎการตรวจจับและไฟล์ config ของ [Hayabusa](https://github.com/Yamato-Security/hayabusa) รวมถึงการตรวจจับ sigma ในตัวของ [Velociraptor](https://github.com/Velocidex/velociraptor)
ข้อได้เปรียบของการใช้ repository นี้แทน [upstream sigma repository](https://github.com/SigmaHQ/sigma) คือเราจะรวมเฉพาะกฎที่เครื่องมือ sigma-native ส่วนใหญ่ควรจะ parse ได้เท่านั้น
นอกจากนี้เรายังลดความเป็นนามธรรมของฟิลด์ `logsource` โดยการเพิ่มฟิลด์ที่จำเป็น เช่น `Channel`, `EventID` ฯลฯ ลงในกฎ เพื่อให้เข้าใจได้ง่ายขึ้นว่ากฎกำลังกรองอะไรอยู่ และที่สำคัญกว่านั้นคือเพื่อลด false positives
เรายังสร้างกฎใหม่ที่มีการแปลงชื่อฟิลด์และค่าต่าง ๆ สำหรับกฎ `process_creation` และกฎที่อิงตาม `registry` เพื่อให้ sigma rules ไม่เพียงตรวจจับบน Sysmon logs เท่านั้น แต่ยังตรวจจับบน Windows logs ในตัวได้ด้วย

## เกี่ยวกับการสร้างไฟล์กฎ

กฎการตรวจจับของ Hayabusa เขียนในรูปแบบ [YAML](https://en.wikipedia.org/wiki/YAML) โดยมีนามสกุลไฟล์เป็น `.yml` (ไฟล์ `.yaml` จะถูกละเว้น)
กฎเหล่านี้เป็นชุดย่อยของ sigma rules แต่ก็มีคุณสมบัติเพิ่มเติมบางอย่างด้วย
เราพยายามทำให้กฎเหล่านี้ใกล้เคียงกับ sigma rules มากที่สุดเท่าที่จะเป็นไปได้ เพื่อให้แปลงกฎ Hayabusa กลับเป็น sigma เพื่อตอบแทนชุมชนได้ง่าย
กฎ Hayabusa สามารถแสดงกฎการตรวจจับที่ซับซ้อนได้โดยการรวมไม่เพียงแค่การจับคู่สตริงแบบง่าย ๆ เท่านั้น แต่ยังรวมถึงนิพจน์ปกติ (regular expressions), เงื่อนไข `AND`, `OR` และเงื่อนไขอื่น ๆ
ในส่วนนี้ เราจะอธิบายวิธีการเขียนกฎการตรวจจับของ Hayabusa

### รูปแบบไฟล์กฎ

ตัวอย่าง:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## ส่วน Author

- **author [required]**: ชื่อของผู้เขียน
- **date [required]**: วันที่สร้างกฎ
- **modified** [optional]: วันที่อัปเดตกฎ

> ## ส่วน Alert

- **title [required]**: ชื่อของไฟล์กฎ นี่จะเป็นชื่อของ alert ที่แสดงด้วย ดังนั้นยิ่งกระชับยิ่งดี (ไม่ควรยาวเกิน 85 ตัวอักษร)
- **details** [optional]: รายละเอียดของ alert ที่แสดงผล โปรดแสดงฟิลด์ใด ๆ ใน Windows event log ที่เป็นประโยชน์ต่อการวิเคราะห์ ฟิลด์ต่าง ๆ คั่นด้วย `" ¦ "` ตัวแทนของฟิลด์ (placeholder) จะถูกล้อมด้วย `%` (ตัวอย่าง: `%MemberName%`) และต้องถูกกำหนดไว้ใน `rules/config/eventkey_alias.txt` (อธิบายด้านล่าง)
- **description** [optional]: คำอธิบายของกฎ ส่วนนี้ไม่ได้แสดงผล ดังนั้นคุณสามารถเขียนให้ยาวและละเอียดได้

> ## ส่วน Rule

- **id [required]**: UUID เวอร์ชัน 4 ที่สร้างขึ้นแบบสุ่ม ใช้เพื่อระบุกฎอย่างไม่ซ้ำกัน คุณสามารถสร้างได้ [ที่นี่](https://www.uuidgenerator.net/version4)
- **level [required]**: ระดับความรุนแรงตาม [นิยามของ sigma](https://github.com/SigmaHQ/sigma/wiki/Specification) โปรดเขียนหนึ่งในค่าต่อไปนี้: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: สถานะตาม [นิยามของ sigma](https://github.com/SigmaHQ/sigma/wiki/Specification) โปรดเขียนหนึ่งในค่าต่อไปนี้: `deprecated`, `experimental`, `test`, `stable`
- **logsource [required]**: แม้ว่าปัจจุบัน Hayabusa จะยังไม่ได้ใช้ค่านี้จริง ๆ แต่เราก็กำหนด logsource ในลักษณะเดียวกับ sigma เพื่อให้เข้ากันได้กับ sigma rules
- **detection  [required]**: ตรรกะการตรวจจับอยู่ตรงนี้ (อธิบายด้านล่าง)
- **falsepositives [required]**: ความเป็นไปได้ที่จะเกิด false positives ตัวอย่างเช่น: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none` หากไม่ทราบ โปรดเขียน `unknown`
- **tags** [optional]: หากเทคนิคเป็นเทคนิค [LOLBINS/LOLBAS](https://lolbas-project.github.io/) โปรดเพิ่มแท็ก `lolbas` หาก alert สามารถจับคู่กับเทคนิคในเฟรมเวิร์ก [MITRE ATT&CK](https://attack.mitre.org/) ได้ โปรดเพิ่ม tactic ID (ตัวอย่าง: `attack.t1098`) และ tactics ที่เกี่ยวข้องด้านล่าง:
  - `attack.reconnaissance` -> Reconnaissance (Recon)
  - `attack.resource-development` -> Resource Development  (ResDev)
  - `attack.initial-access` -> Initial Access (InitAccess)
  - `attack.execution` -> Execution (Exec)
  - `attack.persistence` -> Persistence (Persis)
  - `attack.privilege-escalation` -> Privilege Escalation (PrivEsc)
  - `attack.stealth` -> Stealth (Stealth)
  - `attack.defense-impairment` -> Defense Impairment (DefImpair)
  - `attack.credential-access` -> Credential Access (CredAccess)
  - `attack.discovery` -> Discovery (Disc)
  - `attack.lateral-movement` -> Lateral Movement (LatMov)
  - `attack.collection` -> Collection (Collect)
  - `attack.command-and-control` -> Command and Control (C2)
  - `attack.exfiltration` -> Exfiltration (Exfil)
  - `attack.impact` -> Impact (Impact)
- **references** [optional]: ลิงก์ใด ๆ ไปยังเอกสารอ้างอิง
- **ruletype [required]**: `Hayabusa` สำหรับกฎ hayabusa กฎที่แปลงโดยอัตโนมัติจาก sigma Windows rules จะเป็น `Sigma`

> ## Sample XML Event

- **sample-message [required]**: ตั้งแต่นี้ต่อไป เราขอให้ผู้เขียนกฎใส่ตัวอย่างข้อความสำหรับกฎของตน นี่คือข้อความที่ Event Viewer ของ Windows แสดงผล
- **sample-evtx [required]**: ตั้งแต่นี้ต่อไป เราขอให้ผู้เขียนกฎใส่ตัวอย่าง XML events สำหรับกฎของตน
