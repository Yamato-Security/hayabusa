# การคัดสรรกฎ Sigma สำหรับ Windows Event Log

หน้านี้อธิบายวิธีที่ Yamato Security คัดสรรกฎ [Sigma](https://github.com/SigmaHQ/sigma) ต้นทาง (upstream) สำหรับ Windows event log ให้อยู่ในรูปแบบที่ใช้งานได้สะดวกยิ่งขึ้น โดยการลดการทำ abstraction ของฟิลด์ `logsource` และคัดกรองกฎที่ใช้งานไม่ได้หรือใช้งานได้ยากออกไป การดำเนินการนี้ทำผ่านเครื่องมือ [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) ซึ่งใช้เป็นหลักในการสร้างชุดกฎ Sigma ที่คัดสรรแล้วซึ่งโฮสต์อยู่ใน [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) ชุดกฎดังกล่าวถูกใช้งานโดย [Hayabusa](https://github.com/Yamato-Security/hayabusa) และ [Velociraptor](https://github.com/Velocidex/velociraptor)

!!! info "แหล่งที่มา"
    เอกสารนี้ได้รับการดูแลควบคู่ไปกับเครื่องมือ converter ที่ [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) เราหวังว่าข้อมูลนี้จะเป็นประโยชน์ต่อโปรเจกต์อื่น ๆ ที่ต้องการใช้กฎ Sigma เพื่อตรวจจับการโจมตีใน Windows event log ด้วยเช่นกัน ดูเพิ่มเติมที่ [การสร้างไฟล์กฎ](creating-rules.md) และ [ตัวปรับแต่งฟิลด์](field-modifiers.md)

## สรุปโดยย่อ

* การลดการทำ abstraction ของฟิลด์ `logsource` และการสร้างไฟล์กฎ `.yml` ใหม่สำหรับกฎแบบ built-in ควบคู่ไปกับกฎดั้งเดิมที่อ้างอิงกับ Sysmon ทำให้การรองรับเหตุการณ์ built-in อย่างเต็มรูปแบบสำหรับกฎ Sigma ทำได้ง่ายขึ้น และทำให้นักวิเคราะห์อ่านกฎได้ง่ายขึ้น
* เมื่อเขียนกฎ Sigma สำหรับ Windows event log สิ่งสำคัญคือต้องเข้าใจความแตกต่างระหว่างล็อกดั้งเดิมที่อ้างอิงกับ Sysmon และล็อก built-in ที่เข้ากันได้ และในทางที่ดีควรเขียนกฎให้เข้ากันได้กับทั้งสองแบบ
* หลายองค์กรไม่สามารถหรือไม่ต้องการติดตั้งและดูแล Sysmon agent บน Windows endpoint ทั้งหมดของตน เนื่องจากไม่มีทรัพยากรเฉพาะที่จะจัดการได้ หรือต้องการหลีกเลี่ยงความเสี่ยงจากการทำงานช้าลงหรือระบบล่มที่เกิดจาก Sysmon ด้วยเหตุนี้ จึงเป็นเรื่องสำคัญที่จะเปิดใช้งาน built-in event log ให้ได้มากที่สุดเท่าที่จะทำได้ และใช้เครื่องมือที่สามารถตรวจจับการโจมตีในล็อก built-in เหล่านั้น

## ความท้าทายของกฎ Sigma ต้นทางสำหรับ Windows event log

จากประสบการณ์ของเรา ความท้าทายหลักในการสร้าง parser ของกฎ Sigma แบบเนทีฟสำหรับ Windows event log คือการรองรับฟิลด์ `logsource` ปัจจุบันนี่เป็นหนึ่งในไม่กี่สิ่งที่ Hayabusa ยังไม่รองรับแบบเนทีฟ เนื่องจากยังคงมีความซับซ้อนมากและอยู่ระหว่างการพัฒนา ในระหว่างนี้ เราแก้ปัญหาชั่วคราวด้วยการแปลงกฎต้นทางให้อยู่ในรูปแบบที่ใช้งานง่ายขึ้น ตามที่อธิบายโดยละเอียดด้านล่าง

### เกี่ยวกับฟิลด์ `logsource`

ในกฎ Sigma สำหรับ Windows event log ฟิลด์ `product` จะถูกกำหนดเป็น `windows` ตามด้วยฟิลด์ `service` หรือฟิลด์ `category`

ตัวอย่างฟิลด์ `service`:

```yaml
logsource:
    product: windows
    service: application
```

ตัวอย่างฟิลด์ `category`:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### ฟิลด์ Service

ฟิลด์ `service` จัดการได้ค่อนข้างง่าย และบอกให้ backend ใดก็ตามที่ใช้กฎ Sigma ค้นหาแชนเนลเดียวหรือหลายแชนเนลโดยอ้างอิงจากฟิลด์ `Channel` ใน Windows XML event log

**ตัวอย่างแชนเนลเดียว**

`service: application` มีความหมายเดียวกันกับการเพิ่มเงื่อนไข selection ว่า `Channel: Application` เข้าไปในกฎ Sigma

**ตัวอย่างหลายแชนเนล**

ปัจจุบัน `service: applocker` สร้างแชนเนลให้ต้องค้นหามากที่สุด เนื่องจาก AppLocker บันทึกข้อมูลไว้ในล็อกสี่แบบที่แตกต่างกัน เพื่อค้นหาเฉพาะล็อกของ AppLocker ได้อย่างถูกต้อง จำเป็นต้องเพิ่มเงื่อนไขต่อไปนี้เข้าไปในลอจิกของกฎ Sigma:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**รายการ mapping ของ service ในปัจจุบัน**

| บริการ                                     | แชนเนล                                                                                                                              |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**แหล่งที่มาของ mapping สำหรับ service**

เราได้สร้างไฟล์ mapping แบบ YAML สำหรับแมป service ไปยังชื่อ channel ซึ่งเราดูแลรักษาเป็นระยะ ๆ และโฮสต์ไว้ใน repository ของ converter ไฟล์เหล่านี้อ้างอิงจากข้อมูล mapping ของ service จาก [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml): แม้ว่าไฟล์นี้ดูเหมือนจะไม่ใช่ไฟล์ config แบบ generic อย่างเป็นทางการสำหรับให้ผู้คนนำไปใช้ แต่ก็ดูเหมือนจะเป็นไฟล์ที่มีความเป็นปัจจุบันมากที่สุด

#### ฟิลด์ Category

ฟิลด์ `category` ส่วนใหญ่เพียงแค่เพิ่มเงื่อนไขเพื่อตรวจสอบ event ID บางค่าในฟิลด์ `EventID` เพิ่มเติมจากการค้นหา `Channel` ที่ระบุ ชื่อของหมวดหมู่ส่วนใหญ่อ้างอิงจากเหตุการณ์ของ [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) โดยมีหมวดหมู่เพิ่มเติมบางส่วนสำหรับล็อก PowerShell แบบ built-in และ Windows Defender

**ตัวอย่างฟิลด์ category**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**รายการ mapping ของ category ในปัจจุบัน**

บางหมวดหมู่แมปไปยังมากกว่าหนึ่ง service/EventID (แสดงด้วย **ตัวหนา**)

| หมวดหมู่                  | บริการ             | Event ID                                                              |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**ความท้าทายของฟิลด์ category**

ดังที่แสดงไว้ข้างต้น `category` เดียวกันสามารถใช้ได้กับหลาย service และหลาย event ID (ระบุด้วย **ตัวหนา**) นั่นหมายความว่าเป็นไปได้ที่จะใช้กฎ Sigma บางส่วนที่ออกแบบมาสำหรับ `sysmon` กับ Windows `security` event log แบบ built-in ที่คล้ายกัน หากฟิลด์ที่กฎใช้นั้นมีอยู่ใน built-in event log ด้วย ในกรณีเช่นนั้น ชื่อฟิลด์ — และบางครั้งก็รวมถึงค่าด้วย — อาจจำเป็นต้องถูกแปลงให้ตรงกับชื่อฟิลด์และค่าของ `security` event log แบบ built-in แม้ว่าสำหรับบางหมวดหมู่การแปลงนี้อาจง่ายเพียงแค่การเปลี่ยนชื่อฟิลด์บางส่วน แต่สำหรับหมวดหมู่อื่น ๆ ก็อาจต้องมีการแปลงค่าฟิลด์ในหลากหลายรูปแบบด้วย วิธีที่เราทำการแปลงนี้ และความเข้ากันได้ระหว่างล็อก `sysmon` กับล็อก `security` ได้อธิบายไว้โดยละเอียด[ด้านล่าง](#sysmon-builtin-comparison)

**แหล่งที่มาของ mapping สำหรับ category**

ไฟล์ mapping แบบ YAML สำหรับ category ก็โฮสต์อยู่ใน repository ของ converter เช่นกัน และอ้างอิงจากข้อมูลใน [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) เช่นกัน

## ประโยชน์และความท้าทายของการทำ abstraction ให้กับ log source

การทำ abstraction ให้กับ log source และการสร้าง mapping สำหรับ `Channel`, `EventID` และฟิลด์ต่าง ๆ ที่ฝั่ง backend นั้นมีทั้งประโยชน์และความท้าทาย

### ประโยชน์

1. อาจแปลงชื่อฟิลด์ `Channel` และ `EventID` ให้เป็นชื่อฟิลด์ที่ถูกต้องของ backend ได้ง่ายขึ้น เมื่อแปลงกฎ Sigma ไปเป็น query ของ backend อื่น ๆ
2. เป็นไปได้ที่จะรวมสองกฎเข้าเป็นกฎเดียว ตัวอย่างเช่น เหตุการณ์การสร้างโปรเซสสามารถถูกบันทึกได้ทั้งใน `Sysmon 1` และ `Security 4688` แทนที่จะเขียนสองกฎที่ดูแชนเนล event ID และฟิลด์ที่ต่างกัน แต่มีลอจิกที่เหมือนกันในส่วนที่เหลือ ก็สามารถทำให้ฟิลด์เป็นมาตรฐานตามที่ Sysmon ใช้ แล้วให้ backend converter เพิ่มฟิลด์ `Channel` และ `EventID` เข้าไป และแปลงข้อมูลฟิลด์อื่น ๆ หากจำเป็น วิธีนี้ทำให้การดูแลรักษากฎง่ายขึ้น เนื่องจากมีกฎที่ต้องดูแลน้อยลง
3. แม้จะเกิดขึ้นได้ยากมาก แต่หาก log source เริ่มบันทึกข้อมูลใน `Channel` หรือ `EventID` ที่ต่างออกไป ก็เพียงแค่ต้องอัปเดตลอจิกของ mapping เท่านั้น แทนที่จะต้องอัปเดตกฎ Sigma ทั้งหมด ทำให้การดูแลรักษาง่ายขึ้น

### ความท้าทาย

1. จะเกิดอะไรขึ้นหากกฎ Sigma ดั้งเดิมที่อ้างอิงกับ Sysmon ใช้ฟิลด์ที่ไม่มีอยู่ในล็อก built-in เพื่อคัดกรอง false positive ออกไป? คุณควรสร้างกฎนั้นต่อไปโดยให้ความสำคัญกับการตรวจจับที่เป็นไปได้ หรือควรละเว้นเพื่อให้ความสำคัญกับการมี false positive ที่น้อยลง? ในทางที่ดี ควรสร้างสองกฎที่มี `severity`, `status` และข้อมูล false positive ที่ต่างกัน เพื่อให้ผู้ใช้จัดการได้ดียิ่งขึ้น
2. ทำให้การคัดกรองกฎยากขึ้น เนื่องจากคุณไม่สามารถคัดกรองโดยอ้างอิงเพียงฟิลด์ `Channel` หรือ `EventID` ในไฟล์ `.yml` หรือเส้นทางไฟล์ของกฎได้ หากยังไม่ได้สร้างไฟล์นั้นขึ้นมา — เพราะมันเป็นกฎที่ได้มา (derived) สำหรับล็อก built-in แทนที่จะเป็นกฎ Sysmon ดั้งเดิม นอกจากนี้ เนื่องจาก rule ID เหมือนกัน คุณจึงไม่สามารถคัดกรองด้วย rule ID ได้
3. ทำให้การยืนยันการแจ้งเตือน (alert) ยากขึ้นเมื่อการแจ้งเตือนมาจากกฎสำหรับล็อก built-in ที่ได้มาจากล็อก Sysmon ชื่อฟิลด์และค่าจะไม่ตรงกัน ดังนั้นนักวิเคราะห์จึงจำเป็นต้องเข้าใจกระบวนการแปลงที่ค่อนข้างซับซ้อน
4. ทำให้การสร้างลอจิกฝั่ง backend ซับซ้อนยิ่งขึ้น

แม้ว่าเราจะไม่สามารถทำอะไรกับปัญหาข้อแรกได้นอกจากสร้างและดูแลกฎใหม่เมื่อมีกรณีการใช้งานที่สำคัญมากพอที่จะคุ้มค่ากับความพยายาม แต่เพื่อจัดการกับปัญหาข้อ 2–4 เราได้ตัดสินใจลดการทำ abstraction ของฟิลด์ `logsource` และสร้างกฎสองชุดสำหรับกฎใดก็ตามที่สามารถสร้างออกมาได้หลายกฎ กฎที่สามารถตรวจจับการโจมตีในล็อก built-in จะถูกส่งออกไปยังไดเรกทอรี `builtin` และกฎสำหรับ Sysmon จะถูกส่งออกไปยังไดเรกทอรี `sysmon`

## ตัวอย่างการแปลง

ต่อไปนี้เป็นตัวอย่างง่าย ๆ เพื่อให้เข้าใจกระบวนการแปลงได้ดียิ่งขึ้น

**ก่อนการแปลง** — กฎ Sigma ดั้งเดิม:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**หลังการแปลง** — กฎที่เข้ากันได้กับ Hayabusa สำหรับล็อก Sysmon:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

...และกฎที่เข้ากันได้กับ Hayabusa สำหรับล็อก built-in ของ Windows:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

อย่างที่เห็น มีการสร้างสองกฎ: กฎหนึ่งสำหรับล็อก Sysmon 1 และอีกกฎหนึ่งสำหรับล็อก Security 4688 แบบ built-in มีการเพิ่มเงื่อนไข `process_creation` ใหม่พร้อมข้อมูล channel และ event ID และมีการเพิ่มเงื่อนไขนี้เข้าไปในฟิลด์ `condition` เพื่อกำหนดให้ต้องเป็นไปตามเงื่อนไขนี้ นอกจากนี้ ชื่อฟิลด์ `Image` ดั้งเดิมได้ถูกเปลี่ยนเป็น `NewProcessName`

## สิ่งที่เหมือนกันในการแปลง

ก่อนที่จะอธิบายโดยละเอียดว่าเราแปลงหมวดหมู่ที่เฉพาะเจาะจงอย่างไร ต่อไปนี้เป็นส่วนของการแปลงที่ใช้กับกฎทั้งหมด

1. กฎใดก็ตามที่มี ID อยู่ใน `ignore-uuid-list.txt` จะถูกละเว้น ปัจจุบันเราละเว้นเฉพาะกฎที่ทำให้เกิด false positive กับ Windows Defender เนื่องจากมีคีย์เวิร์ดอย่าง `mimikatz` อยู่ในกฎ
2. กฎแบบ "Placeholder" จะถูกละเว้นเนื่องจากไม่สามารถใช้งานได้ในทันที กฎเหล่านี้คือกฎที่อยู่ในโฟลเดอร์ [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) ใน repository ของ Sigma
3. กฎที่ใช้ field modifier ที่เข้ากันไม่ได้จะถูกตัดออก Hayabusa รองรับ field modifier ส่วนใหญ่ ดังนั้น converter จะไม่ส่งออกกฎใด ๆ ที่ใช้ modifier นอกเหนือจากรายการต่อไปนี้ เพื่อหลีกเลี่ยงข้อผิดพลาดในการ parse (ดู [ตัวปรับแต่งฟิลด์](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. กฎที่มีข้อผิดพลาดทางไวยากรณ์ (syntax error) จะไม่ถูกแปลง
5. แท็กในกฎที่เป็น `deprecated` และ `unsupported` จะถูกอัปเดตจากรูปแบบ V1 ไปเป็นรูปแบบ V2 ซึ่งใช้ `-` แทน `_` เพื่อให้ทุกอย่างสอดคล้องกันและเพื่อจัดการกับคำย่อใน Hayabusa ได้ง่ายขึ้น ตัวอย่าง: `initial_access` จะกลายเป็น `initial-access`
6. เนื่องจากเรากำลังเพิ่มข้อมูล `Channel` และ `EventID` เข้าไปในกฎ เราจึงสร้าง ID แบบ UUIDv4 ใหม่โดยใช้ค่า MD5 hash ของ ID ดั้งเดิม ระบุ ID ดั้งเดิมไว้ในฟิลด์ `related` และกำหนด `type` เป็น `derived` สำหรับกฎที่สามารถแปลงออกมาได้หลายกฎ (`sysmon` และ `builtin`) เราจำเป็นต้องสร้าง rule ID ใหม่สำหรับกฎ `builtin` ที่ได้มา (derived) ด้วยเช่นกัน ในการทำเช่นนี้ เราจะคำนวณค่า MD5 hash ของ rule ID ของ `sysmon` แล้วนำมาใช้เป็น ID แบบ UUIDv4 ตัวอย่างเช่น:

    กฎ Sigma ดั้งเดิม:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    กฎ `sysmon` ใหม่:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    กฎ `builtin` ใหม่:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. กฎที่ตรวจจับสิ่งต่าง ๆ ใน Windows event log แบบ built-in จะถูกส่งออกไปยังไดเรกทอรี `builtin` ในขณะที่กฎที่อาศัยล็อก Sysmon จะถูกส่งออกไปยังไดเรกทอรี `sysmon` โดยมีไดเรกทอรีย่อยที่ตรงกับไดเรกทอรีใน repository ของ Sigma ต้นทาง

## ข้อจำกัดของการแปลง

ในขณะนี้มี[บั๊กที่ทราบแล้ว](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2)เพียงหนึ่งอย่างเท่านั้น: บรรทัดคอมเมนต์ในกฎ Sigma จะไม่ถูกรวมเข้าไปในกฎที่ส่งออก เว้นแต่คอมเมนต์นั้นจะตามหลังซอร์สโค้ดบางอย่าง

## Sysmon และการเปรียบเทียบเหตุการณ์ built-in และการแปลงกฎ { #sysmon-builtin-comparison }

### การสร้างโปรเซส (Process creation)

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Built-in log
    * Channel: `Security`
    * Event ID: `4688`

**การเปรียบเทียบ**

![การเปรียบเทียบการสร้างโปรเซส](../assets/rules-doc/process_creation_comparison.png)

**หมายเหตุในการแปลง**

1. ข้อมูลของฟิลด์ `User` จำเป็นต้องถูกแยกออกเป็นฟิลด์ `SubjectUserName` และ `SubjectDomainName`
2. ชื่อฟิลด์ `LogonId` เปลี่ยนเป็น `SubjectLogonId` และตัวอักษรใด ๆ ในค่าเลขฐานสิบหก (hex) จำเป็นต้องเป็นตัวพิมพ์เล็ก
3. ชื่อฟิลด์ `ProcessId` เปลี่ยนเป็น `NewProcessId` และค่าจำเป็นต้องถูกแปลงเป็นเลขฐานสิบหก (hex)
4. ชื่อฟิลด์ `Image` เปลี่ยนเป็น `NewProcessName`
5. ชื่อฟิลด์ `ParentProcessId` เปลี่ยนเป็น `ProcessId` และค่าจำเป็นต้องถูกแปลงเป็นเลขฐานสิบหก (hex)
6. ชื่อฟิลด์ `ParentImage` เปลี่ยนเป็น `ParentProcessName`
7. ชื่อฟิลด์ `IntegrityLevel` เปลี่ยนเป็น `MandatoryLabel` และจำเป็นต้องมีการแปลงค่าดังต่อไปนี้:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. หากกฎมีฟิลด์ต่อไปนี้ที่มีอยู่เฉพาะในเหตุการณ์ `Security 4688` เท่านั้น เราจะไม่สร้างกฎ `Sysmon 1`:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. หากกฎมีฟิลด์ต่อไปนี้ที่มีอยู่เฉพาะในเหตุการณ์ `Sysmon 1` เท่านั้น เราจะไม่สร้างกฎ `Security 4688`:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. มีข้อยกเว้นสำหรับข้อ #8 และ #9: แม้ว่าจะมีการใช้ฟิลด์ที่มีอยู่เฉพาะในเหตุการณ์ล็อกแบบเดียวเท่านั้น หากฟิลด์นั้นอยู่ในเงื่อนไข `OR` คุณก็ยังควรสร้างกฎนั้น ตัวอย่างเช่น กฎต่อไปนี้**ไม่ควร**สร้างกฎ `Security 4688` เนื่องจากฟิลด์ `OriginalFileName` เป็นสิ่งที่จำเป็น (ลอจิก `AND` ภายใน selection):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    อย่างไรก็ตาม กฎที่มีเงื่อนไขต่อไปนี้**ควร**สร้างกฎ `Security 4688` เนื่องจาก `OriginalFileName` เป็นตัวเลือก (ลอจิก `OR` ภายใน selection):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    สิ่งที่ยากขึ้นก็คือ parser ของคุณจะต้องเข้าใจไม่เพียงแค่ลอจิกภายใน selection เท่านั้น แต่รวมถึงลอจิกภายในฟิลด์ `condition` ด้วย ตัวอย่างเช่น กฎต่อไปนี้**ไม่ควร**สร้างกฎ `Security 4688` เนื่องจากใช้ลอจิก `AND`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    อย่างไรก็ตาม กฎต่อไปนี้**ควร**สร้างกฎ `Security 4688` เนื่องจากใช้ลอจิก `OR`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**หมายเหตุอื่น ๆ**

* ฟิลด์ `SubjectUserSid` ใน `Security 4688` จะแสดง SID อย่างไรก็ตาม ใน `Message` ของ event log ที่ถูกเรนเดอร์ออกมา มันจะถูกแปลงเป็น `DOMAIN\User`
* เหตุการณ์ `Security 4688` อาจไม่มีข้อมูลออปชันของ command line ในฟิลด์ `CommandLine` ขึ้นอยู่กับการตั้งค่า
* `TokenElevationType` จะแสดงตามเดิมใน `Message` และไม่ถูกเรนเดอร์
* `S-1-16-4096` และค่าอื่น ๆ ภายใน `MandatoryLabel` จะถูกแปลงเป็น `Mandatory Label\Low Mandatory Level` และอื่น ๆ ใน `Message` ที่ถูกเรนเดอร์

**การตั้งค่าล็อก built-in**

!!! warning "ไม่ได้เปิดใช้งานโดยค่าเริ่มต้น"
    ล็อกเหตุการณ์การสร้างโปรเซส `Security 4688` แบบ built-in ที่สำคัญนั้นไม่ได้เปิดใช้งานโดยค่าเริ่มต้น คุณจำเป็นต้องเปิดใช้งานทั้งเหตุการณ์ `4688` และการบันทึกออปชันของ command line เพื่อให้สามารถใช้กฎ Sigma ส่วนใหญ่ได้

*การเปิดใช้งานด้วย group policy:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*การเปิดใช้งานผ่าน command line:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### การเชื่อมต่อเครือข่าย (Network connection)

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Built-in log
    * Channel: `Security`
    * Event ID: `5156`

**การเปรียบเทียบ**

![การเปรียบเทียบการเชื่อมต่อเครือข่าย](../assets/rules-doc/network_connection_comparison.png)

**หมายเหตุในการแปลง**

1. ชื่อฟิลด์ `ProcessId` เปลี่ยนเป็น `ProcessID`
2. ชื่อฟิลด์ `Image` เปลี่ยนเป็น `Application` และ `C:\` เปลี่ยนเป็น `\device\harddiskvolume?\` (หมายเหตุ: เนื่องจากเราไม่ทราบหมายเลข volume ของฮาร์ดดิสก์ เราจึงแทนที่ด้วย wildcard อักขระเดียว `?`)
3. ค่าฟิลด์ `Protocol` จาก `tcp` เปลี่ยนเป็น `6` และ `udp` เปลี่ยนเป็น `17`
4. ชื่อฟิลด์ `Initiated` เปลี่ยนเป็น `Direction` และค่า `true` เปลี่ยนเป็น `%%14593` และ `false` เปลี่ยนเป็น `%%14592`
5. ชื่อฟิลด์ `SourceIp` เปลี่ยนเป็น `SourceAddress`
6. ชื่อฟิลด์ `DestinationIp` เปลี่ยนเป็น `DestAddress`
7. ชื่อฟิลด์ `DestinationPort` เปลี่ยนเป็น `DestPort`

**การตั้งค่าล็อก built-in**

!!! warning "ไม่ได้เปิดใช้งานโดยค่าเริ่มต้น"
    ล็อกการเชื่อมต่อเครือข่าย `Security 5156` แบบ built-in ไม่ได้เปิดใช้งานโดยค่าเริ่มต้น ล็อกเหล่านี้สร้างข้อมูลจำนวนมาก ซึ่งอาจเขียนทับล็อกสำคัญอื่น ๆ ใน `Security` event log และอาจทำให้ระบบทำงานช้าลงหากมีการเชื่อมต่อเครือข่ายจำนวนมาก ตรวจสอบให้แน่ใจว่าขนาดไฟล์สูงสุดของล็อก `Security` นั้นตั้งไว้สูง และทดสอบเพื่อให้แน่ใจว่าไม่มีผลกระทบในทางลบต่อระบบ

*การเปิดใช้งานด้วย group policy:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*การเปิดใช้งานผ่าน command line:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...หรือใช้คำสั่งต่อไปนี้หากคุณใช้ locale ที่ไม่ใช่ภาษาอังกฤษ:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "ดูเพิ่มเติม"
    สำหรับข้อมูลเพิ่มเติมเกี่ยวกับการเปิดใช้งาน Windows event log แบบ built-in ที่จำเป็นต่อการเก็บหลักฐานที่กฎเหล่านี้อาศัยอยู่ ดูที่ [Windows Logging & Sysmon](../resources/logging.md) และโปรเจกต์ [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings)

## คำแนะนำในการเขียนกฎ Sigma

!!! tip
    หากคุณใช้ฟิลด์ใด ๆ ที่มีอยู่ในล็อก `sysmon` แต่ไม่มีในล็อก `builtin` ควรทำให้ฟิลด์นั้นเป็นตัวเลือก (optional) เพื่อให้ยังสามารถใช้กฎนั้นกับล็อก `builtin` ได้

ตัวอย่างเช่น:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

selection นี้จะค้นหากรณีที่โปรเซส (`Image`) มีชื่อว่า `addinutil.exe` ปัญหาคือผู้โจมตีสามารถเพียงแค่เปลี่ยนชื่อไฟล์เพื่อหลบเลี่ยงกฎได้ ฟิลด์ `OriginalFileName` ซึ่งมีอยู่เฉพาะในล็อก Sysmon เท่านั้น คือชื่อไฟล์ที่ถูกฝังไว้ในไบนารีในเวลาคอมไพล์ แม้ว่าผู้โจมตีจะเปลี่ยนชื่อไฟล์ ชื่อที่ฝังไว้ก็จะไม่เปลี่ยนแปลง ดังนั้นกฎนี้จึงสามารถตรวจจับการโจมตีที่ผู้โจมตีเปลี่ยนชื่อไฟล์เมื่อใช้ Sysmon ได้ และยังสามารถตรวจจับการโจมตีที่ไม่มีการเปลี่ยนชื่อไฟล์เมื่อใช้ล็อก built-in มาตรฐานได้ด้วย

## กฎ Sigma ที่แปลงไว้ล่วงหน้า

กฎ Sigma ที่คัดสรรด้วยวิธีที่อธิบายไว้ในหน้านี้ — โดยการลดการทำ abstraction ของฟิลด์ `logsource` — โฮสต์อยู่ใน repository [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) ภายใต้โฟลเดอร์ `sigma`

## สภาพแวดล้อมของเครื่องมือ

หากคุณต้องการแปลงกฎ Sigma ให้อยู่ในรูปแบบที่เข้ากันได้กับ Hayabusa ในเครื่องของคุณเอง คุณจำเป็นต้องติดตั้ง [Poetry](https://python-poetry.org/) ก่อน โปรดดูที่[เอกสารการติดตั้ง](https://python-poetry.org/docs/#installation)อย่างเป็นทางการของ Poetry

## การใช้งานเครื่องมือ

`sigma-to-hayabusa-converter.py` เป็นเครื่องมือหลักของเราในการแปลงฟิลด์ `logsource` ของกฎ Sigma ให้อยู่ในรูปแบบที่เข้ากันได้กับ Hayabusa ทำตามขั้นตอนต่อไปนี้เพื่อรันเครื่องมือ:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

หลังจากรันคำสั่งข้างต้นแล้ว กฎที่ถูกแปลงเป็นรูปแบบที่เข้ากันได้กับ Hayabusa จะถูกส่งออกไปยังไดเรกทอรี `./converted_sigma_rules`
