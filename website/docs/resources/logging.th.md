# Windows Logging & Sysmon

## คำแนะนำเกี่ยวกับการบันทึก Log ของ Windows

เพื่อตรวจจับกิจกรรมที่เป็นอันตรายบนเครื่อง Windows ได้อย่างเหมาะสม คุณจำเป็นต้องปรับปรุงการตั้งค่า log แบบดีฟอลต์
เราได้สร้างโปรเจกต์แยกต่างหากเพื่อจัดทำเอกสารว่าต้องเปิดใช้งานการตั้งค่า log ใดบ้าง รวมถึงสคริปต์สำหรับเปิดใช้งานการตั้งค่าที่เหมาะสมโดยอัตโนมัติได้ที่ [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings)

นอกจากนี้เรายังแนะนำเว็บไซต์ต่อไปนี้เพื่อเป็นแนวทาง:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## โปรเจกต์ที่เกี่ยวข้องกับ Sysmon

เพื่อสร้างหลักฐานทางนิติวิทยาศาสตร์ให้ได้มากที่สุดและตรวจจับด้วยความแม่นยำสูงสุด คุณจำเป็นต้องติดตั้ง sysmon เราแนะนำเว็บไซต์และไฟล์ config ต่อไปนี้:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
