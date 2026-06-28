# โครงการและระบบนิเวศ

## โครงการที่เกี่ยวข้อง

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - เอกสารและสคริปต์สำหรับเปิดใช้งาน Windows event logs อย่างถูกต้อง
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - เหมือนกับ repository ของ Hayabusa Rules แต่ไฟล์กฎและไฟล์ config ถูกเก็บไว้ในไฟล์เดียวและทำ XOR เพื่อป้องกัน false positive จากโปรแกรมแอนตี้ไวรัส
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - กฎตรวจจับของ Hayabusa และกฎ Sigma ที่คัดสรรแล้วซึ่งใช้กับ Hayabusa
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - fork ของ crate `evtx` ที่ได้รับการดูแลรักษามากกว่า
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - ไฟล์ evtx ตัวอย่างสำหรับใช้ทดสอบกฎตรวจจับของ hayabusa/sigma
* [Presentations](https://github.com/Yamato-Security/Presentations) - งานนำเสนอจากการบรรยายที่เราได้จัดขึ้นเกี่ยวกับเครื่องมือและทรัพยากรของเรา
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - คัดสรรกฎ Sigma ที่อิงกับ Windows event log จากต้นทางให้อยู่ในรูปแบบที่ใช้งานง่ายขึ้น
* [Takajo](https://github.com/Yamato-Security/takajo) - เครื่องมือวิเคราะห์ผลลัพธ์ของ hayabusa
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - เครื่องมือวิเคราะห์ Windows event logs ที่เขียนด้วย PowerShell (เลิกใช้งานแล้วและถูกแทนที่ด้วย Takajo)

## โครงการของบุคคลที่สามที่ใช้ Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - เวิร์กโฟลว์ NodeRED ที่นำเข้าผลลัพธ์ของ Plaso และ Hayabusa เข้าสู่ Timesketch
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - ให้บริการเครื่องมือและโครงสร้างพื้นฐานด้านความปลอดภัยบนคลาวด์เพื่อตอบโจทย์ความต้องการของคุณ 
* [OpenRelik](https://openrelik.org/) - แพลตฟอร์มโอเพนซอร์ส (Apache-2.0) ที่ออกแบบมาเพื่อให้การสืบสวนทางนิติวิทยาศาสตร์ดิจิทัลแบบทำงานร่วมกันเป็นไปอย่างราบรื่น
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - สร้าง splunk instance ขึ้นมาอย่างรวดเร็วด้วย Docker เพื่อเรียกดู log และผลลัพธ์ของเครื่องมือต่าง ๆ ระหว่างการสืบสวนของคุณ
* [Velociraptor](https://github.com/Velocidex/velociraptor) - เครื่องมือสำหรับเก็บรวบรวมข้อมูลสถานะที่อิงกับโฮสต์โดยใช้คำสั่งค้นหาแบบ The Velociraptor Query Language (VQL)

## เครื่องมือวิเคราะห์ Windows Event Log อื่น ๆ และทรัพยากรที่เกี่ยวข้อง

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - เครื่องมือตรวจจับการโจมตีที่เขียนด้วย Python
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  คอลเลกชันทรัพยากร Event ID ที่มีประโยชน์สำหรับ Digital Forensics และ Incident Response
* [Chainsaw](https://github.com/countercept/chainsaw) - เครื่องมือตรวจจับการโจมตีที่อิงกับ sigma อีกตัวหนึ่งซึ่งเขียนด้วย Rust
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - เครื่องมือตรวจจับการโจมตีที่เขียนด้วย Powershell โดย [Eric Conrad](https://twitter.com/eric_conrad)
* [Epagneul](https://github.com/jurelou/epagneul) - การแสดงผลแบบกราฟสำหรับ Windows event logs
* [EventList](https://github.com/miriamxyra/EventList/) - จับคู่ event ID ของ security baseline เข้ากับ MITRE ATT&CK โดย [Miriam Wiesner](https://github.com/miriamxyra)
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - โดย [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - ตัวแยกวิเคราะห์ Evtx โดย [Eric Zimmerman](https://twitter.com/ericrzimmerman)
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - กู้คืนไฟล์ log EVTX จากพื้นที่ที่ยังไม่ได้จัดสรรและ memory image
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - เครื่องมือ Python สำหรับส่งข้อมูล Evtx ไปยัง Elastic Stack
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - ไฟล์ log เหตุการณ์ตัวอย่างการโจมตี EVTX โดย [SBousseaden](https://twitter.com/SBousseaden)
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - ไฟล์ log เหตุการณ์ตัวอย่างการโจมตี EVTX ที่จับคู่กับ ATT&CK โดย [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - ไลบรารี evtx ของ Rust ที่เราใช้ เขียนโดย [@OBenamram](https://twitter.com/obenamram)
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - เครื่องมือแสดงผล log ของ Sysmon และ PowerShell
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - อินเทอร์เฟซแบบกราฟิกเพื่อแสดงผลการล็อกออนสำหรับตรวจจับการเคลื่อนที่ในแนวขวาง (lateral movement) โดย [JPCERTCC](https://twitter.com/jpcert_en)
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - คู่มือของ NSA ว่าควรเฝ้าระวังอะไรบ้าง
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - การพอร์ต DeepBlueCLI เป็น Rust โดย Yamato Security
* [Sigma](https://github.com/SigmaHQ/sigma) - กฎ SIEM ทั่วไปที่อิงกับชุมชน
* [SOF-ELK](https://github.com/philhagen/sof-elk) - VM ที่แพ็กเกจมาพร้อม Elastic Stack เพื่อนำเข้าข้อมูลสำหรับการวิเคราะห์ DFIR โดย [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - นำเข้าไฟล์ evtx เข้าสู่ Security Onion
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - เครื่องมือสำหรับตั้งค่าและแสดงผล log แบบออฟไลน์สำหรับ Sysmon
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - เครื่องมือวิเคราะห์ไทม์ไลน์ CSV ที่ดีที่สุด โดย [Eric Zimmerman](https://twitter.com/ericrzimmerman)
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - โดย Steve Anson จาก Forward Defense
* [Zircolite](https://github.com/wagga40/Zircolite) - เครื่องมือตรวจจับการโจมตีที่อิงกับ Sigma ซึ่งเขียนด้วย Python
