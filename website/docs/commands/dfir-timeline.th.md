# คำสั่งสำหรับ DFIR Timeline

## ตัวช่วยสแกน (Scan Wizard)

ปัจจุบันคำสั่ง `csv-timeline` และ `json-timeline` มีตัวช่วยสแกน (scan wizard) เปิดใช้งานเป็นค่าเริ่มต้น
สิ่งนี้มีจุดประสงค์เพื่อช่วยให้ผู้ใช้สามารถเลือกกฎตรวจจับที่ต้องการเปิดใช้งานได้อย่างง่ายดายตามความต้องการและความชอบของตน
ชุดกฎตรวจจับที่จะโหลดนั้นอ้างอิงจากรายการอย่างเป็นทางการในโครงการ Sigma
รายละเอียดได้อธิบายไว้ใน [บล็อกโพสต์นี้](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81)
คุณสามารถปิดตัวช่วยและใช้ Hayabusa ในรูปแบบดั้งเดิมได้อย่างง่ายดายโดยการเพิ่มตัวเลือก `-w, --no-wizard`

### กฎ Core

ชุดกฎ `core` จะเปิดใช้งานกฎที่มีสถานะเป็น `test` หรือ `stable` และมีระดับเป็น `high` หรือ `critical`
กฎเหล่านี้เป็นกฎคุณภาพสูงที่มีความมั่นใจและความเกี่ยวข้องสูง และไม่ควรสร้างผลบวกลวงมากนัก
สถานะของกฎคือ `test` หรือ `stable` ซึ่งหมายความว่าไม่มีการรายงานผลบวกลวงเป็นเวลานานกว่า 6 เดือน
กฎจะตรงกับเทคนิคของผู้โจมตี กิจกรรมน่าสงสัยทั่วไป หรือพฤติกรรมที่เป็นอันตราย
ซึ่งเหมือนกับการใช้ตัวเลือก `--exclude-status deprecated,unsupported,experimental --min-level high`

### กฎ Core+

ชุดกฎ `core+` จะเปิดใช้งานกฎที่มีสถานะเป็น `test` หรือ `stable` และมีระดับเป็น `medium` หรือสูงกว่า
กฎระดับ `medium` มักจำเป็นต้องมีการปรับแต่งเพิ่มเติม เนื่องจากแอปพลิเคชันบางอย่าง พฤติกรรมผู้ใช้ที่ถูกต้องตามกฎหมาย หรือสคริปต์ขององค์กรอาจถูกจับคู่ได้
ซึ่งเหมือนกับการใช้ตัวเลือก `--exclude-status deprecated,unsupported,experimental --min-level medium`

### กฎ Core++

ชุดกฎ `core++` จะเปิดใช้งานกฎที่มีสถานะเป็น `experimental`, `test` หรือ `stable` และมีระดับเป็น `medium` หรือสูงกว่า
กฎเหล่านี้เป็นกฎที่ล้ำสมัยที่สุด
กฎเหล่านี้ได้รับการตรวจสอบกับไฟล์ evtx พื้นฐานที่มีอยู่ในโครงการ SigmaHQ และผ่านการตรวจทานโดยวิศวกรด้านการตรวจจับหลายคน
นอกเหนือจากนั้นแล้ว กฎเหล่านี้แทบจะยังไม่ได้รับการทดสอบในช่วงแรก
ใช้กฎเหล่านี้หากคุณต้องการที่จะสามารถตรวจจับภัยคุกคามได้เร็วที่สุดเท่าที่จะเป็นไปได้ โดยแลกกับการจัดการกับผลบวกลวงที่อาจมีจำนวนสูงขึ้น
ซึ่งเหมือนกับการใช้ตัวเลือก `--exclude-status deprecated,unsupported --min-level medium`

### กฎเสริม Emerging Threats (ET)

ชุดกฎ `Emerging Threats (ET)` จะเปิดใช้งานกฎที่มีแท็กเป็น `detection.emerging_threats`
กฎเหล่านี้มุ่งเป้าไปที่ภัยคุกคามเฉพาะ และมีประโยชน์อย่างยิ่งสำหรับภัยคุกคามในปัจจุบันที่ยังมีข้อมูลไม่มากนัก
กฎเหล่านี้ไม่ควรมีผลบวกลวงมากนัก แต่ความเกี่ยวข้องจะลดลงเมื่อเวลาผ่านไป
เมื่อกฎเหล่านี้ไม่ถูกเปิดใช้งาน จะเหมือนกับการใช้ตัวเลือก `--exclude-tag detection.emerging_threats`
เมื่อรัน Hayabusa ในรูปแบบดั้งเดิมโดยไม่ใช้ตัวช่วย กฎเหล่านี้จะถูกรวมเข้ามาเป็นค่าเริ่มต้น

### กฎเสริม Threat Hunting (TH)

ชุดกฎ `Threat Hunting (TH)` จะเปิดใช้งานกฎที่มีแท็กเป็น `detection.threat_hunting`
กฎเหล่านี้อาจตรวจจับกิจกรรมที่เป็นอันตรายซึ่งยังไม่เป็นที่รู้จัก อย่างไรก็ตาม โดยทั่วไปแล้วจะมีผลบวกลวงมากกว่า
เมื่อกฎเหล่านี้ไม่ถูกเปิดใช้งาน จะเหมือนกับการใช้ตัวเลือก `--exclude-tag detection.threat_hunting`
เมื่อรัน Hayabusa ในรูปแบบดั้งเดิมโดยไม่ใช้ตัวช่วย กฎเหล่านี้จะถูกรวมเข้ามาเป็นค่าเริ่มต้น

## การกรองบันทึกเหตุการณ์และกฎตามช่อง (Channel)

ตั้งแต่ Hayabusa v2.16.0 เป็นต้นไป เราได้เปิดใช้งานตัวกรองตามช่อง (Channel) เมื่อโหลดไฟล์ `.evtx` และกฎ `.yml`
จุดประสงค์คือเพื่อทำให้การสแกนมีประสิทธิภาพมากที่สุดเท่าที่จะเป็นไปได้โดยการโหลดเฉพาะสิ่งที่จำเป็นเท่านั้น
แม้ว่าจะเป็นไปได้ที่จะมี provider หลายตัวในบันทึกเหตุการณ์เดียว แต่ก็ไม่ใช่เรื่องปกติที่จะมีหลายช่องภายในไฟล์ evtx เดียว
(ครั้งเดียวที่เราเคยเห็นเช่นนี้คือเมื่อมีคนรวมไฟล์ evtx สองไฟล์ที่แตกต่างกันเข้าด้วยกันอย่างเทียมๆ สำหรับโครงการ [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx))
เราสามารถใช้ประโยชน์จากสิ่งนี้ได้โดยการตรวจสอบฟิลด์ `Channel` ในเรกคอร์ดแรกของทุกไฟล์ `.evtx` ที่ระบุให้สแกนก่อน
นอกจากนี้เรายังตรวจสอบว่ากฎ `.yml` ใดใช้ช่องใดที่ระบุไว้ในฟิลด์ `Channel` ของกฎ
ด้วยรายการทั้งสองนี้ เราจะโหลดเฉพาะกฎที่ใช้ช่องที่มีอยู่จริงภายในไฟล์ `.evtx` เท่านั้น

ตัวอย่างเช่น หากผู้ใช้ต้องการสแกน `Security.evtx` จะมีการใช้เฉพาะกฎที่ระบุ `Channel: Security` เท่านั้น
ไม่มีประโยชน์ที่จะโหลดกฎตรวจจับอื่นๆ เช่น กฎที่มองหาเฉพาะเหตุการณ์ในบันทึก `Application` เป็นต้น
โปรดทราบว่าฟิลด์ช่อง (เช่น `Channel: Security`) นั้นไม่ได้ถูก**กำหนดอย่างชัดเจน** ภายในกฎ Sigma ดั้งเดิม
สำหรับกฎ Sigma ฟิลด์ช่องและ event ID จะถูก**กำหนดโดยปริยาย** ด้วยฟิลด์ `service` และ `category` ภายใต้ `logsource` (เช่น `service: security`)
เมื่อจัดทำกฎ Sigma ในที่เก็บ [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) เราจะลดความเป็นนามธรรมของฟิลด์ `logsource` และกำหนดฟิลด์ช่องและ event ID อย่างชัดเจน
เราอธิบายอย่างละเอียดว่าเราทำสิ่งนี้อย่างไรและทำไม [ที่นี่](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)

ปัจจุบัน มีเพียงกฎตรวจจับสองกฎเท่านั้นที่ไม่มีการกำหนด `Channel` และมีจุดประสงค์เพื่อสแกนไฟล์ `.evtx` ทั้งหมด ได้แก่ดังต่อไปนี้:
- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

หากคุณต้องการใช้กฎสองกฎนี้และสแกนกฎทั้งหมดกับไฟล์ `.evtx` ที่โหลดไว้ คุณจะต้องเพิ่มตัวเลือก `-A, --enable-all-rules` ในคำสั่ง `csv-timeline` และ `json-timeline`
ในการทดสอบประสิทธิภาพของเรา การกรองกฎมักจะให้การปรับปรุงความเร็วประมาณ 20% ถึง 10 เท่า ขึ้นอยู่กับไฟล์ที่กำลังสแกน และแน่นอนว่าใช้หน่วยความจำน้อยลง

การกรองตามช่องยังถูกใช้เมื่อโหลดไฟล์ `.evtx` ด้วย
ตัวอย่างเช่น หากคุณระบุกฎที่มองหาเหตุการณ์ที่มีช่องเป็น `Security` ก็ไม่มีประโยชน์ที่จะโหลดไฟล์ `.evtx` ที่ไม่ได้มาจากบันทึก `Security`
ในการทดสอบประสิทธิภาพของเรา สิ่งนี้ให้ประโยชน์ด้านความเร็วประมาณ 10% สำหรับการสแกนปกติ และเพิ่มประสิทธิภาพได้มากถึง 60%+ เมื่อสแกนด้วยกฎเดียว
หากคุณแน่ใจว่ามีการใช้หลายช่องภายในไฟล์ `.evtx` เดียว เช่น มีคนใช้เครื่องมือรวมไฟล์ `.evtx` หลายไฟล์เข้าด้วยกัน คุณสามารถปิดการกรองนี้ด้วยตัวเลือก `-a, --scan-all-evtx-files` ในคำสั่ง `csv-timeline` และ `json-timeline`

> หมายเหตุ: การกรองตามช่องทำงานได้กับไฟล์ `.evtx` เท่านั้น และคุณจะได้รับข้อผิดพลาดหากคุณพยายามโหลดบันทึกเหตุการณ์จากไฟล์ JSON ด้วย `-J, --json-input` และยังระบุ `-A` หรือ `-a` ด้วย

## คำสั่ง `csv-timeline`

คำสั่ง `csv-timeline` จะสร้างไทม์ไลน์ทางนิติวิทยาศาสตร์ของเหตุการณ์ในรูปแบบ CSV

```
Usage: csv-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -M, --multiline                    Output event field information in multiple rows
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in CSV format (ex: results.csv)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)
  -S, --tab-separator                Separate event field information by tabs

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### ตัวอย่างคำสั่ง `csv-timeline`

* รัน hayabusa กับไฟล์บันทึกเหตุการณ์ Windows หนึ่งไฟล์โดยใช้โปรไฟล์ `standard` เริ่มต้น:

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* รัน hayabusa กับไดเรกทอรี sample-evtx ที่มีไฟล์บันทึกเหตุการณ์ Windows หลายไฟล์โดยใช้โปรไฟล์ verbose:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* ส่งออกเป็นไฟล์ CSV เดียวสำหรับการวิเคราะห์เพิ่มเติมด้วย LibreOffice, Timeline Explorer, Elastic Stack เป็นต้น และรวมข้อมูลฟิลด์ทั้งหมด (คำเตือน: ขนาดไฟล์เอาต์พุตของคุณจะใหญ่ขึ้นมากเมื่อใช้โปรไฟล์ `super-verbose`!):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* เปิดใช้งานตัวกรอง EID (Event ID):

> หมายเหตุ: การเปิดใช้งานตัวกรอง EID จะเพิ่มความเร็วในการวิเคราะห์ประมาณ 10-15% ในการทดสอบของเรา แต่มีความเป็นไปได้ที่จะพลาดการแจ้งเตือน

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* รันเฉพาะกฎ hayabusa เท่านั้น (ค่าเริ่มต้นคือการรันกฎทั้งหมดใน `-r .\rules`):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* รันเฉพาะกฎ hayabusa สำหรับบันทึกที่เปิดใช้งานเป็นค่าเริ่มต้นบน Windows:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* รันเฉพาะกฎ hayabusa สำหรับบันทึก sysmon:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* รันเฉพาะกฎ sigma:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* เปิดใช้งานกฎที่เลิกใช้แล้ว (กฎที่มี `status` ระบุเป็น `deprecated`) และกฎที่มีเสียงรบกวน (กฎที่มี rule ID อยู่ในรายการ `.\rules\config\noisy_rules.txt`):

> หมายเหตุ: เมื่อเร็วๆ นี้ กฎที่เลิกใช้แล้วถูกย้ายไปอยู่ในไดเรกทอรีแยกต่างหากในที่เก็บ sigma จึงไม่ถูกรวมเข้ามาเป็นค่าเริ่มต้นใน Hayabusa อีกต่อไป
> ดังนั้น คุณอาจไม่จำเป็นต้องเปิดใช้งานกฎที่เลิกใช้แล้ว

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* รันเฉพาะกฎเพื่อวิเคราะห์การล็อกออนและส่งออกในเขตเวลา UTC:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* รันบนเครื่อง Windows ที่ทำงานอยู่จริง (ต้องมีสิทธิ์ผู้ดูแลระบบ) และตรวจจับเฉพาะการแจ้งเตือนเท่านั้น (พฤติกรรมที่อาจเป็นอันตราย):

```
hayabusa.exe csv-timeline -l -m low
```

* พิมพ์ข้อมูลแบบละเอียด (มีประโยชน์สำหรับการระบุว่าไฟล์ใดใช้เวลานานในการประมวลผล ข้อผิดพลาดในการแยกวิเคราะห์ เป็นต้น):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* ตัวอย่างเอาต์พุตแบบละเอียด:

การโหลดกฎ:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

ข้อผิดพลาดระหว่างการสแกน:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* ส่งออกเป็นรูปแบบ CSV ที่เข้ากันได้สำหรับการนำเข้าใน [Timesketch](https://timesketch.org/):

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* โหมดข้อผิดพลาดแบบเงียบ:
โดยค่าเริ่มต้น hayabusa จะบันทึกข้อความข้อผิดพลาดลงในไฟล์บันทึกข้อผิดพลาด
หากคุณไม่ต้องการบันทึกข้อความข้อผิดพลาด โปรดเพิ่ม `-Q`

### ขั้นสูง - การเสริมข้อมูลบันทึกด้วย GeoIP

คุณสามารถเพิ่มข้อมูล GeoIP (องค์กร ASN, เมือง และประเทศ) ลงในฟิลด์ SrcIP (IP ต้นทาง) และฟิลด์ TgtIP (IP ปลายทาง) ด้วยข้อมูลตำแหน่งทางภูมิศาสตร์ GeoLite2 ที่ใช้งานได้ฟรี

ขั้นตอน:
1. ก่อนอื่นสมัครบัญชี MaxMind [ที่นี่](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. ดาวน์โหลดไฟล์ `.mmdb` ทั้งสามไฟล์จาก [หน้าดาวน์โหลด](https://www.maxmind.com/en/accounts/current/geoip/downloads) และบันทึกลงในไดเรกทอรี ชื่อไฟล์ควรเป็น `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` และ `GeoLite2-Country.mmdb`
3. เมื่อรันคำสั่ง `csv-timeline` หรือ `json-timeline` ให้เพิ่มตัวเลือก `-G` ตามด้วยไดเรกทอรีที่มีฐานข้อมูล MaxMind

* เมื่อใช้ `csv-timeline` คอลัมน์เพิ่มเติม 6 คอลัมน์ต่อไปนี้จะถูกส่งออก: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`
* เมื่อใช้ `json-timeline` ฟิลด์ `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` เดียวกันจะถูกเพิ่มลงในออบเจกต์ `Details` แต่จะเพิ่มเฉพาะเมื่อมีข้อมูลอยู่เท่านั้น

* เมื่อ `SrcIP` หรือ `TgtIP` เป็น localhost (`127.0.0.1`, `::1` เป็นต้น) `SrcASN` หรือ `TgtASN` จะถูกส่งออกเป็น `Local`
* เมื่อ `SrcIP` หรือ `TgtIP` เป็น IP address ส่วนตัว (`10.0.0.0/8`, `fe80::/10` เป็นต้น) `SrcASN` หรือ `TgtASN` จะถูกส่งออกเป็น `Private`

#### ไฟล์กำหนดค่า GeoIP

ชื่อฟิลด์ที่มี IP address ต้นทางและปลายทางที่ถูกค้นหาในฐานข้อมูล GeoIP จะถูกกำหนดไว้ใน `rules/config/geoip_field_mapping.yaml`
คุณสามารถเพิ่มลงในรายการนี้ได้หากจำเป็น
นอกจากนี้ยังมีส่วนตัวกรองในไฟล์นี้ที่กำหนดว่าจะดึงข้อมูล IP address จากเหตุการณ์ใด

#### การอัปเดตฐานข้อมูล GeoIP อัตโนมัติ

ฐานข้อมูล MaxMind GeoIP จะถูกอัปเดตทุก 2 สัปดาห์
คุณสามารถติดตั้งเครื่องมือ `geoipupdate` ของ MaxMind [ที่นี่](https://github.com/maxmind/geoipupdate) เพื่ออัปเดตฐานข้อมูลเหล่านี้โดยอัตโนมัติ

ขั้นตอนบน macOS:
1. `brew install geoipupdate`
2. แก้ไข `/usr/local/etc/GeoIP.conf` หรือ `/opt/homebrew/etc/GeoIP.conf`: ใส่ `AccountID` และ `LicenseKey` ของคุณที่สร้างขึ้นหลังจากเข้าสู่ระบบเว็บไซต์ MaxMind ตรวจสอบให้แน่ใจว่าบรรทัด `EditionIDs` ระบุว่า `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`
3. รัน `geoipupdate`
4. เพิ่ม `-G /usr/local/var/GeoIP` หรือ `-G /opt/homebrew/var/GeoIP` เมื่อคุณต้องการเพิ่มข้อมูล GeoIP

ขั้นตอนบน Windows:
1. ดาวน์โหลดไบนารี Windows ล่าสุด (เช่น `geoipupdate_4.10.0_windows_amd64.zip`) จากหน้า [Releases](https://github.com/maxmind/geoipupdate/releases)
2. แก้ไข `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: ใส่ `AccountID` และ `LicenseKey` ของคุณที่สร้างขึ้นหลังจากเข้าสู่ระบบเว็บไซต์ MaxMind ตรวจสอบให้แน่ใจว่าบรรทัด `EditionIDs` ระบุว่า `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`
3. รันไฟล์ปฏิบัติการ `geoipupdate`

### ไฟล์กำหนดค่าของคำสั่ง `csv-timeline`

`./rules/config/channel_abbreviations.txt`: การแมประหว่างชื่อช่องและตัวย่อของช่อง

`./rules/config/default_details.txt`: ไฟล์กำหนดค่าสำหรับข้อมูลฟิลด์เริ่มต้น (ฟิลด์ `%Details%`) ที่ควรถูกส่งออกหากไม่มีการระบุบรรทัด `details:` ในกฎ
สิ่งนี้อ้างอิงจากชื่อ provider และ event ID

`./rules/config/eventkey_alias.txt`: ไฟล์นี้มีการแมประหว่างชื่อย่อ (alias) สำหรับฟิลด์และชื่อฟิลด์ดั้งเดิมที่ยาวกว่า

ตัวอย่าง:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

หากฟิลด์ไม่ได้ถูกกำหนดไว้ที่นี่ Hayabusa จะตรวจสอบฟิลด์ภายใต้ `Event.EventData` โดยอัตโนมัติ

`./rules/config/exclude_rules.txt`: ไฟล์นี้มีรายการ rule ID ที่จะถูกยกเว้นจากการใช้งาน
โดยปกติแล้วเป็นเพราะกฎหนึ่งได้แทนที่อีกกฎหนึ่ง หรือกฎนั้นไม่สามารถใช้งานได้ตั้งแต่แรก
เช่นเดียวกับไฟร์วอลล์และ IDS เครื่องมือใดๆ ที่อิงตามลายเซ็น (signature-based) จะต้องมีการปรับแต่งบางอย่างเพื่อให้เหมาะสมกับสภาพแวดล้อมของคุณ ดังนั้นคุณอาจจำเป็นต้องยกเว้นกฎบางอย่างอย่างถาวรหรือชั่วคราว
คุณสามารถเพิ่ม rule ID (ตัวอย่าง: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) ลงใน `./rules/config/exclude_rules.txt` เพื่อเพิกเฉยต่อกฎใดๆ ที่คุณไม่ต้องการหรือไม่สามารถใช้งานได้

`./rules/config/noisy_rules.txt`: ไฟล์นี้มีรายการ rule ID ที่ถูกปิดใช้งานเป็นค่าเริ่มต้น แต่สามารถเปิดใช้งานได้โดยการเปิดใช้งานกฎที่มีเสียงรบกวนด้วยตัวเลือก `-n, --enable-noisy-rules`
กฎเหล่านี้มักจะมีเสียงรบกวนโดยธรรมชาติหรือเนื่องจากผลบวกลวง

`./rules/config/target_event_IDs.txt`: เฉพาะ event ID ที่ระบุไว้ในไฟล์นี้เท่านั้นที่จะถูกสแกนหากเปิดใช้งานตัวกรอง EID
โดยค่าเริ่มต้น Hayabusa จะสแกนเหตุการณ์ทั้งหมด แต่หากคุณต้องการปรับปรุงประสิทธิภาพ โปรดใช้ตัวเลือก `-E, --EID-filter`
สิ่งนี้มักจะส่งผลให้ความเร็วเพิ่มขึ้น 10~25%

## คำสั่ง `json-timeline`

คำสั่ง `json-timeline` จะสร้างไทม์ไลน์ทางนิติวิทยาศาสตร์ของเหตุการณ์ในรูปแบบ JSON หรือ JSONL
การส่งออกเป็น JSONL จะเร็วกว่าและมีขนาดไฟล์เล็กกว่า JSON จึงเหมาะหากคุณจะเพียงนำเข้าผลลัพธ์ไปยังเครื่องมืออื่นเช่น Elastic Stack
JSON เหมาะกว่าหากคุณจะวิเคราะห์ผลลัพธ์ด้วยตนเองโดยใช้โปรแกรมแก้ไขข้อความ
เอาต์พุต CSV เหมาะสำหรับการนำเข้าไทม์ไลน์ขนาดเล็กกว่า (โดยปกติน้อยกว่า 2GB) ไปยังเครื่องมือเช่น LibreOffice หรือ Timeline Explorer
JSON เหมาะที่สุดสำหรับการวิเคราะห์ข้อมูลที่ละเอียดยิ่งขึ้น (รวมถึงไฟล์ผลลัพธ์ขนาดใหญ่) ด้วยเครื่องมือเช่น `jq` เนื่องจากฟิลด์ `Details` ถูกแยกออกเพื่อให้วิเคราะห์ได้ง่ายขึ้น
(ในเอาต์พุต CSV ฟิลด์บันทึกเหตุการณ์ทั้งหมดอยู่ในคอลัมน์ `Details` ขนาดใหญ่คอลัมน์เดียว ทำให้การเรียงลำดับข้อมูล เป็นต้น ยากขึ้น)

```
Usage: json-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -L, --JSONL-output                 Save the timeline in JSONL format (ex: -L -o results.jsonl)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in JSON format (ex: results.json)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### ตัวอย่างคำสั่งและไฟล์กำหนดค่าของ `json-timeline`

ตัวเลือกและไฟล์กำหนดค่าสำหรับ `json-timeline` เหมือนกับ `csv-timeline` แต่มีตัวเลือกเพิ่มเติมอีกหนึ่งตัวคือ `-L, --JSONL-output` สำหรับการส่งออกเป็นรูปแบบ JSONL

## คำสั่ง `level-tuning`

คำสั่ง `level-tuning` จะให้คุณปรับแต่งระดับการแจ้งเตือนสำหรับกฎ ไม่ว่าจะเพิ่มหรือลดระดับความเสี่ยงตามที่คุณต้องการ
คำสั่งนี้ใช้ไฟล์กำหนดค่าเพื่อเขียนทับระดับความเสี่ยง (ฟิลด์ `level`) ของกฎในโฟลเดอร์ `rules`

> คำเตือน: ทุกครั้งที่คุณรันคำสั่ง `update-rules` ระดับความเสี่ยงจะถูกคืนค่ากลับไปเป็นค่าดั้งเดิม ดังนั้นคุณจะต้องรันคำสั่ง `level-tuning` อีกครั้งหลังจากนั้น

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### ตัวอย่างคำสั่ง `level-tuning`

* การใช้งานปกติ: `hayabusa.exe level-tuning`
* ปรับแต่งระดับการแจ้งเตือนของกฎตามไฟล์กำหนดค่าที่กำหนดเอง: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### ไฟล์กำหนดค่า `level-tuning`

ผู้เขียนกฎ Hayabusa และ Sigma จะประเมินระดับความเสี่ยงที่เหมาะสมของการแจ้งเตือนเมื่อเขียนกฎของตน
อย่างไรก็ตาม บางครั้งระดับความเสี่ยงอาจไม่สอดคล้องกัน และระดับความเสี่ยงที่แท้จริงอาจแตกต่างกันไปตามสภาพแวดล้อมของคุณ
Yamato Security จัดเตรียมและดูแลไฟล์กำหนดค่าที่ `./rules/config/level_tuning.txt` ที่คุณสามารถใช้เพื่อปรับแต่งกฎของคุณได้เช่นกัน

ตัวอย่าง `./rules/config/level_tuning.txt`:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

ในกรณีนี้ ระดับความเสี่ยงของกฎที่มี `id` เป็น `570ae5ec-33dc-427c-b815-db86228ad43e` ในไดเรกทอรีกฎจะมีฟิลด์ `level` ถูกเขียนใหม่เป็น `informational`
ระดับที่สามารถตั้งค่าได้คือ `critical`, `high`, `medium`, `low` และ `informational`

> คำเตือน: ไฟล์กำหนดค่า `./rules/config/level_tuning.txt` จะถูกอัปเดตเป็นเวอร์ชันล่าสุดในที่เก็บ hayabusa-rules ทุกครั้งที่คุณรัน `update-rules` ด้วย
> ดังนั้น หากคุณทำการเปลี่ยนแปลงไฟล์นี้ คุณจะสูญเสียการเปลี่ยนแปลงเหล่านั้น!
> หากคุณต้องการเก็บไฟล์กำหนดค่าไว้สำหรับตนเอง ให้สร้างไฟล์กำหนดค่าใน `./config/level_tuning.txt` และรัน `hayabusa.exe level-tuning -f ./config/level_tuning.txt`
> คุณยังสามารถทำการปรับแต่งระดับด้วยไฟล์กำหนดค่าที่ Yamato Security จัดเตรียมไว้ก่อน แล้วจึงปรับแต่งเพิ่มเติมด้วยไฟล์กำหนดค่าของคุณเองได้

## คำสั่ง `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## คำสั่ง `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### ตัวอย่างคำสั่ง `set-default-profile`

* ตั้งค่าโปรไฟล์เริ่มต้นเป็น `minimal`: `hayabusa.exe set-default-profile minimal`
* ตั้งค่าโปรไฟล์เริ่มต้นเป็น `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## คำสั่ง `update-rules`

คำสั่ง `update-rules` จะซิงค์โฟลเดอร์ `rules` กับ [ที่เก็บ Hayabusa rules บน github](https://github.com/Yamato-Security/hayabusa-rules) เพื่ออัปเดตกฎและไฟล์กำหนดค่า

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### ตัวอย่างคำสั่ง `update-rules`

โดยปกติคุณจะเพียงแค่รันคำสั่งนี้: `hayabusa.exe update-rules`
