# রুল ফাইল তৈরি করা

## Hayabusa-Rules সম্পর্কে

এটি একটি রিপোজিটরি যেখানে Windows ইভেন্ট লগে আক্রমণ শনাক্ত করার জন্য সংগৃহীত sigma রুল রয়েছে।
এটি মূলত [Hayabusa](https://github.com/Yamato-Security/hayabusa) এর শনাক্তকরণ রুল এবং কনফিগ ফাইলের জন্য, পাশাপাশি [Velociraptor](https://github.com/Velocidex/velociraptor) এর অন্তর্নির্মিত sigma শনাক্তকরণের জন্য ব্যবহৃত হয়।
[আপস্ট্রিম sigma রিপোজিটরি](https://github.com/SigmaHQ/sigma) এর পরিবর্তে এই রিপোজিটরি ব্যবহারের সুবিধা হলো আমরা কেবল সেইসব রুল অন্তর্ভুক্ত করি যা বেশিরভাগ sigma-নেটিভ টুল পার্স করতে সক্ষম হওয়া উচিত।
আমরা রুলগুলোতে প্রয়োজনীয় `Channel`, `EventID` ইত্যাদি ফিল্ড যোগ করে `logsource` ফিল্ডকে ডি-অ্যাবস্ট্রাক্ট করি যাতে রুলটি কীসের উপর ফিল্টার করছে তা বোঝা সহজ হয় এবং আরও গুরুত্বপূর্ণভাবে ফলস পজিটিভ কমে।
আমরা `process_creation` রুল এবং `registry` ভিত্তিক রুলের জন্য রূপান্তরিত ফিল্ড নাম ও মান সহ নতুন রুলও তৈরি করি যাতে sigma রুলগুলো কেবল Sysmon লগেই নয়, বরং অন্তর্নির্মিত Windows লগেও শনাক্ত করতে পারে।

## রুল ফাইল তৈরি করা সম্পর্কে

Hayabusa শনাক্তকরণ রুল [YAML](https://en.wikipedia.org/wiki/YAML) ফরম্যাটে `.yml` ফাইল এক্সটেনশন দিয়ে লেখা হয়। (`.yaml` ফাইল উপেক্ষা করা হবে।)
এগুলো sigma রুলের একটি উপসেট তবে কিছু অতিরিক্ত বৈশিষ্ট্যও ধারণ করে।
আমরা এগুলোকে যথাসম্ভব sigma রুলের কাছাকাছি করার চেষ্টা করছি যাতে Hayabusa রুলকে আবার sigma তে রূপান্তর করে কমিউনিটিকে ফিরিয়ে দেওয়া সহজ হয়।
Hayabusa রুল কেবল সাধারণ স্ট্রিং ম্যাচিং নয়, বরং রেগুলার এক্সপ্রেশন, `AND`, `OR` এবং অন্যান্য শর্ত একত্রিত করে জটিল শনাক্তকরণ রুল প্রকাশ করতে পারে।
এই বিভাগে, আমরা ব্যাখ্যা করব কীভাবে Hayabusa শনাক্তকরণ রুল লিখতে হয়।

### রুল ফাইল ফরম্যাট

উদাহরণ:

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

> ## Author section

- **author [required]**: লেখক(গণ) এর নাম।
- **date [required]**: রুলটি যে তারিখে তৈরি হয়েছিল।
- **modified** [optional]: রুলটি যে তারিখে হালনাগাদ হয়েছিল।

> ## Alert section

- **title [required]**: রুল ফাইলের শিরোনাম। এটি প্রদর্শিত অ্যালার্টের নামও হবে তাই যত সংক্ষিপ্ত তত ভালো। (৮৫ অক্ষরের বেশি হওয়া উচিত নয়।)
- **details** [optional]: প্রদর্শিত অ্যালার্টের বিবরণ। অনুগ্রহ করে Windows ইভেন্ট লগের যেকোনো ফিল্ড আউটপুট করুন যা বিশ্লেষণের জন্য উপযোগী। ফিল্ডগুলো `" ¦ "` দ্বারা পৃথক করা হয়। ফিল্ড প্লেসহোল্ডারগুলো `%` দিয়ে আবদ্ধ থাকে (উদাহরণ: `%MemberName%`) এবং `rules/config/eventkey_alias.txt` এ সংজ্ঞায়িত করতে হয়। (নিচে ব্যাখ্যা করা হয়েছে।)
- **description** [optional]: রুলের একটি বিবরণ। এটি প্রদর্শিত হয় না তাই আপনি এটি দীর্ঘ ও বিস্তারিত করতে পারেন।

> ## Rule section

- **id [required]**: রুলটিকে স্বতন্ত্রভাবে শনাক্ত করার জন্য ব্যবহৃত একটি র‍্যান্ডমভাবে তৈরি করা ভার্সন ৪ UUID। আপনি একটি [এখানে](https://www.uuidgenerator.net/version4) তৈরি করতে পারেন।
- **level [required]**: [sigma এর সংজ্ঞা](https://github.com/SigmaHQ/sigma/wiki/Specification) ভিত্তিক তীব্রতার মাত্রা। অনুগ্রহ করে নিম্নলিখিতগুলোর একটি লিখুন: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: [sigma এর সংজ্ঞা](https://github.com/SigmaHQ/sigma/wiki/Specification) ভিত্তিক স্ট্যাটাস। অনুগ্রহ করে নিম্নলিখিতগুলোর একটি লিখুন: `deprecated`, `experimental`, `test`, `stable`।
- **logsource [required]**: যদিও এটি বর্তমানে Hayabusa দ্বারা প্রকৃতপক্ষে ব্যবহৃত হয় না, আমরা sigma রুলের সাথে সামঞ্জস্যপূর্ণ হওয়ার জন্য sigma এর মতোই logsource সংজ্ঞায়িত করি।
- **detection  [required]**: শনাক্তকরণ লজিক এখানে যায়। (নিচে ব্যাখ্যা করা হয়েছে।)
- **falsepositives [required]**: ফলস পজিটিভের সম্ভাবনা। উদাহরণস্বরূপ: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`। যদি অজানা হয়, অনুগ্রহ করে `unknown` লিখুন।
- **tags** [optional]: যদি কৌশলটি একটি [LOLBINS/LOLBAS](https://lolbas-project.github.io/) কৌশল হয়, অনুগ্রহ করে `lolbas` ট্যাগ যোগ করুন। যদি অ্যালার্টটি [MITRE ATT&CK](https://attack.mitre.org/) ফ্রেমওয়ার্কের একটি কৌশলে ম্যাপ করা যায়, অনুগ্রহ করে ট্যাকটিক ID (উদাহরণ: `attack.t1098`) এবং নিচের প্রযোজ্য ট্যাকটিকগুলো যোগ করুন:
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
- **references** [optional]: রেফারেন্সের যেকোনো লিঙ্ক।
- **ruletype [required]**: hayabusa রুলের জন্য `Hayabusa`। sigma Windows রুল থেকে স্বয়ংক্রিয়ভাবে রূপান্তরিত রুলগুলো হবে `Sigma`।

> ## Sample XML Event

- **sample-message [required]**: এখন থেকে, আমরা রুল লেখকদের তাদের রুলের জন্য নমুনা বার্তা অন্তর্ভুক্ত করতে অনুরোধ করি। এটি হলো রেন্ডার করা বার্তা যা Windows এর Event Viewer প্রদর্শন করে।
- **sample-evtx [required]**: এখন থেকে, আমরা রুল লেখকদের তাদের রুলের জন্য নমুনা XML ইভেন্ট অন্তর্ভুক্ত করতে অনুরোধ করি।
