# Rule ဖိုင်များ ဖန်တီးခြင်း

## Hayabusa-Rules အကြောင်း

ဤသည်မှာ Windows event log များတွင် တိုက်ခိုက်မှုများကို ရှာဖွေဖော်ထုတ်သည့် ရွေးချယ်စုဆောင်းထားသော sigma rule များ ပါဝင်သည့် repository တစ်ခုဖြစ်သည်။
၎င်းကို အဓိကအားဖြင့် [Hayabusa](https://github.com/Yamato-Security/hayabusa) detection rule များနှင့် config ဖိုင်များအတွက်လည်းကောင်း၊ [Velociraptor](https://github.com/Velocidex/velociraptor) ၏ built-in sigma detection အတွက်လည်းကောင်း အသုံးပြုသည်။
[upstream sigma repository](https://github.com/SigmaHQ/sigma) ထက် ဤ repository ကို အသုံးပြုခြင်း၏ အားသာချက်မှာ sigma-native tool အများစုက parse လုပ်နိုင်ရမည့် rule များကိုသာ ကျွန်ုပ်တို့ ထည့်သွင်းထားခြင်းဖြစ်သည်။
ထို့အပြင် rule က မည်သည့်အရာကို filter လုပ်နေသည်ကို နားလည်ရန် ပိုမိုလွယ်ကူစေရန်နှင့် ပို၍အရေးကြီးသည်မှာ false positive များကို လျှော့ချရန်အတွက် လိုအပ်သော `Channel`၊ `EventID` စသည့် field များကို rule များတွင် ထည့်သွင်းခြင်းဖြင့် `logsource` field ကို de-abstract လုပ်ပါသည်။
ထို့အပြင် sigma rule များသည် Sysmon log များတွင်သာမက built-in Windows log များတွင်ပါ ရှာဖွေဖော်ထုတ်နိုင်စေရန် `process_creation` rule များနှင့် `registry` အခြေခံ rule များအတွက် field အမည်များနှင့် value များကို ပြောင်းလဲ၍ rule အသစ်များကိုလည်း ကျွန်ုပ်တို့ ဖန်တီးပါသည်။

## Rule ဖိုင်များ ဖန်တီးခြင်းအကြောင်း

Hayabusa detection rule များကို [YAML](https://en.wikipedia.org/wiki/YAML) format ဖြင့် `.yml` ဖိုင်တိုးချဲ့အမည်ဖြင့် ရေးသားသည်။ (`.yaml` ဖိုင်များကို လျစ်လျူရှုမည်ဖြစ်သည်။)
၎င်းတို့သည် sigma rule များ၏ အစုခွဲတစ်ခုဖြစ်သော်လည်း ထပ်ဆောင်း feature အချို့ကိုလည်း ပါဝင်ပါသည်။
Hayabusa rule များကို sigma သို့ ပြန်ပြောင်း၍ community အား ပြန်လည်ပေးအပ်ရန် လွယ်ကူစေရန်အတွက် ၎င်းတို့ကို sigma rule များနှင့် တတ်နိုင်သမျှ နီးစပ်အောင် ကျွန်ုပ်တို့ ကြိုးစားနေပါသည်။
Hayabusa rule များသည် ရိုးရှင်းသော string matching သာမက regular expression များ၊ `AND`၊ `OR` နှင့် အခြားအခြေအနေများကို ပေါင်းစပ်ခြင်းဖြင့် ရှုပ်ထွေးသော detection rule များကို ဖော်ပြနိုင်သည်။
ဤအပိုင်းတွင် Hayabusa detection rule များကို မည်သို့ရေးသားရမည်ကို ကျွန်ုပ်တို့ ရှင်းပြပါမည်။

### Rule ဖိုင် format

ဥပမာ:

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

- **author [required]**: ရေးသားသူ(များ)၏ အမည်။
- **date [required]**: rule ကို ဖန်တီးခဲ့သည့် ရက်စွဲ။
- **modified** [optional]: rule ကို update လုပ်ခဲ့သည့် ရက်စွဲ။

> ## Alert section

- **title [required]**: rule ဖိုင်၏ ခေါင်းစဉ်။ ၎င်းသည် ဖော်ပြမည့် alert ၏ အမည်လည်း ဖြစ်မည်ဖြစ်သောကြောင့် တိုတောင်းလေ ကောင်းလေဖြစ်သည်။ (စာလုံး ၈၅ လုံးထက် မရှည်သင့်ပါ။)
- **details** [optional]: ဖော်ပြမည့် alert ၏ အသေးစိတ်အချက်အလက်များ။ ပိုင်းခြားစိတ်ဖြာရန် အသုံးဝင်သော Windows event log ရှိ မည်သည့် field များကိုမဆို ထုတ်ပြပါ။ Field များကို `" ¦ "` ဖြင့် ပိုင်းခြားသည်။ Field placeholder များကို `%` ဖြင့် ဝိုင်းရံထားပြီး (ဥပမာ: `%MemberName%`) ၎င်းတို့ကို `rules/config/eventkey_alias.txt` တွင် သတ်မှတ်ထားရန် လိုအပ်သည်။ (အောက်တွင် ရှင်းပြထားသည်။)
- **description** [optional]: rule ၏ ဖော်ပြချက်။ ၎င်းကို ဖော်ပြမည်မဟုတ်သောကြောင့် ဤအရာကို ရှည်လျား၍ အသေးစိတ်ရေးနိုင်သည်။

> ## Rule section

- **id [required]**: rule ကို တစ်မူထူးခြားစွာ ခွဲခြားသတ်မှတ်ရန် အသုံးပြုသော ကျပန်းထုတ်လုပ်ထားသည့် version 4 UUID တစ်ခု။ [ဤနေရာတွင်](https://www.uuidgenerator.net/version4) တစ်ခု ထုတ်လုပ်နိုင်သည်။
- **level [required]**: [sigma ၏ အဓိပ္ပါယ်ဖွင့်ဆိုချက်](https://github.com/SigmaHQ/sigma/wiki/Specification) အပေါ်အခြေခံသော ပြင်းထန်မှု အဆင့်။ အောက်ပါတို့မှ တစ်ခုကို ရေးပါ: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: [sigma ၏ အဓိပ္ပါယ်ဖွင့်ဆိုချက်](https://github.com/SigmaHQ/sigma/wiki/Specification) အပေါ်အခြေခံသော status။ အောက်ပါတို့မှ တစ်ခုကို ရေးပါ: `deprecated`, `experimental`, `test`, `stable`။
- **logsource [required]**: ၎င်းကို လောလောဆယ် Hayabusa က အမှန်တကယ် အသုံးမပြုသော်လည်း sigma rule များနှင့် တွဲဖက်အသုံးပြုနိုင်ရန်အတွက် logsource ကို sigma နှင့် တူညီသောနည်းဖြင့် သတ်မှတ်ပါသည်။
- **detection  [required]**: detection logic သည် ဤနေရာတွင် ရှိသည်။ (အောက်တွင် ရှင်းပြထားသည်။)
- **falsepositives [required]**: false positive ဖြစ်နိုင်ခြေများ။ ဥပမာ: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`။ မသိရှိပါက `unknown` ဟု ရေးပါ။
- **tags** [optional]: technique သည် [LOLBINS/LOLBAS](https://lolbas-project.github.io/) technique တစ်ခုဖြစ်ပါက `lolbas` tag ကို ထည့်ပါ။ alert ကို [MITRE ATT&CK](https://attack.mitre.org/) framework ရှိ technique တစ်ခုသို့ map လုပ်နိုင်ပါက tactic ID (ဥပမာ: `attack.t1098`) နှင့် အောက်ပါ သက်ဆိုင်ရာ tactic များကို ထည့်ပါ:
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
- **references** [optional]: ကိုးကားချက်များဆီသို့ link များ။
- **ruletype [required]**: hayabusa rule များအတွက် `Hayabusa`။ sigma Windows rule များမှ အလိုအလျောက် ပြောင်းလဲထားသော rule များသည် `Sigma` ဖြစ်မည်။

> ## Sample XML Event

- **sample-message [required]**: ယခုမှစ၍ rule ရေးသားသူများအား ၎င်းတို့၏ rule များအတွက် sample message များ ထည့်သွင်းရန် ကျွန်ုပ်တို့ တောင်းဆိုပါသည်။ ၎င်းသည် Windows ၏ Event Viewer က ဖော်ပြသော render လုပ်ပြီး message ဖြစ်သည်။
- **sample-evtx [required]**: ယခုမှစ၍ rule ရေးသားသူများအား ၎င်းတို့၏ rule များအတွက် sample XML event များ ထည့်သွင်းရန် ကျွန်ုပ်တို့ တောင်းဆိုပါသည်။
