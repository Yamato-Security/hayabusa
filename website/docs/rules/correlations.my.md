## Event Count rules

ဤ rule များသည် သတ်မှတ်ထားသော event အချို့ကို ရေတွက်ပြီး အချိန်ကာလတစ်ခုအတွင်း ထို event များ အလွန်အကျွံ များလွန်းခြင်း သို့မဟုတ် မလုံလောက်ခြင်း ဖြစ်ပါက သတိပေးချက် ထုတ်ပေးသော rule များဖြစ်သည်။
အချိန်ကာလတစ်ခုအတွင်း event များစွာကို တွေ့ရှိခြင်းအတွက် အသုံးများသော ဥပမာများမှာ password ခန့်မှန်းတိုက်ခိုက်မှု၊ password spray တိုက်ခိုက်မှု နှင့် denial of service တိုက်ခိုက်မှုများကို ဖော်ထုတ်ခြင်းတို့ဖြစ်သည်။
event အချို့သည် သတ်မှတ်ထားသော threshold အောက် ကျသွားသည့်အခါကဲ့သို့ log source ၏ ယုံကြည်စိတ်ချရမှုဆိုင်ရာ ပြဿနာများကို ဖော်ထုတ်ရန်လည်း ဤ rule များကို အသုံးပြုနိုင်သည်။

### Event Count rule example:

အောက်ပါဥပမာသည် password ခန့်မှန်းတိုက်ခိုက်မှုများကို ဖော်ထုတ်ရန် rule နှစ်ခုကို အသုံးပြုသည်။
ကိုးကားထားသော rule သည် ၅ မိနစ်အတွင်း ၅ ကြိမ် သို့မဟုတ် ထိုထက်ပို၍ ကိုက်ညီပြီး ထို event များအတွက် `IpAddress` field တူညီသည့်အခါ သတိပေးချက်တစ်ခု ထွက်ပေါ်လာမည်ဖြစ်သည်။

> သဘောတရားကို နားလည်ရန် လိုအပ်သော field များကိုသာ ကျွန်ုပ်တို့ ထည့်သွင်းထားကြောင်း သတိပြုပါ။
> ဤဥပမာ၏ အခြေခံဖြစ်သော rule အပြည့်အစုံကို သင့်ကိုးကားရန်အတွက် [ဤနေရာတွင်](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) ထားရှိသည်။

### Event Count correlation rule:

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

### Failed Logon - Incorrect Password rule:

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

### Deprecated `count` rule example:

အထက်ပါ correlation နှင့် ကိုးကားထားသော rule များသည် ပိုမိုဟောင်းသော `count` modifier ကို အသုံးပြုသည့် အောက်ပါ rule နှင့် တူညီသော ရလဒ်များကို ပေးသည်-

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
### Event Count rule output:

အထက်ပါ rule များသည် အောက်ပါ output ကို ဖန်တီးပေးမည်ဖြစ်သည်-
```
% ./hayabusa dfir-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Value Count rules

ဤ rule များသည် အချိန်ကာလတစ်ခုအတွင်း သတ်မှတ်ထားသော field ၏ **မတူညီသော** တန်ဖိုးများဖြင့် တူညီသော event များကို ရေတွက်သည်။

ဥပမာများ-

- source IP address တစ်ခုတည်းက မတူညီသော destination IP address များနှင့်/သို့မဟုတ် port များစွာသို့ ချိတ်ဆက်ရန် ကြိုးစားသည့် Network scan များ။
- source တစ်ခုတည်းက မတူညီသော user များစွာဖြင့် authentication လုပ်ရန် မအောင်မြင်သည့် Password spraying တိုက်ခိုက်မှုများ။
- အချိန်တိုအတွင်း high-privilege AD group များစွာကို စစ်ဆေးဖော်ထုတ်သည့် BloodHound ကဲ့သို့သော tool များကို ဖော်ထုတ်ခြင်း။

### Value Count rule example:

အောက်ပါ rule သည် တိုက်ခိုက်သူတစ်ဦးက username များကို ခန့်မှန်းရန် ကြိုးစားနေသည့်အခါ ဖော်ထုတ်သည်။
ဆိုလိုသည်မှာ **တူညီသော** source IP address (`IpAddress`) သည် ၅ မိနစ်အတွင်း မတူညီသော username (`TargetUserName`) ၃ ခုထက်ပို၍ logon လုပ်ရန် မအောင်မြင်သည့်အခါ ဖြစ်သည်။

> သဘောတရားကို နားလည်ရန် လိုအပ်သော field များကိုသာ ကျွန်ုပ်တို့ ထည့်သွင်းထားကြောင်း သတိပြုပါ။
> ဤဥပမာ၏ အခြေခံဖြစ်သော rule အပြည့်အစုံကို သင့်ကိုးကားရန်အတွက် [ဤနေရာတွင်](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) ထားရှိသည်။

### Value Count correlation rule:

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

### Value Count Logon Failure (Non-existant User) rule:

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

### Deprecated `count` modifier rule:

အထက်ပါ correlation နှင့် ကိုးကားထားသော rule များသည် ပိုမိုဟောင်းသော `count` modifier ကို အသုံးပြုသည့် အောက်ပါ rule နှင့် တူညီသော ရလဒ်များကို ပေးသည်-

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

### Value Count rule output:

အထက်ပါ rule များသည် အောက်ပါ output ကို ဖန်တီးပေးမည်ဖြစ်သည်-
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Temporal Proximity rules

rule field မှ ကိုးကားထားသော rule များဖြင့် သတ်မှတ်ထားသော event အားလုံးသည် timespan ဖြင့် သတ်မှတ်ထားသော အချိန်ကာလအတွင်း ဖြစ်ပွားရမည်ဖြစ်သည်။
`group-by` တွင် သတ်မှတ်ထားသော field များ၏ တန်ဖိုးများသည် အားလုံး တူညီသော တန်ဖိုး ဖြစ်ရမည် (ဥပမာ- တူညီသော host, user စသည်...)။

### Temporal Proximity rule example:

ဥပမာ- Sigma rule သုံးခုတွင် သတ်မှတ်ထားသော Reconnaissance command များကို တူညီသော user တစ်ဦးက system တစ်ခုပေါ်တွင် ၅ မိနစ်အတွင်း မည်သည့်အစီအစဉ်ဖြင့်မဆို ခေါ်ယူသည်။

### Temporal Proximity correlation rule:

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

## Ordered Temporal Proximity rules

`temporal_ordered` correlation type သည် `temporal` ကဲ့သို့ ပြုမူပြီး၊ ထို့အပြင် event များသည် `rules` attribute တွင် ပေးထားသော အစီအစဉ်အတိုင်း ပေါ်လာရန်လည်း လိုအပ်သည်။

### Ordered Temporal Proximity rule example:

ဥပမာ- အထက်တွင် သတ်မှတ်ထားသည့်အတိုင်း failed login များစွာ၏နောက်တွင် တူညီသော user account မှ အောင်မြင်သော login တစ်ခုသည် ၁ နာရီအတွင်း ဖြစ်ပွားသည်-

### Ordered Temporal Proximity correlation rule:

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

## Notes on correlation rules

1. သင်၏ correlation နှင့် ကိုးကားထားသော rule အားလုံးကို file တစ်ခုတည်းတွင် ထည့်သွင်းပြီး `---` ၏ YAML separator ဖြင့် ခွဲခြားသင့်သည်။

2. default အားဖြင့် ကိုးကားထားသော correlation rule များကို output ထုတ်မည်မဟုတ်ပါ။ ကိုးကားထားသော rule များ၏ output ကို ကြည့်လိုပါက `correlation` အောက်တွင် `generate: true` ကို ထည့်ရန် လိုအပ်သည်။ ၎င်းသည် correlation rule များ ဖန်တီးသည့်အခါ ဖွင့်ပြီး စစ်ဆေးရန် အလွန်အသုံးဝင်သည်။

    ဥပမာ-
    ```
    correlation:
        generate: true
    ```
3. အရာများကို နားလည်ရန် ပိုမိုလွယ်ကူစေရန်အတွက် rule များကို ကိုးကားသည့်အခါ rule ID များအစား alias name များကို သုံးနိုင်သည်။

4. rule များစွာကို ကိုးကားနိုင်သည်။

5. `group-by` တွင် field များစွာကို သုံးနိုင်သည်။ ထိုသို့သုံးပါက ထို field များရှိ တန်ဖိုးအားလုံး တူညီရန် လိုအပ်ပြီး မဟုတ်ပါက သတိပေးချက် ရရှိမည်မဟုတ်ပါ။ အများအားဖြင့် false positive များကို လျှော့ချရန်အတွက် `group-by` ဖြင့် field အချို့ကို filter လုပ်သော rule များ ရေးသားလေ့ရှိသော်လည်း၊ ပိုမိုယေဘုယျသော rule တစ်ခု ဖန်တီးရန် `group-by` ကို ချန်လှပ်ထားနိုင်သည်။

6. correlation rule ၏ timestamp သည် တိုက်ခိုက်မှု၏ အစဦးဆုံးဖြစ်မည်ဖြစ်သောကြောင့် false positive ဟုတ်မဟုတ် အတည်ပြုရန် ထို့နောက်မှ event များကို စစ်ဆေးသင့်သည်။
