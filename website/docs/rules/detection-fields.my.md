# Detection field

## Selection fundamentals

ပထမဦးစွာ၊ selection rule တစ်ခုကို မည်သို့ဖန်တီးရမည်ဆိုသည့် အခြေခံများကို ရှင်းပြပါမည်။

### AND နှင့် OR logic ရေးသားနည်း

AND logic ရေးသားရန် nested dictionary များကို အသုံးပြုပါသည်။
အောက်ပါ detection rule သည် rule ကိုက်ညီရန်အတွက် **အခြေအနေနှစ်ခုစလုံး** မှန်ကန်ရမည်ဟု သတ်မှတ်ထားသည်။
- EventID သည် `7040` အတိအကျ ဖြစ်ရမည်။
- **AND**
- Channel သည် `System` အတိအကျ ဖြစ်ရမည်။

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

OR logic ရေးသားရန် list များ (`-` ဖြင့်စတင်သော dictionary များ) ကို အသုံးပြုပါသည်။
အောက်ပါ detection rule တွင် အခြေအနေများ၏ **တစ်ခုခု** က rule ကို အစပျိုးစေပါမည်။
- EventID သည် `7040` အတိအကျ ဖြစ်ရမည်။
- **OR**
- Channel သည် `System` အတိအကျ ဖြစ်ရမည်။

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

`AND` နှင့် `OR` logic ကို အောက်ပါအတိုင်း ပေါင်းစပ်အသုံးပြုနိုင်ပါသည်။
ဤကိစ္စတွင် အောက်ပါ အခြေအနေနှစ်ခုစလုံး မှန်ကန်သောအခါ rule ကိုက်ညီပါသည်။
- EventID သည် `7040` **OR** `7041` အတိအကျ ဖြစ်ရမည်။
- **AND**
- Channel သည် `System` အတိအကျ ဖြစ်ရမည်။

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

အောက်ပါသည် မူရင်း XML ဖြင့် ဖော်ပြထားသော Windows event log တစ်ခု၏ ကောက်နုတ်ချက်ဖြစ်သည်။
အထက်ပါ rule file ဥပမာတွင်ပါဝင်သော `Event.System.Channel` field သည် မူရင်း XML tag ဖြစ်သော `<Event><System><Channel>System<Channel><System></Event>` ကို ရည်ညွှန်းသည်။
Nested XML tag များကို tag အမည်များဖြင့် အစက် (`.`) ခြားထားသည့်ပုံစံဖြင့် အစားထိုးထားသည်။
hayabusa rule များတွင် အစက်များဖြင့် ဆက်စပ်ထားသော ဤ field string များကို `eventkeys` ဟုခေါ်သည်။

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

#### Eventkey Aliases

`.` ခြားများစွာပါသော ရှည်လျားသည့် eventkey များသည် အဖြစ်များသောကြောင့်၊ hayabusa သည် ၎င်းတို့ကို ပိုမိုလွယ်ကူစွာ အသုံးပြုနိုင်ရန် alias များကို အသုံးပြုပါမည်။ Alias များကို `rules/config/eventkey_alias.txt` ဖိုင်တွင် သတ်မှတ်ထားသည်။ ဤဖိုင်သည် `alias` နှင့် `event_key` mapping များဖြင့် ဖွဲ့စည်းထားသော CSV ဖိုင်ဖြစ်သည်။ အထက်ပါ rule ကို alias များဖြင့် အောက်ပါအတိုင်း ပြန်လည်ရေးသားနိုင်ပြီး rule ကို ပိုမိုဖတ်ရှုလွယ်စေပါသည်။

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### သတိပြုရန်: သတ်မှတ်မထားသော Eventkey Alias များ

Eventkey alias အားလုံးကို `rules/config/eventkey_alias.txt` တွင် သတ်မှတ်ထားခြင်းမရှိပါ။ အကယ်၍ `details` (`Alert details`) message တွင် မှန်ကန်သော data ကို မရရှိဘဲ `n/a` (not available) ကိုသာ ရရှိနေပါက သို့မဟုတ် သင်၏ detection logic ထဲရှိ selection သည် မှန်ကန်စွာ အလုပ်မလုပ်ပါက `rules/config/eventkey_alias.txt` ကို alias အသစ်ဖြင့် ပြင်ဆင်ရန် လိုအပ်နိုင်ပါသည်။

### Condition များတွင် XML attribute များကို အသုံးပြုနည်း

XML element များတွင် element ၌ space တစ်ခုထည့်ခြင်းဖြင့် သတ်မှတ်ထားသော attribute များ ရှိနိုင်ပါသည်။ ဥပမာအားဖြင့် အောက်ပါ `Provider Name` ထဲရှိ `Name` သည် `Provider` element ၏ XML attribute ဖြစ်သည်။

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

Eventkey တစ်ခုတွင် XML attribute များကို သတ်မှတ်ရန် `{eventkey}_attributes.{attribute_name}` format ကို အသုံးပြုပါ။ ဥပမာအားဖြင့် rule file တစ်ခုတွင် `Provider` element ၏ `Name` attribute ကို သတ်မှတ်ရန် အောက်ပါအတိုင်း ဖြစ်မည်ဖြစ်သည်။

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep search

Hayabusa သည် eventkey မည်သည့်တစ်ခုကိုမျှ မသတ်မှတ်ဘဲ Windows event log ဖိုင်များတွင် grep search များ ပြုလုပ်နိုင်ပါသည်။

grep search တစ်ခုပြုလုပ်ရန် detection ကို အောက်ပါအတိုင်း သတ်မှတ်ပါ။ ဤကိစ္စတွင် `mimikatz` သို့မဟုတ် `metasploit` string များ Windows Event log တွင် ပါဝင်ပါက ကိုက်ညီပါမည်။ wildcard များကိုလည်း သတ်မှတ်နိုင်ပါသည်။

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Note: Hayabusa သည် data ကို မလုပ်ဆောင်မီ Windows event log data ကို JSON format သို့ အတွင်းပိုင်းတွင် ပြောင်းလဲသောကြောင့် XML tag များပေါ်တွင် ကိုက်ညီခြင်း မပြုလုပ်နိုင်ပါ။

### EventData

Windows event log များကို အပိုင်းနှစ်ပိုင်း ခွဲထားသည်။ အခြေခံ data (Event ID, Timestamp, Record ID, Log name (Channel)) ကို ရေးထားသော `System` အပိုင်းနှင့်၊ Event ID ပေါ်မူတည်၍ မည်သည့် data ကိုမဆို ရေးထားသော `EventData` သို့မဟုတ် `UserData` အပိုင်းတို့ဖြစ်သည်။
မကြာခဏ ဖြစ်ပေါ်လေ့ရှိသော ပြဿနာတစ်ခုမှာ `EventData` ထဲတွင် nest လုပ်ထားသော field များ၏ အမည်များအားလုံးကို `Data` ဟုခေါ်သောကြောင့်၊ ယခုအထိ ဖော်ပြခဲ့သော eventkey များသည် `SubjectUserSid` နှင့် `SubjectUserName` ကို ခွဲခြားနိုင်ခြင်းမရှိပါ။

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

ဤပြဿနာကို ဖြေရှင်းရန် `Data Name` တွင် သတ်မှတ်ထားသော value ကို သတ်မှတ်နိုင်ပါသည်။ ဥပမာအားဖြင့် EventData ထဲရှိ `SubjectUserName` နှင့် `SubjectDomainName` ကို rule တစ်ခု၏ condition အဖြစ် အသုံးပြုလိုပါက အောက်ပါအတိုင်း ဖော်ပြနိုင်ပါသည်။

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventData ရှိ ပုံမှန်မဟုတ်သော pattern များ

`EventData` ထဲတွင် nest လုပ်ထားသော tag အချို့တွင် `Name` attribute မရှိပါ။

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

အထက်ပါကဲ့သို့ event log တစ်ခုကို detect လုပ်ရန် `Data` အမည်ရှိ eventkey တစ်ခုကို သတ်မှတ်နိုင်ပါသည်။
ဤကိစ္စတွင် nest လုပ်ထားသော `Data` tag များ၏ တစ်ခုခုက `None` နှင့်ညီသရွေ့ condition ကိုက်ညီပါမည်။

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### အမည်တူ field အများအပြားမှ field data ကို output ထုတ်ခြင်း

အချို့ event များသည် ၎င်းတို့၏ data ကို ယခင်ဥပမာကဲ့သို့ `Data` ဟုခေါ်သော field အမည်များတွင် သိမ်းဆည်းကြသည်။
`details:` တွင် `%Data%` ကို သတ်မှတ်ပါက data အားလုံးကို array တစ်ခုအဖြစ် output ထုတ်ပေးပါမည်။

ဥပမာအားဖြင့်:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

ပထမဆုံး `Data` field data ကိုသာ print ထုတ်လိုပါက သင်၏ `details:` alert string တွင် `%Data[1]%` ကို သတ်မှတ်နိုင်ပြီး `rundll32.exe` ကိုသာ output ထုတ်ပေးပါမည်။

## Field Modifiers

string များ ကိုက်ညီမှုအတွက် eventkey များနှင့်အတူ pipe character ကို အောက်ပါအတိုင်း အသုံးပြုနိုင်ပါသည်။
ယခုအထိ ဖော်ပြခဲ့သော condition အားလုံးသည် exact match များ အသုံးပြုသော်လည်း၊ field modifier များ အသုံးပြုခြင်းဖြင့် ပိုမိုပြောင်းလွယ်ပြင်လွယ်ရှိသော detection rule များကို ဖော်ပြနိုင်ပါသည်။
အောက်ပါဥပမာတွင် `Data` ၏ value တစ်ခုသည် `EngineVersion=2` string ပါဝင်ပါက condition ကိုက်ညီပါမည်။

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

String match များသည် စာလုံးအကြီးအသေး ခွဲခြားမှုမရှိပါ။ သို့သော် `|re` သို့မဟုတ် `|equalsfield` ကို အသုံးပြုသည့်အခါတိုင်း ၎င်းတို့သည် စာလုံးအကြီးအသေး ခွဲခြားမှုရှိလာပါသည်။

### Support လုပ်ထားသော Sigma Field Modifier များ

Hayabusa သည် Sigma specification အားလုံးကို အပြည့်အဝ support လုပ်သော တစ်ခုတည်းသော open-source tool လက်ရှိတွင် ဖြစ်ပါသည်။

Support လုပ်ထားသော field modifier အားလုံး၏ လက်ရှိအခြေအနေနှင့် ၎င်း modifier များကို Sigma နှင့် Hayabusa rule များတွင် မည်မျှအသုံးပြုထားသည်ကို https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md တွင် စစ်ဆေးနိုင်ပါသည်။
ဤစာရွက်စာတမ်းကို Sigma သို့မဟုတ် Hayabusa rule များ update ဖြစ်တိုင်း dynamic ပုံစံဖြင့် update လုပ်ပါသည်။

- `'|all':`: ဤ field modifier သည် အထက်ပါတို့နှင့် ကွဲပြားသည်။ အကြောင်းမှာ ၎င်းသည် field တစ်ခုခုပေါ်တွင် မဟုတ်ဘဲ field အားလုံးပေါ်တွင် အသုံးပြုသောကြောင့်ဖြစ်သည်။

    ဤဥပမာတွင် `Keyword-1` နှင့် `Keyword-2` string နှစ်ခုစလုံး တည်ရှိရန်လိုသော်လည်း မည်သည့် field တွင်မဆို မည်သည့်နေရာတွင်မဆို တည်ရှိနိုင်ပါသည်။
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Data ကို encode လုပ်ထားသော string ထဲတွင် ၎င်း၏နေရာပေါ်မူတည်၍ နည်းလမ်းသုံးမျိုးဖြင့် base64 သို့ encode လုပ်ပါမည်။ ဤ modifier သည် string တစ်ခုကို variation သုံးမျိုးစလုံးသို့ encode လုပ်ပြီး၊ string ကို base64 string ၏ တစ်နေရာရာတွင် encode လုပ်ထားခြင်း ရှိမရှိ စစ်ဆေးပါမည်။
- `|cased`: search ကို စာလုံးအကြီးအသေး ခွဲခြားမှုရှိစေသည်။
- `|cidr`: field value တစ်ခုသည် IPv4 သို့မဟုတ် IPv6 CIDR notation နှင့် ကိုက်ညီမှုရှိမရှိ စစ်ဆေးသည်။ (ဥပမာ: `192.0.2.0/24`)
- `|contains`: field value တစ်ခုတွင် string တစ်ခု ပါဝင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|contains|all`: data ထဲတွင် စကားလုံးအများအပြား ပါဝင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|contains|all|windash`: `|contains|windash` နှင့်တူသော်လည်း keyword အားလုံး ပါရှိရန်လိုသည်။
- `|contains|cased`: field value တစ်ခုတွင် စာလုံးအကြီးအသေး ခွဲခြားသော string တစ်ခု ပါဝင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|contains|expand`: field value တစ်ခုတွင် `/config/expand/` အတွင်းရှိ `expand` config ဖိုင်ထဲက string တစ်ခု ပါဝင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|contains|windash`: string ကို ရှိသည့်အတိုင်း စစ်ဆေးမည်ဖြစ်သလို၊ ပထမဆုံး `-` character ကို `/`, `–` (en dash), `—` (em dash), နှင့် `―` (horizontal bar) character permutation များသို့ ပြောင်းလဲ၍လည်း စစ်ဆေးပါမည်။
- `|endswith`: field value တစ်ခုသည် string တစ်ခုဖြင့် အဆုံးသတ်မှုရှိမရှိ စစ်ဆေးသည်။
- `|endswith|cased`: field value တစ်ခုသည် စာလုံးအကြီးအသေး ခွဲခြားသော string တစ်ခုဖြင့် အဆုံးသတ်မှုရှိမရှိ စစ်ဆေးသည်။
- `|endswith|windash`: string ၏ အဆုံးကို စစ်ဆေးပြီး dash များအတွက် variation များ ပြုလုပ်သည်။
- `|exists`: field တစ်ခု တည်ရှိမှုရှိမရှိ စစ်ဆေးသည်။
- `|expand`: field value တစ်ခုသည် `/config/expand/` အတွင်းရှိ `expand` config ဖိုင်ထဲက string တစ်ခုနှင့် ညီမှုရှိမရှိ စစ်ဆေးသည်။
- `|fieldref`: field နှစ်ခုရှိ value များ တူညီမှုရှိမရှိ စစ်ဆေးသည်။ field နှစ်ခု ကွဲပြားမှုရှိမရှိ စစ်ဆေးလိုပါက `condition` တွင် `not` ကို အသုံးပြုနိုင်သည်။
- `|fieldref|contains`: field တစ်ခု၏ value သည် အခြား field တစ်ခုတွင် ပါဝင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|fieldref|endswith`: ဘယ်ဘက်ရှိ field သည် ညာဘက်ရှိ field ၏ string ဖြင့် အဆုံးသတ်မှုရှိမရှိ စစ်ဆေးသည်။ ၎င်းတို့ ကွဲပြားမှုရှိမရှိ စစ်ဆေးရန် `condition` တွင် `not` ကို အသုံးပြုနိုင်သည်။
- `|fieldref|startswith`: ဘယ်ဘက်ရှိ field သည် ညာဘက်ရှိ field ၏ string ဖြင့် စတင်မှုရှိမရှိ စစ်ဆေးသည်။ ၎င်းတို့ ကွဲပြားမှုရှိမရှိ စစ်ဆေးရန် `condition` တွင် `not` ကို အသုံးပြုနိုင်သည်။
- `|gt`: field value တစ်ခုသည် ဂဏန်းတစ်ခုထက် ကြီးမှုရှိမရှိ စစ်ဆေးသည်။
- `|gte`: field value တစ်ခုသည် ဂဏန်းတစ်ခုထက် ကြီးမှု သို့မဟုတ် ညီမှုရှိမရှိ စစ်ဆေးသည်။
- `|lt`: field value တစ်ခုသည် ဂဏန်းတစ်ခုထက် ငယ်မှုရှိမရှိ စစ်ဆေးသည်။
- `|lte`: field value တစ်ခုသည် ဂဏန်းတစ်ခုထက် ငယ်မှု သို့မဟုတ် ညီမှုရှိမရှိ စစ်ဆေးသည်။
- `|re`: စာလုံးအကြီးအသေး ခွဲခြားသော regular expression များကို အသုံးပြုသည်။ (ကျွန်ုပ်တို့သည် regex crate ကို အသုံးပြုနေသောကြောင့် support လုပ်ထားသော regular expression များ မည်သို့ရေးသားရမည်ကို လေ့လာရန် <https://docs.rs/regex/latest/regex/#syntax> ရှိ documentation ကို ကြည့်ရှုပါ။)
    > သတိပြုရန်: [Sigma rule များရှိ Regular expression syntax](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) သည် character class, lookbehind, atomic grouping စသည်တို့အတွက် metacharacter အချို့ support မလုပ်သော PCRE ကို အသုံးပြုသည်။ Rust regex crate သည် Sigma rule များရှိ regular expression အားလုံးကို အသုံးပြုနိုင်ရမည်ဖြစ်သော်လည်း မကိုက်ညီမှု ဖြစ်နိုင်ခြေ ရှိပါသည်။ 
- `|re|i`: (Insensitive) စာလုံးအကြီးအသေး ခွဲခြားမှုမရှိသော regular expression များကို အသုံးပြုသည်။
- `|re|m`: (Multi-line) စာကြောင်းအများအပြားကို ဖြတ်၍ ကိုက်ညီစစ်ဆေးသည်။ `^` / `$` သည် စာကြောင်း၏ အစ/အဆုံးကို ကိုက်ညီသည်။
- `|re|s`: (Single-line) dot (`.`) သည် newline character အပါအဝင် character အားလုံးကို ကိုက်ညီသည်။
- `|startswith`: field value တစ်ခုသည် string တစ်ခုဖြင့် စတင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|startswith|cased`: field value တစ်ခုသည် စာလုံးအကြီးအသေး ခွဲခြားသော string တစ်ခုဖြင့် စတင်မှုရှိမရှိ စစ်ဆေးသည်။
- `|utf16|base64offset|contains`: သတ်မှတ်ထားသော UTF-16 string တစ်ခုသည် base64 string တစ်ခုအတွင်း encode လုပ်ထားခြင်း ရှိမရှိ စစ်ဆေးသည်။
- `|utf16be|base64offset|contains`: သတ်မှတ်ထားသော UTF-16 big-endian string တစ်ခုသည် base64 string တစ်ခုအတွင်း encode လုပ်ထားခြင်း ရှိမရှိ စစ်ဆေးသည်။
- `|utf16le|base64offset|contains`: သတ်မှတ်ထားသော UTF-16 little-endian string တစ်ခုသည် base64 string တစ်ခုအတွင်း encode လုပ်ထားခြင်း ရှိမရှိ စစ်ဆေးသည်။
- `|wide|base64offset|contains`: `utf16le|base64offset|contains` ၏ alias ဖြစ်ပြီး UTF-16 little-endian string များကို စစ်ဆေးသည်။

### အသုံးမပြုတော့သော Field Modifier များ

အောက်ပါ modifier များသည် ယခုအခါ အသုံးမပြုတော့ဘဲ sigma specification များနှင့် ပိုမိုကိုက်ညီသော modifier များဖြင့် အစားထိုးထားပါသည်။

- `|equalsfield`: ယခုအခါ `|fieldref` ဖြင့် အစားထိုးထားသည်။
- `|endswithfield`: ယခုအခါ `|fieldref|endswith` ဖြင့် အစားထိုးထားသည်။

### Expand Field Modifier များ

`expand` field modifier များသည် ထူးခြားသည်။ အကြောင်းမှာ ၎င်းတို့သည် အသုံးပြုရန် ကြိုတင်ပြင်ဆင်ခြင်း လိုအပ်သော တစ်ခုတည်းသော field modifier ဖြစ်သောကြောင့်ဖြစ်သည်။
ဥပမာအားဖြင့် ၎င်းတို့သည် `%DC-MACHINE-NAME%` ကဲ့သို့သော placeholder များကို အသုံးပြုပြီး၊ ဖြစ်နိုင်သော DC machine အမည်အားလုံးပါဝင်သော `/config/expand/DC-MACHINE-NAME.txt` အမည်ရှိ config ဖိုင်တစ်ခု လိုအပ်ပါသည်။

ဤအရာကို မည်သို့ configure လုပ်ရမည်ကို [ဤနေရာ](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command) တွင် ပိုမိုအသေးစိတ် ရှင်းပြထားပါသည်။

## Wildcard များ

Eventkey များတွင် wildcard များကို အသုံးပြုနိုင်ပါသည်။ အောက်ပါဥပမာတွင် `ProcessCommandLine` သည် "malware" string ဖြင့် စတင်ပါက rule ကိုက်ညီပါမည်။
specification သည် sigma rule wildcard များနှင့် အခြေခံအားဖြင့် တူညီသောကြောင့် စာလုံးအကြီးအသေး ခွဲခြားမှုမရှိပါ။

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

အောက်ပါ wildcard နှစ်ခုကို အသုံးပြုနိုင်ပါသည်။
- `*`: character သုညခု သို့မဟုတ် ထို့ထက်ပိုသော မည်သည့် string ကိုမဆို ကိုက်ညီသည်။ (အတွင်းပိုင်းတွင် regular expression `.*` သို့ ပြောင်းလဲသည်။)
- `?`: မည်သည့် character တစ်လုံးကိုမဆို ကိုက်ညီသည်။ (အတွင်းပိုင်းတွင် regular expression `.` သို့ ပြောင်းလဲသည်။)

Wildcard များ escape လုပ်ခြင်းအကြောင်း:
- Wildcard များ (`*` နှင့် `?`) ကို backslash အသုံးပြု၍ escape လုပ်နိုင်သည်: `\*`, `\?`။
- Wildcard တစ်ခု၏ ရှေ့တွင်တိုက်ရိုက် backslash တစ်ခုကို အသုံးပြုလိုပါက `\\*` သို့မဟုတ် `\\?` ဟု ရေးပါ။
- Backslash များကို သီးသန့်အသုံးပြုနေပါက escape လုပ်ရန် မလိုအပ်ပါ။

## null keyword

`null` keyword ကို field တစ်ခု မတည်ရှိခြင်း ရှိမရှိ စစ်ဆေးရန် အသုံးပြုနိုင်ပါသည်။

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Note: ဤအရာသည် field တစ်ခု၏ value ဗလာဖြစ်မှုရှိမရှိ စစ်ဆေးသော `ProcessCommandLine: ''` နှင့် ကွဲပြားပါသည်။

## condition

အထက်တွင် ရှင်းပြခဲ့သော notation ဖြင့် `AND` နှင့် `OR` logic ကို ဖော်ပြနိုင်သော်လည်း၊ ရှုပ်ထွေးသော logic ကို သတ်မှတ်ရန် ကြိုးစားပါက ၎င်းသည် ရှုပ်ထွေးနိုင်ပါသည်။
ပိုမိုရှုပ်ထွေးသော rule များ ပြုလုပ်လိုသောအခါ အောက်ပါအတိုင်း `condition` keyword ကို အသုံးပြုသင့်ပါသည်။

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

`condition` အတွက် အောက်ပါ expression များကို အသုံးပြုနိုင်ပါသည်။
- `{expression1} and {expression2}`: {expression1} AND {expression2} နှစ်ခုစလုံး လိုအပ်သည်
- `{expression1} or {expression2}`: {expression1} OR {expression2} တစ်ခုခု လိုအပ်သည်
- `not {expression}`: {expression} ၏ logic ကို ပြောင်းပြန်လှန်သည်
- `( {expression} )`: {expression} ၏ ဦးစားပေးအဆင့်ကို သတ်မှတ်သည်။ ၎င်းသည် သင်္ချာတွင်ကဲ့သို့ ဦးစားပေး logic အတိုင်း လိုက်နာသည်။

အထက်ပါဥပမာတွင် `SELECTION_1`, `SELECTION_2` စသည့် selection အမည်များကို အသုံးပြုထားသော်လည်း၊ ၎င်းတို့တွင် အောက်ပါ character များသာ ပါဝင်သရွေ့ မည်သည့်အမည်ကိုမဆို ပေးနိုင်ပါသည်: `a-z A-Z 0-9 _`
> သို့သော် ဖြစ်နိုင်သမျှ ဖတ်ရှုလွယ်စေရန် `selection_1`, `selection_2`, `filter_1`, `filter_2` စသည့် standard convention ကို အသုံးပြုပါ။

## not logic

Rule များစွာသည် false positive များ ဖြစ်ပေါ်စေသောကြောင့်၊ ရှာဖွေရန် signature များအတွက် selection တစ်ခုရှိရုံသာမက false positive များတွင် alert မထုတ်ရန် filter selection တစ်ခုလည်း ရှိခြင်းမှာ အလွန်အဖြစ်များပါသည်။
ဥပမာအားဖြင့်:

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

Sigma version 2.0.0 correlation အားလုံးကို [ဤနေရာ](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md) တွင် သတ်မှတ်ထားသည့်အတိုင်း ကျွန်ုပ်တို့ အကောင်အထည်ဖော်ထားပါသည်။

Support လုပ်ထားသော correlation များ:
- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

၂၀၂၅ ခုနှစ် စက်တင်ဘာ ၁၂ ရက်တွင် Sigma version 2.1.0 တွင် ထွက်ရှိခဲ့သော "metrics" correlation rule အသစ်များ (`value_sum`, `value_avg`, `value_percentile`) ကို လက်ရှိတွင် support မလုပ်ပါ။
