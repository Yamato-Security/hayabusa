# Timeline အထွက်

## Output Profiles

Hayabusa တွင် `config/profiles.yaml` တွင် အသုံးပြုရန် ကြိုတင်သတ်မှတ်ထားသော output profile ၅ ခု ရှိသည်:

1. `minimal`
2. `standard` (default)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

ဤဖိုင်ကို တည်းဖြတ်ခြင်းဖြင့် သင့်ကိုယ်ပိုင် profile များကို လွယ်ကူစွာ စိတ်ကြိုက်ပြင်ဆင်ခြင်း သို့မဟုတ် ထည့်သွင်းခြင်း ပြုလုပ်နိုင်သည်။
`set-default-profile --profile <profile>` ဖြင့် default profile ကိုလည်း လွယ်ကူစွာ ပြောင်းလဲနိုင်သည်။
ရရှိနိုင်သော profile များနှင့် ၎င်းတို့၏ field အချက်အလက်များကို ပြသရန် `list-profiles` command ကို အသုံးပြုပါ။

### 1. `minimal` profile output

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard` profile output

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose` profile output

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info` profile output

အနည်းဆုံး `details` အချက်အလက်ကို ထုတ်ပေးမည့်အစား၊ `EventData` နှင့် `UserData` အပိုင်းများရှိ field အချက်အလက်အားလုံးကို ၎င်းတို့၏ မူရင်း field အမည်များနှင့်အတူ ထုတ်ပေးမည်ဖြစ်သည်။

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose` profile output

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose` profile output

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal` profile output

[Timesketch](https://timesketch.org/) သို့ import လုပ်ခြင်းနှင့် တွဲဖက်အသုံးပြုနိုင်သော format သို့ ထုတ်ပေးသည်။

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose` profile output

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Profile နှိုင်းယှဉ်ချက်

အောက်ပါ benchmark များကို evtx data 3GB နှင့် rule 3891 ခု ဖွင့်ထားသော 2018 Lenovo P51 (Xeon 4 Core CPU / 64GB RAM) ပေါ်တွင် လုပ်ဆောင်ခဲ့သည်။ (2023/06/01)

| Profile | Processing Time | Output Filesize | Filesize Increase |
| :---: | :---: | :---: | :---: |
| minimal | 8 minutes 50 seconds | 770 MB | -30% |
| standard (default) | 9 minutes 00 seconds | 1.1 GB | None |
| verbose | 9 minutes 10 seconds | 1.3 GB | +20% |
| all-field-info | 9 minutes 3 seconds | 1.2 GB | +10% |
| all-field-info-verbose | 9 minutes 10 seconds | 1.3 GB | +20% |
| super-verbose | 9 minutes 12 seconds | 1.5 GB | +35% |

### Profile Field Aliases

အောက်ပါ အချက်အလက်များကို built-in output profile များဖြင့် ထုတ်ပေးနိုင်သည်:

| Alias name | Hayabusa output information|
| :--- | :--- |
|%AllFieldInfo% | Field အချက်အလက်အားလုံး။ |
|%Channel% | log ၏ အမည်။ `<Event><System><Channel>` field။ |
|%Computer% | `<Event><System><Computer>` field။ |
|%Details% | YML detection rule ရှိ `details` field ဖြစ်သော်လည်း hayabusa rule များတွင်သာ ဤ field ရှိသည်။ ဤ field သည် alert သို့မဟုတ် event အကြောင်း ထပ်ဆောင်းအချက်အလက်ကို ပေးပြီး event log များရှိ field များမှ အသုံးဝင်သော data ကို ထုတ်ယူနိုင်သည်။ ဥပမာ၊ username များ၊ command line အချက်အလက်၊ process အချက်အလက် စသည်တို့... placeholder တစ်ခုသည် မရှိသော field ကို ညွှန်ပြသည့်အခါ သို့မဟုတ် မှားယွင်းသော alias mapping ရှိသည့်အခါ `n/a` (not available) အဖြစ် ထုတ်ပေးမည်။ `details` field ကို မသတ်မှတ်ထားပါက (ဆိုလိုသည်မှာ sigma rule များ)၊ `./rules/config/default_details.txt` တွင် သတ်မှတ်ထားသော field များကို ထုတ်ယူရန် default `details` message များကို ထုတ်ပေးမည်။ `default_details.txt` တွင် ထုတ်ပေးလိုသော `Provider Name`၊ `EventID` နှင့် `details` message ကို ထည့်သွင်းခြင်းဖြင့် default `details` message များ ပိုမိုထည့်နိုင်သည်။ rule တွင်လည်းကောင်း `default_details.txt` တွင်လည်းကောင်း `details` field မသတ်မှတ်ထားသည့်အခါ field အားလုံးကို `details` column သို့ ထုတ်ပေးမည်။ |
|%ExtraFieldInfo% | %Details% တွင် ထုတ်မပေးခဲ့သော field အချက်အလက်ကို print ထုတ်သည်။ |
|%EventID% | `<Event><System><EventID>` field။ |
|%EvtxFile% | alert သို့မဟုတ် event ကို ဖြစ်ပေါ်စေသော evtx filename။ |
|%Level% | YML detection rule ရှိ `level` field။ (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [tactics](https://attack.mitre.org/tactics/enterprise/) (ဥပမာ: Initial Access, Lateral Movement, စသည်...)။ |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID နှင့် Software ID။ |
|%OtherTags% | `MitreTactics` သို့မဟုတ် `MitreTags` တွင် မပါဝင်သော YML detection rule ၏ `tags` field ရှိ မည်သည့် keyword မဆို။ |
|%Provider% | `<Event><System><Provider>` field ရှိ `Name` attribute။ |
|%RecordID% | `<Event><System><EventRecordID>` field မှ Event Record ID။ |
|%RuleAuthor% | YML detection rule ရှိ `author` field။ |
|%RuleCreationDate% | YML detection rule ရှိ `date` field။ |
|%RuleFile% | alert သို့မဟုတ် event ကို ဖြစ်ပေါ်စေသော detection rule ၏ filename။ |
|%RuleID% | YML detection rule ရှိ `id` field။ |
|%RuleModifiedDate% | YML detection rule ရှိ `modified` field။ |
|%RuleTitle% | YML detection rule ရှိ `title` field။ |
|%Status% | YML detection rule ရှိ `status` field။ |
|%Timestamp% | Default မှာ `YYYY-MM-DD HH:mm:ss.sss +hh:mm` format ဖြစ်သည်။ event log ရှိ `<Event><System><TimeCreated SystemTime>` field။ Default timezone သည် local timezone ဖြစ်မည်ဖြစ်သော်လည်း `--UTC` option ဖြင့် timezone ကို UTC သို့ ပြောင်းနိုင်သည်။ |

#### Extra Profile Field Alias

လိုအပ်ပါက သင့် output profile သို့ ဤ extra alias များကိုလည်း ထည့်နိုင်သည်:

| Alias name | Hayabusa output information|
| :--- | :--- |
|%RenderedMessage% | WEC forwarded log များရှိ `<Event><RenderingInfo><Message>` field။ |

မှတ်ချက်: ၎င်းသည် မည်သည့် built in profile တွင်မျှ ပါဝင်ခြင်း **မရှိ** သဖြင့် `config/default_profile.yaml` ဖိုင်ကို ကိုယ်တိုင်တည်းဖြတ်၍ အောက်ပါ line ကို ထည့်ရန် လိုအပ်မည်ဖြစ်သည်:

```
Message: "%RenderedMessage%"
```

အခြား field များကို ထုတ်ပေးရန် [event key aliases](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) ကိုလည်း သတ်မှတ်နိုင်သည်။
