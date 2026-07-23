# Hayabusa ၏ ရလဒ်များကို jq ဖြင့် ခွဲခြမ်းစိတ်ဖြာခြင်း

# ရေးသားသူ

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# အကြောင်းအရာ

log များအတွင်းရှိ အရေးကြီးသော field များကို ဖော်ထုတ်ခြင်း၊ ထုတ်နုတ်ခြင်း နှင့် metric များ ဖန်တီးနိုင်ခြင်းသည် DFIR နှင့် threat hunting ခွဲခြမ်းစိတ်ဖြာသူများအတွက် မရှိမဖြစ် လိုအပ်သော ကျွမ်းကျင်မှုတစ်ခု ဖြစ်သည်။
Hayabusa ၏ ရလဒ်များကို timeline ခွဲခြမ်းစိတ်ဖြာမှုအတွက် Excel သို့မဟုတ် Timeline Explorer ကဲ့သို့သော ပရိုဂရမ်များထဲသို့ ထည့်သွင်းနိုင်ရန် ပုံမှန်အားဖြင့် `.csv` ဖိုင်များတွင် သိမ်းဆည်းလေ့ရှိသည်။
သို့သော် တူညီသော event ရာဂဏန်းနှင့်အထက် ရှိလာသောအခါ ၎င်းတို့ကို ကိုယ်တိုင် စစ်ဆေးရန် လက်တွေ့မကျတော့ဘဲ မဖြစ်နိုင်တော့ပါ။
ဤအခြေအနေများတွင် ခွဲခြမ်းစိတ်ဖြာသူများသည် ပုံမှန်အားဖြင့် တူညီသော data အမျိုးအစားများကို စီစဉ်ပြီး ရေတွက်ကာ ထူးကဲသော အရာများ (outliers) ကို ရှာဖွေလေ့ရှိသည်။
ဤနည်းကို long tail analysis, stack ranking, frequency analysis စသည်ဖြင့်လည်း ခေါ်ဆိုကြသည်...
၎င်းကို Hayabusa ဖြင့် ရလဒ်များကို `.json` သို့မဟုတ် `.jsonl` ဖိုင်များအဖြစ် ထုတ်ပြီးနောက် `jq` ဖြင့် ခွဲခြမ်းစိတ်ဖြာခြင်းဖြင့် ဆောင်ရွက်နိုင်သည်။

ဥပမာအားဖြင့်၊ ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးသည် အဖွဲ့အစည်းတစ်ခုရှိ workstation အားလုံးတွင် တပ်ဆင်ထားသော service များကို နှိုင်းယှဉ်နိုင်သည်။
malware တစ်ခုသည် workstation တိုင်းတွင် တပ်ဆင်ခံရနိုင်ခြေ ရှိသော်လည်း၊ system အနည်းငယ်တွင်သာ ရှိနေဖို့ ပိုများသည်။
ဤကိစ္စတွင် system အားလုံးတွင် တပ်ဆင်ထားသော service များသည် အန္တရာယ်ကင်းဖို့ ပိုများပြီး၊ ရှားပါးသော service များက ပို၍ သံသယဖြစ်ဖွယ်ဖြစ်တတ်ကာ အချိန်အပိုင်းအခြားတွင် စစ်ဆေးသင့်သည်။

အခြားအသုံးပြုနိုင်သည့် ကိစ္စတစ်ခုမှာ တစ်ခုခုသည် မည်မျှ သံသယဖြစ်ဖွယ်ရှိသည်ကို ဆုံးဖြတ်ရန် ကူညီခြင်းဖြစ်သည်။
ဥပမာအားဖြင့်၊ ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးသည် `4625` failed logon log များကို ခွဲခြမ်းစိတ်ဖြာ၍ IP address တစ်ခုသည် မည်မျှအကြိမ် logon ဝင်ရန် မအောင်မြင်ခဲ့သည်ကို ဆုံးဖြတ်နိုင်သည်။
failed logon အနည်းငယ်သာ ရှိပါက၊ administrator တစ်ဦးက password ကို ရိုက်မှားခဲ့ဖို့သာ ဖြစ်နိုင်သည်။
သို့သော် IP address တစ်ခုက အချိန်တိုအတွင်း failed logon ရာဂဏန်းနှင့်အထက် ရှိနေပါက၊ ထို IP address သည် အန္တရာယ်ရှိဖို့ ဖြစ်နိုင်သည်။

`jq` ကို အသုံးပြုနည်း သင်ယူခြင်းသည် Windows event log များကို ခွဲခြမ်းစိတ်ဖြာခြင်းသာမက JSON ဖော်မတ်ဖြင့် log အားလုံးကိုပါ ကျွမ်းကျင်ရန် ကူညီပေးပါမည်။
ယခုအခါ JSON သည် အလွန်ရေပန်းစားသော log ဖော်မတ်တစ်ခု ဖြစ်လာပြီး cloud provider အများစုက ၎င်းတို့၏ log များအတွက် အသုံးပြုနေသဖြင့် ၎င်းတို့ကို `jq` ဖြင့် parse လုပ်နိုင်ခြင်းသည် ခေတ်မီ security ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးအတွက် မရှိမဖြစ်လိုအပ်သော ကျွမ်းကျင်မှုတစ်ခု ဖြစ်လာသည်။

ဤလမ်းညွှန်တွင် `jq` ကို တစ်ခါမှ မသုံးဖူးသူများအတွက် ၎င်းကို မည်သို့အသုံးချရမည်ကို ဦးစွာ ရှင်းပြပြီးနောက် ပိုမိုရှုပ်ထွေးသော အသုံးပြုနည်းများကို လက်တွေ့ဥပမာများနှင့်အတူ ရှင်းပြသွားမည်ဖြစ်သည်။
`jq` ကို `sort`, `uniq`, `grep`, `sed` စသည့် အခြားအသုံးဝင်သော command များနှင့် ပေါင်းစပ်အသုံးပြုနိုင်ရန် linux, macOS သို့မဟုတ် Windows ပေါ်ရှိ linux ကို အသုံးပြုရန် အကြံပြုပါသည်...

# jq တပ်ဆင်ခြင်း

[https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) ကို ကိုးကားပြီး `jq` command ကို တပ်ဆင်ပါ။

# JSON ဖော်မတ်အကြောင်း

JSON log များသည် curly bracket `{` `}` အတွင်း ပါဝင်သော object များ၏ စာရင်းတစ်ခု ဖြစ်သည်။
ဤ object များအတွင်းတွင် colon များဖြင့် ပိုင်းခြားထားသော key-value pair များ ရှိသည်။
key များသည် string ဖြစ်ရမည်၊ သို့သော် value များသည် အောက်ပါတို့အနက် တစ်ခုခု ဖြစ်နိုင်သည်−
  * string (ဥပမာ: `"string"`)
  * number (ဥပမာ: `10`)
  * အခြား object (ဥပမာ: `{ xxxx }`)
  * array (ဥပမာ: `["string", 10]`)
  * boolean (ဥပမာ: `true`, `false`)
  * `null`

object များအတွင်းတွင် object များကို သင်လိုသလောက် nest လုပ်နိုင်သည်။

ဤဥပမာတွင် `Details` သည် root object တစ်ခုအတွင်းရှိ nested object တစ်ခု ဖြစ်သည်−
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Hayabusa ဖြင့် JSON နှင့် JSONL ဖော်မတ်များအကြောင်း

အစောပိုင်း version များတွင် Hayabusa သည် `{ xxx }` log object အားလုံးကို array ကြီးတစ်ခုထဲ ထည့်သွင်းသည့် ရိုးရာ JSON ဖော်မတ်ကို အသုံးပြုခဲ့သည်။

ဥပမာ:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

ဤနေရာတွင် ပြဿနာ နှစ်ခု ရှိသည်။
ပထမပြဿနာမှာ အရာအားလုံးသည် ထို array အတွင်းသို့ ကြည့်ရန် ပြောရန် အပို `.[]` ဖြင့် စတင်ရသဖြင့် `jq` query များသည် ပို၍ ရှုပ်ထွေးလာခြင်း ဖြစ်သည်။
ပိုကြီးသော ပြဿနာမှာ ထိုသို့သော log များကို parse လုပ်ရန်အတွက် array အတွင်းရှိ data အားလုံးကို ဦးစွာ load လုပ်ရန် လိုအပ်ခြင်း ဖြစ်သည်။
JSON ဖိုင် အလွန်ကြီးပြီး memory ပေါများမှု မရှိပါက ၎င်းသည် ပြဿနာဖြစ်လာသည်။
လိုအပ်သော CPU နှင့် memory အသုံးပြုမှုကို လျှော့ချရန်အတွက် အရာအားလုံးကို array ကြီးတစ်ခုထဲ မထည့်သွင်းသော JSONL (JSON Lines) ဖော်မတ်သည် ပို၍ ရေပန်းစားလာသည်။
Hayabusa သည် JSON နှင့် JSONL ဖော်မတ်များဖြင့် ထုတ်ပေးသည်၊ သို့သော် JSON ဖော်မတ်ကို array အတွင်း မသိမ်းဆည်းတော့ပါ။
ကွဲပြားချက်တစ်ခုတည်းမှာ JSON ဖော်မတ်သည် text editor သို့မဟုတ် console ပေါ်တွင် ဖတ်ရန် ပိုလွယ်ကူပြီး၊ JSONL ဖော်မတ်သည် JSON object တိုင်းကို တစ်ကြောင်းတည်းတွင် သိမ်းဆည်းခြင်း ဖြစ်သည်။
JSONL ဖော်မတ်သည် အနည်းငယ် ပိုမြန်ပြီး အရွယ်အစား ပိုသေးငယ်သဖြင့် log များကို SIEM စသည်ထဲသို့ ထည့်သွင်းရုံသာ ပြုလုပ်ပြီး ၎င်းတို့ကို မကြည့်ပါက သင့်တော်သည်...
JSON ဖော်မတ်သည် ကိုယ်တိုင် စစ်ဆေးမှု အချို့ ပြုလုပ်မည်ဆိုပါက သင့်တော်သည်။

# JSON ရလဒ်ဖိုင်များ ဖန်တီးခြင်း

လက်ရှိ Hayabusa 2.x version တွင် ရလဒ်များကို `hayabusa dfir-timeline -t json -d <directory> -o results.json` ဖြင့် JSON အဖြစ်လည်းကောင်း၊ JSONL ဖော်မတ်အတွက် `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` ဖြင့်လည်းကောင်း သိမ်းဆည်းနိုင်သည်။

Hayabusa သည် default `standard` profile ကို အသုံးပြုပြီး `Details` object အတွင်း ခွဲခြမ်းစိတ်ဖြာရန်အတွက် အနည်းဆုံး data ပမာဏကိုသာ သိမ်းဆည်းမည်ဖြစ်သည်။
.evtx log များရှိ မူရင်း field အချက်အလက်အားလုံးကို သိမ်းဆည်းလိုပါက `--profile all-field-info` option ဖြင့် `all-field-info` profile ကို အသုံးပြုနိုင်သည်။
၎င်းသည် field အချက်အလက်အားလုံးကို `AllFieldInfo` object သို့ သိမ်းဆည်းမည်ဖြစ်သည်။
ကြိုတင်ကာကွယ်သည့်အနေဖြင့် `Details` နှင့် `AllFieldInfo` object နှစ်ခုစလုံးကို သိမ်းဆည်းလိုပါက `super-verbose` profile ကို အသုံးပြုနိုင်သည်။

## AllFieldInfo ထက် Details ကို အသုံးပြုခြင်း၏ အကျိုးကျေးဇူးများ

`AllFieldInfo` ထက် `Details` ကို အသုံးပြုခြင်း၏ ပထမအကျိုးကျေးဇူးမှာ အရေးကြီးသော field များကိုသာ သိမ်းဆည်းပြီး၊ ဖိုင်နေရာ ချွေတာရန် field အမည်များကို တိုတောင်းအောင် ပြုလုပ်ထားခြင်း ဖြစ်သည်။
အားနည်းချက်မှာ သင် အမှန်တကယ် ဂရုစိုက်ခဲ့သော်လည်း လွတ်သွားသော data ပျောက်ဆုံးနိုင်ခြေ ရှိခြင်း ဖြစ်သည်။
ဒုတိယအကျိုးကျေးဇူးမှာ Hayabusa သည် field အမည်များကို normalize ပြုလုပ်ခြင်းဖြင့် field များကို ပို၍ တညီတည်းရှိသော ပုံစံဖြင့် သိမ်းဆည်းမည်ဖြစ်ခြင်း ဖြစ်သည်။
ဥပမာအားဖြင့်၊ မူရင်း Windows log များတွင် user name သည် ပုံမှန်အားဖြင့် `SubjectUserName` သို့မဟုတ် `TargetUserName` field တွင် ရှိသည်။
သို့သော် တစ်ခါတစ်ရံ username သည် `AccountName` field တွင် ရှိမည်၊ တစ်ခါတစ်ရံ target user သည် `SubjectUserName` field တွင် အမှန်တကယ် ရှိနေမည် စသည်ဖြင့်...
ကံမကောင်းစွာဖြင့် Windows event log များတွင် မညီညွတ်သော field အမည် အများအပြား ရှိနေသည်။
Hayabusa သည် ဤ field များကို normalize ပြုလုပ်ရန် ကြိုးစားသဖြင့် ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးသည် Windows ရှိ event ID များအကြား မရေတွက်နိုင်သော ထူးဆန်းမှုနှင့် ကွဲလွဲချက်များကို နားလည်ရန် မလိုဘဲ ဘုံအမည်တစ်ခုကိုသာ parse လုပ်ရန် လိုအပ်တော့သည်။

ဤနေရာတွင် user field ၏ ဥပမာတစ်ခု ဖြစ်သည်။
Hayabusa သည် `SubjectUserName`, `TargetUserName`, `AccountName` စသည်တို့ကို အောက်ပါအတိုင်း normalize ပြုလုပ်မည်ဖြစ်သည်−
  * `SrcUser` (Source User): user တစ်ဦးထံ**မှ** action တစ်ခု ဖြစ်ပွားသောအခါ။ (ပုံမှန်အားဖြင့် remote user တစ်ဦး။)
  * `TgtUser` (Target User): user တစ်ဦးထံ**သို့** action တစ်ခု ဖြစ်ပွားသောအခါ။ (ဥပမာ user တစ်ဦးထံ**သို့** logon ဝင်ခြင်း။)
  * `User`: လက်ရှိ logon ဝင်ထားသော user တစ်ဦးက action တစ်ခု ဖြစ်ပွားစေသောအခါ။ (action တွင် သီးခြား ဦးတည်ရာ မရှိပါ။)

အခြားဥပမာတစ်ခုမှာ process များ ဖြစ်သည်။
မူရင်း Windows event log များတွင် process field ကို အမည်ပေး စည်းမျဉ်း အများအပြားဖြင့် ရည်ညွှန်းသည်− `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName` စသည်ဖြင့်...
field normalization မရှိဘဲဆိုလျှင် ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးသည် မတူညီသော field အမည်အားလုံးအကြောင်း ဦးစွာ ကျွမ်းကျင်ရမည်၊ ထို့နောက် ဤ field အမည်များဖြင့် log အားလုံးကို ထုတ်နုတ်ရမည်၊ ထို့နောက် ၎င်းတို့ကို ပေါင်းစပ်ရမည် ဖြစ်သည်။

ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးသည် Hayabusa က `Details` object တွင် ပေးထားသော normalize ပြုလုပ်ထားသည့် single `Proc` field ကို အသုံးပြုရုံဖြင့် အချိန်နှင့် ဒုက္ခ အများအပြားကို ချွေတာနိုင်သည်။

# jq သင်ခန်းစာများ/Recipe များ

ယခု သင့်အလုပ်တွင် ကူညီနိုင်မည့် လက်တွေ့ဥပမာများ၏ သင်ခန်းစာ/recipe အများအပြားကို ဖော်ပြသွားမည် ဖြစ်သည်။

## 1. jq နှင့် Less In Color ဖြင့် ကိုယ်တိုင် စစ်ဆေးခြင်း

ဤသည်မှာ log များတွင် မည်သည့် field များ ရှိသည်ကို နားလည်ရန် ဦးစွာ ပြုလုပ်ရမည့်အရာများထဲမှ တစ်ခု ဖြစ်သည်။
သင်သည် `less results.json` ကို ရိုးရိုး ပြုလုပ်နိုင်သည်၊ သို့သော် ပိုကောင်းသော နည်းလမ်းမှာ အောက်ပါအတိုင်း ဖြစ်သည်−
`cat results.json | jq -C | less -R`

`jq` သို့ ပေးပို့ခြင်းဖြင့်၊ field အားလုံးကို အစကတည်းက သပ်ရပ်စွာ format မလုပ်ထားလျှင်ပင် သင့်အတွက် သပ်ရပ်စွာ format လုပ်ပေးမည်ဖြစ်သည်။
`jq` ဖြင့် `-C` (color) option နှင့် `less` ဖြင့် `-R` (raw output) option ကို အသုံးပြုခြင်းဖြင့် အရောင်ဖြင့် အပေါ်အောက် scroll လုပ်နိုင်သည်။

## 2. Metric များ

Hayabusa တွင် event ID များအပေါ် အခြေခံ၍ event အရေအတွက်နှင့် ရာခိုင်နှုန်းကို print ထုတ်သည့် လုပ်ဆောင်ချက် ရှိပြီးဖြစ်သော်လည်း၊ ၎င်းကို `jq` ဖြင့် မည်သို့ ပြုလုပ်ရမည်ကိုလည်း သိထားခြင်းသည် ကောင်းသည်။
၎င်းသည် သင် metric ဖန်တီးလိုသော data ကို စိတ်ကြိုက်ပြုလုပ်ခွင့် ပေးမည်ဖြစ်သည်။

ဦးစွာ အောက်ပါ command ဖြင့် Event ID များ၏ စာရင်းကို ထုတ်နုတ်ကြပါစို့−

`cat results.json | jq '.EventID'`

၎င်းသည် log တစ်ခုစီမှ Event ID နံပါတ်ကိုသာ ထုတ်နုတ်မည်ဖြစ်သည်။
`jq` ၏နောက်တွင် single quote အတွင်း `.` တစ်ခုနှင့် သင်ထုတ်နုတ်လိုသော field အမည်ကို ရိုက်ထည့်ရုံသာ ဖြစ်သည်။
သင်သည် အောက်ပါကဲ့သို့ ရှည်လျားသော စာရင်းတစ်ခုကို တွေ့ရမည်ဖြစ်သည်−

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

ယခု event ID များ မည်မျှအကြိမ် ဖြစ်ပွားခဲ့သည်ကို ရေတွက်ရန် ရလဒ်များကို `sort` နှင့် `uniq -c` command များသို့ pipe ပေးပါ−

`cat results.json | jq '.EventID' | sort | uniq -c`

`uniq` ၏ `-c` option သည် ထူးခြားသော event ID တစ်ခု မည်မျှအကြိမ် ဖြစ်ပွားခဲ့သည်ကို ရေတွက်မည်ဖြစ်သည်။

သင်သည် အောက်ပါကဲ့သို့ တစ်ခုခုကို တွေ့ရမည်ဖြစ်သည်−

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 ဘယ်ဘက်မှာ count ဖြစ်ပြီး ညာဘက်မှာ Event ID ဖြစ်သည်။
 သင်တွေ့မြင်နိုင်သည့်အတိုင်း ၎င်းကို sort မလုပ်ထားသဖြင့် မည်သည့် event ID များ အများဆုံး ဖြစ်ပွားခဲ့သည်ကို ပြောရန် ခက်ခဲသည်။

 ၎င်းကို ပြင်ဆင်ရန် အဆုံးတွင် `sort -n` ကို ထည့်နိုင်သည်−

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

`-n` option သည် `sort` ကို နံပါတ်အလိုက် စီစဉ်ရန် ပြောသည်။

သင်သည် အောက်ပါကဲ့သို့ တစ်ခုခုကို တွေ့ရမည်ဖြစ်သည်−
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

`4688` (Process creation) event များ အများဆုံး မှတ်တမ်းတင်ထားသည်ကို တွေ့နိုင်သည်။
ဒုတိယ အများဆုံး မှတ်တမ်းတင်ထားသော event မှာ `4625` (Failed Logon) ဖြစ်သည်။

အများဆုံး မှတ်တမ်းတင်ထားသော event များကို ထိပ်တွင် print ထုတ်လိုပါက `sort -n -r` သို့မဟုတ် `sort -nr` ဖြင့် sort ကို ပြောင်းပြန်လှန်နိုင်သည်။
ရလဒ်များကို `head -n 10` သို့ pipe ပေးခြင်းဖြင့် အများဆုံး မှတ်တမ်းတင်ထားသော ထိပ်တန်း event 10 ခုကိုသာ print ထုတ်နိုင်သည်။

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

၎င်းသည် သင့်အား ပေးမည်−
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

EID (Event ID) များသည် ထူးခြားသည် မဟုတ်သဖြင့် တူညီသော Event ID ဖြင့် လုံးဝ မတူညီသော event များ ရှိနိုင်သည်ကို ထည့်သွင်းစဉ်းစားရန် အရေးကြီးသည်။
ထို့ကြောင့် `Channel` ကိုလည်း စစ်ဆေးရန် အရေးကြီးသည်။

ဤ field အချက်အလက်ကို အောက်ပါအတိုင်း ထည့်နိုင်သည်−

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

field အားလုံးကို comma များဖြင့် ပိုင်းခြားပြီး `\n` new line character ဖြင့် အဆုံးသတ်ကာ ပေါင်းစပ်ရန် `jq` သို့ `-j` (join) option ကို ထည့်ပါသည်။

၎င်းသည် ကျွန်ုပ်တို့အား ပေးမည်−
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 မှတ်ချက်: `Security` ကို `Sec` အဖြစ်၊ `System` ကို `Sys` အဖြစ်၊ `PowerShell` ကို `PwSh` အဖြစ် အတိုကောက်ထားသည်။

rule title ကို အောက်ပါအတိုင်း ထည့်နိုင်သည်−

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

၎င်းသည် ကျွန်ုပ်တို့အား ပေးမည်−
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

ယခု သင်သည် log များမှ မည်သည့် data ကိုမဆို လွတ်လပ်စွာ ထုတ်နုတ်ပြီး ဖြစ်ပွားမှုများကို ရေတွက်နိုင်ပြီ ဖြစ်သည်။

## 3. သတ်မှတ်ထားသော Data အပေါ် Filtering ပြုလုပ်ခြင်း

အကြိမ်ပေါင်းများစွာ သင်သည် သတ်မှတ်ထားသော Event ID, user, process, LID (Logon ID) စသည်တို့အပေါ် filter လုပ်လိုလိမ့်မည်...
၎င်းကို `jq` query အတွင်းရှိ `select` ဖြင့် ပြုလုပ်နိုင်သည်။

ဥပမာအားဖြင့်၊ `4624` successful logon event အားလုံးကို ထုတ်နုတ်ကြပါစို့−

`cat results.json | jq 'select ( .EventID == 4624 ) '`

၎င်းသည် EID `4624` အတွက် JSON object အားလုံးကို ပြန်ပေးမည်ဖြစ်သည်−
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

အခြေအနေ အများအပြားအပေါ် filter လုပ်လိုပါက `and`, `or` နှင့် `not` ကဲ့သို့သော keyword များကို အသုံးပြုနိုင်သည်။

ဥပမာအားဖြင့်၊ type သည် `3` (Network logon) ဖြစ်သော `4624` event များကို ရှာကြပါစို့။

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

၎င်းသည် `EventID` သည် `4624` ဖြစ်ပြီး nested `"Details": { "Type" }` field သည် `3` ဖြစ်သော object အားလုံးကို ပြန်ပေးမည်ဖြစ်သည်။

သို့သော် ပြဿနာတစ်ခု ရှိသည်။
သင်သည် `jq: error (at <stdin>:10636): Cannot index string with string "Type"` ဟု ဆိုသော error များကို သတိပြုမိနိုင်သည်။
`Cannot index string with string` error ကို မြင်တိုင်း ၎င်းသည် မရှိသော သို့မဟုတ် မှားသော type ဖြစ်သော field တစ်ခုကို ထုတ်ရန် `jq` ကို သင်ပြောနေခြင်း ဖြစ်သည်ကို ဆိုလိုသည်။
field ၏ အဆုံးတွင် `?` တစ်ခု ထည့်ခြင်းဖြင့် ဤ error များကို ဖယ်ရှားနိုင်သည်။
၎င်းသည် `jq` ကို error များကို လျစ်လျူရှုရန် ပြောသည်။

ဥပမာ: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

ယခု သတ်မှတ်ထားသော စံနှုန်းများအပေါ် filter လုပ်ပြီးနောက် `jq` query အတွင်း `|` ကို အသုံးပြု၍ စိတ်ဝင်စားသော field အချို့ကို ရွေးချယ်နိုင်ပြီ ဖြစ်သည်။

ဥပမာအားဖြင့်၊ target user name `TgtUser` နှင့် source IP address `SrcIP` ကို ထုတ်နုတ်ကြပါစို့−

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

တစ်ဖန်၊ output ထုတ်ရန် field အများအပြားကို ရွေးချယ်ရန် `jq` သို့ `-j` (join) option ကို ထည့်ပါသည်။
ထို့နောက် ယခင်ဥပမာများကဲ့သို့ `sort`, `uniq -c` စသည်တို့ကို run ၍ သတ်မှတ်ထားသော IP address တစ်ခုက type 3 network logon မှတစ်ဆင့် user တစ်ဦးထဲသို့ မည်မျှအကြိမ် logon ဝင်ခဲ့သည်ကို ရှာဖွေနိုင်သည်။

## 4. Output ကို CSV ဖော်မတ်ဖြင့် သိမ်းဆည်းခြင်း

ကံမကောင်းစွာဖြင့် Windows event log များရှိ field များသည် event အမျိုးအစားအလိုက် လုံးဝ ကွဲပြားမည်ဖြစ်သဖြင့်၊ column ရာဂဏန်းမရှိဘဲ field များဖြင့် comma separated timeline များ ဖန်တီးရန် မလွယ်ကူပါ။
သို့သော် event အမျိုးအစား တစ်ခုတည်းအတွက် field separated timeline များ ဖန်တီးနိုင်သည်။
ဘုံဥပမာ နှစ်ခုမှာ lateral movement နှင့် password guessing/spraying ကို စစ်ဆေးရန် Security `4624` (Successful Logons) နှင့် `4625` (Failed Logons) ဖြစ်သည်။

ဤဥပမာတွင် ကျွန်ုပ်တို့သည် Security 4624 log များကိုသာ ထုတ်နုတ်ပြီး timestamp, computer name နှင့် `Details` အချက်အလက်အားလုံးကို output ထုတ်ပါသည်။
ကျွန်ုပ်တို့သည် ၎င်းကို `| @csv` ကို အသုံးပြု၍ CSV ဖိုင်တစ်ခုသို့ သိမ်းဆည်းသည်၊ သို့သော် data ကို array အဖြစ် ပေးပို့ရန် လိုအပ်သည်။
ကျွန်ုပ်တို့သည် ယခင်ကဲ့သို့ output ထုတ်လိုသော field များကို ရွေးချယ်ပြီး ၎င်းတို့ကို array အဖြစ် ပြောင်းရန် `[ ]` square bracket ဖြင့် ဖုံးခြင်းဖြင့် ၎င်းကို ပြုလုပ်နိုင်သည်။

ဥပမာ: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

မှတ်ချက်များ−
  * `Details` object ရှိ field အားလုံးကို ရွေးချယ်ရန် `[]` ကို ထည့်ပါသည်။
  * `Details` သည် array မဟုတ်ဘဲ string ဖြစ်ပြီး `Cannot iterate over string` error များ ပေးသော ကိစ္စများ ရှိသဖြင့် `?` ကို ထည့်ရန် လိုအပ်သည်။
  * double quote များကို backslash မ escape လုပ်ရန် `jq` သို့ `-r` (Raw output) option ကို ထည့်ပါသည်။

ရလဒ်များ−
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

successful logon ရှိသူကိုသာ စစ်ဆေးနေပါက နောက်ဆုံး `LID` (Logon ID) field ကို လိုအပ်မည် မဟုတ်ပါ။
`del` function ဖြင့် မလိုအပ်သော column ကို ဖျက်နိုင်သည်။

ဥပမာ: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

array သည် `0` မှ ရေတွက်သဖြင့် 7th field ကို ဖယ်ရှားရန် ကျွန်ုပ်တို့သည် `6` ကို အသုံးပြုသည်။

ယခု သင်သည် `> 4624-logs.csv` ကို ထည့်ခြင်းဖြင့် CSV ဖိုင်ကို သိမ်းဆည်းပြီး၊ နောက်ထပ် ခွဲခြမ်းစိတ်ဖြာမှုအတွက် Excel သို့မဟုတ် Timeline Explorer ထဲသို့ import လုပ်နိုင်သည်။

filtering ပြုလုပ်ရန် header တစ်ခု ထည့်ရန် လိုအပ်မည်ကို သတိပြုပါ။
`jq` query အတွင်း heading တစ်ခု ထည့်နိုင်သော်လည်း၊ ပုံမှန်အားဖြင့် ဖိုင်ကို သိမ်းဆည်းပြီးနောက် ထိပ်တန်း row တစ်ခုကို ကိုယ်တိုင် ထည့်ခြင်းသည် အလွယ်ဆုံး ဖြစ်သည်။

## 5. Alert အများဆုံးရှိသော ရက်စွဲများကို ရှာဖွေခြင်း

Hayabusa သည် default အားဖြင့် severity level အလိုက် alert အများဆုံးရှိသော ရက်စွဲများကို သင့်အား ပြောပြမည်ဖြစ်သည်။
သို့သော် alert ရှိသော ဒုတိယ၊ တတိယ စသည့် အများဆုံး ရက်စွဲများကိုလည်း သင် ရှာဖွေလိုနိုင်သည်။
ကျွန်ုပ်တို့သည် သင့်လိုအပ်ချက်အလိုက် နှစ်၊ လ သို့မဟုတ် ရက်စွဲဖြင့် grouping လုပ်ရန် timestamp ကို string slicing ပြုလုပ်ခြင်းဖြင့် ၎င်းကို ပြုလုပ်နိုင်သည်။

ဥပမာ: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` သည် `jq` ကို `Timestamp` မှ ပထမ 10 byte ကိုသာ ထုတ်နုတ်ရန် ပြောသည်။

၎င်းသည် ကျွန်ုပ်တို့အား event အများဆုံးရှိသော ရက်စွဲများကို ပေးမည်ဖြစ်သည်−
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

event အများဆုံးရှိသော လကို သိလိုပါက ပထမ 7 byte ကို ထုတ်နုတ်ရန် `.[:10]` ကို `.[:7]` သို့ ပြောင်းရုံသာ ဖြစ်သည်။

`high` alert အများဆုံးရှိသော ရက်စွဲများကို စာရင်းပြုစုလိုပါက ၎င်းကို ပြုလုပ်နိုင်သည်−

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

သင့်လိုအပ်ချက်အလိုက် computer name, event ID စသည်တို့အလိုက် `select` function သို့ filter condition များကို ဆက်လက် ထည့်နိုင်သည်။

## 6. PowerShell Log များကို ပြန်လည်တည်ဆောက်ခြင်း

PowerShell log များ၏ ကံမကောင်းသော အချက်တစ်ခုမှာ log များသည် log အများအပြားအဖြစ် ကွဲထွက်လေ့ရှိပြီး ဖတ်ရန် ခက်ခဲစေခြင်း ဖြစ်သည်။
attacker run ခဲ့သော command များကိုသာ ထုတ်နုတ်ခြင်းဖြင့် log များကို ဖတ်ရန် ပို၍ လွယ်ကူအောင် ပြုလုပ်နိုင်သည်။

ဥပမာအားဖြင့်၊ EID `4104` ScriptBlock log များ ရှိပါက၊ ဖတ်ရလွယ်ကူသော timeline တစ်ခု ဖန်တီးရန် ထို field ကိုသာ ထုတ်နုတ်နိုင်သည်။

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

၎င်းသည် အောက်ပါအတိုင်း timeline တစ်ခုကို ရရှိစေမည်ဖြစ်သည်−
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. သံသယဖြစ်ဖွယ် Network Connection များ ရှာဖွေခြင်း

ဦးစွာ အောက်ပါ command ဖြင့် target IP address အားလုံး၏ စာရင်းကို ရယူနိုင်သည်−

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

threat intelligence ရှိပါက IP address များထဲမှ မည်သည့်တစ်ခုမဆို အန္တရာယ်ရှိသည်ဟု သိရှိထားသည်ကို စစ်ဆေးနိုင်သည်။

အောက်ပါအတိုင်း သတ်မှတ်ထားသော target IP address တစ်ခုသို့ connect လုပ်ခဲ့သော အကြိမ်အရေအတွက်ကို ရေတွက်နိုင်သည်−

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

`TgtIP` ကို `SrcIP` သို့ ပြောင်းခြင်းဖြင့် source IP address များအပေါ် အခြေခံ၍ အန္တရာယ်ရှိသော IP address များအတွက် တူညီသော threat intelligence စစ်ဆေးမှုကို ပြုလုပ်နိုင်သည်။

သင့်ပတ်ဝန်းကျင်မှ `93.184.220.29` ဟူသော အန္တရာယ်ရှိသော IP address သို့ connect လုပ်နေသည်ကို တွေ့ရှိသည်ဟု ဆိုကြပါစို့။
အောက်ပါ query ဖြင့် ထို event များ၏ အသေးစိတ်ကို ရယူနိုင်သည်−

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

၎င်းသည် သင့်အား အောက်ပါကဲ့သို့ JSON ရလဒ်များကို ပေးမည်ဖြစ်သည်−
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

contact လုပ်ခဲ့သော domain များကို စာရင်းပြုစုလိုပါက အောက်ပါ command ကို အသုံးပြုနိုင်သည်−

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> မှတ်ချက်: NETBIOS hostname များကို ဖယ်ရှားရန် `.` အတွက် grep filter တစ်ခု ထည့်ထားသည်။

## 8. Executable Binary Hash များ ထုတ်နုတ်ခြင်း

Sysmon EID `1` Process Creation log များတွင် sysmon ကို binary ၏ hash များ တွက်ချက်ရန် ပြင်ဆင်နိုင်သည်။
Security ခွဲခြမ်းစိတ်ဖြာသူများသည် ဤ hash များကို threat intelligence ဖြင့် သိရှိထားသော အန္တရာယ်ရှိ hash များနှင့် နှိုင်းယှဉ်နိုင်သည်။
`Hashes` field ကို အောက်ပါအတိုင်း ထုတ်နုတ်နိုင်သည်−

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

၎င်းသည် သင့်အား အောက်ပါကဲ့သို့ hash များ၏ စာရင်းကို ပေးမည်ဖြစ်သည်−

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon သည် ပုံမှန်အားဖြင့် `MD5`, `SHA1` နှင့် `IMPHASH` ကဲ့သို့ hash အများအပြားကို တွက်ချက်မည်ဖြစ်သည်။
`jq` ရှိ regular expression များဖြင့် ဤ hash များကို ထုတ်နုတ်နိုင်သည် သို့မဟုတ် ပိုကောင်းသော performance အတွက် string splicing ကိုသာ အသုံးပြုနိုင်သည်။

ဥပမာအားဖြင့်၊ MD5 hash များကို ထုတ်နုတ်ပြီး ထပ်နေသည်များကို အောက်ပါအတိုင်း ဖယ်ရှားနိုင်သည်−

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. PowerShell Log များ ထုတ်နုတ်ခြင်း

PowerShell Scriptblock log များ (EID: 4104) သည် ပုံမှန်အားဖြင့် log အများအပြားအဖြစ် ကွဲထွက်ပြီး CSV ဖော်မတ်သို့ output ထုတ်သောအခါ Hayabusa သည် output ကို ပို၍ တိုတောင်းအောင် tab များနှင့် return character များကို ဖျက်မည်ဖြစ်သည်။
သို့သော် powershell log များကို မူရင်း tab နှင့် return character formatting ဖြင့် log များကို ပေါင်းစပ်၍ ခွဲခြမ်းစိတ်ဖြာခြင်းသည် အလွယ်ဆုံး ဖြစ်သည်။
ဤနေရာတွင် `COMPUTER-A` မှ PowerShell EID 4104 log များကို ထုတ်နုတ်ပြီး VSCode စသည်ဖြင့် ဖွင့်ကြည့်ကာ ခွဲခြမ်းစိတ်ဖြာရန် `.ps1` ဖိုင်တစ်ခုသို့ သိမ်းဆည်းခြင်း၏ ဥပမာ ဖြစ်သည်။
ScriptBlock field ကို ထုတ်နုတ်ပြီးနောက် ကျွန်ုပ်တို့သည် `\r\n` နှင့် `\n` ကို return character များဖြင့်လည်းကောင်း၊ `\t` ကို tab များဖြင့်လည်းကောင်း အစားထိုးရန် `awk` ကို အသုံးပြုသည်။

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

ခွဲခြမ်းစိတ်ဖြာသူသည် အန္တရာယ်ရှိသော PowerShell command များအတွက် log များကို ခွဲခြမ်းစိတ်ဖြာပြီးနောက် ၎င်းတို့သည် ထို command များကို မည်သည့်အချိန်တွင် run ခဲ့သည်ကို ရှာဖွေရန် ပုံမှန်အားဖြင့် လိုအပ်လိမ့်မည်။
ဤနေရာတွင် command တစ်ခု run ခဲ့သော အချိန်ကို ရှာဖွေရန် Timestamp နှင့် PowerShell log များကို CSV ဖိုင်တစ်ခုသို့ output ထုတ်ခြင်း၏ ဥပမာ ဖြစ်သည်−

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

မှတ်ချက်: single နှင့် double quote များကို PowerShell log များတွင် မကြာခဏ တွေ့ရှိပြီး CSV output ကို ပျက်စီးစေသဖြင့် အသုံးပြုသော string delimeter မှာ `¦` ဖြစ်သည်။
CSV ဖိုင်ကို import လုပ်သောအခါ application သို့ string delimeter `¦` ကို သတ်မှတ်ပေးရန် လိုအပ်သည်။
