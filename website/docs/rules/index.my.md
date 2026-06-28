# Hayabusa Rules များ

Hayabusa ၏ detection rule များကို sigma နှင့်ဆင်တူသော YML format ဖြင့်ရေးသားထားပြီး `rules` folder အတွင်းတွင် တည်ရှိသည်။
ဤ rule များကို [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) တွင် host လုပ်ထားသောကြောင့် rule များနှင့်ပတ်သက်သော issue နှင့် pull request များကို Hayabusa repository အဓိကအစား ထိုနေရာသို့ ပေးပို့ပါ။

rule format နှင့် rule များကို မည်သို့ဖန်တီးရမည်ကို နားလည်ရန် ဤအပိုင်းရှိ [Creating Rule Files](creating-rules.md)၊ [Detection Fields](detection-fields.md) နှင့် [Sigma Correlations](correlations.md) တို့ကို ကြည့်ပါ။ (အရင်းအမြစ်: [hayabusa-rules repository](https://github.com/Yamato-Security/hayabusa-rules)။)

hayabusa-rules repository မှ rule အားလုံးကို `rules` folder အတွင်းတွင် ထားရှိသင့်သည်။
`informational` level rule များကို `events` အဖြစ်သတ်မှတ်ပြီး၊ `level` သည် `low` နှင့်အထက်ရှိသမျှအရာများကို `alerts` အဖြစ်သတ်မှတ်သည်။

hayabusa rule directory ဖွဲ့စည်းပုံကို directory ၂ ခုအဖြစ် ခွဲခြားထားသည်:

* `builtin`: Windows built-in functionality မှ ထုတ်လုပ်နိုင်သော log များ။
* `sysmon`: [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) မှ ထုတ်လုပ်သော log များ။

rule များကို log type အလိုက် directory များဖြင့် ထပ်မံခွဲခြားထားပြီး (ဥပမာ: Security, System, စသည်ဖြင့်...) အောက်ပါ format ဖြင့် အမည်ပေးထားသည်:

new rule များဖန်တီးရာတွင် template အဖြစ်အသုံးပြုရန် သို့မဟုတ် detection logic ကိုစစ်ဆေးရန်အတွက် လက်ရှိ rule များကို ကြည့်ရှုပါ။

## Sigma v.s. Hayabusa (Built-in Sigma Compatible) Rules များ

Hayabusa သည် Sigma rule များကို `logsource` field များကို အတွင်းပိုင်း၌ ကိုင်တွယ်သည့်အချက်တစ်ခုမှလွဲ၍ မူရင်းအတိုင်း ပံ့ပိုးပေးသည်။
false positive များကို လျှော့ချရန်အတွက် Sigma rule များကို [ဤနေရာ](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md) တွင်ရှင်းပြထားသော ကျွန်ုပ်တို့၏ convertor မှ ဖြတ်သန်းသင့်သည်။
ဤသည်သည် သင့်လျော်သော `Channel` နှင့် `EventID` ကိုထည့်ပေးမည်ဖြစ်ပြီး `process_creation` ကဲ့သို့သော အချို့ category များအတွက် field mapping ကို လုပ်ဆောင်ပေးမည်ဖြစ်သည်။

Hayabusa rule အားလုံးနီးပါးသည် Sigma format နှင့် တွဲဖက်အသုံးပြုနိုင်သောကြောင့် ၎င်းတို့ကို Sigma rule များကဲ့သို့ အသုံးပြု၍ အခြား SIEM format များသို့ ပြောင်းလဲနိုင်သည်။
Hayabusa rule များကို Windows event log analysis အတွက်သာ ဒီဇိုင်းရေးဆွဲထားပြီး အောက်ပါအကျိုးကျေးဇူးများ ရှိသည်:

1. log အတွင်းရှိ အသုံးဝင်သော field များမှသာ ထုတ်ယူထားသော အပိုအချက်အလက်များကို ပြသရန် အပို `details` field တစ်ခု။
2. ၎င်းတို့အားလုံးကို sample log များဖြင့် စမ်းသပ်ထားပြီး အလုပ်လုပ်ကြောင်း သိရှိထားသည်။
3. `|equalsfield` နှင့် `|endswithfield` ကဲ့သို့ sigma တွင်မတွေ့ရသော အပို aggregator များ။

ကျွန်ုပ်တို့သိရှိသမျှအရ၊ hayabusa သည် open source Windows event log analysis tool များအနက် Sigma rule များအတွက် အကြီးမားဆုံးသော native support ကို ပေးစွမ်းသည်။
