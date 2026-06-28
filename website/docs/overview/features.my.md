# လုပ်ဆောင်ချက်များ

* Cross-platform ပံ့ပိုးမှု - Windows၊ Linux၊ macOS။
* memory safe ဖြစ်ပြီး လျင်မြန်စေရန် Rust ဖြင့် ရေးသားထားသည်။
* Multi-thread ပံ့ပိုးမှုဖြင့် အမြန်နှုန်း ၅ ဆအထိ တိုးတက်စေသည်။
* forensic စုံစမ်းစစ်ဆေးမှုများနှင့် incident response အတွက် ခွဲခြမ်းစိတ်ဖြာရလွယ်ကူသော timeline တစ်ခုတည်းကို ဖန်တီးပေးသည်။
* ဖတ်ရှု/ဖန်တီး/တည်းဖြတ်ရလွယ်ကူသော YML အခြေခံ hayabusa rule များတွင် ရေးသားထားသည့် IoC signature များအပေါ် အခြေခံ၍ ခြိမ်းခြောက်မှု ရှာဖွေခြင်း။
* sigma rule များကို hayabusa rule များအဖြစ် ပြောင်းလဲရန် Sigma rule ပံ့ပိုးမှု။
* လက်ရှိတွင် အလားတူ tool အခြားများနှင့် နှိုင်းယှဉ်ပါက sigma rule အများဆုံးကို ပံ့ပိုးပြီး count rule များနှင့် `|equalsfield` နှင့် `|endswithfield` ကဲ့သို့သော aggregator အသစ်များကိုပါ ပံ့ပိုးသည်။
* Computer metrics။ (event အများအပြားရှိသော computer အချို့ကို စစ်ထုတ်ရန်/ဖယ်ထုတ်ရန် အသုံးဝင်သည်။)
* Event ID metrics။ (မည်သည့် event အမျိုးအစားများ ရှိသည်ကို ပုံဖော်ကြည့်ရန်နှင့် log setting များကို ညှိနှိုင်းရန် အသုံးဝင်သည်။)
* မလိုအပ်သော သို့မဟုတ် ဆူညံသော rule များကို ဖယ်ထုတ်ခြင်းဖြင့် Rule tuning ပြင်ဆင်မှု။
* tactic များ၏ MITRE ATT&CK mapping။
* Rule level tuning။
* ပုံမှန်မဟုတ်သော user၊ hostname၊ process စသည်တို့ကို လျင်မြန်စွာ ဖော်ထုတ်ရန်နှင့် event များကို ဆက်စပ်ရန် တစ်မူထူးခြားသော pivot keyword စာရင်းကို ဖန်တီးပါ။
* ပိုမိုစေ့စပ်သော စုံစမ်းစစ်ဆေးမှုများအတွက် field အားလုံးကို ထုတ်ပေးခြင်း။
* အောင်မြင်သော နှင့် မအောင်မြင်သော logon အကျဉ်းချုပ်။
* [Velociraptor](https://docs.velociraptor.app/) ဖြင့် endpoint အားလုံးပေါ်တွင် Enterprise တစ်ခုလုံး ခြိမ်းခြောက်မှု ရှာဖွေခြင်းနှင့် DFIR။
* CSV၊ JSON/JSONL နှင့် HTML အကျဉ်းချုပ် Report များအဖြစ် ထုတ်ပေးခြင်း။
* နေ့စဉ် Sigma rule update များ။
* JSON-format log input အတွက် ပံ့ပိုးမှု။
* Log field normalization။ (အမည်ပေးစည်းမျဉ်း မတူညီသော field များစွာကို တူညီသော field name အဖြစ် ပြောင်းလဲခြင်း။)
* IP address များတွင် GeoIP (ASN၊ city၊ country) အချက်အလက်ထည့်ခြင်းဖြင့် Log enrichment။
* keyword များ သို့မဟုတ် regular expression များအတွက် event အားလုံးကို ရှာဖွေခြင်း။
* Field data mapping။ (ဥပမာ - `0xc0000234` -> `ACCOUNT LOCKED`)
* evtx slack space မှ Evtx record carving။
* ထုတ်ပေးသည့်အခါ Event de-duplication။ (recovery record များ enable လုပ်ထားသည့်အခါ သို့မဟုတ် backup လုပ်ထားသော evtx file များ၊ VSS မှ evtx file များ စသည်တို့ ထည့်သွင်းသည့်အခါ အသုံးဝင်သည်။)
* မည်သည့် rule များကို enable လုပ်ရမည်ကို ပိုမိုလွယ်ကူစွာ ရွေးချယ်ရန် အကူအညီပေးသော Scan setting wizard။ (false positive များ လျှော့ချရန် စသည်ဖြင့်။)
* PowerShell classic log field parsing နှင့် extraction။
* memory အသုံးပြုမှု နည်းခြင်း။ (မှတ်ချက် - ၎င်းသည် ရလဒ်များကို စီစဉ်ခြင်းမပြုဘဲ ဖြစ်နိုင်သည်။ agent များပေါ်တွင် သို့မဟုတ် big data အတွက် run ရန် အကောင်းဆုံးဖြစ်သည်။)
* အကောင်းဆုံး performance အတွက် Channel များနှင့် Rule များအပေါ် စစ်ထုတ်ခြင်း။
* log များတွင် တွေ့ရှိသော Base64 string များကို ဖော်ထုတ်၊ ထုတ်ယူ၊ decode လုပ်ခြင်း။
* အရေးကြီးသော system များအပေါ် အခြေခံ၍ Alert level ညှိနှိုင်းခြင်း။
