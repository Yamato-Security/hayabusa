# အဓိကရည်ရွယ်ချက်များ

## ခြိမ်းခြောက်မှုရှာဖွေခြင်းနှင့် လုပ်ငန်းတစ်ခုလုံးအတိုင်းအတာ DFIR

Hayabusa တွင် လက်ရှိ၌ Sigma rule ၄၀၀၀ ကျော်နှင့် Hayabusa built-in detection rule ၁၇၀ ကျော်ရှိပြီး rule အသစ်များကို ပုံမှန်ထပ်မံထည့်သွင်းနေပါသည်။
၎င်းကို လုပ်ငန်းတစ်ခုလုံးအတိုင်းအတာ ကြိုတင်ကာကွယ်သည့် ခြိမ်းခြောက်မှုရှာဖွေခြင်းအတွက်လည်းကောင်း၊ [Velociraptor](https://docs.velociraptor.app/) ၏ [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) ဖြင့် DFIR (Digital Forensics and Incident Response) အတွက်လည်းကောင်း အခမဲ့အသုံးပြုနိုင်ပါသည်။
ဤopen-source tool နှစ်ခုကို ပေါင်းစပ်အသုံးပြုခြင်းဖြင့် ပတ်ဝန်းကျင်တွင် SIEM တပ်ဆင်ထားခြင်းမရှိသည့်အခါ SIEM တစ်ခုကို အခြေခံအားဖြင့် နောက်ကြောင်းပြန်လိုက်၍ ပြန်လည်တည်ဆောက်နိုင်ပါသည်။
ဤအရာကို မည်သို့ပြုလုပ်ရမည်ကို [Eric Capuano](https://twitter.com/eric_capuano) ၏ Velociraptor walkthrough ကို [ဤနေရာတွင်](https://www.youtube.com/watch?v=Q1IoGX--814) ကြည့်ရှုခြင်းဖြင့် လေ့လာနိုင်ပါသည်။

## မြန်ဆန်သော Forensics Timeline ဖန်တီးခြင်း

Windows event log ခွဲခြမ်းစိတ်ဖြာခြင်းသည် ရိုးရာအားဖြင့် အလွန်ရှည်လျားပြီး ပျင်းရိစရာကောင်းသော လုပ်ငန်းစဉ်တစ်ခုဖြစ်ခဲ့သည်။ အကြောင်းမှာ Windows event log များသည် ၁) ခွဲခြမ်းစိတ်ဖြာရန်ခက်ခဲသော data format ဖြစ်ပြီး ၂) data အများစုသည် noise ဖြစ်ကာ စုံစမ်းစစ်ဆေးမှုများအတွက် အသုံးမဝင်သောကြောင့်ဖြစ်သည်။
Hayabusa ၏ ရည်ရွယ်ချက်မှာ အသုံးဝင်သော data ကိုသာ ထုတ်နုတ်ပြီး ၎င်းကို ဖတ်ရှုရလွယ်ကူပြီး တတ်နိုင်သမျှတိုတောင်းသော format ဖြင့် တင်ပြရန်ဖြစ်ကာ ၎င်းကို ကျွမ်းကျင်စွာသင်တန်းပေးထားသော analyst များသာမက မည်သည့် Windows system administrator မဆို အသုံးပြုနိုင်စေရန်ဖြစ်သည်။
Hayabusa သည် ရိုးရာ Windows event log ခွဲခြမ်းစိတ်ဖြာခြင်းနှင့်နှိုင်းယှဉ်လျှင် analyst များအား ၎င်းတို့၏လုပ်ငန်း၏ ၈၀% ကို အချိန်၏ ၂၀% အတွင်း ပြီးမြောက်စေနိုင်ရန် မျှော်လင့်ပါသည်။

![DFIR Timeline](../assets/doc/DFIR-TimelineCreation-EN.png)
