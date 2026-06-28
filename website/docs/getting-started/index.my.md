# ဒေါင်းလုဒ်များ

Hayabusa ၏ နောက်ဆုံးထွက် တည်ငြိမ်သော ဗားရှင်းကို ကွန်ပိုင်းလုပ်ပြီးသား binary များဖြင့် ဒေါင်းလုဒ်လုပ်ပါ သို့မဟုတ် [Releases](https://github.com/Yamato-Security/hayabusa/releases) စာမျက်နှာမှ source code ကို ကွန်ပိုင်းလုပ်ပါ။

အောက်ပါ architecture များအတွက် binary များကို ကျွန်ုပ်တို့ ပံ့ပိုးပေးပါသည်-
- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [အကြောင်းတစ်ခုခုကြောင့် Linux ARM MUSL binary သည် မှန်ကန်စွာ အလုပ်မလုပ်ပါ](https://github.com/Yamato-Security/hayabusa/issues/1332) ထို့ကြောင့် ထို binary ကို ကျွန်ုပ်တို့ မပံ့ပိုးပါ။ ၎င်းသည် ကျွန်ုပ်တို့၏ ထိန်းချုပ်မှုပြင်ပတွင် ရှိသောကြောင့် ပြုပြင်ပြီးသောအခါ အနာဂတ်တွင် ၎င်းကို ပံ့ပိုးပေးရန် စီစဉ်ထားပါသည်။

## Windows live response packages

v2.18.0 မှ စတင်၍၊ ကျွန်ုပ်တို့သည် တစ်ခုတည်းသော ဖိုင်တွင် ပံ့ပိုးထားသော XOR-encoded rules များကို အသုံးပြုသည့် အထူး Windows packages များနှင့်အတူ config ဖိုင်အားလုံးကို တစ်ခုတည်းသော ဖိုင်အဖြစ် ပေါင်းစပ်ထားသည်များကို ပံ့ပိုးပေးပါသည် ([hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules) တွင် host လုပ်ထားသည်)။
အမည်တွင် `live-response` ပါသော zip packages များကို ဒေါင်းလုဒ်လုပ်ရုံသာဖြစ်သည်။
zip ဖိုင်များတွင် ဖိုင်သုံးဖိုင်သာ ပါဝင်သည်- Hayabusa binary၊ XOR-encoded rules ဖိုင်နှင့် config ဖိုင်တို့ဖြစ်သည်။
ဤ live response packages များ၏ ရည်ရွယ်ချက်မှာ client endpoints များတွင် Hayabusa ကို run သောအခါ Windows Defender ကဲ့သို့သော anti-virus scanners များက `.yml` rule ဖိုင်များအပေါ် false positives များ မပေးကြောင်း သေချာစေလိုခြင်းဖြစ်သည်။
ထို့အပြင်၊ USN Journal ကဲ့သို့သော forensics artifacts များ ပြန်လည်ရေးသားမှု မဖြစ်စေရန် system သို့ ရေးသားသည့် ဖိုင်အရေအတွက်ကို အနည်းဆုံးဖြစ်အောင် ကျွန်ုပ်တို့ လိုလားပါသည်။
