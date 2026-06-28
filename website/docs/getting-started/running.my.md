# Hayabusa ကို Run ခြင်း

## သတိ - Anti-Virus/EDR သတိပေးချက်များနှင့် နှေးကွေးသော Runtime များ

hayabusa ကို run ရန်ကြိုးစားသည့်အခါ သို့မဟုတ် `.yml` rule များကို download လုပ်ရုံမျှဖြင့်ပင် anti-virus သို့မဟုတ် EDR ထုတ်ကုန်များမှ သတိပေးချက်တစ်ခု ရရှိနိုင်ပါသည်။ အကြောင်းမှာ detection signature တွင် `mimikatz` နှင့် သံသယဖြစ်ဖွယ် PowerShell command များကဲ့သို့သော keyword များ ပါဝင်နေသောကြောင့်ဖြစ်ပါသည်။
ဤအရာများသည် false positive များဖြစ်သောကြောင့် hayabusa ကို run နိုင်ရန် သင်၏ security ထုတ်ကုန်များတွင် exclusion များကို configure လုပ်ရန် လိုအပ်ပါသည်။
malware သို့မဟုတ် supply chain တိုက်ခိုက်မှုများအတွက် စိုးရိမ်ပါက ကျေးဇူးပြု၍ hayabusa source code ကို စစ်ဆေးပြီး binary များကို သင်ကိုယ်တိုင် compile လုပ်ပါ။

အထူးသဖြင့် reboot ပြုလုပ်ပြီးနောက် ပထမဆုံးအကြိမ် run သည့်အခါ Windows Defender ၏ real-time protection ကြောင့် runtime နှေးကွေးမှုကို သင်တွေ့ကြုံရနိုင်ပါသည်။
real-time protection ကို ယာယီပိတ်ထားခြင်း သို့မဟုတ် hayabusa runtime directory သို့ exclusion တစ်ခု ထည့်သွင်းခြင်းဖြင့် ဤအရာကို သင်ရှောင်ရှားနိုင်ပါသည်။
(ဤအရာများ မပြုလုပ်မီ security ဆိုင်ရာ အန္တရာယ်များကို ကျေးဇူးပြု၍ ထည့်သွင်းစဉ်းစားပါ။)

## Windows

Command/PowerShell Prompt သို့မဟုတ် Windows Terminal တွင် သင့်လျော်သော 32-bit သို့မဟုတ် 64-bit Windows binary ကို run လိုက်ရုံသာဖြစ်သည်။

### path တွင် space ပါသော file သို့မဟုတ် directory ကို scan လုပ်ရန် ကြိုးစားသည့်အခါ ဖြစ်ပေါ်သော Error

Windows ၏ built-in Command သို့မဟုတ် PowerShell prompt ကို အသုံးပြုသည့်အခါ သင်၏ file သို့မဟုတ် directory path တွင် space ပါဝင်ပါက Hayabusa သည် .evtx file များကို load မလုပ်နိုင်ကြောင်း error တစ်ခု သင်ရရှိနိုင်ပါသည်။
.evtx file များကို မှန်ကန်စွာ load လုပ်နိုင်ရန် အောက်ပါတို့ကို ပြုလုပ်ရန် သေချာပါစေ-

1. file သို့မဟုတ် directory path ကို double quote ဖြင့် ဝိုက်ထားပါ။
2. directory path ဖြစ်ပါက နောက်ဆုံးစာလုံးအဖြစ် backslash ကို ထည့်သွင်းမထားရန် သေချာပါစေ။

### စာလုံးများ မှန်ကန်စွာ မပြသခြင်း

Windows ပေါ်ရှိ default font `Lucida Console` ဖြင့် logo နှင့် table များတွင် အသုံးပြုထားသော အမျိုးမျိုးသော စာလုံးများ မှန်ကန်စွာ ပြသမည်မဟုတ်ပါ။
ဤအရာကို ဖြေရှင်းရန် font ကို `Consalas` သို့ ပြောင်းသင့်ပါသည်။

ဤအရာသည် closing message များတွင် Japanese စာလုံးများ ပြသခြင်းမှလွဲ၍ စာသား rendering အများစုကို ဖြေရှင်းပေးပါမည်-

![Mojibake](../assets/screenshots/Mojibake.png)

ဤအရာကို ဖြေရှင်းရန် သင့်တွင် ရွေးချယ်စရာ လေးခု ရှိပါသည်-

1. Command သို့မဟုတ် PowerShell prompt အစား [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) ကို အသုံးပြုပါ။ (အကြံပြုထားသည်)
2. `MS Gothic` font ကို အသုံးပြုပါ။ backslash များသည် Yen သင်္ကေတများအဖြစ် ပြောင်းသွားမည်ကို သတိပြုပါ။
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. [HackGen](https://github.com/yuru7/HackGen/releases) font များကို install လုပ်ပြီး `HackGen Console NF` ကို အသုံးပြုပါ။
4. Japanese ပါဝင်သော closing message များကို မပြသရန် `-q, --quiet` ကို အသုံးပြုပါ။

## Linux

ဦးစွာ binary ကို executable ဖြစ်အောင် ပြုလုပ်ရန် လိုအပ်ပါသည်။

```bash
chmod +x ./hayabusa
```

ထို့နောက် Hayabusa root directory မှ ၎င်းကို run ပါ-

```bash
./hayabusa
```

## macOS

Terminal သို့မဟုတ် iTerm2 မှ ဦးစွာ binary ကို executable ဖြစ်အောင် ပြုလုပ်ရန် လိုအပ်ပါသည်။

```bash
chmod +x ./hayabusa
```

ထို့နောက် Hayabusa root directory မှ ၎င်းကို run ရန် ကြိုးစားပါ-

```bash
./hayabusa
```

macOS ၏ နောက်ဆုံးထွက် version တွင် ၎င်းကို run ရန် ကြိုးစားသည့်အခါ အောက်ပါ security error ကို သင်ရရှိနိုင်ပါသည်-

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

"Cancel" ကို နှိပ်ပြီး System Preferences မှ "Security & Privacy" ကို ဖွင့်ကာ General tab မှ "Allow Anyway" ကို နှိပ်ပါ။

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

ထို့နောက် ၎င်းကို ထပ်မံ run ရန် ကြိုးစားပါ။

```bash
./hayabusa
```

အောက်ပါ သတိပေးချက် ပေါ်လာမည်ဖြစ်သောကြောင့် ကျေးဇူးပြု၍ "Open" ကို နှိပ်ပါ။

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

ယခု သင် hayabusa ကို run နိုင်ပြီဖြစ်ပါသည်။
