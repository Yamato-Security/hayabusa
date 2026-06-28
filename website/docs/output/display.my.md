# Output ဖော်ပြမှုနှင့် အကျဉ်းချုပ်

## Progress Bar

Progress bar သည် evtx ဖိုင်များစွာရှိမှသာ အလုပ်လုပ်ပါမည်။
၎င်းသည် ခွဲခြမ်းစိတ်ဖြာပြီးစီးပြီးဖြစ်သော evtx ဖိုင်များ၏ အရေအတွက်နှင့် ရာခိုင်နှုန်းကို အချိန်နှင့်တစ်ပြေးညီ ဖော်ပြပါမည်။

## အရောင် Output

Alert များကို alert `level` အပေါ်အခြေခံ၍ အရောင်ဖြင့် ထုတ်ပေးပါမည်။
ပုံသေအရောင်များကို `./config/level_color.txt` ရှိ config ဖိုင်တွင် `level,(RGB 6-digit ColorHex)` ပုံစံဖြင့် ပြောင်းလဲနိုင်ပါသည်။
အရောင် output ကို ပိတ်လိုပါက `-K, --no-color` option ကို အသုံးပြုနိုင်ပါသည်။

## ရလဒ် အကျဉ်းချုပ်

စုစုပေါင်း events များ၊ hit ဖြစ်သော events အရေအတွက်၊ ဒေတာလျှော့ချမှု metrics များ၊ စုစုပေါင်းနှင့် ထူးခြားသော detection များ၊ detection အများဆုံးဖြစ်သော ရက်စွဲများ၊ detection ပါဝင်သော ထိပ်တန်း computer များနှင့် ထိပ်တန်း alert များကို scan တိုင်းပြီးနောက် ဖော်ပြပါသည်။

### Detection Fequency Timeline

`-T, --visualize-timeline` option ကို ထည့်ပါက Event Frequency Timeline feature သည် detect ဖြစ်သော events များ၏ sparkline frequency timeline ကို ဖော်ပြပါသည်။
မှတ်ချက်- events ၅ ခုထက် ပိုရှိရန်လိုအပ်ပါသည်။ ထို့အပြင်၊ ပုံသေ Command Prompt သို့မဟုတ် PowerShell Prompt တွင် စာလုံးများ မှန်ကန်စွာ render ဖြစ်မည်မဟုတ်သောကြောင့်၊ Windows Terminal၊ iTerm2 စသည်တို့ကဲ့သို့သော terminal ကို အသုံးပြုပါ...
