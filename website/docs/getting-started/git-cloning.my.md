# Git Cloning

အောက်ပါ command ဖြင့် repository ကို `git clone` လုပ်ပြီး source code မှ binary ကို compile လုပ်နိုင်ပါသည်။

**သတိပြုရန်:** repository ၏ main branch သည် development ရည်ရွယ်ချက်အတွက် ဖြစ်သောကြောင့် တရားဝင်မထွက်ရှိသေးသော feature အသစ်များကို သင်အသုံးပြုနိုင်သော်လည်း bug များ ရှိနိုင်သဖြင့် မတည်ငြိမ်ဟု သတ်မှတ်ပါ။

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **မှတ်ချက်:** --recursive option ကို အသုံးပြုရန် မေ့သွားပါက git submodule အဖြစ် စီမံခန့်ခွဲထားသော `rules` folder ကို clone လုပ်မည်မဟုတ်ပါ။

`rules` folder ကို `git pull --recurse-submodules` ဖြင့် sync လုပ်၍ နောက်ဆုံးထွက် Hayabusa rules များကို ရယူနိုင်သည် သို့မဟုတ် အောက်ပါ command ကို အသုံးပြုနိုင်ပါသည်။

```bash
hayabusa.exe update-rules
```

update မအောင်မြင်ပါက `rules` folder ကို အမည်ပြောင်းပြီး ထပ်မံကြိုးစားရန် လိုအပ်နိုင်ပါသည်။

>> သတိ: update လုပ်သည့်အခါ `rules` folder အတွင်းရှိ rules နှင့် config file များကို [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository ရှိ နောက်ဆုံးထွက် rules နှင့် config file များဖြင့် အစားထိုးပါသည်။
>> ရှိပြီးသား file များတွင် သင်ပြုလုပ်ထားသော ပြောင်းလဲမှုများကို overwrite လုပ်မည်ဖြစ်သောကြောင့် update မလုပ်မီ သင်တည်းဖြတ်ထားသော file များကို backup ကူးယူထားရန် အကြံပြုပါသည်။
>> `level-tuning` ဖြင့် level tuning ပြုလုပ်နေပါက update တစ်ကြိမ်စီပြီးတိုင်း သင်၏ rule file များကို ပြန်လည် tune လုပ်ပါ။
>> `rules` folder အတွင်း rule **အသစ်** များ ထည့်သွင်းပါက update လုပ်သည့်အခါ ၎င်းတို့ကို overwrite သို့မဟုတ် ဖျက်ပစ်မည် **မဟုတ်** ပါ။
