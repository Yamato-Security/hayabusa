# Rule ဖန်တီးခြင်းဆိုင်ရာ အကြံပြုချက်များ

## Rule ဖန်တီးခြင်းဆိုင်ရာ အကြံပြုချက်

1. **ဖြစ်နိုင်သမျှ `Channel` သို့မဟုတ် `ProviderName` အမည်နှင့် `EventID` နံပါတ်ကို အမြဲတမ်း သတ်မှတ်ပါ။** ပုံသေအားဖြင့် `./rules/config/target_event_IDs.txt` တွင် ဖော်ပြထားသော event ID များကိုသာ scan လုပ်မည်ဖြစ်သောကြောင့် EID သည် ထိုဖိုင်ထဲတွင် မရှိသေးပါက `EventID` နံပါတ်အသစ်ကို ထိုဖိုင်ထဲသို့ ထည့်သွင်းရန် လိုအပ်နိုင်ပါသည်။

2. **မလိုအပ်သည့်အခါ `selection` သို့မဟုတ် `filter` field များ စွာစွာနှင့် အလွန်အကျွံ grouping ပြုလုပ်ခြင်းကို ကျေးဇူးပြု၍ မသုံးပါနှင့်။** ဥပမာ -

#### ဤသို့ပြုမည့်အစား

```yaml
detection:
    SELECTION_1:
        Channnel: Security
    SELECTION_2:
        EventID: 4625
    SELECTION_3:
        LogonType: 3
    FILTER_1:
        SubStatus: "0xc0000064"   #Non-existent user
    FILTER_2:
        SubStatus: "0xc000006a"   #Wrong password
    condition: SELECTION_1 and SELECTION_2 and SELECTION_3 and not (FILTER_1 or FILTER_2)
```

#### ကျေးဇူးပြု၍ ဤသို့ပြုပါ

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        - SubStatus: "0xc0000064"   #Non-existent user
        - SubStatus: "0xc000006a"   #Wrong password
    condition: selection and not filter
```

3. **section များစွာ လိုအပ်သည့်အခါ ပထမ section ကို channel နှင့် event ID အချက်အလက်များဖြင့် `section_basic` section အဖြစ် အမည်ပေးပြီး အခြား selection များကို `section_` နှင့် `filter_` နောက်တွင် အဓိပ္ပာယ်ရှိသော အမည်များဖြင့် အမည်ပေးပါ။ ထို့အပြင် နားလည်ရန်ခက်ခဲသည့်အရာများကို ရှင်းပြရန် comment များ ရေးပါ။** ဥပမာ -

#### ဤသို့ပြုမည့်အစား

```yaml
detection:
    Takoyaki:
        Channel: Security
        EventID: 4648
    Naruto:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    Sushi:
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    Godzilla:
        SubjectUserName|endswith: "$"
    Ninja:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$"
        IpAddress: "-"
    Daisuki:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: Takoyaki and Daisuki and not (Naruto and not Godzilla) and not Ninja and not Sushi
```

#### ကျေးဇူးပြု၍ ဤသို့ပြုပါ

```yaml
detection:
    selection_basic:
        Channel: Security
        EventID: 4648
    selection_TargetUserIsComputerAccount:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    filter_UsersAndTargetServerAreComputerAccounts:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_SubjectUserIsComputerAccount:
        SubjectUserName|endswith: "$"
    filter_SystemAccounts:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_SuspiciousProcess:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_basic and selection_SuspiciousProcess and not (selection_TargetUserIsComputerAccount
               and not filter_SubjectUserIsComputerAccount) and not filter_SystemAccounts and not filter_UsersAndTargetServerAreComputerAccounts
```

## Sigma rule များကို Hayabusa format သို့ ပြောင်းလဲခြင်း

Sigma မှ Hayabusa နှင့် တွဲဖက်အသုံးပြုနိုင်သော format သို့ rule များ ပြောင်းလဲရန် backend တစ်ခုကို ကျွန်ုပ်တို့ [ဤနေရာတွင်](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) ဖန်တီးထားပါသည်။
