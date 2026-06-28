# Config Commands

## `config-critical-systems` command

ဤ command သည် domain controller များနှင့် file server များကဲ့သို့သော အရေးကြီးသော system များကို အလိုအလျောက်ရှာဖွေပြီး `./config/critical_systems.txt` config ဖိုင်ထဲသို့ ထည့်သွင်းပေးမည်ဖြစ်ပြီး၊ alert အားလုံးကို level တစ်ဆင့်တိုးမြှင့်ပေးမည်ဖြစ်သည်။
၎င်းသည် domain controller ဟုတ်မဟုတ်ဆုံးဖြတ်ရန် Security 4768 (Kerberos TGT requested) event များကို ရှာဖွေမည်ဖြစ်သည်။
၎င်းသည် file server ဟုတ်မဟုတ်ဆုံးဖြတ်ရန် Security 5145 (Network Share File Access) event များကို ရှာဖွေမည်ဖြစ်သည်။
`critical_systems.txt` ဖိုင်ထဲသို့ ထည့်သွင်းထားသော hostname များအတွက် low ထက်မြင့်သော alert အားလုံးကို level တစ်ဆင့်တိုးမြှင့်ပေးမည်ဖြစ်ပြီး အမြင့်ဆုံး `emergency` level အထိဖြစ်သည်။

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### `config-critical-systems` command examples

* `../hayabusa-sample-evtx` directory တွင် domain controller များနှင့် file server များကို ရှာဖွေရန်:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
