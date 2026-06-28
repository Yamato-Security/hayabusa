- [ရလဒ်များကို SOF-ELK (Elastic Stack) သို့ Import လုပ်ခြင်း](#importing-results-into-sof-elk-elastic-stack)
  - [SOF-ELK ကို Install လုပ်ပြီး စတင်ခြင်း](#install-and-start-sof-elk)
    - [Mac များတွင် ကွန်ရက်ချိတ်ဆက်မှု ပြဿနာ](#network-connectivity-trouble-on-macs)
  - [SOF-ELK ကို Update လုပ်ပါ။](#update-sof-elk)
  - [Hayabusa ကို Run ခြင်း](#run-hayabusa)
  - [ရွေးချယ်နိုင်သည်: Import လုပ်ထားသော ဒေတာဟောင်းများကို ဖျက်ခြင်း](#optional-deleting-old-imported-data)
  - [SOF-ELK တွင် Hayabusa logstash config ဖိုင်ကို Configure လုပ်ခြင်း](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Hayabusa ရလဒ်များကို SOF-ELK သို့ Import လုပ်ခြင်း](#import-hayabusa-results-into-sof-elk)
  - [Import အလုပ်လုပ်ခဲ့ကြောင်း Kibana တွင် စစ်ဆေးခြင်း](#check-that-the-import-worked-in-kibana)
  - [Discover တွင် ရလဒ်များကို ကြည့်ရှုခြင်း](#view-results-in-discover)
  - [ရလဒ်များကို ခွဲခြမ်းစိတ်ဖြာခြင်း](#analyzing-results)
    - [Column များ ထည့်ခြင်း](#adding-columns)
    - [Filter လုပ်ခြင်း](#filtering)
    - [Details များကို Toggle လုပ်ခြင်း](#toggling-details)
    - [ပတ်ဝန်းကျင်ရှိ documents များကို ကြည့်ရှုခြင်း](#view-surrounding-documents)
    - [Field များအတွက် မြန်ဆန်သော metrics ရယူခြင်း](#get-quick-metrics-on-fields)
  - [အနာဂတ် အစီအစဉ်များ](#future-plans)

# ရလဒ်များကို SOF-ELK (Elastic Stack) သို့ Import လုပ်ခြင်း

## SOF-ELK ကို Install လုပ်ပြီး စတင်ခြင်း

Hayabusa ၏ ရလဒ်များကို Elastic Stack သို့ လွယ်ကူစွာ Import လုပ်နိုင်ပါသည်။
DFIR စုံစမ်းစစ်ဆေးမှုများကို အဓိကထားသော အခမဲ့ elastic stack Linux distro ဖြစ်သည့် [SOF-ELK](https://github.com/philhagen/sof-elk) ကို အသုံးပြုရန် အကြံပြုပါသည်။

ပထမဦးစွာ [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README) မှ SOF-ELK 7-zipped VMware image ကို download လုပ်ပြီး unzip လုပ်ပါ။

ဗားရှင်းနှစ်မျိုး ရှိပါသည်၊ Intel CPU များအတွက် x86 နှင့် Apple M-series ကွန်ပျူတာများအတွက် ARM ဗားရှင်း ဖြစ်ပါသည်။

VM ကို boot လုပ်သောအခါ၊ ဤကဲ့သို့သော screen ကို မြင်ရပါမည်:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Kibana URL နှင့် SSH server ၏ IP address ကို မှတ်သားထားပါ။

အောက်ပါ credentials များဖြင့် log in ဝင်နိုင်ပါသည်:
* Username: `elk_user`
* Password: `forensics`

ဖော်ပြထားသော URL အရ web browser တွင် Kibana ကို ဖွင့်ပါ။
ဥပမာ: http://172.16.23.128:5601/

> Note: Kibana load ဖြစ်ရန် အချိန်အနည်းငယ် ကြာနိုင်ပါသည်။

အောက်ပါအတိုင်း webpage ကို မြင်ရပါမည်:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

VM အတွင်း command များကို ရိုက်ထည့်မည့်အစား `ssh elk_user@172.16.23.128` ဖြင့် VM ထဲသို့ SSH ဝင်ရန် အကြံပြုပါသည်။

> Note: default keyboard layout သည် US keyboard ဖြစ်ပါသည်။

### Mac များတွင် ကွန်ရက်ချိတ်ဆက်မှု ပြဿနာ

အကယ်၍ သင်သည် macOS တွင် ရှိနေပြီး terminal တွင် `no route to host` error ရရှိပါက သို့မဟုတ် browser တွင် Kibana ကို access မလုပ်နိုင်ပါက၊ ၎င်းသည် macOS ၏ local network privacy controls ကြောင့် ဖြစ်နိုင်ပါသည်။

`System Settings` တွင် `Privacy & Security` -> `Local Network` ကို ဖွင့်ပြီး သင်၏ browser နှင့် terminal program များသည် သင်၏ local network ပေါ်ရှိ devices များနှင့် ဆက်သွယ်နိုင်ရန် enable ဖြစ်နေကြောင်း သေချာအောင်လုပ်ပါ။

## SOF-ELK ကို Update လုပ်ပါ။

ဒေတာ import မလုပ်မီ၊ `sudo sof-elk_update.sh` command ဖြင့် SOF-ELK ကို update လုပ်ရန် သေချာပါစေ။

## Hayabusa ကို Run ခြင်း

Hayabusa ကို run ၍ ရလဒ်များကို JSONL သို့ သိမ်းဆည်းပါ။

ဥပမာ: `./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## ရွေးချယ်နိုင်သည်: Import လုပ်ထားသော ဒေတာဟောင်းများကို ဖျက်ခြင်း

အကယ်၍ ၎င်းသည် Hayabusa ရလဒ်များကို ပထမဆုံးအကြိမ် import လုပ်ခြင်း မဟုတ်ဘဲ အရာအားလုံးကို ရှင်းလင်းလိုပါက၊ အောက်ပါအတိုင်း ပြုလုပ်နိုင်ပါသည်:

1. SOF-ELK တွင် လက်ရှိ records များကို စစ်ဆေးပါ: `sof-elk_clear.py -i list`
2. လက်ရှိ ဒေတာကို ဖျက်ပါ: `sof-elk_clear.py -a`
3. logstash directory ရှိ ဖိုင်များကို ဖျက်ပါ: `rm /logstash/hayabusa/*`

## SOF-ELK တွင် Hayabusa logstash config ဖိုင်ကို Configure လုပ်ခြင်း

field name များကို Elastic Common Schema format သို့ ပြောင်းပေးသော Hayabusa logstash config ဖိုင်တစ်ခု SOF-ELK တွင် ပါဝင်ပြီးသား ရှိနှင့်ပါသည်။
အကယ်၍ သင်သည် Hayabusa field name များနှင့် ပိုမိုရင်းနှီးပါက၊ ကျွန်ုပ်တို့ ပေးထားသော ဖိုင်ကို အသုံးပြုရန် အကြံပြုပါသည်။

1. ပထမဦးစွာ SOF-ELK ထဲသို့ SSH ဝင်ပါ: `ssh elk_user@172.16.23.128`
2. လက်ရှိ logstash config ဖိုင်ကို ဖျက်ပါ သို့မဟုတ် ရွှေ့ပါ: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. အသစ်ဖြစ်သော [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) ဖိုင်ကို `/etc/logstash/conf.d/` သို့ upload လုပ်ပါ: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. logstash ကို reboot လုပ်ပါ: `sudo systemctl restart logstash`

ဤ config ဖိုင်သည် record တစ်ခုစီကို တစ်ခုပြီးတစ်ခု ဖွင့်၍ field အားလုံးကို ကြည့်ရှုရန် အချိန်ယူရမည့်အစား အရေးအကြီးဆုံး field များကို တစ်ချက်ကြည့်ရုံဖြင့် မြန်ဆန်စွာ မြင်နိုင်စေသည့် ပေါင်းစပ်ထားသော `DetailsText` နှင့် `ExtraFieldInfoText` field များကို ဖန်တီးပေးပါမည်။

## Hayabusa ရလဒ်များကို SOF-ELK သို့ Import လုပ်ခြင်း

Log များကို `/logstash` directory အတွင်းရှိ သင့်လျော်သော directory သို့ ကူးယူခြင်းဖြင့် SOF-ELK သို့ ingest လုပ်ပါသည်။

ပထမဦးစွာ SSH မှ `exit` ထွက်ပြီးနောက်၊ သင်ဖန်တီးခဲ့သော Hayabusa ရလဒ်ဖိုင်ကို ကူးယူပါ:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Import အလုပ်လုပ်ခဲ့ကြောင်း Kibana တွင် စစ်ဆေးခြင်း

ပထမဦးစွာ သင်၏ Hayabusa scan ၏ `Results Summary` ရှိ `Total detections`၊ `First Timestamp` နှင့် `Last Timestamp` တို့ကို မှတ်သားပါ။

ဤအချက်အလက်ကို မရရှိနိုင်ပါက၊ `Total detections` အတွက် စုစုပေါင်း line count ရရှိရန် *nix တွင် `wc -l results.jsonl` ကို run နိုင်ပါသည်။

default အားဖြင့် Hayabusa သည် performance တိုးတက်စေရန် ရလဒ်များကို အစီအစဉ်အလိုက် sort မလုပ်ပါ၊ ထို့ကြောင့် ပထမနှင့် နောက်ဆုံး timestamp ရရှိရန် ပထမနှင့် နောက်ဆုံး line များကို ကြည့်၍ မရနိုင်ပါ။
အကယ်၍ တိကျသော ပထမနှင့် နောက်ဆုံး timestamp များကို မသိပါက၊ Kibana တွင် ပထမရက်စွဲကို 2007 ခုနှစ်အဖြစ်လည်းကောင်း၊ နောက်ဆုံးနေ့ကို `now` အဖြစ်လည်းကောင်း သတ်မှတ်လိုက်ရုံဖြင့် ရလဒ်အားလုံးကို ရရှိမည်ဖြစ်သည်။

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

import လုပ်ပြီးသော event များ၏ `Total Records` အပြင် ပထမနှင့် နောက်ဆုံး timestamp များကိုပါ ယခု မြင်ရပါမည်။

event အားလုံးကို import လုပ်ရန် တစ်ခါတစ်ရံ အချိန်အနည်းငယ် ကြာတတ်သောကြောင့်၊ `Total Records` သည် သင်မျှော်လင့်ထားသော count ဖြစ်လာသည်အထိ page ကို refresh ဆက်လုပ်ပါ။

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

import အောင်မြင်ခဲ့ခြင်း ရှိမရှိ ကြည့်ရှုရန် `sof-elk_clear.py -i list` ကို run ၍ terminal မှလည်း စစ်ဆေးနိုင်ပါသည်။
သင်၏ `evtxlogs` index တွင် record များ ပိုများလာသည်ကို မြင်ရပါမည်:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

import လုပ်စဉ် parsing error များ ရှိပါက GitHub တွင် issue တစ်ခု ဖန်တီးပေးပါ။
`/var/log/logstash/logstash-plain.log` log ဖိုင်၏ အဆုံးပိုင်းကို ကြည့်ရှုခြင်းဖြင့် ၎င်းကို စစ်ဆေးနိုင်ပါသည်။

## Discover တွင် ရလဒ်များကို ကြည့်ရှုခြင်း

ဘယ်ဘက်အပေါ်ထောင့်ရှိ sidebar icon ကို click ၍ `Discover` ကို click ပါ:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

`No results match your search criteria` ကို မြင်ရဖွယ်ရှိပါသည်။

ဘယ်ဘက်အပေါ်ထောင့်ရှိ `logstash-*` index ဟု ရေးထားသည့်နေရာတွင် ၎င်းကို click ၍ `evtxlogs-*` သို့ ပြောင်းပါ။
Discover timeline ကို ယခု မြင်ရပါမည်။

## ရလဒ်များကို ခွဲခြမ်းစိတ်ဖြာခြင်း

default Discover view သည် ဤကဲ့သို့ ဖြစ်သင့်ပါသည်:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

အပေါ်ရှိ histogram ကို ကြည့်ခြင်းဖြင့် event များ မည်သည့်အချိန်တွင် ဖြစ်ပွားခဲ့သည်နှင့် event များ၏ ကြိမ်နှုန်းကို ခြုံငုံသိမြင်နိုင်ပါသည်။ 

### Column များ ထည့်ခြင်း

ဘယ်ဘက် sidebar တွင်၊ field တစ်ခုပေါ်သို့ hover လုပ်ပြီးနောက် plus sign ကို click ခြင်းဖြင့် column များတွင် ဖော်ပြလိုသော field များကို ထည့်နိုင်ပါသည်။
field များစွာ ရှိသောကြောင့်၊ သင်ရှာဖွေနေသော field name ၏ နာမည်ကို search box တွင် ရိုက်ထည့်လိုပေမည်။

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

အစပြုရန်အတွက်၊ အောက်ပါ column များကို အကြံပြုပါသည်:
- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

သင်၏ monitor သည် ကျယ်လုံလောက်ပါက၊ field အချက်အလက်အားလုံးကို မြင်နိုင်ရန် `ExtraFieldInfoText` ကိုပါ ထည့်လိုပေမည်။

သင်၏ Discover view သည် ယခု ဤကဲ့သို့ ဖြစ်သင့်ပါသည်:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### Filter လုပ်ခြင်း

သတ်မှတ်ထားသော event များနှင့် alert များကို ရှာဖွေရန် KQL(Kibana Query Language) ဖြင့် filter လုပ်နိုင်ပါသည်။ ဥပမာ:
  * `Level: "crit"`: critical alert များကိုသာ ပြသပါ။
  * `Level: "crit" OR Level: "high"`: high နှင့် critical alert များကို ပြသပါ။
  * `NOT Level: info`: informational event များကို မပြသဘဲ alert များကိုသာ ပြသပါ။
  * `MitreTactics: *LatMov*`: lateral movement နှင့် သက်ဆိုင်သော event များနှင့် alert များကို ပြသပါ။
  * `"PW Spray"`: "Password Spray" ကဲ့သို့သော သတ်မှတ်ထားသော တိုက်ခိုက်မှုများကိုသာ ပြသပါ။
  * `"LID: 0x8724ead"`: Logon ID 0x8724ead နှင့် ဆက်စပ်နေသော လုပ်ဆောင်ချက်အားလုံးကို ဖော်ပြပါ။
  * `Details_TgtUser: admmig`: target user သည် `admmig` ဖြစ်သော event အားလုံးကို ရှာဖွေပါ။

### Details များကို Toggle လုပ်ခြင်း

record တစ်ခုရှိ field အားလုံးကို စစ်ဆေးရန်၊ timestamp ၏ ဘေးရှိ icon (Toggle dialog with details) ကို click လိုက်ရုံပါ:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### ပတ်ဝန်းကျင်ရှိ documents များကို ကြည့်ရှုခြင်း

သတ်မှတ်ထားသော alert တစ်ခု၏ မတိုင်မီနှင့် အပြီးရှိ event များကို တိုက်ရိုက်ကြည့်ရှုလိုပါက၊ ပထမဦးစွာ ထို alert ၏ details များကို ဖွင့်ပြီးနောက် ညာဘက်အပေါ်ထောင့်ရှိ `View surrounding documents` ကို click ပါ:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

ဤဥပမာတွင်၊ Pass the Hash တိုက်ခိုက်မှု alert ၏ မတိုင်မီနှင့် အပြီးရှိ event များကို ကျွန်ုပ်တို့ မြင်ရပါသည်:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Note: event ပိုမိုရယူရန် အပေါ်ရှိ `Load x newer documents` သို့မဟုတ် အောက်ရှိ `Load x older documents` ရှိ နံပါတ်များကို ပြောင်းပါ။

### Field များအတွက် မြန်ဆန်သော metrics ရယူခြင်း

ဘယ်ဘက် column တွင်၊ field name တစ်ခုကို click လိုက်ပါက ၎င်း၏ အသုံးပြုမှုဆိုင်ရာ မြန်ဆန်သော metrics ကို ပေးပါမည်:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> ဒေတာကို မြန်ဆန်စေရန် sample ယူထားသောကြောင့် ၎င်းသည် 100% တိကျမှု မရှိကြောင်း သတိပြုပါ။

## အနာဂတ် အစီအစဉ်များ

* CSV အတွက် Logstash parser များ
* ကြိုတင်တည်ဆောက်ထားသော dashboard
