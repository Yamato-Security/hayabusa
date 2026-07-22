# Timesketch ဖြင့် Hayabusa ရလဒ်များကို ခွဲခြမ်းစိတ်ဖြာခြင်း

## အကြောင်း

"[Timesketch](https://timesketch.org/) သည် ပူးပေါင်းဆောင်ရွက်သော forensic timeline ခွဲခြမ်းစိတ်ဖြာမှုအတွက် open-source ကိရိယာတစ်ခုဖြစ်သည်။ sketches များကို အသုံးပြုခြင်းဖြင့် သင်နှင့် သင်၏ပူးပေါင်းဆောင်ရွက်သူများသည် သင်တို့၏ timelines များကို လွယ်ကူစွာ စီစဉ်နိုင်ပြီး အားလုံးကို တစ်ပြိုင်နက်တည်း ခွဲခြမ်းစိတ်ဖြာနိုင်သည်။ ကြွယ်ဝသော annotation များ၊ comment များ၊ tag များနှင့် star များဖြင့် သင်၏ raw data သို့ အဓိပ္ပါယ်ဖြည့်ဆည်းပါ။"

သင်သည် တစ်ဦးတည်း အလုပ်လုပ်နေပြီး အရွယ်အစား MB ရာဂဏန်းအနည်းငယ်သာရှိသော CSV ဖိုင်တစ်ခုကိုသာ ခွဲခြမ်းစိတ်ဖြာနေသည့် သေးငယ်သော စုံစမ်းစစ်ဆေးမှုများအတွက် Timeline Explorer သည် သင့်တော်ပါသည်၊ သို့သော် သင်သည် ပိုကြီးသော data သို့မဟုတ် အဖွဲ့တစ်ဖွဲ့နှင့် အလုပ်လုပ်နေသည့်အခါ Timesketch ကဲ့သို့သော ကိရိယာတစ်ခုသည် များစွာ ပိုကောင်းပါသည်။

Timesketch သည် အောက်ပါ အကျိုးကျေးဇူးများကို ပေးသည်-

1. ၎င်းသည် အလွန်မြန်ပြီး ကြီးမားသော data ကို ကိုင်တွယ်နိုင်သည်
2. ၎င်းသည် အသုံးပြုသူများစွာ တစ်ပြိုင်နက်တည်း အသုံးပြုနိုင်သော ပူးပေါင်းဆောင်ရွက်ရေး ကိရိယာတစ်ခုဖြစ်သည်
3. ၎င်းသည် အဆင့်မြင့် data ခွဲခြမ်းစိတ်ဖြာမှု၊ histogram များနှင့် ပုံဖော်ပြသမှုများကို ပေးသည်
4. ၎င်းသည် Windows တွင်သာ ကန့်သတ်ထားခြင်းမရှိပါ
5. ၎င်းသည် အဆင့်မြင့် querying ကို ပံ့ပိုးသည်

CTI ပံ့ပိုးမှု၊ analyzer အမျိုးမျိုး၊ interactive notebook များ စသည်ဖြင့် အခြားအကျိုးကျေးဇူးများစွာ ရှိသည်...
ပိုမိုသိရှိလိုပါက [user's guide](https://timesketch.org/guides/user/upload-data/) နှင့် [YouTube channel](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) ကို ကျေးဇူးပြု၍ ကြည့်ရှုပါ။

တစ်ခုတည်းသော အားနည်းချက်မှာ သင်၏ lab environment တွင် Timesketch server တစ်ခုကို setup လုပ်ရမည်ဖြစ်သော်လည်း ကံကောင်းစွာဖြင့် ၎င်းသည် ပြုလုပ်ရန် အလွန်လွယ်ကူသည်။

## Installing
### Docker
တရားဝင် ညွှန်ကြားချက်များကို [here](https://docs.docker.com/compose/install) တွင် လိုက်နာပါ။

### Ubuntu
**မှတ်ချက်:** ဆက်လက်မလုပ်ဆောင်မီ Docker ကို install လုပ်ထားရမည်။ Docker ကို install မလုပ်ရသေးပါက [အထက်ပါ Docker installation ညွှန်ကြားချက်များ](#docker) ကို ကျေးဇူးပြု၍ လိုက်နာပါ။
ကျွန်ုပ်တို့သည် အနည်းဆုံး memory 8GB ရှိသော နောက်ဆုံးထွက် Ubuntu LTS Server edition ကို အသုံးပြုရန် အကြံပြုပါသည်။
၎င်းကို [here](https://ubuntu.com/download/server) တွင် download လုပ်နိုင်သည်။
၎င်းကို setup လုပ်သည့်အခါ minimal install ကို ရွေးချယ်ပါ။
OS ကို setup လုပ်သည့်အခါ docker ကို install မလုပ်ပါနှင့်။
သင့်တွင် `ifconfig` ရရှိနိုင်မည်မဟုတ်သဖြင့် ၎င်းကို `sudo apt install net-tools` ဖြင့် install လုပ်ပါ။

ထို့နောက် VM ၏ IP address ကိုရှာရန် `ifconfig` ကို run ပြီး လိုအပ်ပါက ၎င်းသို့ ssh ဝင်ပါ။

အောက်ပါ command များကို run ပါ-
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**မှတ်ချက်:** ဆက်လက်မလုပ်ဆောင်မီ သင်၏စနစ်တွင် [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/) ကို install လုပ်ပြီး run နေကြောင်း သေချာစေပါ။
Timesketch repository ကို clone လုပ်ပြီး directory ထဲသို့ ပြောင်းပါ။
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
အောက်ပါ အဆင့်များကို လိုက်နာ၍ Docker container ကို စတင်ပါ။

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Logging in

`ifconfig` ဖြင့် Timesketch server ၏ IP address ကိုရှာ၍ web browser ဖြင့် ဖွင့်ပါ။
သင်သည် login page သို့ ပြန်ညွှန်းခံရမည်ဖြစ်သည်။
အသုံးပြုသူတစ်ဦးထည့်သည့်အခါ သင်အသုံးပြုခဲ့သော user credentials များဖြင့် log in ဝင်ပါ။

## Creating a new sketch

`Start a new investigation` အောက်တွင် `BLANK SKETCH` ကို နှိပ်ပါ။
sketch ကို သင်၏စုံစမ်းစစ်ဆေးမှုနှင့် ဆက်စပ်သည့်အရာတစ်ခုဖြင့် အမည်ပေးပါ။

## Uploading your timeline

`+ ADD TIMELINE` ကို နှိပ်ပြီးနောက် Plaso, JSONL သို့မဟုတ် CSV ဖိုင်တစ်ခု upload လုပ်ရန် တောင်းဆိုသော dialog box တစ်ခုကို သင်တွေ့မြင်ရမည်။
ကံမကောင်းစွာဖြင့် Timesketch သည် Hayabusa ၏ `JSONL` format ကို လက်ရှိတွင် import လုပ်၍မရသေးသဖြင့် အောက်ပါ command ဖြင့် CSV timeline တစ်ခုကို ဖန်တီး၍ upload လုပ်ပါ-

```shell
hayabusa-x.x.x-win-x64.exe dfir-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --iso-8601
```

> မှတ်ချက်: `timesketch*` profile တစ်ခုကို ရွေးချယ်ပြီး timestamp ကို UTC အတွက် `--iso-8601` သို့မဟုတ် local time အတွက် `--rfc-3339` အဖြစ် သတ်မှတ်ရန် လိုအပ်သည်။ သင်အလိုရှိပါက အခြား Hayabusa option များကို ထည့်နိုင်သော်လည်း newline character များက import ကို ပျက်စီးစေမည်ဖြစ်သဖြင့် `-M, --multiline` option ကို မထည့်ပါနှင့်။

"Select file to upload" dialog box တွင် သင်၏ timeline ကို `hayabusa` ကဲ့သို့ အမည်ပေး၍ `Comma (,)` CSV delimiter ကို ရွေးချယ်ပြီး `SUBMIT` ကို နှိပ်ပါ။

> သင်၏ CSV ဖိုင်သည် upload လုပ်ရန် ကြီးလွန်းပါက Takajo ၏ [split-dfir-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-dfir-timeline-command) command ဖြင့် ဖိုင်ကို CSV ဖိုင်များစွာအဖြစ် ခွဲခြားနိုင်သည်။

ဖိုင်ကို import လုပ်နေစဉ် လည်ပတ်နေသော စက်ဝိုင်းတစ်ခုကို သင်တွေ့မြင်ရမည်ဖြစ်သဖြင့် ၎င်းပြီးဆုံးပြီး `hayabusa` ပေါ်လာသည်အထိ ကျေးဇူးပြု၍ စောင့်ဆိုင်းပါ။

## Analysis tips

### Showing the timeline

**မှတ်ချက်: import အောင်မြင်စွာ ပြီးဆုံးပြီးနောက်ပင် ၎င်းသည် `Your search did not match any events` ကို ပြသမည်ဖြစ်ပြီး `hayabusa` timeline တွင် event `0` ခုရှိမည်ဖြစ်သည်။**

`*` ကိုရှာဖွေပါက အောက်တွင်ပြထားသည့်အတိုင်း event များ ပေါ်လာမည်-

![Timesketch results](../assets/doc/TimesketchImport/TimesketchResults.png)

### Alert details

`message` column အောက်ရှိ alert rule title တစ်ခုကို နှိပ်ပါက alert အကြောင်း အသေးစိတ်အချက်အလက်ကို သင်ရရှိမည်-

![Alert details](../assets/doc/TimesketchImport/AlertDetails.png)

sigma rule logic ကို နားလည်လိုပါက description နှင့် reference များ စသည်တို့ကို ရှာဖွေလိုပါက ကျေးဇူးပြု၍ [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository တွင် rule ကို ရှာဖွေပါ။

#### Field filtering

event တစ်ခု၏ rule title ကို နှိပ်ခြင်းဖြင့် ၎င်း၏အသေးစိတ်ကို ဖွင့်ပြီးနောက် မည်သည့် field အပေါ်တွင်မဆို hover လုပ်ခြင်းဖြင့် value ကို လွယ်ကူစွာ filter in သို့မဟုတ် filter out လုပ်နိုင်သည်-

![Filter In Out](../assets/doc/TimesketchImport/FilterInOut.png)

#### Aggregation analytics

hover လုပ်နေစဉ် ဘယ်ဘက်အစွန်ဆုံးရှိ `Aggregation dialog` icon ကို နှိပ်ပါက ထို field နှင့်ပတ်သက်သော အလွန်ကောင်းမွန်သော event data analytics ကို သင်ရရှိမည်-

![Event Data Analytics](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### User comments

alert တစ်ခုကို နှိပ်၍ အသေးစိတ်အချက်အလက်ရယူသည့်အခါ အောက်တွင်ပြထားသည့်အတိုင်း ညာဘက်ခြမ်းတွင် comment dialog box icon အသစ်တစ်ခု ပေါ်လာသည်-

![Comment Icon](../assets/doc/TimesketchImport/CommentIcon.png)

ဤနေရာတွင် အသုံးပြုသူများသည် chat တစ်ခုစတင်ပြီး စုံစမ်းစစ်ဆေးမှုအကြောင်း comment များ ရေးနိုင်သည်။

> သင်အဖွဲ့တစ်ဖွဲ့တွင် အလုပ်လုပ်နေပါက မည်သူက မည်သည့်အရာ ရေးခဲ့သည်ကို သိရှိနိုင်ရန် အဖွဲ့ဝင်တစ်ဦးစီအတွက် မတူညီသော user account များ ဖန်တီးသင့်သည်။

![Comment chat](../assets/doc/TimesketchImport/CommentChat.png)

> comment တစ်ခုအပေါ်တွင် hover လုပ်ပါက message များကို လွယ်ကူစွာ edit လုပ်ပြီး delete လုပ်နိုင်သည်။

### Modifying columns

default အားဖြင့် timestamp နှင့် alert rule title ကိုသာ ပြသမည်ဖြစ်သဖြင့် field များကို စိတ်ကြိုက်ပြင်ဆင်ရန် `Modify columns` icon များကို နှိပ်ပါ-

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

ဤသည်က အောက်ပါ dialog box ကို ဖွင့်ပေးမည်-

![Select columns](../assets/doc/TimesketchImport/SelectColumns.png)

ကျွန်ုပ်တို့သည် အနည်းဆုံး အောက်ပါ column များကို **အစဉ်လိုက်** ထည့်ရန် အကြံပြုသည်-

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

column များ၏ အစီအစဉ်သည် သင်ထည့်သည့်အစီအစဉ်အပေါ်မူတည်၍ ပြောင်းလဲမည်ဖြစ်သဖြင့် ပိုအရေးကြီးသော field များကို ဦးစွာထည့်ပါ။

သင်၏ screen တွင် နေရာကျန်နေသေးပါက ဤနေရာတွင်ပြထားသည့်အတိုင်း `Details` ကိုလည်း ထည့်ရန် ကျွန်ုပ်တို့ အကြံပြုသည်-

![Details](../assets/doc/TimesketchImport/Details.png)

သင်၏ screen တွင် နေရာကျန်နေသေးပါက `ExtraFieldInfo` ကိုလည်း ထည့်ရန် ကျွန်ုပ်တို့ အကြံပြုသော်လည်း ဤနေရာတွင် သင်တွေ့မြင်ရသည့်အတိုင်း column များ အလွန်များစွာ ထည့်ပါက `message` field သည် အလွန်ကျဉ်းသွားပြီး alert title များကို ဖတ်၍မရတော့ပါ-

![Too much details](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Top icons

#### Elipsis icon

`···` icon ကို နှိပ်ပါက row များကို ပိုကျစ်လစ်စေပြီး ရလဒ်များအတွက် နေရာပိုရစေရန် `Timeline name` ကို ဖယ်ရှားနိုင်သည်-

![More room](../assets/doc/TimesketchImport/MoreRoom.png)

#### Event histogram

timeline ကို ပုံဖော်ပြသရန် event histogram ကို toggle on လုပ်နိုင်သည်-

![Event Histogram](../assets/doc/TimesketchImport/EventHistogram.png)

bar တစ်ခုကို နှိပ်ပါက ထိုကာလအတွင်းရှိ ရလဒ်များကိုသာ ပြသရန် time filter တစ်ခု ဖန်တီးပေးမည်ဖြစ်သည်။

#### Save current search

timestamp များ၏ အထက်နှင့် `Toggle Event Histogram` icon ၏ ဘယ်ဘက်ရှိ `Save current search` icon ကို နှိပ်ပါက သင်၏လက်ရှိ search query နှင့် column configuration ကို `Saved Searches` သို့ သိမ်းဆည်းနိုင်သည်။
နောက်ပိုင်းတွင် ဘယ်ဘက်ခြမ်း sidebar မှ သင်နှစ်သက်သော search များကို လွယ်ကူစွာ ဝင်ရောက်နိုင်သည်။

### Search bar

သတ်မှတ်ထားသော severity level အချို့ရှိ alert များကိုသာ ပြသခြင်းဖြင့် စတင်ရန် အသုံးဝင်သော query အချို့ ဤနေရာတွင် ရှိသည်-

1. critical alert များကိုသာ ပြသရန် `Level:crit`။
2. high နှင့် critical alert များကို ပြသရန် `Level:crit OR Level:high`
3. informational alert များကို ဖွက်ထားရန် `NOT Level:info`

field name အပြင် `:` အပြင် value ကို ရိုက်ထည့်ခြင်းဖြင့် လွယ်ကူစွာ filter လုပ်နိုင်သည်။
filter များကို `AND`, `OR`, နှင့် `NOT` ဖြင့် ပေါင်းစပ်နိုင်သည်။
Wildcard များနှင့် regular expression များကို ပံ့ပိုးသည်။

ပိုမိုအဆင့်မြင့်သော query များအတွက် [here](https://timesketch.org/guides/user/search-query-guide/) ရှိ user guide ကို ကိုးကားပါ။

#### Search history

search bar ၏ ဘယ်ဘက်ရှိ clock icon ကို နှိပ်ပါက ယခင်ထည့်သွင်းခဲ့သော query များကို ပြသနိုင်သည်။
ယခင်နှင့် နောက်ထပ် query များကို run ရန် ဘယ်နှင့်ညာ arrow icon များကိုလည်း နှိပ်နိုင်သည်။

![Search History](../assets/doc/TimesketchImport/SearchHistory.png)

### Vertical elipsis

timestamp တစ်ခု၏ ဘယ်ဘက်ရှိ vertical elipsis ကို နှိပ်ပြီး `Context search` ကို နှိပ်ပါက သတ်မှတ်ထားသော event တစ်ခု၏ မတိုင်မီနှင့် နောက်တွင် ဖြစ်ပွားခဲ့သော alert များကို သင်မြင်နိုင်သည်-

![Vertical elipsis](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

ဤသည်က အောက်ပါအရာကို ဖော်ပြပေးမည်-

![Context Search](../assets/doc/TimesketchImport/ContextSearch.png)

အထက်ပါဥပမာတွင် 60 စက္ကန့် (`60S`) မတိုင်မီနှင့် နောက်ရှိ event များကို ပြသနေသော်လည်း ၎င်းကို +- 1 စက္ကန့် (`1S`) မှ +- 60 မိနစ် (`60M`) အထိ ချိန်ညှိနိုင်သည်။

ပြသထားသော event များကို ပိုမိုနက်ရှိုင်းစွာ ဖော်ထုတ်လိုပါက standard timeline တွင် event များကို ပြသရန် `Replace Search` ကို နှိပ်ပါ။

### Stars and tags

timestamp တစ်ခု၏ ဘယ်ဘက်ရှိ star icon ကို နှိပ်ခြင်းဖြင့် ၎င်းကို star ပေးပြီး အရေးကြီးသော event တစ်ခုအဖြစ် မှတ်သားနိုင်သည်။

event များတွင် tag များကိုလည်း ထည့်နိုင်သည်။
ဤသည်က event တစ်ခုသည် သံသယဖြစ်ဖွယ်၊ အန္တရာယ်ရှိ၊ false positive စသည်ဖြင့် ဖြစ်ကြောင်း သင်အတည်ပြုပြီးကြောင်း အခြားသူများသို့ ညွှန်ပြရန် အသုံးဝင်သည်...
သင်အဖွဲ့တစ်ဖွဲ့တွင် အလုပ်လုပ်နေပါက တစ်စုံတစ်ဦးက alert ကို လက်ရှိ စုံစမ်းစစ်ဆေးနေကြောင်း ညွှန်ပြရန် `under investigation by xxx` ကဲ့သို့သော tag များ ဖန်တီးနိုင်သည်။

![Stars and tags](../assets/doc/TimesketchImport/StarsAndTags.png)
