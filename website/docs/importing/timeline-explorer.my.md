# Timeline Explorer ဖြင့် Hayabusa ရလဒ်များကို ခွဲခြမ်းစိတ်ဖြာခြင်း

## အကြောင်း

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) သည် DFIR ရည်ရွယ်ချက်များအတွက် CSV ဖိုင်များကို ခွဲခြမ်းစိတ်ဖြာသည့်အခါ Excel ကို အစားထိုးရန်အတွက် အခမဲ့ဖြစ်သော်လည်း source-code ပိတ်ထားသည့် tool တစ်ခုဖြစ်သည်။
၎င်းသည် C# ဖြင့်ရေးသားထားသော Windows သီးသန့်အသုံးပြုသည့် GUI tool တစ်ခုဖြစ်သည်။
ဤ tool သည် ခွဲခြမ်းစိတ်ဖြာသူတစ်ဦးတည်းက ဆောင်ရွက်သော စုံစမ်းစစ်ဆေးမှုငယ်များအတွက်နှင့် DFIR ခွဲခြမ်းစိတ်ဖြာမှုကို စတင်လေ့လာနေသူများအတွက် အလွန်ကောင်းမွန်သော်လည်း၊ interface သည် ပထမဆုံးအချိန်တွင် နားလည်ရန်ခက်ခဲနိုင်သဖြင့် မတူညီသော features များကို နားလည်ရန် ဤလမ်းညွှန်ကို အသုံးပြုပါ။

## တပ်ဆင်ခြင်းနှင့် Run ခြင်း

application ကို တပ်ဆင်ရန် မလိုအပ်ပါ။
[https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) မှ နောက်ဆုံးဗားရှင်းကို download လုပ်ပြီး unzip လုပ်ကာ `TimelineExplorer.exe` ကို run လိုက်ပါ။
သင့်တွင် သင့်လျော်သော .NET runtime မရှိပါက ၎င်းကို တပ်ဆင်ရန်လိုအပ်ကြောင်း message တစ်ခု pop up ဖြစ်လာမည်ဖြစ်သည်။
ဤစာရေးချိန် (2025/2/14) တွင် နောက်ဆုံးဗားရှင်းသည် .NET ဗားရှင်း `9` ပေါ်တွင် run သော `2.1.0` ဖြစ်သည်။

## CSV ဖိုင်တစ်ခုကို Load လုပ်ခြင်း

CSV ဖိုင်တစ်ခုကို load လုပ်ရန် menu မှ `File` -> `Open` ကို နှိပ်လိုက်ပါ။

အောက်ပါအတိုင်း မြင်တွေ့ရမည်ဖြစ်သည်-

![First Start](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

အောက်ခြေဆုံးတွင် filename, `Total lines` နှင့် `Visible lines` တို့ကို မြင်တွေ့နိုင်သည်။

CSV ဖိုင်တွင် တွေ့ရသော columns များအပြင် Timeline Explorer က ဘယ်ဘက်တွင် ထည့်ထားသော columns နှစ်ခုရှိသည်- `Line` နှင့် `Tag`။
`Line` သည် line နံပါတ်ကို ပြသသော်လည်း စုံစမ်းစစ်ဆေးမှုများအတွက် ပုံမှန်အားဖြင့် အသုံးမဝင်သဖြင့် ဤ column ကို ဖျောက်ထားလိုနိုင်သည်။
`Tag` သည် နောက်ပိုင်း ထပ်မံခွဲခြမ်းစိတ်ဖြာရန် မှတ်သားလိုသော events များအတွက် checkmark ထည့်ခွင့်ပြုသည် စသည်...
ကံမကောင်းစွာဖြင့်၊ data ကို ထပ်ရေးခြင်းမှ ကာကွယ်ရန် CSV ဖိုင်ကို read-only mode ဖြင့် ဖွင့်ထားသဖြင့် events များတွင် custom tags များ ထည့်ခြင်းနှင့် events များအကြောင်း comments များ ရေးချခြင်းတို့ လုပ်နိုင်သည့်နည်းလမ်း မရှိပါ။

## Data Filtering

header တစ်ခု၏ ညာဘက်အပေါ်ပိုင်းတွင် မောက်စ်ကို ထားလိုက်ပါက အမည်းရောင် filter icon တစ်ခု ပေါ်လာသည်ကို မြင်တွေ့ရမည်ဖြစ်သည်။

![Basic Data Filtering](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

`high` နှင့် `crit` (`critical`) alerts များကို ဦးစွာ triage လုပ်ရန် severity level တွင် checkmark များ ထည့်နိုင်သည်။
ဤ filtering သည် `Rule Title` အောက်ရှိ အရာအားလုံးကို check လုပ်ပြီးနောက် ဆူညံသော rules များကို un-check လုပ်ခြင်းဖြင့် ဆူညံသော alerts များကို စစ်ထုတ်ရန်အတွက်လည်း အလွန်အသုံးဝင်သည်။

အောက်တွင် ပြထားသည့်အတိုင်း `Text Filters` ကို နှိပ်ပါက ပိုမိုအဆင့်မြင့်သော filters များကို ဖန်တီးနိုင်သည်-

![Advanced Data Filtering](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

သို့သော် ဤနေရာတွင် filters များ ဖန်တီးမည့်အစား header အောက်ရှိ `ABC` icon ကို နှိပ်ပြီး ဤနေရာတွင် filters များ apply လုပ်ခြင်းက အများအားဖြင့် ပိုမိုလွယ်ကူသည်-

![ABC Filtering](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

ကံမကောင်းစွာဖြင့်၊ ဤနေရာနှစ်ခုသည် အနည်းငယ်ကွဲပြားသော filtering options များကို ပေးသဖြင့် data ကို filter လုပ်ရန် နေရာနှစ်ခုလုံးကို သိရှိထားသင့်သည်။

ဥပမာအားဖြင့်၊ စစ်ထုတ်လိုသော `Proc Exec` events များ အလွန်များနေပါက `Does not contain` ကို ရွေးပြီး `Proc Exec` ကို ရိုက်ထည့်ကာ ထို events များကို လျစ်လျူရှုနိုင်သည်-

![Rule Filtering](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

အောက်ဘက်သို့ ကြည့်လိုက်ပါက filter အတွက် rule ကို မတူညီသော အရောင်များဖြင့် မြင်တွေ့နိုင်သည်။
filter ကို ယာယီ ပိတ်ထားလိုပါက ၎င်းကို uncheck လုပ်လိုက်ရုံဖြစ်သည်။
filters အားလုံးကို ရှင်းလင်းလိုပါက `X` ခလုတ်ကို နှိပ်ပါ။

နောက်ထပ် ဆူညံသော rule တစ်ခုကို လျစ်လျူရှုလိုပါက အောက်ညာဘက်ထောင့်ရှိ `Edit Filter` ကို နှိပ်ခြင်းဖြင့် `Filter Editor` ကို ဖွင့်သင့်သည်-

![Filter Editor](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

`Not Contains([Rule Title], 'Proc Exec')` text ကို copy ကူးပြီး `and` ထည့်ကာ၊ တူညီသော filter ကို paste လုပ်ပြီး `Proc Exec` ကို `Possible LOLBIN` သို့ ပြောင်းပါက ယခု ဤ rules နှစ်ခုကို လျစ်လျူရှုနိုင်သည်-

![Multiple Filters](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

filters များစွာကို ပေါင်းစပ်ရန် အလွယ်ကူဆုံးနည်းလမ်းမှာ ဦးစွာ `ABC` icon မှ filter syntax ကို ဖန်တီးပြီး၊ ထို text ကို copy, paste လုပ်ကာ တည်းဖြတ်ပြီး `and`, `or` နှင့် `not` တို့ဖြင့် filters များကို ပေါင်းစပ်ခြင်းဖြစ်သည်။

သင့် filters များကို တည်းဖြတ်ရန် ဖြစ်နိုင်သော options များအတွက် dropdown box တစ်ခု ရရှိရန် အရောင်ပါ text တစ်ခုခုကိုလည်း နှိပ်နိုင်သည်-

![Dropdown editing](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Header Options

header တစ်ခုခုကို right-click နှိပ်ပါက အောက်ပါ options များ ရရှိမည်ဖြစ်သည်-

![Header Options](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

ဤ options အများစုသည် ၎င်းတို့ဘာသာ ရှင်းလင်းနေသည်။

* column တစ်ခုကို ဖျောက်ပြီးနောက်၊ `Column Chooser` ကို ဖွင့်ပြီး column အမည်ကို right-click နှိပ်ကာ `Show Column` ကို နှိပ်ခြင်းဖြင့် ၎င်းကို ပြန်ပြသနိုင်သည်။
* `Group By This Column` သည် column တစ်ခုဖြင့် group by လုပ်ရန် column header ကို အပေါ်သို့ ဆွဲတင်ခြင်းနှင့် တူညီသော အကျိုးသက်ရောက်မှု ရှိသည်။ (နောက်ပိုင်းတွင် ပိုမိုအသေးစိတ် ရှင်းပြထားသည်။)
* `Hide Group By Box` သည် `Drag a column header here to group by that column` text ကို ဖျောက်ပြီး search bar ကို ရွှေ့ပေးရုံသာ ဖြစ်သည်။

### Conditional Formatting

`Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...` ကို နှိပ်ခြင်းဖြင့် text ကို အရောင်၊ bold font စသည်တို့ဖြင့် format လုပ်နိုင်သည်-

![Conditional Formatting](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

ဥပမာအားဖြင့်၊ `critical` alerts များကို `Red Fill` ဖြင့် ပြသလိုပါက `crit` ကို ရိုက်ထည့်ပြီး options များမှ `Red Fill` ကို ရွေးကာ `Apply formatting to an entire row` ကို check လုပ်ပြီး `OK` ကို နှိပ်လိုက်ရုံဖြစ်သည်။

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

ယခု `critical` alerts များသည် အောက်တွင် ပြထားသည့်အတိုင်း အနီရောင်ဖြင့် ပေါ်လာမည်ဖြစ်သည်-

![Red fill](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

`low`, `medium` နှင့် `high` alerts များအတွက်လည်း အရောင်ထည့်ခြင်းဖြင့် ဤအတိုင်း ဆက်လက်လုပ်ဆောင်နိုင်သည်။

## ရှာဖွေခြင်း

ပုံမှန်အားဖြင့်၊ search bar တွင် text အချို့ ရိုက်ထည့်လိုက်သည့်အခါ ၎င်းသည် filtering ပြုလုပ်ပြီး row တစ်ခုခု၌ ထို text ပါဝင်သော ရလဒ်များကိုသာ ပြသမည်ဖြစ်သည်။
အောက်ခြေရှိ `Visible lines` field ကို စစ်ဆေးခြင်းဖြင့် မည်မျှ hits ရှိသည်ကို မြင်တွေ့နိုင်သည်။

အောက်ညာဘက်ဆုံးရှိ `Search options` ကို နှိပ်ခြင်းဖြင့် ဤအပြုအမူကို ပြောင်းလဲနိုင်သည်။
၎င်းသည် အောက်ပါအတိုင်း ပြသမည်ဖြစ်သည်-

![Search Options](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

`Behavior` ကို `Filter` မှ `Search` သို့ ပြောင်းပါက text ကို ပုံမှန်အတိုင်း ရှာဖွေနိုင်သည်။

> မှတ်ချက်- behavior ကို ပြောင်းရန် အများအားဖြင့် အချိန်ယူသဖြင့် Timeline Explorer သည် ခဏကြာ hang ဖြစ်နေမည်ဖြစ်ရာ၊ နှိပ်ပြီးနောက် စိတ်ရှည်စွာ စောင့်ဆိုင်းပါ။

default `Match criteria` သည် `Mixed` ဖြစ်သော်လည်း `Or`, `And` သို့မဟုတ် `Exact` သို့ ပြောင်းနိုင်သည်။
၎င်းကို `Mixed` မှလွဲ၍ မည်သည့်အရာသို့မဆို ပြောင်းပါက `Condition` ကို `Contains` မှ `Starts with`, `Like` သို့မဟုတ် `Equals` သို့ သတ်မှတ်နိုင်သည်။

`Mixed` ၏ `Match criteria` သည် တစ်ခါတစ်ရံ `AND` logic ကိုလည်းကောင်း တစ်ခါတစ်ရံ `OR` ကိုလည်းကောင်း အသုံးပြုသဖြင့် ရှုပ်ထွေးသော်လည်း တစ်ကြိမ်သင်ယူပြီးပါက အလွန်ပြောင်းလွယ်ပြင်လွယ် ရှိနိုင်သည်။
၎င်းသည် အောက်ပါအတိုင်း လုပ်ဆောင်သည်-
* စကားလုံးများကို space များဖြင့် ခွဲခြားပါက `OR` logic အဖြစ် သတ်မှတ်မည်ဖြစ်သည်။
* သင့်ရှာဖွေမှုတွင် space များ ထည့်သွင်းလိုပါက quotes များ ထည့်ရန် လိုအပ်သည်။
* `AND` logic အတွက် condition တစ်ခု၏ရှေ့တွင် `+` ထည့်ပါ။
* ရလဒ်များကို ဖယ်ထုတ်ရန် condition တစ်ခု၏ရှေ့တွင် `-` ထည့်ပါ။
* `ColumnName:FilterString` format ဖြင့် သတ်မှတ်ထားသော column တစ်ခုပေါ်တွင် filter လုပ်ပါ။
* သတ်မှတ်ထားသော column တစ်ခုပေါ်တွင် filter လုပ်ပြီး သီးခြား keyword တစ်ခုကိုလည်း ထည့်သွင်းပါက ၎င်းသည် `AND` logic ဖြစ်မည်ဖြစ်သည်။

ဥပမာများ-
| ရှာဖွေမှု စံသတ်မှတ်ချက်                  | ဖော်ပြချက်                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | search column တစ်ခုခုတွင် `mimikatz` string ပါဝင်သော records များကို ရွေးချယ်သည်။                                                                        |
| one two three                    | search column တစ်ခုခုတွင် `one` OR `two` OR `three` တစ်ခုခု ပါဝင်သော records များကို ရွေးချယ်သည်။                                                             |
| "hoge hoge"                      | search column တစ်ခုခုတွင် `hoge hoge` ပါဝင်သော records များကို ရွေးချယ်သည်။                                                                                  |
| mimikatz +"Bad Guy"              | search column တစ်ခုခုတွင် `mimikatz` AND `Bad Guy` နှစ်ခုလုံး ပါဝင်သော records များကို ရွေးချယ်သည်။                                                                |
| EventID:4624 kali                | `EventID` ဖြင့်စသော column တွင် `4624` ပါဝင်ပြီး search column တစ်ခုခုတွင် `kali` ပါဝင်သော records များကို ရွေးချယ်သည်။                          |
| data +entry -mark                | search column တစ်ခုခုတွင် `data` AND `entry` နှစ်ခုလုံး ပါဝင်ပြီး `mark` ပါဝင်သော records များကို ဖယ်ထုတ်ကာ ရွေးချယ်သည်။                               |
| manu mask -file                  | `menu` OR `mask` ပါဝင်ပြီး `file` ပါဝင်သော records များကို ဖယ်ထုတ်ကာ ရွေးချယ်သည်။                                                           |
| From:Roller Subj:"currency mask" | `From` ဖြင့်စသော column တွင် `Roller` ပါဝင်ပြီး `Subj` ဖြင့်စသော column တွင် `currency mask` ပါဝင်သော records များကို ရွေးချယ်သည်။ |
| import -From:Steve               | search column တစ်ခုခုတွင် `import` ပါဝင်ပြီး `From` ဖြင့်စသော column တွင် `Steve` ပါဝင်သော records များကို ဖယ်ထုတ်ကာ ရွေးချယ်သည်။       |

## Columns များကို Freeze လုပ်ခြင်း

search option တစ်ခု မဟုတ်သော်လည်း `Search options` menu အောက်တွင် `First scrollable column` ကို configure လုပ်နိုင်သည်။
ခွဲခြမ်းစိတ်ဖြာသူ အများစုသည် events အချို့ ဖြစ်ပွားသည့်အချိန်ကို အမြဲမြင်နိုင်ရန်အတွက် ၎င်းကို `Timestamp` သို့ သတ်မှတ်ကြမည်ဖြစ်သည်။

## Column headers များကို ဆွဲ၍ group by လုပ်ခြင်း

column header တစ်ခုကို `Drag a column header here to group by that column` သို့ ဆွဲတင်ပါက Timeline Explorer သည် ထို column ဖြင့် group by လုပ်မည်ဖြစ်သည်။
severity အလိုက် alerts များကို ဦးစားပေးနိုင်ရန် `Level` ဖြင့် group by လုပ်ခြင်းသည် အဖြစ်များသည်-

![Group by](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

သင့်ရလဒ်များတွင် computers များစွာ ရှိပါက computer တစ်ခုစီအတွက် မတူညီသော severity levels များအလိုက် triage လုပ်ရန် `Computer` ဖြင့် ထပ်မံ group-by လုပ်နိုင်သည်။

## Fields များကို စစ်ဆေးခြင်း

ပုံမှန်အားဖြင့်၊ Hayabusa သည် field data ကို broken pipe symbol- `¦` ဖြင့် ခွဲခြားမည်ဖြစ်သည်။
field data သည် အလျားလိုက်တန်းပေါ်တွင် ရှိသည့်အခါ ဤ character သည် logs များတွင် မကြာခဏ မတွေ့ရသဖြင့် field များစွာကို ခွဲခြားရန် အလွန်လွယ်ကူစေသည်-

![Field Information](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

သို့သော် တစ်ခါတစ်ရံ log တွင် field information များ အလွန်များနေပြီး အရာအားလုံးကို screen တစ်ခုတည်းတွင် အံဝင်ခွင်ကျ မထည့်နိုင်ပါ။
ဤကိစ္စတွင် cell ကို double-click နှိပ်ခြင်းဖြင့် field information အားလုံးကို ပြသသော pop-up တစ်ခု ရရှိနိုင်သည်-

![Cell Contents](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

ပြဿနာမှာ Timeline Explorer သည် field data ကို newline characters (`CRLF`, `CR`, `LF`), commas များနှင့် tabs များဖြင့်သာ format လုပ်ခွင့်ပြုခြင်းဖြစ်သည်။

`-M, --multiline` option ကို အသုံးပြုပါက fields များကို newline character တစ်ခုဖြင့် ခွဲခြားနိုင်ပြီး cell ၏ contents ကို ဖွင့်ရန် double-click နှိပ်သည့်အခါ ၎င်းကို သင့်လျော်စွာ format လုပ်ပေးမည်ဖြစ်သည်-

![Multi-line formatting](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

ပြဿနာမှာ ယခု timeline တွင် ပထမ field ကိုသာ ပြသမည်ဖြစ်ရာ အခြား field data ကို စစ်ဆေးလိုသည့်အခါတိုင်း double-click နှိပ်ပြီး window အသစ်တစ်ခု ဖွင့်ရမည်ဖြစ်သည်-

![Multiline single fiels](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

ကံမကောင်းစွာဖြင့်၊ Timeline Explorer သည် timeline view တွင် line များစွာကို support မလုပ်ပါ။

ဤအတွက် ဖြေရှင်းရန်အနေဖြင့်၊ Hayabusa `v3.1.0` အရ fields များကို tabs များဖြင့် ခွဲခြားနိုင်သည်-

![Tab separation](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

field တစ်ခု မည်သည့်နေရာတွင် ပြီးဆုံးပြီး နောက်တစ်ခု မည်သည့်နေရာတွင် စတင်သည်ကို ခွဲခြားရန် အနည်းငယ် ပိုခက်သည်။
ထို့အပြင် cell ၏ contents ကို double-click နှိပ်ပြီး ဖွင့်သည့်အခါ fields များကို အလိုအလျောက် format မလုပ်ပေးပါ-

![Tab separation not formatted](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

သို့သော် အောက်ခြေရှိ `Tab` ကို နှိပ်ပြီးနောက် `Format` ကို နှိပ်ပါက fields များကို ဖတ်ရလွယ်ကူသော view အဖြစ် format လုပ်နိုင်သည်-

![Tab separation formatted](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Skins

dark mode စသည်တို့ကို နှစ်သက်ပါက `Tools` -> `Skins` မှ color theme ကို ပြောင်းလဲနိုင်သည်...

## Sessions

columns များ၊ appearance ကို စိတ်ကြိုက်ပြင်ဆင်ခြင်း၊ filters များ ထည့်ခြင်း စသည်တို့ ပြုလုပ်ပြီး ထို settings များကို နောက်အတွက် သိမ်းဆည်းလိုပါက သင့် session ကို `File` -> `Session` -> `Save` မှ မဖြစ်မနေ သိမ်းဆည်းပါ။
