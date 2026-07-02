# Windows Event Log များအတွက် Sigma စည်းမျဉ်းများ စီစစ်ရွေးချယ်ခြင်း

ဤစာမျက်နှာသည် Yamato Security အနေဖြင့် Windows event log များအတွက် upstream [Sigma](https://github.com/SigmaHQ/sigma) စည်းမျဉ်းများကို `logsource` အကွက်ကို de-abstract ပြုလုပ်ခြင်းနှင့် အသုံးမပြုနိုင်သော သို့မဟုတ် အသုံးပြုရန်ခက်ခဲသော စည်းမျဉ်းများကို စစ်ထုတ်ခြင်းဖြင့် ပိုမိုအသုံးဝင်သောပုံစံအဖြစ် မည်သို့စီစစ်ရွေးချယ်သည်ကို မှတ်တမ်းတင်ထားပါသည်။ ဤအရာကို [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) tool ဖြင့် ဆောင်ရွက်ပြီး၊ ၎င်းကို အဓိကအားဖြင့် [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) တွင် host ထားသော စီစစ်ရွေးချယ်ထားသည့် Sigma ruleset ကို ဖန်တီးရန် အသုံးပြုသည်။ ထို ruleset ကို [Hayabusa](https://github.com/Yamato-Security/hayabusa) နှင့် [Velociraptor](https://github.com/Velocidex/velociraptor) တို့က အသုံးပြုကြသည်။

!!! info "အရင်းအမြစ်"
    ဤစာရွက်စာတမ်းကို [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) ရှိ converter tool နှင့်အတူ ထိန်းသိမ်းထားပါသည်။ Windows event log များတွင် တိုက်ခိုက်မှုများကို ထောက်လှမ်းရန်အတွက် Sigma စည်းမျဉ်းများကို အသုံးပြုလိုသည့် အခြားပရောဂျက်များအတွက်လည်း ဤအချက်အလက်များ အသုံးဝင်လိမ့်မည်ဟု မျှော်လင့်ပါသည်။ [စည်းမျဉ်းဖိုင်များဖန်တီးခြင်း](creating-rules.md) နှင့် [အကွက်ပြုပြင်မွမ်းမံကိရိယာများ](field-modifiers.md) တို့ကိုလည်း ကြည့်ပါ။

## အနှစ်ချုပ်

* `logsource` အကွက်ကို de-abstract ပြုလုပ်ပြီး မူရင်း Sysmon-based စည်းမျဉ်းများအပြင် built-in စည်းမျဉ်းများအတွက် `.yml` စည်းမျဉ်းဖိုင်အသစ်များ ဖန်တီးခြင်းသည် Sigma စည်းမျဉ်းများအတွက် built-in event ပြည့်ဝသော support ကို ပိုမိုလွယ်ကူစေပြီး၊ analyst များ ဖတ်ရှုရန်လည်း ပိုမိုလွယ်ကူစေသည်။
* Windows event log များအတွက် Sigma စည်းမျဉ်းများ ရေးသားသည့်အခါ၊ မူရင်း Sysmon-based log များနှင့် လိုက်ဖက်ညီသော built-in log များအကြား ကွာခြားချက်များကို နားလည်ရန်နှင့်၊ အကောင်းဆုံးအားဖြင့် သင်၏စည်းမျဉ်းများကို နှစ်မျိုးလုံးနှင့် လိုက်ဖက်ညီစေရန် ရေးသားရန် အရေးကြီးသည်။
* အဖွဲ့အစည်းများစွာသည် ၎င်းကို ကိုင်တွယ်ရန် သီးသန့်အရင်းအမြစ်များ မရှိသောကြောင့်၊ သို့မဟုတ် Sysmon ကြောင့်ဖြစ်ပေါ်လာနိုင်သည့် နှေးကွေးမှု သို့မဟုတ် crash ဖြစ်မှုများ၏ အန္တရာယ်ကို ရှောင်ရှားလိုသောကြောင့်၊ ၎င်းတို့၏ Windows endpoint အားလုံးတွင် Sysmon agent များကို install ပြုလုပ်၍ ထိန်းသိမ်း၍ မရနိုင်ကြ သို့မဟုတ် မလုပ်ဆောင်လိုကြပါ။ ဤအကြောင်းကြောင့်၊ ဖြစ်နိုင်သမျှ built-in event log များစွာကို ဖွင့်ရန်နှင့် ထို built-in log များတွင် တိုက်ခိုက်မှုများကို ထောက်လှမ်းတွေ့ရှိနိုင်သော tool များကို အသုံးပြုရန် အရေးကြီးသည်။

## Windows event log များအတွက် upstream Sigma စည်းမျဉ်းများ၏ စိန်ခေါ်မှုများ

ကျွန်ုပ်တို့၏ အတွေ့အကြုံအရ၊ Windows event log များအတွက် native Sigma rule parser တစ်ခု ဖန်တီးရာတွင် အဓိကစိန်ခေါ်မှုမှာ `logsource` အကွက်ကို support ပေးရန်ဖြစ်သည်။ ၎င်းသည် အလွန်ရှုပ်ထွေးပြီး ဆောင်ရွက်ဆဲဖြစ်နေသောကြောင့်၊ လက်ရှိတွင် Hayabusa အနေဖြင့် native အဖြစ် မ support ရသေးသည့် အနည်းငယ်သောအရာများထဲမှ တစ်ခုဖြစ်သည်။ ယခုအချိန်အထိ၊ အောက်တွင် အသေးစိတ်ရှင်းပြထားသည့်အတိုင်း upstream စည်းမျဉ်းများကို ပိုမိုအသုံးပြုရလွယ်ကူသော format အဖြစ် ပြောင်းလဲခြင်းဖြင့် ဤကိစ္စကို ဖြေရှင်းသည်။

### `logsource` အကွက်အကြောင်း

Windows event log များအတွက် Sigma စည်းမျဉ်းများတွင်၊ `product` အကွက်ကို `windows` အဖြစ် သတ်မှတ်ပြီး၊ ၎င်းနောက်တွင် `service` အကွက် သို့မဟုတ် `category` အကွက် တစ်ခုခု လိုက်ပါသည်။

`service` အကွက်ဥပမာ:

```yaml
logsource:
    product: windows
    service: application
```

`category` အကွက်ဥပမာ:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Service အကွက်များ

`service` အကွက်များသည် ကိုင်တွယ်ရန် အတော်လေး ရိုးရှင်းပြီး၊ Sigma စည်းမျဉ်းကို အသုံးပြုနေသည့် မည်သည့် backend ကိုမဆို Windows XML event log ရှိ `Channel` အကွက်အပေါ် အခြေခံ၍ channel တစ်ခု သို့မဟုတ် channel များစွာကို ရှာဖွေရန် ပြောပြသည်။

**Single channel ဥပမာ**

`service: application` သည် Sigma စည်းမျဉ်းသို့ `Channel: Application` ဟူသော selection condition တစ်ခု ထည့်ခြင်းနှင့် အတူတူပင်ဖြစ်သည်။

**Multiple channel ဥပမာ**

AppLocker သည် log လေးမျိုးတွင် အချက်အလက်များကို သိမ်းဆည်းသောကြောင့် `service: applocker` သည် လက်ရှိတွင် ရှာဖွေရန် channel အများဆုံးကို ဖန်တီးသည်။ AppLocker log များကိုသာ မှန်ကန်စွာ ရှာဖွေနိုင်ရန်အတွက် အောက်ပါ condition ကို Sigma စည်းမျဉ်း logic တွင် ထည့်သွင်းရန် လိုအပ်သည်:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**လက်ရှိ service mapping စာရင်း**

| ဝန်ဆောင်မှု (Service)                        | Channel                                                                                                                             |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**Service mapping အရင်းအမြစ်များ**

ကျွန်ုပ်တို့သည် service များမှ channel အမည်များသို့ mapping ပြုလုပ်ရန် YAML mapping ဖိုင်များကို ဖန်တီးထားပြီး ၎င်းတို့ကို အခါအားလျော်စွာ ထိန်းသိမ်းကာ converter repository တွင် host ထားပါသည်။ ၎င်းတို့သည် [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) မှ service mapping အချက်အလက်များအပေါ် အခြေခံထားသည်။ ၎င်းသည် လူများအသုံးပြုရန်အတွက် တရားဝင် generic config ဖိုင်တစ်ခုဟု မထင်ရသော်လည်း၊ နောက်ဆုံးမွမ်းမံထားဆုံး (up-to-date) ဖြစ်ဟန်တူသည်။

#### Category အကွက်များ

`category` အကွက်အများစုသည် သီးခြား `Channel` တစ်ခုကို ရှာဖွေခြင်းအပြင်၊ `EventID` အကွက်တွင် သတ်မှတ်ထားသော event ID များကို စစ်ဆေးရန် condition တစ်ခုကို ရိုးရှင်းစွာ ထည့်သွင်းပေးသည်။ category အမည်များသည် အများအားဖြင့် [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) event များအပေါ် အခြေခံထားပြီး၊ built-in PowerShell log များနှင့် Windows Defender အတွက် ထပ်ဆောင်း category အချို့ ပါဝင်သည်။

**Category အကွက်ဥပမာ**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**လက်ရှိ category mapping စာရင်း**

category အချို့သည် service/EventID တစ်ခုထက်ပို၍ mapping ပြုလုပ်သည် (**စာလုံးမည်း** ဖြင့် ပြထားသည်)။

| အမျိုးအစား (Category)      | ဝန်ဆောင်မှု (Service) | Event ID များ                                                          |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**Category အကွက်ဆိုင်ရာ စိန်ခေါ်မှုများ**

အထက်တွင်ပြထားသည့်အတိုင်း၊ တူညီသော `category` သည် service များနှင့် event ID များစွာကို အသုံးပြုနိုင်သည် (**စာလုံးမည်း** ဖြင့် ဖော်ပြထားသည်)။ ဆိုလိုသည်မှာ စည်းမျဉ်းက အသုံးပြုသည့် အကွက်များသည် built-in event log တွင်လည်း တည်ရှိပါက၊ `sysmon` အတွက် ဒီဇိုင်းရေးဆွဲထားသော Sigma စည်းမျဉ်းအချို့ကို အလားတူ built-in Windows `security` event log များနှင့် အသုံးပြုနိုင်သည်။ ထိုသို့သောအခါ၊ အကွက်အမည်များ — တစ်ခါတစ်ရံ တန်ဖိုးများကိုပါ — built-in `security` event log ၏ အကွက်အမည်များနှင့် တန်ဖိုးများနှင့် ကိုက်ညီစေရန် ပြောင်းလဲရန် လိုအပ်နိုင်သည်။ ဤသည်မှာ အချို့ category များအတွက် အကွက်အမည်အချို့ကို ပြန်လည်အမည်ပေးရုံမျှ ရိုးရှင်းနိုင်သော်လည်း၊ အခြား category များအတွက်မူ အကွက်တန်ဖိုးများတွင်လည်း အမျိုးမျိုးသော ပြောင်းလဲမှုများ လိုအပ်နိုင်သည်။ ဤပြောင်းလဲမှုကို ကျွန်ုပ်တို့ မည်သို့ပြုလုပ်သည်နှင့် `sysmon` log များနှင့် `security` log များအကြား လိုက်ဖက်ညီမှုတို့ကို [အောက်တွင်](#sysmon-builtin-comparison) အသေးစိတ်ရှင်းပြထားသည်။

**Category mapping အရင်းအမြစ်များ**

category များအတွက် YAML mapping ဖိုင်များကိုလည်း converter repository တွင် host ထားပြီး၊ ၎င်းတို့သည်လည်း [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) မှ အချက်အလက်များအပေါ် အခြေခံထားသည်။

## log source ကို abstract ပြုလုပ်ခြင်း၏ အကျိုးကျေးဇူးများနှင့် စိန်ခေါ်မှုများ

log source ကို abstract ပြုလုပ်ခြင်းနှင့် backend တွင် မတူညီသော `Channel`, `EventID` နှင့် အကွက်များအတွက် mapping များ ဖန်တီးခြင်းတွင် အကျိုးကျေးဇူးများနှင့် စိန်ခေါ်မှုများ နှစ်မျိုးလုံး ရှိသည်။

### အကျိုးကျေးဇူးများ

1. Sigma စည်းမျဉ်းများကို အခြား backend query များအဖြစ် ပြောင်းလဲသည့်အခါ `Channel` နှင့် `EventID` အကွက်အမည်များကို သင့်လျော်သော backend အကွက်အမည်များအဖြစ် ပြောင်းလဲရန် ပိုမိုလွယ်ကူနိုင်သည်။
2. စည်းမျဉ်းနှစ်ခုကို တစ်ခုအဖြစ် ပေါင်းစည်းနိုင်သည်။ ဥပမာအားဖြင့်၊ process creation event များကို `Sysmon 1` တွင်သာမက `Security 4688` တွင်လည်း log ဖမ်းယူနိုင်သည်။ မတူညီသော channel များ၊ event ID များနှင့် အကွက်များကို ကြည့်ရှုသော်လည်း ကျန်အပိုင်းများတွင် တူညီသော logic ပါဝင်သည့် စည်းမျဉ်းနှစ်ခုကို ရေးသားမည့်အစား၊ အကွက်များကို Sysmon အသုံးပြုသည့်ပုံစံသို့ စံသတ်မှတ်ပြီးနောက် backend converter တစ်ခုအား `Channel` နှင့် `EventID` အကွက်များ ထည့်သွင်းစေကာ လိုအပ်ပါက အခြားအကွက်အချက်အလက်များကို ပြောင်းလဲစေနိုင်သည်။ ဤသည်က ထိန်းသိမ်းရမည့် စည်းမျဉ်းအရေအတွက် နည်းပါးသွားသောကြောင့် စည်းမျဉ်းများ ထိန်းသိမ်းရန် ပိုမိုလွယ်ကူစေသည်။
3. အလွန်ရှားပါးသော်လည်း၊ log source တစ်ခုသည် ၎င်း၏ဒေတာကို မတူညီသော `Channel` သို့မဟုတ် `EventID` တစ်ခုတွင် စတင် log ဖမ်းယူပါက၊ Sigma စည်းမျဉ်းအားလုံးကို update ပြုလုပ်မည့်အစား mapping logic ကိုသာ update ပြုလုပ်ရန် လိုအပ်သဖြင့် ထိန်းသိမ်းမှုကို ပိုမိုလွယ်ကူစေသည်။

### စိန်ခေါ်မှုများ

1. Sysmon အပေါ်အခြေခံသော မူရင်း Sigma စည်းမျဉ်းသည် false positive များကို စစ်ထုတ်ရန်အတွက် built-in log များတွင် မတည်ရှိသော အကွက်တစ်ခုကို အသုံးပြုပါက မည်သို့ဖြစ်မည်နည်း။ ဖြစ်နိုင်ခြေရှိသော ထောက်လှမ်းတွေ့ရှိမှုကို ဦးစားပေးကာ စည်းမျဉ်းကို မည်သို့ပင်ဆိုစေ ဖန်တီးသင့်သလား၊ သို့မဟုတ် false positive နည်းပါးမှုကို ဦးစားပေးရန် ၎င်းကို လျစ်လျူရှုသင့်သလား။ အကောင်းဆုံးအားဖြင့်၊ အသုံးပြုသူက ပိုမိုကောင်းမွန်စွာ ကိုင်တွယ်နိုင်ရန်အတွက် မတူညီသော `severity`, `status` နှင့် false positive အချက်အလက်များဖြင့် စည်းမျဉ်းနှစ်ခု ဖန်တီးရန် လိုအပ်မည်။
2. ၎င်းသည် စည်းမျဉ်းများကို filter ပြုလုပ်ရန် ပိုမိုခက်ခဲစေသည်။ အဘယ်ကြောင့်ဆိုသော် ဖိုင်ကို မဖန်တီးရသေးပါက `.yml` ဖိုင်ရှိ `Channel` သို့မဟုတ် `EventID` အကွက်များ သို့မဟုတ် စည်းမျဉ်း၏ ဖိုင်လမ်းကြောင်းအပေါ် အခြေခံ၍ filter ပြုလုပ်၍မရသောကြောင့်ဖြစ်သည် — ၎င်းသည် မူရင်း Sysmon စည်းမျဉ်းအစား built-in log အတွက် derived စည်းမျဉ်းဖြစ်သည်။ ထို့အပြင်၊ rule ID တူညီသောကြောင့် rule ID များအပေါ် filter ပြုလုပ်၍မရပါ။
3. Sysmon log မှ ဆင်းသက်လာသော built-in log အတွက် စည်းမျဉ်းတစ်ခုမှ alert ရောက်ရှိလာသည့်အခါ ၎င်း alert ကို အတည်ပြုရန် ပိုမိုခက်ခဲစေသည်။ အကွက်အမည်များနှင့် တန်ဖိုးများ ကိုက်ညီမည်မဟုတ်သောကြောင့်၊ analyst သည် အနည်းငယ်ရှုပ်ထွေးသော ပြောင်းလဲမှုလုပ်ငန်းစဉ်ကို နားလည်ရန် လိုအပ်သည်။
4. ၎င်းသည် backend logic ဖန်တီးခြင်းကို ပိုမိုရှုပ်ထွေးစေသည်။

ကြိုးပမ်းအားထုတ်မှုကို တန်ဖိုးရှိစေသည့် အရေးပါသော အသုံးပြုမှုကိစ္စတစ်ခုရှိသည့်အခါ စည်းမျဉ်းအသစ်များ ဖန်တီးထိန်းသိမ်းခြင်းမှလွဲ၍ ပထမကိစ္စအတွက် ကျွန်ုပ်တို့ မည်သည့်အရာမျှ ဆောင်ရွက်၍မရသော်လည်း၊ ကိစ္စ ၂–၄ ကို ဖြေရှင်းရန်အတွက် `logsource` အကွက်ကို de-abstract ပြုလုပ်ရန်နှင့် စည်းမျဉ်းများစွာ ထုတ်ပေးနိုင်သည့် မည်သည့်စည်းမျဉ်းအတွက်မဆို စည်းမျဉ်းအစုနှစ်ခု ဖန်တီးရန် ကျွန်ုပ်တို့ ဆုံးဖြတ်ခဲ့သည်။ built-in log များတွင် တိုက်ခိုက်မှုများကို ထောက်လှမ်းတွေ့ရှိနိုင်သော စည်းမျဉ်းများကို `builtin` directory သို့ ထုတ်ပေးပြီး၊ Sysmon အတွက် စည်းမျဉ်းများကို `sysmon` directory သို့ ထုတ်ပေးသည်။

## ပြောင်းလဲမှုဥပမာ

ပြောင်းလဲမှုလုပ်ငန်းစဉ်ကို ပိုမိုနားလည်နိုင်ရန် ရိုးရှင်းသောဥပမာတစ်ခု ဖော်ပြထားသည်။

**ပြောင်းလဲခြင်းမပြုမီ** — မူရင်း Sigma စည်းမျဉ်း:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**ပြောင်းလဲပြီးနောက်** — Sysmon log များအတွက် Hayabusa-compatible စည်းမျဉ်း:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

...နှင့် Windows built-in log များအတွက် Hayabusa-compatible စည်းမျဉ်း:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

မြင်တွေ့ရသည့်အတိုင်း၊ စည်းမျဉ်းနှစ်ခု ဖန်တီးထားသည်: တစ်ခုမှာ Sysmon 1 log များအတွက်ဖြစ်ပြီး တစ်ခုမှာ built-in Security 4688 log များအတွက်ဖြစ်သည်။ channel နှင့် event ID အချက်အလက်များပါဝင်သော `process_creation` condition အသစ်တစ်ခု ထည့်သွင်းထားပြီး၊ ဤ condition ကို လိုအပ်စေရန် `condition` အကွက်တွင် ထည့်သွင်းထားသည်။ ထို့အပြင်၊ မူရင်း `Image` အကွက်အမည်ကို `NewProcessName` သို့ ပြောင်းလဲထားသည်။

## ပြောင်းလဲမှုတွင် ဘုံတူညီချက်များ

သီးခြား category များကို ကျွန်ုပ်တို့ မည်သို့ပြောင်းလဲသည်ကို အသေးစိတ်ရှင်းပြခြင်းမပြုမီ၊ စည်းမျဉ်းအားလုံးနှင့် သက်ဆိုင်သော ပြောင်းလဲမှုအပိုင်းကို ဖော်ပြထားသည်။

1. `ignore-uuid-list.txt` တွင် ID ရှိသော မည်သည့်စည်းမျဉ်းမဆို လျစ်လျူရှုခံရသည်။ လက်ရှိတွင် ကျွန်ုပ်တို့သည် `mimikatz` ကဲ့သို့သော keyword များ ပါဝင်သောကြောင့် Windows Defender တွင် false positive များ ဖြစ်စေသည့် စည်းမျဉ်းများကိုသာ လျစ်လျူရှုသည်။
2. "Placeholder" စည်းမျဉ်းများကို ရှိသည့်အတိုင်း အသုံးပြု၍မရသောကြောင့် လျစ်လျူရှုသည်။ ၎င်းတို့သည် Sigma repository ရှိ [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) folder တွင် ထားရှိသော စည်းမျဉ်းများဖြစ်သည်။
3. လိုက်ဖက်ညီမှုမရှိသော field modifier များကို အသုံးပြုသည့် စည်းမျဉ်းများကို ဖယ်ထုတ်သည်။ Hayabusa သည် field modifier အများစုကို support ပေးသောကြောင့်၊ parsing error များ ရှောင်ရှားရန်အတွက် converter သည် အောက်ပါတို့မှလွဲ၍ modifier တစ်ခုကို အသုံးပြုသည့် မည်သည့်စည်းမျဉ်းကိုမျှ ထုတ်ပေးမည်မဟုတ်ပါ ([အကွက်ပြုပြင်မွမ်းမံကိရိယာများ](field-modifiers.md) ကိုကြည့်ပါ):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. syntax error များပါရှိသော စည်းမျဉ်းများကို ပြောင်းလဲမပေးပါ။
5. `deprecated` နှင့် `unsupported` စည်းမျဉ်းများရှိ tag များကို အရာအားလုံး တသမတ်တည်းဖြစ်စေရန်နှင့် Hayabusa တွင် အတိုကောက်များကို ပိုမိုလွယ်ကူစွာ ကိုင်တွယ်နိုင်ရန်အတွက် `_` အစား `-` ကိုအသုံးပြုသော V2 format သို့ V1 format မှ update ပြုလုပ်သည်။ ဥပမာ: `initial_access` သည် `initial-access` ဖြစ်လာသည်။
6. ကျွန်ုပ်တို့သည် စည်းမျဉ်းများသို့ `Channel` နှင့် `EventID` အချက်အလက်များ ထည့်သွင်းနေသောကြောင့်၊ မူရင်း ID ၏ MD5 hash ကိုအသုံးပြု၍ UUIDv4 ID အသစ်တစ်ခု ဖန်တီးပြီး၊ မူရင်း ID ကို `related` အကွက်တွင် သတ်မှတ်ကာ `type` ကို `derived` အဖြစ် မှတ်သားသည်။ စည်းမျဉ်းများစွာ (`sysmon` နှင့် `builtin`) အဖြစ် ပြောင်းလဲနိုင်သော စည်းမျဉ်းများအတွက်၊ ကျွန်ုပ်တို့သည် ဆင်းသက်လာသော `builtin` စည်းမျဉ်းများအတွက်လည်း rule ID အသစ်များ ဖန်တီးရန် လိုအပ်သည်။ ဤသို့ပြုလုပ်ရန်၊ ကျွန်ုပ်တို့သည် `sysmon` rule ID ၏ MD5 hash ကို တွက်ချက်ပြီး ၎င်းကို UUIDv4 ID အတွက် အသုံးပြုသည်။ ဥပမာ:

    မူရင်း Sigma စည်းမျဉ်း:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    `sysmon` စည်းမျဉ်းအသစ်:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    `builtin` စည်းမျဉ်းအသစ်:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. built-in Windows event log များတွင် အရာများကို ထောက်လှမ်းတွေ့ရှိသော စည်းမျဉ်းများကို `builtin` directory သို့ ထုတ်ပေးပြီး၊ Sysmon log များအပေါ် အားကိုးသော စည်းမျဉ်းများကို `sysmon` directory သို့ ထုတ်ပေးကာ၊ sub-directory များသည် upstream Sigma repository ရှိ directory များနှင့် ကိုက်ညီသည်။

## ပြောင်းလဲမှုကန့်သတ်ချက်များ

လက်ရှိတွင် [သိရှိထားသော bug](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2) တစ်ခုသာ ရှိသည်: Sigma စည်းမျဉ်းများရှိ comment လိုင်းများသည် source code တစ်ချို့၏ နောက်တွင် လိုက်ပါမလာလျှင် output စည်းမျဉ်းများတွင် ပါဝင်မည်မဟုတ်ပါ။

## Sysmon နှင့် built-in event နှိုင်းယှဉ်ခြင်းနှင့် စည်းမျဉ်းပြောင်းလဲခြင်း { #sysmon-builtin-comparison }

### Process ဖန်တီးခြင်း

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Built-in log
    * Channel: `Security`
    * Event ID: `4688`

**နှိုင်းယှဉ်ချက်**

![Process ဖန်တီးခြင်း နှိုင်းယှဉ်ချက်](../assets/rules-doc/process_creation_comparison.png)

**ပြောင်းလဲမှုမှတ်ချက်များ**

1. `User` အကွက်အချက်အလက်ကို `SubjectUserName` နှင့် `SubjectDomainName` အကွက်များအဖြစ် ခွဲခြားရန် လိုအပ်သည်။
2. `LogonId` အကွက်အမည်သည် `SubjectLogonId` သို့ ပြောင်းလဲပြီး၊ hex တန်ဖိုးရှိ စာလုံးများအားလုံးကို စာလုံးအသေး (lowercase) ဖြစ်စေရန် လိုအပ်သည်။
3. `ProcessId` အကွက်အမည်သည် `NewProcessId` သို့ ပြောင်းလဲပြီး၊ တန်ဖိုးကို hex သို့ ပြောင်းလဲရန် လိုအပ်သည်။
4. `Image` အကွက်အမည်သည် `NewProcessName` သို့ ပြောင်းလဲသည်။
5. `ParentProcessId` အကွက်အမည်သည် `ProcessId` သို့ ပြောင်းလဲပြီး၊ တန်ဖိုးကို hex သို့ ပြောင်းလဲရန် လိုအပ်သည်။
6. `ParentImage` အကွက်အမည်သည် `ParentProcessName` သို့ ပြောင်းလဲသည်။
7. `IntegrityLevel` အကွက်အမည်သည် `MandatoryLabel` သို့ ပြောင်းလဲပြီး၊ အောက်ပါ တန်ဖိုးပြောင်းလဲမှု လိုအပ်သည်:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. စည်းမျဉ်းတွင် `Security 4688` event များတွင်သာ တည်ရှိသော အောက်ပါအကွက်များ ပါဝင်ပါက၊ ကျွန်ုပ်တို့သည် `Sysmon 1` စည်းမျဉ်းကို ဖန်တီးမည်မဟုတ်ပါ:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. စည်းမျဉ်းတွင် `Sysmon 1` event များတွင်သာ တည်ရှိသော အောက်ပါအကွက်များ ပါဝင်ပါက၊ ကျွန်ုပ်တို့သည် `Security 4688` စည်းမျဉ်းကို ဖန်တီးမည်မဟုတ်ပါ:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. #8 နှင့် #9 အတွက် ခြွင်းချက်တစ်ခုရှိသည်: log event တစ်ခုတွင်သာ တည်ရှိသော အကွက်တစ်ခုကို အသုံးပြုစေကာမူ၊ ထိုအကွက်သည် `OR` condition အတွင်း ရှိပါက ထိုစည်းမျဉ်းကို သင်ဖန်တီးသင့်ဆဲဖြစ်သည်။ ဥပမာအားဖြင့်၊ အောက်ပါစည်းမျဉ်းသည် `OriginalFileName` အကွက် လိုအပ်သောကြောင့် (selection အတွင်း `AND` logic) `Security 4688` စည်းမျဉ်းကို **မ**ထုတ်ပေးသင့်ပါ:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    သို့သော်၊ အောက်ပါ condition ပါသော စည်းမျဉ်းသည် `OriginalFileName` သည် optional ဖြစ်သောကြောင့် (selection အတွင်း `OR` logic) `Security 4688` စည်းမျဉ်းကို ဖန်တီး**သင့်**သည်:

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    သင်၏ parser သည် selection များအတွင်းရှိ logic သာမက `condition` အကွက်အတွင်းရှိ logic ကိုပါ နားလည်ရမည်ဖြစ်သောကြောင့် အခက်အခဲရှိလာသည်။ ဥပမာအားဖြင့်၊ အောက်ပါစည်းမျဉ်းသည် `AND` logic ကိုအသုံးပြုသောကြောင့် `Security 4688` စည်းမျဉ်းကို ဖန်တီး**သင့်မ**ပါ:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    သို့သော်၊ အောက်ပါစည်းမျဉ်းသည် `OR` logic ကိုအသုံးပြုသောကြောင့် `Security 4688` စည်းမျဉ်းကို ဖန်တီး**သင့်**သည်:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**အခြားမှတ်ချက်များ**

* `Security 4688` ရှိ `SubjectUserSid` အကွက်သည် SID ကို ပြသသည်။ သို့သော်၊ render ပြုလုပ်ပြီးသော event log `Message` တွင် ၎င်းကို `DOMAIN\User` အဖြစ် ပြောင်းလဲသည်။
* `Security 4688` event များသည် ဆက်တင်များပေါ်မူတည်၍ `CommandLine` တွင် command line option အချက်အလက်များ ပါဝင်ချင်မှ ပါဝင်မည်ဖြစ်သည်။
* `TokenElevationType` ကို `Message` တွင် ရှိသည့်အတိုင်း ဖော်ပြထားပြီး render မပြုလုပ်ပါ။
* `MandatoryLabel` အတွင်းရှိ `S-1-16-4096` စသည်တို့ကို render ပြုလုပ်ပြီးသော `Message` တွင် `Mandatory Label\Low Mandatory Level` စသည်ဖြင့် ပြောင်းလဲသည်။

**Built-in log ဆက်တင်များ**

!!! warning "မူရင်းအတိုင်း ဖွင့်ထားခြင်း မရှိပါ"
    အရေးကြီးသော built-in `Security 4688` process creation event log များကို မူရင်းအတိုင်းဆိုလျှင် ဖွင့်ထားခြင်းမရှိပါ။ Sigma စည်းမျဉ်းအများစုကို အသုံးပြုနိုင်ရန်အတွက် `4688` event များနှင့် command line option logging နှစ်ခုလုံးကို ဖွင့်ရန် လိုအပ်သည်။

*group policy ဖြင့် ဖွင့်ခြင်း:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*command line ဖြင့် ဖွင့်ခြင်း:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### ကွန်ရက်ချိတ်ဆက်ခြင်း

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Built-in log
    * Channel: `Security`
    * Event ID: `5156`

**နှိုင်းယှဉ်ချက်**

![ကွန်ရက်ချိတ်ဆက်ခြင်း နှိုင်းယှဉ်ချက်](../assets/rules-doc/network_connection_comparison.png)

**ပြောင်းလဲမှုမှတ်ချက်များ**

1. `ProcessId` အကွက်အမည်သည် `ProcessID` သို့ ပြောင်းလဲသည်။
2. `Image` အကွက်အမည်သည် `Application` သို့ ပြောင်းလဲပြီး၊ `C:\` သည် `\device\harddiskvolume?\` သို့ ပြောင်းလဲသည်။ (မှတ်ချက်: hard disk volume နံပါတ်ကို ကျွန်ုပ်တို့ မသိသောကြောင့်၊ ၎င်းကို စာလုံးတစ်လုံး wildcard `?` ဖြင့် အစားထိုးသည်။)
3. `Protocol` အကွက်တန်ဖိုး `tcp` သည် `6` သို့ ပြောင်းလဲပြီး `udp` သည် `17` သို့ ပြောင်းလဲသည်။
4. `Initiated` အကွက်အမည်သည် `Direction` သို့ ပြောင်းလဲပြီး၊ `true` တန်ဖိုးသည် `%%14593` သို့ ပြောင်းလဲကာ `false` သည် `%%14592` သို့ ပြောင်းလဲသည်။
5. `SourceIp` အကွက်အမည်သည် `SourceAddress` သို့ ပြောင်းလဲသည်။
6. `DestinationIp` အကွက်အမည်သည် `DestAddress` သို့ ပြောင်းလဲသည်။
7. `DestinationPort` အကွက်အမည်သည် `DestPort` သို့ ပြောင်းလဲသည်။

**Built-in log ဆက်တင်များ**

!!! warning "မူရင်းအတိုင်း ဖွင့်ထားခြင်း မရှိပါ"
    built-in `Security 5156` network connection log များကို မူရင်းအတိုင်းဆိုလျှင် ဖွင့်ထားခြင်းမရှိပါ။ ၎င်းတို့သည် log အများအပြားကို ဖန်တီးသဖြင့်၊ `Security` event log ရှိ အခြားအရေးကြီးသော log များကို ထပ်ရေးဖျက်နိုင်ပြီး၊ network connection အရေအတွက်များပါက စနစ်ကို နှေးကွေးစေနိုင်သည်။ `Security` log အတွက် အများဆုံးဖိုင်အရွယ်အစားကို မြင့်မားစေရန် သေချာစေပြီး၊ စနစ်အပေါ် ဆိုးကျိုးမရှိစေရန် စမ်းသပ်ပါ။

*group policy ဖြင့် ဖွင့်ခြင်း:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*command line ဖြင့် ဖွင့်ခြင်း:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...သို့မဟုတ် သင်သည် အင်္ဂလိပ်မဟုတ်သော locale ကို အသုံးပြုနေပါက အောက်ပါအတိုင်း:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "ဆက်လက်ကြည့်ရှုရန်"
    ဤစည်းမျဉ်းများ အားကိုးသည့် သက်သေအထောက်အထားများ ဖမ်းယူရန် လိုအပ်သော built-in Windows event log များ ဖွင့်ခြင်းအကြောင်း ပိုမိုသိရှိလိုပါက [Windows Logging နှင့် Sysmon](../resources/logging.md) နှင့် [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) ပရောဂျက်ကို ကြည့်ပါ။

## Sigma စည်းမျဉ်း ရေးသားခြင်းဆိုင်ရာ အကြံပြုချက်

!!! tip
    `sysmon` log တွင် တည်ရှိသော်လည်း `builtin` log တွင် မတည်ရှိသော အကွက်တစ်ခုခုကို သင်အသုံးပြုပါက၊ `builtin` log များအတွက် ထိုစည်းမျဉ်းကို ဆက်လက်အသုံးပြုနိုင်စေရန် ထိုအကွက်ကို optional ဖြစ်စေရန် သေချာပါစေ။

ဥပမာအားဖြင့်:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

ဤ selection သည် process (`Image`) ကို `addinutil.exe` ဟု အမည်ပေးထားချိန်ကို ရှာဖွေသည်။ ပြဿနာမှာ တိုက်ခိုက်သူသည် စည်းမျဉ်းကို ကျော်လွှားရန် ဖိုင်ကို အမည်ပြန်လည်ပေးရုံဖြင့် ရနိုင်ခြင်းဖြစ်သည်။ Sysmon log များတွင်သာ တည်ရှိသော `OriginalFileName` အကွက်သည် compile ပြုလုပ်ချိန်တွင် binary အတွင်းသို့ ထည့်သွင်းထားသော ဖိုင်အမည်ဖြစ်သည်။ တိုက်ခိုက်သူသည် ဖိုင်ကို အမည်ပြန်လည်ပေးစေကာမူ၊ ထည့်သွင်းထားသောအမည်သည် ပြောင်းလဲမည်မဟုတ်သောကြောင့်၊ ဤစည်းမျဉ်းသည် Sysmon ကို အသုံးပြုသည့်အခါ တိုက်ခိုက်သူက ဖိုင်ကို အမည်ပြန်လည်ပေးထားသော တိုက်ခိုက်မှုများကို ထောက်လှမ်းတွေ့ရှိနိုင်ပြီး၊ စံ built-in log များ အသုံးပြုသည့်အခါ ဖိုင်အမည် မပြောင်းလဲသော တိုက်ခိုက်မှုများကိုလည်း ထောက်လှမ်းတွေ့ရှိနိုင်သည်။

## ကြိုတင်ပြောင်းလဲပြီးသား Sigma စည်းမျဉ်းများ

ဤစာမျက်နှာတွင် ဖော်ပြထားသည့်နည်းလမ်း — `logsource` အကွက်ကို de-abstract ပြုလုပ်ခြင်း — ဖြင့် စီစစ်ရွေးချယ်ထားသော Sigma စည်းမျဉ်းများကို [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository ရှိ `sigma` folder အောက်တွင် host ထားသည်။

## Tool ပတ်ဝန်းကျင်

Sigma စည်းမျဉ်းများကို Hayabusa-compatible format အဖြစ် ဒေသတွင်း (locally) ပြောင်းလဲလိုပါက၊ ဦးစွာ [Poetry](https://python-poetry.org/) ကို install ပြုလုပ်ရန် လိုအပ်သည်။ တရားဝင် Poetry [installation documentation](https://python-poetry.org/docs/#installation) ကို ကိုးကားပါ။

## Tool အသုံးပြုပုံ

`sigma-to-hayabusa-converter.py` သည် Sigma စည်းမျဉ်းများ၏ `logsource` အကွက်ကို Hayabusa-compatible format အဖြစ် ပြောင်းလဲရန် ကျွန်ုပ်တို့၏ အဓိက tool ဖြစ်သည်။ ၎င်းကို run ရန် အောက်ပါလုပ်ငန်းများကို ဆောင်ရွက်ပါ:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

အထက်ပါ command များကို execute ပြုလုပ်ပြီးနောက်၊ Hayabusa-compatible format အဖြစ် ပြောင်းလဲထားသော စည်းမျဉ်းများကို `./converted_sigma_rules` directory သို့ ထုတ်ပေးမည်ဖြစ်သည်။

## ရေးသားသူများ

ဤစာရွက်စာတမ်းကို Zach Mathis (@yamatosecurity) မှ ဖန်တီးခဲ့ပြီး Fukusuke Takahashi (@fukusuket) မှ ဂျပန်ဘာသာသို့ ဘာသာပြန်ဆိုခဲ့သည်။

`sigma-to-hayabusa-converter.py` tool ၏ အကောင်အထည်ဖော်မှုနှင့် ထိန်းသိမ်းမှုကို Fukusuke Takahashi မှ ဆောင်ရွက်သည်။

ယခုအခါ deprecated ဖြစ်သွားပြီဖြစ်သော `sigmac` tool အပေါ် အားကိုးခဲ့သည့် မူရင်းပြောင်းလဲမှု tool ကို ItiB ([@itiB_S144](https://x.com/itib_s144)) နှင့် James Takai / hachiyone (@hach1yon) တို့မှ အကောင်အထည်ဖော်ခဲ့သည်။
