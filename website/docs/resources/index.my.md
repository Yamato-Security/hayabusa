# ပရောဂျက်များနှင့် ဂေဟစနစ်

## တွဲဖက်ပရောဂျက်များ

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Windows event log များကို မှန်ကန်စွာ ဖွင့်ရန် စာရွက်စာတမ်းများနှင့် scripts များ။
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Hayabusa Rules repository နှင့် တူညီသော်လည်း rules နှင့် config file များကို file တစ်ခုတည်းတွင် သိမ်းဆည်းကာ anti-virus မှ false positive များ မဖြစ်စေရန် XOR ပြုလုပ်ထားသည်။
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa တွင် အသုံးပြုသော Hayabusa နှင့် ရွေးချယ်ထားသော Sigma detection rules များ။
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - `evtx` crate ၏ ပိုမိုထိန်းသိမ်းထားသော fork တစ်ခု။
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - hayabusa/sigma detection rules များကို စမ်းသပ်ရန် အသုံးပြုသော နမူနာ evtx file များ။
* [Presentations](https://github.com/Yamato-Security/Presentations) - ကျွန်ုပ်တို့၏ tools နှင့် resource များအကြောင်း ဆွေးနွေးခဲ့သော တင်ဆက်မှုများ။
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - upstream Windows event log အခြေခံ Sigma rules များကို ပိုမိုလွယ်ကူသော ပုံစံအဖြစ် ရွေးချယ်ပြင်ဆင်ပေးသည်။
* [Takajo](https://github.com/Yamato-Security/takajo) - hayabusa ရလဒ်များအတွက် analyzer တစ်ခု။
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - PowerShell ဖြင့်ရေးထားသော Windows event log analyzer တစ်ခု။ (ရပ်ဆိုင်းပြီး Takajo ဖြင့် အစားထိုးထားသည်။)

## Hayabusa ကို အသုံးပြုသော Third-Party ပရောဂျက်များ

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Plaso နှင့် Hayabusa ရလဒ်များကို Timesketch ထဲသို့ import လုပ်ပေးသော NodeRED workflow တစ်ခု။
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - သင့်လိုအပ်ချက်များနှင့် ကိုက်ညီသော cloud အခြေခံ security tools နှင့် infrastructure ကို ပံ့ပိုးပေးသည်။ 
* [OpenRelik](https://openrelik.org/) - ပူးပေါင်းဆောင်ရွက်သော digital forensic စုံစမ်းစစ်ဆေးမှုများကို ချောမွေ့စေရန် ဒီဇိုင်းရေးဆွဲထားသော open-source (Apache-2.0) platform တစ်ခု။
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - သင်၏ စုံစမ်းစစ်ဆေးမှုများအတွင်း log များနှင့် tool output များကို လှော်လျှောကြည့်ရှုရန် Docker ဖြင့် splunk instance တစ်ခုကို လျင်မြန်စွာ ဖန်တီးပေးသည်။
* [Velociraptor](https://github.com/Velocidex/velociraptor) - The Velociraptor Query Language (VQL) queries များကို အသုံးပြု၍ host အခြေခံ state information များ စုဆောင်းရန် tool တစ်ခု။

## အခြား Windows Event Log Analyzer များနှင့် ဆက်စပ် Resource များ

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Python ဖြင့် ရေးထားသော တိုက်ခိုက်မှု ထောက်လှမ်းရေး tool။
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Digital Forensics နှင့် Incident Response အတွက် အသုံးဝင်သော Event ID resource များ စုစည်းမှု
* [Chainsaw](https://github.com/countercept/chainsaw) - Rust ဖြင့်ရေးထားသော အခြား sigma အခြေခံ တိုက်ခိုက်မှု ထောက်လှမ်းရေး tool။
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - [Eric Conrad](https://twitter.com/eric_conrad) မှ Powershell ဖြင့် ရေးထားသော တိုက်ခိုက်မှု ထောက်လှမ်းရေး tool။
* [Epagneul](https://github.com/jurelou/epagneul) - Windows event log များအတွက် Graph visualization။
* [EventList](https://github.com/miriamxyra/EventList/) - [Miriam Wiesner](https://github.com/miriamxyra) မှ security baseline event ID များကို MITRE ATT&CK နှင့် ချိတ်ဆက်မြေပုံဆွဲခြင်း။
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) မှ
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) မှ Evtx parser။
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - unallocated space နှင့် memory image များမှ EVTX log file များ ပြန်လည်ရယူခြင်း။
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Evtx data ကို Elastic Stack သို့ ပို့ပေးသော Python tool။
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - [SBousseaden](https://twitter.com/SBousseaden) မှ EVTX တိုက်ခိုက်မှု နမူနာ event log file များ။
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) မှ ATT&CK နှင့် ချိတ်ဆက်မြေပုံဆွဲထားသော EVTX တိုက်ခိုက်မှု နမူနာ event log file များ
* [EVTX parser](https://github.com/omerbenamram/evtx) - [@OBenamram](https://twitter.com/obenamram) မှ ရေးထားသော ကျွန်ုပ်တို့ အသုံးပြုသည့် Rust evtx library။
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Sysmon နှင့် PowerShell log visualizer။
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - [JPCERTCC](https://twitter.com/jpcert_en) မှ lateral movement ကို ထောက်လှမ်းရန် logon များကို မြင်သာစေသော graphical interface။
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - မည်သည့်အရာကို စောင့်ကြည့်ရမည်ဆိုသည့် NSA ၏ လမ်းညွှန်ချက်။
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Yamato Security မှ DeepBlueCLI ၏ Rust port။
* [Sigma](https://github.com/SigmaHQ/sigma) - အသိုင်းအဝိုင်းအခြေခံ generic SIEM rules များ။
* [SOF-ELK](https://github.com/philhagen/sof-elk) - [Phil Hagen](https://twitter.com/philhagen) မှ DFIR analysis အတွက် data import လုပ်ရန် Elastic Stack ပါဝင်သော ကြိုတင်ထုပ်ပိုးထားသော VM
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtx file များကို Security Onion ထဲသို့ import လုပ်ခြင်း။
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Sysmon အတွက် Configuration နှင့် off-line log visualization tool။
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) မှ အကောင်းဆုံး CSV timeline analyzer။
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - Forward Defense ၏ Steve Anson မှ။
* [Zircolite](https://github.com/wagga40/Zircolite) - Python ဖြင့်ရေးထားသော Sigma အခြေခံ တိုက်ခိုက်မှု ထောက်လှမ်းရေး tool။
