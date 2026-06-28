# প্রকল্পসমূহ ও ইকোসিস্টেম

## সহযোগী প্রকল্পসমূহ

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Windows ইভেন্ট লগ সঠিকভাবে সক্রিয় করার জন্য ডকুমেন্টেশন এবং স্ক্রিপ্ট।
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Hayabusa Rules রিপোজিটরির মতোই, তবে রুল এবং কনফিগ ফাইলগুলো একটি ফাইলে সংরক্ষণ করা হয় এবং অ্যান্টি-ভাইরাস থেকে ফলস পজিটিভ প্রতিরোধ করতে XOR করা হয়।
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa-তে ব্যবহৃত Hayabusa এবং কিউরেটেড Sigma ডিটেকশন রুল।
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - `evtx` ক্রেটের একটি আরও সুপরিচালিত ফর্ক।
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - hayabusa/sigma ডিটেকশন রুল পরীক্ষার জন্য ব্যবহার করার নমুনা evtx ফাইল।
* [Presentations](https://github.com/Yamato-Security/Presentations) - আমাদের টুল এবং রিসোর্স সম্পর্কে আমরা যেসব আলোচনা দিয়েছি তার উপস্থাপনা।
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - আপস্ট্রিম Windows ইভেন্ট লগ ভিত্তিক Sigma রুলকে একটি সহজে ব্যবহারযোগ্য রূপে কিউরেট করে।
* [Takajo](https://github.com/Yamato-Security/takajo) - hayabusa ফলাফলের একটি বিশ্লেষক।
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - PowerShell-এ লেখা Windows ইভেন্ট লগের একটি বিশ্লেষক। (অবচিত এবং Takajo দ্বারা প্রতিস্থাপিত।)

## তৃতীয়-পক্ষের প্রকল্প যেগুলো Hayabusa ব্যবহার করে

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - একটি NodeRED ওয়ার্কফ্লো যা Plaso এবং Hayabusa ফলাফল Timesketch-এ ইমপোর্ট করে।
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - আপনার প্রয়োজন অনুযায়ী ক্লাউড-ভিত্তিক সিকিউরিটি টুল এবং অবকাঠামো সরবরাহ করে। 
* [OpenRelik](https://openrelik.org/) - সহযোগিতামূলক ডিজিটাল ফরেনসিক তদন্তকে সহজতর করার জন্য ডিজাইন করা একটি ওপেন-সোর্স (Apache-2.0) প্ল্যাটফর্ম।
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - আপনার তদন্তের সময় লগ এবং টুল আউটপুট ব্রাউজ করতে Docker দিয়ে দ্রুত একটি splunk ইনস্ট্যান্স চালু করুন।
* [Velociraptor](https://github.com/Velocidex/velociraptor) - The Velociraptor Query Language (VQL) কোয়েরি ব্যবহার করে হোস্ট ভিত্তিক স্টেট তথ্য সংগ্রহের একটি টুল।

## অন্যান্য Windows ইভেন্ট লগ বিশ্লেষক এবং সম্পর্কিত রিসোর্স

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Python-এ লেখা অ্যাটাক ডিটেকশন টুল।
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  ডিজিটাল ফরেনসিক্স এবং ইনসিডেন্ট রেসপন্সের জন্য উপযোগী Event ID রিসোর্সের সংগ্রহ
* [Chainsaw](https://github.com/countercept/chainsaw) - Rust-এ লেখা আরেকটি sigma-ভিত্তিক অ্যাটাক ডিটেকশন টুল।
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - [Eric Conrad](https://twitter.com/eric_conrad) দ্বারা Powershell-এ লেখা অ্যাটাক ডিটেকশন টুল।
* [Epagneul](https://github.com/jurelou/epagneul) - Windows ইভেন্ট লগের জন্য গ্রাফ ভিজ্যুয়ালাইজেশন।
* [EventList](https://github.com/miriamxyra/EventList/) - [Miriam Wiesner](https://github.com/miriamxyra) দ্বারা সিকিউরিটি বেসলাইন ইভেন্ট আইডিকে MITRE ATT&CK-এর সাথে ম্যাপ করুন।
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) দ্বারা
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) দ্বারা Evtx পার্সার।
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - আনঅ্যালোকেটেড স্পেস এবং মেমরি ইমেজ থেকে EVTX লগ ফাইল পুনরুদ্ধার করুন।
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Evtx ডেটা Elastic Stack-এ পাঠানোর Python টুল।
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - [SBousseaden](https://twitter.com/SBousseaden) দ্বারা EVTX অ্যাটাক নমুনা ইভেন্ট লগ ফাইল।
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) দ্বারা ATT&CK-এর সাথে ম্যাপ করা EVTX অ্যাটাক নমুনা ইভেন্ট লগ ফাইল
* [EVTX parser](https://github.com/omerbenamram/evtx) - [@OBenamram](https://twitter.com/obenamram) দ্বারা লেখা আমরা যে Rust evtx লাইব্রেরি ব্যবহার করি।
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Sysmon এবং PowerShell লগ ভিজ্যুয়ালাইজার।
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - [JPCERTCC](https://twitter.com/jpcert_en) দ্বারা ল্যাটারাল মুভমেন্ট শনাক্ত করতে লগঅন ভিজ্যুয়ালাইজ করার একটি গ্রাফিকাল ইন্টারফেস।
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - কী মনিটর করতে হবে সে সম্পর্কে NSA-এর গাইড।
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Yamato Security দ্বারা DeepBlueCLI-এর Rust পোর্ট।
* [Sigma](https://github.com/SigmaHQ/sigma) - কমিউনিটি ভিত্তিক জেনেরিক SIEM রুল।
* [SOF-ELK](https://github.com/philhagen/sof-elk) - [Phil Hagen](https://twitter.com/philhagen) দ্বারা DFIR বিশ্লেষণের জন্য ডেটা ইমপোর্ট করতে Elastic Stack সহ একটি প্রি-প্যাকেজড VM
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtx ফাইল Security Onion-এ ইমপোর্ট করুন।
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Sysmon-এর জন্য কনফিগারেশন এবং অফ-লাইন লগ ভিজ্যুয়ালাইজেশন টুল।
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) দ্বারা সেরা CSV টাইমলাইন বিশ্লেষক।
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - Forward Defense-এর Steve Anson দ্বারা।
* [Zircolite](https://github.com/wagga40/Zircolite) - Python-এ লেখা Sigma-ভিত্তিক অ্যাটাক ডিটেকশন টুল।
