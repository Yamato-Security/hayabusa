# प्रोजेक्ट और इकोसिस्टम

## सहयोगी प्रोजेक्ट

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Windows इवेंट लॉग को सही ढंग से सक्षम करने के लिए दस्तावेज़ और स्क्रिप्ट।
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Hayabusa Rules रिपॉज़िटरी के समान, लेकिन नियम और कॉन्फ़िग फ़ाइलें एक ही फ़ाइल में संग्रहीत होती हैं और एंटी-वायरस से झूठे पॉज़िटिव को रोकने के लिए XOR की जाती हैं।
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa में उपयोग किए जाने वाले Hayabusa और संकलित Sigma डिटेक्शन नियम।
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - `evtx` क्रेट का एक अधिक रखरखाव वाला फ़ोर्क।
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - hayabusa/sigma डिटेक्शन नियमों के परीक्षण के लिए उपयोग करने हेतु नमूना evtx फ़ाइलें।
* [Presentations](https://github.com/Yamato-Security/Presentations) - हमारे टूल और संसाधनों के बारे में हमारे द्वारा दी गई वार्ताओं की प्रस्तुतियाँ।
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - अपस्ट्रीम Windows इवेंट लॉग आधारित Sigma नियमों को अधिक उपयोग में आसान रूप में संकलित करता है।
* [Takajo](https://github.com/Yamato-Security/takajo) - hayabusa परिणामों के लिए एक विश्लेषक।
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - PowerShell में लिखा गया Windows इवेंट लॉग के लिए एक विश्लेषक। (अप्रचलित और Takajo द्वारा प्रतिस्थापित।)

## तृतीय-पक्ष प्रोजेक्ट जो Hayabusa का उपयोग करते हैं

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - एक NodeRED वर्कफ़्लो जो Plaso और Hayabusa परिणामों को Timesketch में आयात करता है।
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - आपकी आवश्यकताओं के अनुरूप क्लाउड-आधारित सुरक्षा उपकरण और बुनियादी ढाँचा प्रदान करता है। 
* [OpenRelik](https://openrelik.org/) - एक ओपन-सोर्स (Apache-2.0) प्लेटफ़ॉर्म जिसे सहयोगात्मक डिजिटल फ़ोरेंसिक जाँच को सुव्यवस्थित करने के लिए डिज़ाइन किया गया है।
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - अपनी जाँच के दौरान लॉग और टूल आउटपुट को ब्राउज़ करने के लिए Docker के साथ शीघ्रता से एक splunk इंस्टेंस आरंभ करें।
* [Velociraptor](https://github.com/Velocidex/velociraptor) - The Velociraptor Query Language (VQL) क्वेरीज़ का उपयोग करके होस्ट आधारित स्थिति जानकारी एकत्र करने के लिए एक टूल।

## अन्य Windows इवेंट लॉग विश्लेषक और संबंधित संसाधन

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Python में लिखा गया अटैक डिटेक्शन टूल।
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Digital Forensics और Incident Response के लिए उपयोगी Event ID संसाधनों का संग्रह
* [Chainsaw](https://github.com/countercept/chainsaw) - Rust में लिखा गया एक और sigma-आधारित अटैक डिटेक्शन टूल।
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - [Eric Conrad](https://twitter.com/eric_conrad) द्वारा Powershell में लिखा गया अटैक डिटेक्शन टूल।
* [Epagneul](https://github.com/jurelou/epagneul) - Windows इवेंट लॉग के लिए ग्राफ़ विज़ुअलाइज़ेशन।
* [EventList](https://github.com/miriamxyra/EventList/) - [Miriam Wiesner](https://github.com/miriamxyra) द्वारा सुरक्षा बेसलाइन इवेंट ID को MITRE ATT&CK से मैप करें।
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) द्वारा
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) द्वारा Evtx पार्सर।
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - अनआवंटित स्थान और मेमोरी इमेज से EVTX लॉग फ़ाइलें पुनर्प्राप्त करें।
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Evtx डेटा को Elastic Stack में भेजने के लिए Python टूल।
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - [SBousseaden](https://twitter.com/SBousseaden) द्वारा EVTX अटैक नमूना इवेंट लॉग फ़ाइलें।
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) द्वारा ATT&CK से मैप की गई EVTX अटैक नमूना इवेंट लॉग फ़ाइलें
* [EVTX parser](https://github.com/omerbenamram/evtx) - [@OBenamram](https://twitter.com/obenamram) द्वारा लिखी गई Rust evtx लाइब्रेरी जिसका हम उपयोग करते हैं।
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Sysmon और PowerShell लॉग विज़ुअलाइज़र।
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - [JPCERTCC](https://twitter.com/jpcert_en) द्वारा लेटरल मूवमेंट का पता लगाने के लिए लॉगऑन को विज़ुअलाइज़ करने हेतु एक ग्राफ़िकल इंटरफ़ेस।
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - किसकी निगरानी करनी है, इस पर NSA की मार्गदर्शिका।
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Yamato Security द्वारा DeepBlueCLI का Rust पोर्ट।
* [Sigma](https://github.com/SigmaHQ/sigma) - समुदाय आधारित सामान्य SIEM नियम।
* [SOF-ELK](https://github.com/philhagen/sof-elk) - [Phil Hagen](https://twitter.com/philhagen) द्वारा DFIR विश्लेषण के लिए डेटा आयात करने हेतु Elastic Stack के साथ एक पूर्व-पैकेज्ड VM
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtx फ़ाइलों को Security Onion में आयात करें।
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Sysmon के लिए कॉन्फ़िगरेशन और ऑफ़-लाइन लॉग विज़ुअलाइज़ेशन टूल।
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) द्वारा सर्वश्रेष्ठ CSV टाइमलाइन विश्लेषक।
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - Forward Defense के Steve Anson द्वारा।
* [Zircolite](https://github.com/wagga40/Zircolite) - Python में लिखा गया Sigma-आधारित अटैक डिटेक्शन टूल।
