# Windows इवेंट लॉग के लिए Sigma नियमों का क्यूरेशन

यह पेज दस्तावेज़ करता है कि Yamato Security किस प्रकार Windows इवेंट लॉग के लिए अपस्ट्रीम [Sigma](https://github.com/SigmaHQ/sigma) नियमों को `logsource` फ़ील्ड को डी-एब्स्ट्रैक्ट करके और ऐसे नियमों को फ़िल्टर करके — जो उपयोग करने योग्य नहीं हैं या उपयोग करने में कठिन हैं — एक अधिक उपयोगी रूप में क्यूरेट करती है। यह [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) टूल से किया जाता है, जिसका उपयोग मुख्य रूप से [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) में होस्ट किए गए क्यूरेटेड Sigma रूलसेट को बनाने के लिए किया जाता है। उस रूलसेट का उपयोग [Hayabusa](https://github.com/Yamato-Security/hayabusa) और [Velociraptor](https://github.com/Velocidex/velociraptor) करते हैं।

!!! info "स्रोत"
    यह दस्तावेज़ीकरण कनवर्टर टूल के साथ [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) पर बनाए रखा जाता है। हमें आशा है कि यह जानकारी अन्य प्रोजेक्ट्स के लिए भी उपयोगी होगी जो Windows इवेंट लॉग में हमलों का पता लगाने के लिए Sigma नियमों का उपयोग करना चाहते हैं। यह भी देखें [नियम फ़ाइलें बनाना](creating-rules.md) और [फ़ील्ड मॉडिफ़ायर](field-modifiers.md)।

## TL;DR

* `logsource` फ़ील्ड को डी-एब्स्ट्रैक्ट करना और बिल्ट-इन नियमों के साथ-साथ मूल Sysmon-आधारित नियमों के लिए नई `.yml` नियम फ़ाइलें बनाना Sigma नियमों के लिए संपूर्ण बिल्ट-इन इवेंट समर्थन को आसान बनाता है, और नियमों को विश्लेषकों के लिए पढ़ने में आसान बनाता है।
* Windows इवेंट लॉग के लिए Sigma नियम लिखते समय, मूल Sysmon-आधारित लॉग और संगत बिल्ट-इन लॉग के बीच के अंतर को समझना महत्वपूर्ण है, और आदर्श रूप से अपने नियमों को इस तरह लिखना चाहिए कि वे दोनों के साथ संगत हों।
* कई संगठन अपने सभी Windows एंडपॉइंट पर Sysmon एजेंट को इंस्टॉल और मेंटेन नहीं कर सकते या नहीं करना चाहते, क्योंकि उनके पास इसे संभालने के लिए समर्पित संसाधन नहीं होते, या वे Sysmon के कारण होने वाली किसी भी धीमेपन या क्रैश के जोखिम से बचना चाहते हैं। इसी कारण, यह महत्वपूर्ण है कि जितने संभव हो उतने बिल्ट-इन इवेंट लॉग सक्षम किए जाएं और ऐसे टूल का उपयोग किया जाए जो उन बिल्ट-इन लॉग में हमलों का पता लगा सकें।

## Windows इवेंट लॉग के लिए अपस्ट्रीम Sigma नियमों के साथ चुनौतियाँ

हमारे अनुभव में, Windows इवेंट लॉग के लिए एक नेटिव Sigma नियम पार्सर बनाने की मुख्य चुनौती `logsource` फ़ील्ड का समर्थन करना रही है। वर्तमान में यह उन कुछ चीज़ों में से एक है जिसका Hayabusa अभी तक नेटिव रूप से समर्थन नहीं करता, क्योंकि यह अभी भी बहुत जटिल है और प्रगति पर है। फ़िलहाल, हम अपस्ट्रीम नियमों को एक आसान-उपयोग-योग्य फ़ॉर्मेट में परिवर्तित करके इसका समाधान करते हैं, जैसा कि नीचे विस्तार से बताया गया है।

### `logsource` फ़ील्ड के बारे में

Windows इवेंट लॉग के लिए Sigma नियमों में, `product` फ़ील्ड को `windows` पर सेट किया जाता है, जिसके बाद या तो `service` फ़ील्ड या `category` फ़ील्ड आता है।

`service` फ़ील्ड का उदाहरण:

```yaml
logsource:
    product: windows
    service: application
```

`category` फ़ील्ड का उदाहरण:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Service फ़ील्ड

`service` फ़ील्ड को संभालना अपेक्षाकृत सरल है और यह Sigma नियम का उपयोग करने वाले किसी भी बैकएंड को Windows XML इवेंट लॉग में `Channel` फ़ील्ड के आधार पर एक या कई चैनलों में खोज करने के लिए बताता है।

**सिंगल चैनल उदाहरण**

`service: application` का अर्थ Sigma नियम में `Channel: Application` की एक selection शर्त जोड़ने के समान ही है।

**मल्टीपल चैनल उदाहरण**

`service: applocker` वर्तमान में खोजने के लिए सबसे अधिक चैनल बनाता है, क्योंकि AppLocker जानकारी को चार अलग-अलग लॉग में सहेजता है। केवल AppLocker लॉग को ठीक से खोजने के लिए, Sigma नियम की लॉजिक में निम्नलिखित शर्त जोड़नी होगी:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**service मैपिंग की वर्तमान सूची**

| Service                                    | Channel                                                                                                                             |
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

**service मैपिंग के स्रोत**

हमने services से चैनल नामों के लिए YAML मैपिंग फ़ाइलें बनाई हैं, जिन्हें हम समय-समय पर मेंटेन करते हैं और कनवर्टर रिपॉज़िटरी में होस्ट करते हैं। ये [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) से service मैपिंग जानकारी पर आधारित हैं: हालाँकि यह लोगों के उपयोग के लिए एक आधिकारिक जेनेरिक कॉन्फ़िग फ़ाइल नहीं लगती, फिर भी यह सबसे अद्यतित प्रतीत होती है।

#### Category फ़ील्ड

अधिकांश `category` फ़ील्ड किसी विशिष्ट `Channel` की खोज के अतिरिक्त `EventID` फ़ील्ड में कुछ निश्चित इवेंट ID की जाँच के लिए बस एक शर्त जोड़ते हैं। category नाम अधिकतर [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) इवेंट पर आधारित हैं, जिनमें बिल्ट-इन PowerShell लॉग और Windows Defender के लिए कुछ अतिरिक्त categories हैं।

**category फ़ील्ड का उदाहरण**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**category मैपिंग की वर्तमान सूची**

कुछ categories एक से अधिक service/EventID से मैप होती हैं (**बोल्ड** में दिखाया गया है)।

| Category                  | Service            | EventIDs                                                               |
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

**category फ़ील्ड की चुनौतियाँ**

जैसा कि ऊपर दिखाया गया है, वही `category` कई services और इवेंट ID का उपयोग कर सकती है (**बोल्ड** में दर्शाया गया है)। इसका अर्थ है कि `sysmon` के लिए डिज़ाइन किए गए कुछ Sigma नियमों का उपयोग समान बिल्ट-इन Windows `security` इवेंट लॉग के साथ करना संभव है, यदि नियम द्वारा उपयोग की जाने वाली फ़ील्ड बिल्ट-इन इवेंट लॉग में भी मौजूद हों। ऐसी स्थिति में, फ़ील्ड नामों — और कभी-कभी मानों — को भी बिल्ट-इन `security` इवेंट लॉग के फ़ील्ड नामों और मानों से मिलाने के लिए परिवर्तित करने की आवश्यकता हो सकती है। हालाँकि कुछ categories के लिए यह उतना ही सरल हो सकता है जितना कुछ फ़ील्ड नामों को बदलना, अन्य categories के लिए इसमें फ़ील्ड मानों में भी विभिन्न परिवर्तनों की आवश्यकता हो सकती है। हम यह परिवर्तन कैसे करते हैं, और `sysmon` लॉग तथा `security` लॉग के बीच संगतता के बारे में [नीचे](#sysmon-builtin-comparison) विस्तार से बताया गया है।

**category मैपिंग के स्रोत**

categories के लिए YAML मैपिंग फ़ाइलें भी कनवर्टर रिपॉज़िटरी में होस्ट की गई हैं और [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) की जानकारी पर आधारित हैं।

## लॉग स्रोत को एब्स्ट्रैक्ट करने के लाभ और चुनौतियाँ

लॉग स्रोत को एब्स्ट्रैक्ट करने और बैकएंड पर विभिन्न `Channel`, `EventID` और फ़ील्ड के लिए मैपिंग बनाने के लाभ और चुनौतियाँ दोनों हैं।

### लाभ

1. Sigma नियमों को अन्य बैकएंड क्वेरी में परिवर्तित करते समय `Channel` और `EventID` फ़ील्ड नामों को उपयुक्त बैकएंड फ़ील्ड नामों में परिवर्तित करना आसान हो सकता है।
2. दो नियमों को एक में समेकित करना संभव है। उदाहरण के लिए, प्रोसेस निर्माण इवेंट को `Sysmon 1` के साथ-साथ `Security 4688` में भी लॉग किया जा सकता है। ऐसे दो नियम लिखने के बजाय जो अलग-अलग चैनल, इवेंट ID और फ़ील्ड देखते हैं लेकिन अन्यथा समान लॉजिक रखते हैं, फ़ील्ड को Sysmon द्वारा उपयोग किए जाने वाले रूप में मानकीकृत करना संभव है और फिर एक बैकएंड कनवर्टर से `Channel` और `EventID` फ़ील्ड जुड़वाना तथा आवश्यकता होने पर अन्य फ़ील्ड जानकारी परिवर्तित करवाना संभव है। इससे नियमों का रखरखाव आसान हो जाता है, क्योंकि रखरखाव के लिए कम नियम होते हैं।
3. हालाँकि बहुत दुर्लभ, यदि कोई लॉग स्रोत अपना डेटा किसी भिन्न `Channel` या `EventID` में लॉग करना शुरू कर देता है, तो सभी Sigma नियमों को अपडेट करने के बजाय केवल मैपिंग लॉजिक को अपडेट करने की आवश्यकता होती है, जिससे रखरखाव आसान हो जाता है।

### चुनौतियाँ

1. यदि Sysmon पर आधारित मूल Sigma नियम किसी ऐसे फ़ील्ड का उपयोग करता है जो झूठे-सकारात्मक (false positive) को फ़िल्टर करने के लिए बिल्ट-इन लॉग में मौजूद नहीं है, तो क्या होगा? क्या आपको संभावित पहचान को प्राथमिकता देते हुए फिर भी नियम बनाना चाहिए, या कम झूठे-सकारात्मक को प्राथमिकता देने के लिए इसे अनदेखा करना चाहिए? आदर्श रूप से, उपयोगकर्ता के लिए इसे बेहतर ढंग से संभालने हेतु अलग-अलग `severity`, `status`, और झूठे-सकारात्मक जानकारी के साथ दो नियम बनाने की आवश्यकता होगी।
2. यह नियमों को फ़िल्टर करना अधिक कठिन बना देता है, क्योंकि आप केवल `.yml` फ़ाइल में `Channel` या `EventID` फ़ील्ड या नियम के फ़ाइल पथ के आधार पर फ़िल्टर नहीं कर सकते यदि फ़ाइल अभी तक बनाई नहीं गई है — क्योंकि यह मूल Sysmon नियम के बजाय बिल्ट-इन लॉग के लिए एक व्युत्पन्न (derived) नियम है। साथ ही, चूँकि नियम ID समान होती है, आप नियम ID पर फ़िल्टर नहीं कर सकते।
3. जब अलर्ट किसी ऐसे बिल्ट-इन लॉग के नियम से आता है जो Sysmon लॉग से व्युत्पन्न किया गया था, तो यह अलर्ट की पुष्टि करना अधिक कठिन बना देता है। फ़ील्ड नाम और मान मेल नहीं खाएंगे, इसलिए विश्लेषक को कुछ हद तक जटिल परिवर्तन प्रक्रिया को समझने की आवश्यकता होती है।
4. यह बैकएंड लॉजिक बनाना अधिक जटिल बना देता है।

जबकि पहली समस्या के बारे में हम कुछ नहीं कर सकते — सिवाय तब जब कोई महत्वपूर्ण उपयोग-मामला हो जो प्रयास को उचित ठहराता है, तब नए नियम बनाने और उनका रखरखाव करने के — समस्याओं 2–4 को हल करने के लिए हमने `logsource` फ़ील्ड को डी-एब्स्ट्रैक्ट करने और किसी भी ऐसे नियम के लिए दो सेट नियम बनाने का निर्णय लिया है जो कई नियम उत्पन्न कर सकते हैं। ऐसे नियम जो बिल्ट-इन लॉग में हमलों का पता लगा सकते हैं उन्हें `builtin` डायरेक्टरी में आउटपुट किया जाता है, और Sysmon के लिए नियम `sysmon` डायरेक्टरी में आउटपुट किए जाते हैं।

## परिवर्तन का उदाहरण

परिवर्तन प्रक्रिया को बेहतर ढंग से समझने के लिए यहाँ एक सरल उदाहरण दिया गया है।

**परिवर्तन से पहले** — मूल Sigma नियम:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**परिवर्तन के बाद** — Sysmon लॉग के लिए एक Hayabusa-संगत नियम:

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

...और Windows बिल्ट-इन लॉग के लिए एक Hayabusa-संगत नियम:

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

जैसा कि आप देख सकते हैं, दो नियम बनाए गए हैं: एक Sysmon 1 लॉग के लिए और एक बिल्ट-इन Security 4688 लॉग के लिए। चैनल और इवेंट ID जानकारी के साथ एक नई `process_creation` शर्त जोड़ी गई है, और इस शर्त को अनिवार्य करने के लिए इसे `condition` फ़ील्ड में जोड़ा गया है। साथ ही, मूल `Image` फ़ील्ड नाम को `NewProcessName` में बदल दिया गया है।

## परिवर्तन की समानताएँ

विशिष्ट categories को हम कैसे परिवर्तित करते हैं, इसे विस्तार से समझाने से पहले, यहाँ परिवर्तन का वह भाग दिया गया है जो सभी नियमों पर लागू होता है।

1. किसी भी नियम को जिसकी ID `ignore-uuid-list.txt` में है, अनदेखा किया जाता है। वर्तमान में हम केवल उन नियमों को अनदेखा करते हैं जो Windows Defender पर झूठे-सकारात्मक उत्पन्न करते हैं क्योंकि उनमें `mimikatz` जैसे कीवर्ड होते हैं।
2. "Placeholder" नियमों को अनदेखा किया जाता है क्योंकि उन्हें जैसे-के-तैसे उपयोग नहीं किया जा सकता। ये वे नियम हैं जो Sigma रिपॉज़िटरी में [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) फ़ोल्डर में रखे गए हैं।
3. असंगत फ़ील्ड मॉडिफ़ायर का उपयोग करने वाले नियमों को हटा दिया जाता है। Hayabusa अधिकांश फ़ील्ड मॉडिफ़ायर का समर्थन करता है, इसलिए कनवर्टर पार्सिंग त्रुटियों से बचने के लिए इनके अलावा किसी मॉडिफ़ायर का उपयोग करने वाला कोई नियम आउटपुट नहीं करेगा (देखें [फ़ील्ड मॉडिफ़ायर](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. सिंटैक्स त्रुटियों वाले नियमों को परिवर्तित नहीं किया जाता।
5. `deprecated` और `unsupported` नियमों में टैग को V1 फ़ॉर्मेट से V2 फ़ॉर्मेट में अपडेट किया जाता है, जो `_` के बजाय `-` का उपयोग करता है, ताकि सब कुछ सुसंगत बना रहे और Hayabusa में संक्षिप्ताक्षरों को अधिक आसानी से संभाला जा सके। उदाहरण: `initial_access` बन जाता है `initial-access`।
6. चूँकि हम नियमों में `Channel` और `EventID` जानकारी जोड़ रहे हैं, इसलिए हम मूल ID के MD5 हैश का उपयोग करके एक नई UUIDv4 ID बनाते हैं, मूल ID को `related` फ़ील्ड में निर्दिष्ट करते हैं, और `type` को `derived` के रूप में चिह्नित करते हैं। ऐसे नियमों के लिए जिन्हें कई नियमों (`sysmon` और `builtin`) में परिवर्तित किया जा सकता है, हमें व्युत्पन्न `builtin` नियमों के लिए भी नई नियम ID बनानी होती हैं। ऐसा करने के लिए, हम `sysmon` नियम ID का MD5 हैश निकालते हैं और उसका उपयोग UUIDv4 ID के लिए करते हैं। उदाहरण के लिए:

    मूल Sigma नियम:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    नया `sysmon` नियम:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    नया `builtin` नियम:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. ऐसे नियम जो बिल्ट-इन Windows इवेंट लॉग में चीज़ों का पता लगाते हैं, उन्हें `builtin` डायरेक्टरी में आउटपुट किया जाता है, जबकि ऐसे नियम जो Sysmon लॉग पर निर्भर करते हैं उन्हें `sysmon` डायरेक्टरी में आउटपुट किया जाता है, जिसमें अपस्ट्रीम Sigma रिपॉज़िटरी की डायरेक्टरियों से मेल खाती उप-डायरेक्टरियाँ होती हैं।

## परिवर्तन की सीमाएँ

फ़िलहाल केवल एक [ज्ञात बग](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2) है: Sigma नियमों में टिप्पणी पंक्तियाँ आउटपुट नियमों में शामिल नहीं की जाएंगी जब तक कि टिप्पणियाँ किसी सोर्स कोड के बाद न आती हों।

## Sysmon और बिल्ट-इन इवेंट की तुलना तथा नियम परिवर्तन { #sysmon-builtin-comparison }

### Process creation

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* बिल्ट-इन लॉग
    * Channel: `Security`
    * Event ID: `4688`

**तुलना**

![Process creation तुलना](../assets/rules-doc/process_creation_comparison.png)

**परिवर्तन नोट्स**

1. `User` फ़ील्ड जानकारी को `SubjectUserName` और `SubjectDomainName` फ़ील्ड में अलग करने की आवश्यकता होती है।
2. `LogonId` फ़ील्ड नाम बदलकर `SubjectLogonId` हो जाता है, और हेक्स मान में कोई भी अक्षर लोअरकेस में होना चाहिए।
3. `ProcessId` फ़ील्ड नाम बदलकर `NewProcessId` हो जाता है, और मान को हेक्स में परिवर्तित करने की आवश्यकता होती है।
4. `Image` फ़ील्ड नाम बदलकर `NewProcessName` हो जाता है।
5. `ParentProcessId` फ़ील्ड नाम बदलकर `ProcessId` हो जाता है, और मान को हेक्स में परिवर्तित करने की आवश्यकता होती है।
6. `ParentImage` फ़ील्ड नाम बदलकर `ParentProcessName` हो जाता है।
7. `IntegrityLevel` फ़ील्ड नाम बदलकर `MandatoryLabel` हो जाता है, और निम्नलिखित मान परिवर्तन आवश्यक है:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. यदि नियम में निम्नलिखित फ़ील्ड हैं जो केवल `Security 4688` इवेंट में मौजूद हैं, तो हम `Sysmon 1` नियम नहीं बनाते:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. यदि नियम में निम्नलिखित फ़ील्ड हैं जो केवल `Sysmon 1` इवेंट में मौजूद हैं, तो हम `Security 4688` नियम नहीं बनाते:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. #8 और #9 का एक अपवाद है: भले ही कोई ऐसा फ़ील्ड उपयोग किया गया हो जो केवल एक लॉग इवेंट में मौजूद हो, यदि वह फ़ील्ड किसी `OR` शर्त में है तो आपको फिर भी वह नियम बनाना चाहिए। उदाहरण के लिए, निम्नलिखित नियम को `Security 4688` नियम उत्पन्न **नहीं** करना चाहिए क्योंकि `OriginalFileName` फ़ील्ड आवश्यक है (selection के भीतर `AND` लॉजिक):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    हालाँकि, निम्नलिखित शर्त वाले नियम को एक `Security 4688` नियम बनाना **चाहिए** क्योंकि `OriginalFileName` वैकल्पिक है (selection के भीतर `OR` लॉजिक):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    यहाँ कठिनाई इस बात में है कि आपके पार्सर को न केवल selections के भीतर की लॉजिक, बल्कि `condition` फ़ील्ड के भीतर की लॉजिक को भी समझना होता है। उदाहरण के लिए, निम्नलिखित नियम को `Security 4688` नियम **नहीं** बनाना चाहिए क्योंकि यह `AND` लॉजिक का उपयोग करता है:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    हालाँकि, निम्नलिखित नियम को `Security 4688` नियम बनाना **चाहिए** क्योंकि यह `OR` लॉजिक का उपयोग करता है:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**अन्य नोट्स**

* `Security 4688` में `SubjectUserSid` फ़ील्ड SID दिखाता है; हालाँकि, रेंडर किए गए इवेंट लॉग `Message` में इसे `DOMAIN\User` में परिवर्तित कर दिया जाता है।
* सेटिंग्स के आधार पर `Security 4688` इवेंट में `CommandLine` में कमांड लाइन विकल्प जानकारी शामिल नहीं हो सकती।
* `TokenElevationType` को `Message` में जैसे-का-तैसा प्रदर्शित किया जाता है और रेंडर नहीं किया जाता।
* `MandatoryLabel` के भीतर `S-1-16-4096` आदि को रेंडर किए गए `Message` में `Mandatory Label\Low Mandatory Level` आदि में परिवर्तित कर दिया जाता है।

**बिल्ट-इन लॉग सेटिंग्स**

!!! warning "डिफ़ॉल्ट रूप से सक्षम नहीं"
    महत्वपूर्ण बिल्ट-इन `Security 4688` प्रोसेस निर्माण इवेंट लॉग डिफ़ॉल्ट रूप से सक्षम नहीं होते। अधिकांश Sigma नियमों का उपयोग करने के लिए आपको `4688` इवेंट और कमांड लाइन विकल्प लॉगिंग दोनों को सक्षम करना होगा।

*ग्रुप पॉलिसी से सक्षम करना:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*कमांड लाइन पर सक्षम करना:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Network connection

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* बिल्ट-इन लॉग
    * Channel: `Security`
    * Event ID: `5156`

**तुलना**

![Network connection तुलना](../assets/rules-doc/network_connection_comparison.png)

**परिवर्तन नोट्स**

1. `ProcessId` फ़ील्ड नाम बदलकर `ProcessID` हो जाता है।
2. `Image` फ़ील्ड नाम बदलकर `Application` हो जाता है, और `C:\` बदलकर `\device\harddiskvolume?\` हो जाता है। (ध्यान दें: चूँकि हमें हार्ड डिस्क वॉल्यूम संख्या ज्ञात नहीं होती, इसलिए हम इसे एकल-वर्ण वाइल्डकार्ड `?` से बदल देते हैं।)
3. `Protocol` फ़ील्ड का मान `tcp` बदलकर `6` और `udp` बदलकर `17` हो जाता है।
4. `Initiated` फ़ील्ड नाम बदलकर `Direction` हो जाता है, और `true` का मान बदलकर `%%14593` और `false` बदलकर `%%14592` हो जाता है।
5. `SourceIp` फ़ील्ड नाम बदलकर `SourceAddress` हो जाता है।
6. `DestinationIp` फ़ील्ड नाम बदलकर `DestAddress` हो जाता है।
7. `DestinationPort` फ़ील्ड नाम बदलकर `DestPort` हो जाता है।

**बिल्ट-इन लॉग सेटिंग्स**

!!! warning "डिफ़ॉल्ट रूप से सक्षम नहीं"
    बिल्ट-इन `Security 5156` नेटवर्क कनेक्शन लॉग डिफ़ॉल्ट रूप से सक्षम नहीं होते। ये बड़ी मात्रा में लॉग बनाते हैं, जो `Security` इवेंट लॉग में अन्य महत्वपूर्ण लॉग को अधिलेखित कर सकते हैं और यदि सिस्टम में नेटवर्क कनेक्शनों की संख्या अधिक हो तो संभावित रूप से सिस्टम को धीमा कर सकते हैं। सुनिश्चित करें कि `Security` लॉग के लिए अधिकतम फ़ाइल आकार अधिक हो, और परीक्षण करें कि सिस्टम पर कोई प्रतिकूल प्रभाव न पड़े।

*ग्रुप पॉलिसी से सक्षम करना:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*कमांड लाइन पर सक्षम करना:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...या यदि आप गैर-अंग्रेज़ी लोकेल का उपयोग कर रहे हैं तो निम्नलिखित:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "यह भी देखें"
    इन नियमों जिन साक्ष्यों पर निर्भर करते हैं, उन्हें कैप्चर करने के लिए आवश्यक बिल्ट-इन Windows इवेंट लॉग को सक्षम करने के बारे में अधिक जानकारी के लिए, देखें [Windows Logging & Sysmon](../resources/logging.md) और [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) प्रोजेक्ट।

## Sigma नियम लेखन सलाह

!!! tip
    यदि आप कोई ऐसा फ़ील्ड उपयोग करते हैं जो `sysmon` लॉग में मौजूद है लेकिन `builtin` लॉग में नहीं, तो सुनिश्चित करें कि आप उस फ़ील्ड को वैकल्पिक बनाएं ताकि नियम का उपयोग `builtin` लॉग के लिए भी संभव रहे।

उदाहरण के लिए:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

यह selection तब खोजता है जब प्रोसेस (`Image`) का नाम `addinutil.exe` हो। समस्या यह है कि एक हमलावर नियम को बायपास करने के लिए बस फ़ाइल का नाम बदल सकता है। `OriginalFileName` फ़ील्ड, जो केवल Sysmon लॉग में मौजूद होता है, वह फ़ाइलनाम है जो कंपाइल समय पर बाइनरी में एम्बेड हो जाता है। भले ही कोई हमलावर फ़ाइल का नाम बदल दे, एम्बेडेड नाम नहीं बदलेगा, इसलिए यह नियम Sysmon का उपयोग करते समय ऐसे हमलों का पता लगा सकता है जहाँ हमलावर ने फ़ाइल का नाम बदल दिया हो, और मानक बिल्ट-इन लॉग का उपयोग करते समय ऐसे हमलों का भी पता लगा सकता है जहाँ फ़ाइलनाम नहीं बदला गया हो।

## पूर्व-परिवर्तित Sigma नियम

इस पेज पर वर्णित तरीके से — `logsource` फ़ील्ड को डी-एब्स्ट्रैक्ट करके — क्यूरेट किए गए Sigma नियम [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) रिपॉज़िटरी में `sigma` फ़ोल्डर के अंतर्गत होस्ट किए गए हैं।

## टूल परिवेश

यदि आप स्थानीय रूप से Sigma नियमों को Hayabusa-संगत फ़ॉर्मेट में परिवर्तित करना चाहते हैं, तो आपको सबसे पहले [Poetry](https://python-poetry.org/) इंस्टॉल करना होगा। कृपया आधिकारिक Poetry [इंस्टॉलेशन दस्तावेज़ीकरण](https://python-poetry.org/docs/#installation) देखें।

## टूल उपयोग

`sigma-to-hayabusa-converter.py` Sigma नियमों के `logsource` फ़ील्ड को Hayabusa-संगत फ़ॉर्मेट में परिवर्तित करने का हमारा मुख्य टूल है। इसे चलाने के लिए निम्नलिखित कार्य करें:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

उपरोक्त कमांड निष्पादित करने के बाद, Hayabusa-संगत फ़ॉर्मेट में परिवर्तित किए गए नियम `./converted_sigma_rules` डायरेक्टरी में आउटपुट किए जाएंगे।
