# डिटेक्शन फ़ील्ड

## सिलेक्शन की मूल बातें

सबसे पहले, सिलेक्शन नियम कैसे बनाया जाए इसकी मूल बातें समझाई जाएंगी।

### AND और OR लॉजिक कैसे लिखें

AND लॉजिक लिखने के लिए, हम नेस्टेड डिक्शनरी का उपयोग करते हैं।
नीचे दिया गया डिटेक्शन नियम परिभाषित करता है कि नियम के मैच होने के लिए **दोनों शर्तें** सत्य होनी चाहिए।

- EventID ठीक `7040` होना चाहिए।
- **AND**
- Channel ठीक `System` होना चाहिए।

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

OR लॉजिक लिखने के लिए, हम लिस्ट का उपयोग करते हैं (ऐसी डिक्शनरी जो `-` से शुरू होती हैं)।
नीचे दिए गए डिटेक्शन नियम में, शर्तों में से **कोई एक** भी पूरी होने पर नियम ट्रिगर हो जाएगा।

- EventID ठीक `7040` होना चाहिए।
- **OR**
- Channel ठीक `System` होना चाहिए।

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

हम नीचे दिखाए अनुसार `AND` और `OR` लॉजिक को भी जोड़ सकते हैं।
इस मामले में, नियम तब मैच होता है जब निम्नलिखित दोनों शर्तें सत्य हों।

- EventID ठीक या तो `7040` **OR** `7041` हो।
- **AND**
- Channel ठीक `System` हो।

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

निम्नलिखित एक Windows इवेंट लॉग का अंश है, जो मूल XML में स्वरूपित है।
ऊपर दिए गए नियम फ़ाइल उदाहरण में `Event.System.Channel` फ़ील्ड मूल XML टैग को संदर्भित करता है: `<Event><System><Channel>System<Channel><System></Event>`
नेस्टेड XML टैग को टैग नामों से बदल दिया जाता है जो डॉट (`.`) से अलग होते हैं।
hayabusa नियमों में, डॉट के साथ जुड़ी इन फ़ील्ड स्ट्रिंग्स को `eventkeys` कहा जाता है।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Eventkey उपनाम (Aliases)

कई `.` विभाजकों वाली लंबी eventkeys आम हैं, इसलिए hayabusa उन्हें संभालने में आसान बनाने के लिए उपनामों का उपयोग करेगा। उपनाम `rules/config/eventkey_alias.txt` फ़ाइल में परिभाषित होते हैं। यह फ़ाइल एक CSV फ़ाइल है जो `alias` और `event_key` मैपिंग से बनी है। आप ऊपर दिए गए नियम को उपनामों के साथ नीचे दिखाए अनुसार फिर से लिख सकते हैं, जिससे नियम पढ़ने में आसान हो जाता है।

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### सावधानी: अपरिभाषित Eventkey उपनाम

सभी eventkey उपनाम `rules/config/eventkey_alias.txt` में परिभाषित नहीं होते। यदि आपको `details` (`Alert details`) संदेश में सही डेटा नहीं मिल रहा है, और इसके बजाय `n/a` (उपलब्ध नहीं) मिल रहा है, या यदि आपके डिटेक्शन लॉजिक में सिलेक्शन ठीक से काम नहीं कर रहा है, तो आपको `rules/config/eventkey_alias.txt` को एक नए उपनाम के साथ अपडेट करने की आवश्यकता हो सकती है।

### शर्तों में XML विशेषताओं (attributes) का उपयोग कैसे करें

XML तत्वों में एलिमेंट में स्पेस जोड़कर विशेषताएँ सेट की जा सकती हैं। उदाहरण के लिए, नीचे `Provider Name` में `Name`, `Provider` एलिमेंट की एक XML विशेषता है।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

किसी eventkey में XML विशेषताओं को निर्दिष्ट करने के लिए, `{eventkey}_attributes.{attribute_name}` प्रारूप का उपयोग करें। उदाहरण के लिए, किसी नियम फ़ाइल में `Provider` एलिमेंट की `Name` विशेषता को निर्दिष्ट करने के लिए, यह इस तरह दिखेगा:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep खोज

Hayabusa किसी भी eventkey को निर्दिष्ट न करके Windows इवेंट लॉग फ़ाइलों में grep खोज कर सकता है।

grep खोज करने के लिए, नीचे दिखाए अनुसार डिटेक्शन निर्दिष्ट करें। इस मामले में, यदि Windows इवेंट लॉग में `mimikatz` या `metasploit` स्ट्रिंग्स शामिल हैं, तो यह मैच होगा। वाइल्डकार्ड निर्दिष्ट करना भी संभव है।

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> नोट: Hayabusa डेटा को प्रोसेस करने से पहले आंतरिक रूप से Windows इवेंट लॉग डेटा को JSON प्रारूप में बदलता है, इसलिए XML टैग पर मैच करना संभव नहीं है।

### EventData

Windows इवेंट लॉग दो भागों में विभाजित होते हैं: `System` भाग जहाँ मूल डेटा (Event ID, Timestamp, Record ID, Log name (Channel)) लिखा जाता है, और `EventData` या `UserData` भाग जहाँ Event ID के आधार पर मनमाना डेटा लिखा जाता है।
एक समस्या जो अक्सर उत्पन्न होती है वह यह है कि `EventData` में नेस्टेड फ़ील्ड्स के नाम सभी `Data` कहलाते हैं, इसलिए अब तक वर्णित eventkeys `SubjectUserSid` और `SubjectUserName` के बीच अंतर नहीं कर सकतीं।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

इस समस्या से निपटने के लिए, आप `Data Name` में निर्दिष्ट मान को निर्दिष्ट कर सकते हैं। उदाहरण के लिए, यदि आप EventData में `SubjectUserName` और `SubjectDomainName` को किसी नियम की शर्त के रूप में उपयोग करना चाहते हैं, तो आप इसे निम्नानुसार वर्णित कर सकते हैं:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventData में असामान्य पैटर्न

`EventData` में नेस्टेड कुछ टैग में `Name` विशेषता नहीं होती।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

ऊपर दिए गए जैसे इवेंट लॉग का पता लगाने के लिए, आप `Data` नामक एक eventkey निर्दिष्ट कर सकते हैं।
इस मामले में, जब तक नेस्टेड `Data` टैग में से कोई एक `None` के बराबर है, तब तक शर्त मैच होगी।

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### एक ही नाम वाले कई फ़ील्ड नामों से फ़ील्ड डेटा आउटपुट करना

कुछ इवेंट अपने डेटा को पिछले उदाहरण की तरह सभी `Data` नामक फ़ील्ड नामों में सहेजेंगे।
यदि आप `details:` में `%Data%` निर्दिष्ट करते हैं, तो सभी डेटा एक array में आउटपुट किए जाएंगे।

उदाहरण के लिए:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

यदि आप केवल पहला `Data` फ़ील्ड डेटा प्रिंट करना चाहते हैं, तो आप अपनी `details:` अलर्ट स्ट्रिंग में `%Data[1]%` निर्दिष्ट कर सकते हैं और केवल `rundll32.exe` आउटपुट होगा।

## फ़ील्ड मॉडिफ़ायर

स्ट्रिंग्स मैच करने के लिए नीचे दिखाए अनुसार eventkeys के साथ एक पाइप कैरेक्टर का उपयोग किया जा सकता है।
अब तक हमने जिन शर्तों का वर्णन किया है वे सभी एक्ज़ैक्ट मैच का उपयोग करती हैं, लेकिन फ़ील्ड मॉडिफ़ायर का उपयोग करके, आप अधिक लचीले डिटेक्शन नियम वर्णित कर सकते हैं।
निम्नलिखित उदाहरण में, यदि `Data` के किसी मान में `EngineVersion=2` स्ट्रिंग शामिल है, तो यह शर्त से मैच होगा।

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

स्ट्रिंग मैच केस-इनसेंसिटिव होते हैं। हालाँकि, जब भी `|re` या `|equalsfield` का उपयोग किया जाता है तो वे केस-सेंसिटिव हो जाते हैं।

### समर्थित Sigma फ़ील्ड मॉडिफ़ायर

Hayabusa वर्तमान में एकमात्र ओपन-सोर्स टूल है जो Sigma विशिष्टता को पूरी तरह से समर्थन करता है।

आप समर्थित सभी फ़ील्ड मॉडिफ़ायर की वर्तमान स्थिति के साथ-साथ इन मॉडिफ़ायर का Sigma और Hayabusa नियमों में कितनी बार उपयोग किया गया है, यह https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md पर देख सकते हैं।
यह दस्तावेज़ Sigma या Hayabusa नियमों में अपडेट होने पर हर बार गतिशील रूप से अपडेट होता है।

- `'|all':`: यह फ़ील्ड मॉडिफ़ायर ऊपर दिए गए मॉडिफ़ायर से अलग है क्योंकि यह किसी निश्चित फ़ील्ड पर नहीं बल्कि सभी फ़ील्ड्स पर लागू होता है।

    इस उदाहरण में, दोनों स्ट्रिंग्स `Keyword-1` और `Keyword-2` का मौजूद होना आवश्यक है लेकिन वे किसी भी फ़ील्ड में कहीं भी मौजूद हो सकती हैं:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: एन्कोडेड स्ट्रिंग में डेटा की स्थिति के आधार पर डेटा को तीन अलग-अलग तरीकों से base64 में एन्कोड किया जाएगा। यह मॉडिफ़ायर किसी स्ट्रिंग को तीनों विविधताओं में एन्कोड करेगा और जाँचेगा कि क्या स्ट्रिंग base64 स्ट्रिंग में कहीं एन्कोडेड है।
- `|cased`: खोज को केस-सेंसिटिव बनाता है।
- `|cidr`: जाँचता है कि क्या कोई फ़ील्ड मान IPv4 या IPv6 CIDR नोटेशन पर मैच करता है। (उदा: `192.0.2.0/24`)
- `|contains`: जाँचता है कि क्या किसी फ़ील्ड मान में कोई निश्चित स्ट्रिंग शामिल है।
- `|contains|all`: जाँचता है कि क्या डेटा में कई शब्द शामिल हैं।
- `|contains|all|windash`: `|contains|windash` के समान लेकिन सभी कीवर्ड्स का मौजूद होना आवश्यक है।
- `|contains|cased`: जाँचता है कि क्या किसी फ़ील्ड मान में कोई निश्चित केस-सेंसिटिव स्ट्रिंग शामिल है।
- `|contains|expand`: जाँचता है कि क्या किसी फ़ील्ड मान में `/config/expand/` के अंदर `expand` कॉन्फ़िग फ़ाइल में मौजूद कोई स्ट्रिंग शामिल है।
- `|contains|windash`: स्ट्रिंग को जैसा है वैसा जाँचेगा, साथ ही पहले `-` कैरेक्टर को `/`, `–` (en dash), `—` (em dash), और `―` (horizontal bar) कैरेक्टर क्रमचय में परिवर्तित करेगा।
- `|endswith`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित स्ट्रिंग से समाप्त होता है।
- `|endswith|cased`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित केस-सेंसिटिव स्ट्रिंग से समाप्त होता है।
- `|endswith|windash`: स्ट्रिंग के अंत की जाँच करता है और डैश के लिए विविधताएँ निष्पादित करता है।
- `|exists`: जाँचता है कि क्या कोई फ़ील्ड मौजूद है।
- `|expand`: जाँचता है कि क्या कोई फ़ील्ड मान `/config/expand/` के अंदर `expand` कॉन्फ़िग फ़ाइल में मौजूद किसी स्ट्रिंग के बराबर है।
- `|fieldref`: जाँचता है कि क्या दो फ़ील्ड्स में मान समान हैं। यदि आप जाँचना चाहते हैं कि क्या दो फ़ील्ड्स अलग हैं तो आप `condition` में `not` का उपयोग कर सकते हैं।
- `|fieldref|contains`: जाँचता है कि क्या एक फ़ील्ड का मान दूसरे फ़ील्ड में शामिल है।
- `|fieldref|endswith`: जाँचें कि क्या बाईं ओर का फ़ील्ड दाईं ओर के फ़ील्ड की स्ट्रिंग से समाप्त होता है। यह जाँचने के लिए कि क्या वे अलग हैं, आप `condition` में `not` का उपयोग कर सकते हैं।
- `|fieldref|startswith`: जाँचें कि क्या बाईं ओर का फ़ील्ड दाईं ओर के फ़ील्ड की स्ट्रिंग से शुरू होता है। यह जाँचने के लिए कि क्या वे अलग हैं, आप `condition` में `not` का उपयोग कर सकते हैं।
- `|gt`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित संख्या से बड़ा है।
- `|gte`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित संख्या से बड़ा या उसके बराबर है।
- `|lt`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित संख्या से छोटा है।
- `|lte`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित संख्या से छोटा या उसके बराबर है।
- `|re`: केस-सेंसिटिव रेगुलर एक्सप्रेशन का उपयोग करें। (हम regex crate का उपयोग कर रहे हैं इसलिए समर्थित रेगुलर एक्सप्रेशन कैसे लिखें यह जानने के लिए कृपया <https://docs.rs/regex/latest/regex/#syntax> पर दस्तावेज़ देखें।)
    > सावधानी: [Sigma नियमों में रेगुलर एक्सप्रेशन सिंटैक्स](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) PCRE का उपयोग करता है जिसमें कुछ मेटाकैरेक्टर जैसे कैरेक्टर क्लासेस, lookbehind, atomic grouping, आदि असमर्थित हैं। Rust regex crate को Sigma नियमों में सभी रेगुलर एक्सप्रेशन का उपयोग करने में सक्षम होना चाहिए लेकिन असंगति की संभावना है।
- `|re|i`: (Insensitive) केस-इनसेंसिटिव रेगुलर एक्सप्रेशन का उपयोग करें।
- `|re|m`: (Multi-line) कई लाइनों में मैच करें। `^` / `$` लाइन के आरंभ/अंत से मैच करते हैं।
- `|re|s`: (Single-line) डॉट (`.`) सभी कैरेक्टर्स से मैच करता है, जिसमें न्यूलाइन कैरेक्टर भी शामिल है।
- `|startswith`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित स्ट्रिंग से शुरू होता है।
- `|startswith|cased`: जाँचता है कि क्या कोई फ़ील्ड मान किसी निश्चित केस-सेंसिटिव स्ट्रिंग से शुरू होता है।
- `|utf16|base64offset|contains`: जाँचता है कि क्या कोई निश्चित UTF-16 स्ट्रिंग base64 स्ट्रिंग के अंदर एन्कोडेड है।
- `|utf16be|base64offset|contains`: जाँचता है कि क्या कोई निश्चित UTF-16 big-endian स्ट्रिंग base64 स्ट्रिंग के अंदर एन्कोडेड है।
- `|utf16le|base64offset|contains`: जाँचता है कि क्या कोई निश्चित UTF-16 little-endian स्ट्रिंग base64 स्ट्रिंग के अंदर एन्कोडेड है।
- `|wide|base64offset|contains`: `utf16le|base64offset|contains` का उपनाम, UTF-16 little-endian स्ट्रिंग्स की जाँच करता है।

### अप्रचलित (Deprecated) फ़ील्ड मॉडिफ़ायर

निम्नलिखित मॉडिफ़ायर अब अप्रचलित हैं और ऐसे मॉडिफ़ायर द्वारा प्रतिस्थापित किए गए हैं जो sigma विशिष्टताओं का अधिक पालन करते हैं।

- `|equalsfield`: अब `|fieldref` द्वारा प्रतिस्थापित किया गया है।
- `|endswithfield`: अब `|fieldref|endswith` द्वारा प्रतिस्थापित किया गया है।

### Expand फ़ील्ड मॉडिफ़ायर

`expand` फ़ील्ड मॉडिफ़ायर इस मायने में अनूठे हैं कि वे एकमात्र ऐसे फ़ील्ड मॉडिफ़ायर हैं जिन्हें उपयोग के लिए पहले से कॉन्फ़िगरेशन की आवश्यकता होती है।
उदाहरण के लिए, वे `%DC-MACHINE-NAME%` जैसे प्लेसहोल्डर्स का उपयोग करते हैं और `/config/expand/DC-MACHINE-NAME.txt` नामक एक कॉन्फ़िग फ़ाइल की आवश्यकता होती है जिसमें सभी संभावित DC मशीन नाम शामिल हों।

इसे कैसे कॉन्फ़िगर करें यह [यहाँ](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command) अधिक विस्तार से समझाया गया है।

## वाइल्डकार्ड

eventkeys में वाइल्डकार्ड का उपयोग किया जा सकता है। नीचे दिए गए उदाहरण में, यदि `ProcessCommandLine` "malware" स्ट्रिंग से शुरू होता है, तो नियम मैच होगा।
विशिष्टता मूल रूप से sigma नियम वाइल्डकार्ड के समान है इसलिए यह केस-इनसेंसिटिव होगी।

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

निम्नलिखित दो वाइल्डकार्ड का उपयोग किया जा सकता है।

- `*`: शून्य या अधिक कैरेक्टर्स की किसी भी स्ट्रिंग से मैच करता है। (आंतरिक रूप से इसे रेगुलर एक्सप्रेशन `.*` में परिवर्तित किया जाता है)
- `?`: किसी एकल कैरेक्टर से मैच करता है। (आंतरिक रूप से रेगुलर एक्सप्रेशन `.` में परिवर्तित किया जाता है)

वाइल्डकार्ड को एस्केप करने के बारे में:

- वाइल्डकार्ड (`*` और `?`) को बैकस्लैश का उपयोग करके एस्केप किया जा सकता है: `\*`, `\?`।
- यदि आप किसी वाइल्डकार्ड से ठीक पहले बैकस्लैश का उपयोग करना चाहते हैं तो `\\*` या `\\?` लिखें।
- यदि आप अकेले बैकस्लैश का उपयोग कर रहे हैं तो एस्केपिंग की आवश्यकता नहीं है।

## null कीवर्ड

`null` कीवर्ड का उपयोग यह जाँचने के लिए किया जा सकता है कि क्या कोई फ़ील्ड मौजूद नहीं है।

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

नोट: यह `ProcessCommandLine: ''` से अलग है जो जाँचता है कि क्या किसी फ़ील्ड का मान खाली है।

## condition

ऊपर समझाए गए नोटेशन से, आप `AND` और `OR` लॉजिक व्यक्त कर सकते हैं लेकिन यदि आप जटिल लॉजिक परिभाषित करने का प्रयास कर रहे हैं तो यह भ्रमित करने वाला होगा।
जब आप अधिक जटिल नियम बनाना चाहते हैं, तो आपको नीचे दिखाए अनुसार `condition` कीवर्ड का उपयोग करना चाहिए।

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

`condition` के लिए निम्नलिखित एक्सप्रेशन का उपयोग किया जा सकता है।

- `{expression1} and {expression2}`: {expression1} AND {expression2} दोनों आवश्यक हैं
- `{expression1} or {expression2}`: या तो {expression1} OR {expression2} आवश्यक है
- `not {expression}`: {expression} के लॉजिक को उलट दें
- `( {expression} )`: {expression} की प्राथमिकता निर्धारित करें। यह गणित के समान प्राथमिकता लॉजिक का पालन करता है।

ऊपर दिए गए उदाहरण में, `SELECTION_1`, `SELECTION_2`, आदि जैसे सिलेक्शन नामों का उपयोग किया गया है लेकिन उन्हें कुछ भी नाम दिया जा सकता है जब तक कि उनमें केवल निम्नलिखित कैरेक्टर्स हों: `a-z A-Z 0-9 _`
> हालाँकि, जब भी संभव हो चीज़ों को पढ़ने में आसान बनाने के लिए कृपया `selection_1`, `selection_2`, `filter_1`, `filter_2`, आदि की मानक परंपरा का उपयोग करें।

## not लॉजिक

कई नियमों के परिणामस्वरूप फ़ॉल्स पॉज़िटिव होते हैं इसलिए खोजने के लिए सिग्नेचर के लिए एक सिलेक्शन रखना और साथ ही फ़ॉल्स पॉज़िटिव पर अलर्ट न करने के लिए एक फ़िल्टर सिलेक्शन रखना बहुत आम है।
उदाहरण के लिए:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma correlations

हमने [यहाँ](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md) परिभाषित अनुसार Sigma संस्करण 2.0.0 की सभी correlations को कार्यान्वित किया है।

समर्थित correlations:

- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

12 सितंबर, 2025 को Sigma संस्करण 2.1.0 में जारी की गई नई "metrics" correlation नियम (`value_sum`, `value_avg`, `value_percentile`) वर्तमान में समर्थित नहीं हैं।
