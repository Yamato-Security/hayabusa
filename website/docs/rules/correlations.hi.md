## इवेंट गणना नियम

ये ऐसे नियम हैं जो कुछ निश्चित इवेंट्स को गिनते हैं और चेतावनी देते हैं यदि इनमें से बहुत अधिक या पर्याप्त संख्या में इवेंट्स एक समय-सीमा के भीतर घटित होते हैं।
एक निश्चित समय अवधि के भीतर कई इवेंट्स का पता लगाने के सामान्य उदाहरण पासवर्ड अनुमान लगाने वाले हमलों, पासवर्ड स्प्रे हमलों और सेवा से इनकार (denial of service) हमलों का पता लगाने के लिए हैं।
आप इन नियमों का उपयोग लॉग स्रोत विश्वसनीयता समस्याओं का पता लगाने के लिए भी कर सकते हैं, जैसे कि जब कुछ इवेंट्स एक निश्चित सीमा से नीचे गिर जाते हैं।

### इवेंट गणना नियम उदाहरण:

निम्नलिखित उदाहरण पासवर्ड अनुमान लगाने वाले हमलों का पता लगाने के लिए दो नियमों का उपयोग करता है।
जब संदर्भित नियम 5 मिनट के भीतर 5 या अधिक बार मेल खाता है और उन इवेंट्स के लिए `IpAddress` फ़ील्ड समान है, तब एक चेतावनी होगी।

> ध्यान दें कि अवधारणा को समझने के लिए हमने केवल आवश्यक फ़ील्ड्स को ही शामिल किया है।
> इस उदाहरण पर आधारित पूर्ण नियम आपके संदर्भ के लिए [यहाँ](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) स्थित है।

### इवेंट गणना सहसंबंध नियम:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### असफल लॉगऑन - गलत पासवर्ड नियम:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### अप्रचलित (deprecated) `count` नियम उदाहरण:

उपरोक्त सहसंबंध और संदर्भित नियम वही परिणाम प्रदान करते हैं जो निम्नलिखित नियम देता है जो पुराने `count` संशोधक (modifier) का उपयोग करता है:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### इवेंट गणना नियम आउटपुट:

उपरोक्त नियम निम्नलिखित आउटपुट बनाएंगे:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## मान गणना (Value Count) नियम

ये नियम किसी दिए गए फ़ील्ड के **भिन्न** मानों के साथ एक समय-सीमा के भीतर समान इवेंट्स को गिनते हैं।

उदाहरण:
- नेटवर्क स्कैन जहाँ एक एकल स्रोत IP पता कई भिन्न गंतव्य IP पतों और/या पोर्ट्स से जुड़ने का प्रयास करता है।
- पासवर्ड स्प्रेइंग हमले जहाँ एक एकल स्रोत कई भिन्न उपयोगकर्ताओं के साथ प्रमाणीकरण करने में विफल रहता है।
- BloodHound जैसे उपकरणों का पता लगाना जो एक छोटी समय-सीमा के भीतर कई उच्च-विशेषाधिकार वाले AD समूहों की गणना करते हैं।

### मान गणना नियम उदाहरण:

निम्नलिखित नियम पता लगाता है कि कब एक हमलावर उपयोगकर्ता नामों का अनुमान लगाने की कोशिश कर रहा है।
अर्थात्, जब **समान** स्रोत IP पता (`IpAddress`) 5 मिनट के भीतर 3 से अधिक **भिन्न** उपयोगकर्ता नामों (`TargetUserName`) के साथ लॉगऑन करने में विफल रहता है।

> ध्यान दें कि अवधारणा को समझने के लिए हमने केवल आवश्यक फ़ील्ड्स को ही शामिल किया है।
> इस उदाहरण पर आधारित पूर्ण नियम आपके संदर्भ के लिए [यहाँ](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) स्थित है।

### मान गणना सहसंबंध नियम:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### मान गणना लॉगऑन विफलता (अस्तित्वहीन उपयोगकर्ता) नियम:

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### अप्रचलित (deprecated) `count` संशोधक नियम:

उपरोक्त सहसंबंध और संदर्भित नियम वही परिणाम प्रदान करते हैं जो निम्नलिखित नियम देता है जो पुराने `count` संशोधक (modifier) का उपयोग करता है:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### मान गणना नियम आउटपुट:

उपरोक्त नियम निम्नलिखित आउटपुट बनाएंगे:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## टेम्पोरल प्रॉक्सिमिटी (Temporal Proximity) नियम

rule फ़ील्ड द्वारा संदर्भित नियमों द्वारा परिभाषित सभी इवेंट्स को timespan द्वारा परिभाषित समय-सीमा में घटित होना चाहिए।
`group-by` में परिभाषित फ़ील्ड्स के मानों का मान समान होना चाहिए (उदा: समान होस्ट, उपयोगकर्ता, आदि...)।

### टेम्पोरल प्रॉक्सिमिटी नियम उदाहरण:

उदाहरण: तीन Sigma नियमों में परिभाषित टोही (reconnaissance) कमांड्स को एक सिस्टम पर समान उपयोगकर्ता द्वारा 5 मिनट के भीतर मनमाने क्रम में चलाया जाता है।

### टेम्पोरल प्रॉक्सिमिटी सहसंबंध नियम:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## क्रमबद्ध टेम्पोरल प्रॉक्सिमिटी (Ordered Temporal Proximity) नियम

`temporal_ordered` सहसंबंध प्रकार `temporal` की तरह व्यवहार करता है और इसके अतिरिक्त यह आवश्यक करता है कि इवेंट्स `rules` विशेषता में दिए गए क्रम में दिखाई दें।

### क्रमबद्ध टेम्पोरल प्रॉक्सिमिटी नियम उदाहरण:

उदाहरण: ऊपर परिभाषित कई असफल लॉगिन के बाद 1 घंटे के भीतर समान उपयोगकर्ता खाते द्वारा एक सफल लॉगिन होता है:

### क्रमबद्ध टेम्पोरल प्रॉक्सिमिटी सहसंबंध नियम:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## सहसंबंध नियमों पर टिप्पणियाँ

1. आपको अपने सभी सहसंबंध और संदर्भित नियमों को एक ही फ़ाइल में शामिल करना चाहिए और उन्हें `---` के YAML विभाजक के साथ अलग करना चाहिए।

2. डिफ़ॉल्ट रूप से, संदर्भित सहसंबंध नियम आउटपुट नहीं किए जाएंगे। यदि आप संदर्भित नियमों का आउटपुट देखना चाहते हैं, तो आपको `correlation` के अंतर्गत `generate: true` जोड़ना होगा। सहसंबंध नियम बनाते समय इसे चालू करना और जाँचना बहुत उपयोगी होता है।

    उदाहरण:
    ```
    correlation:
        generate: true
    ```
3. चीजों को समझना आसान बनाने के लिए आप नियमों को संदर्भित करते समय रूल ID के बजाय उपनाम (alias) नामों का उपयोग कर सकते हैं।

4. आप कई नियमों को संदर्भित कर सकते हैं।

5. आप `group-by` में कई फ़ील्ड्स का उपयोग कर सकते हैं। यदि आप ऐसा करते हैं, तो उन फ़ील्ड्स के सभी मानों का समान होना आवश्यक है अन्यथा आपको चेतावनी नहीं मिलेगी। अधिकांश समय, आप मिथ्या सकारात्मक (false positives) को कम करने के लिए `group-by` के साथ कुछ निश्चित फ़ील्ड्स पर फ़िल्टर करने वाले नियम लिखेंगे, हालाँकि, अधिक सामान्य नियम बनाने के लिए `group-by` को छोड़ना संभव है।

6. सहसंबंध नियम का टाइमस्टैम्प हमले की बिल्कुल शुरुआत होगा इसलिए आपको यह पुष्टि करने के लिए कि यह मिथ्या सकारात्मक है या नहीं, उसके बाद के इवेंट्स की जाँच करनी चाहिए।
