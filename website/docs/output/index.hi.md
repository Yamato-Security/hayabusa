# टाइमलाइन आउटपुट

## आउटपुट प्रोफाइल

Hayabusa में `config/profiles.yaml` में उपयोग करने के लिए 5 पूर्व-परिभाषित आउटपुट प्रोफाइल हैं:

1. `minimal`
2. `standard` (default)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

आप इस फ़ाइल को संपादित करके आसानी से अपनी प्रोफाइल को अनुकूलित या जोड़ सकते हैं।
आप `set-default-profile --profile <profile>` के साथ डिफ़ॉल्ट प्रोफाइल को भी आसानी से बदल सकते हैं।
उपलब्ध प्रोफाइल और उनकी फ़ील्ड जानकारी दिखाने के लिए `list-profiles` कमांड का उपयोग करें।

### 1. `minimal` प्रोफाइल आउटपुट

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard` प्रोफाइल आउटपुट

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose` प्रोफाइल आउटपुट

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info` प्रोफाइल आउटपुट

न्यूनतम `details` जानकारी को आउटपुट करने के बजाय, `EventData` और `UserData` अनुभागों की सभी फ़ील्ड जानकारी उनके मूल फ़ील्ड नामों के साथ आउटपुट की जाएगी।

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose` प्रोफाइल आउटपुट

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose` प्रोफाइल आउटपुट

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal` प्रोफाइल आउटपुट

[Timesketch](https://timesketch.org/) में इम्पोर्ट करने के साथ संगत प्रारूप में आउटपुट करें।

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose` प्रोफाइल आउटपुट

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### प्रोफाइल तुलना

निम्नलिखित बेंचमार्क 2018 Lenovo P51 (Xeon 4 Core CPU / 64GB RAM) पर 3GB evtx डेटा और 3891 नियम सक्षम के साथ किए गए थे। (2023/06/01)

| प्रोफाइल | प्रोसेसिंग समय | आउटपुट फ़ाइल आकार | फ़ाइल आकार वृद्धि |
| :---: | :---: | :---: | :---: |
| minimal | 8 मिनट 50 सेकंड | 770 MB | -30% |
| standard (default) | 9 मिनट 00 सेकंड | 1.1 GB | कोई नहीं |
| verbose | 9 मिनट 10 सेकंड | 1.3 GB | +20% |
| all-field-info | 9 मिनट 3 सेकंड | 1.2 GB | +10% |
| all-field-info-verbose | 9 मिनट 10 सेकंड | 1.3 GB | +20% |
| super-verbose | 9 मिनट 12 सेकंड | 1.5 GB | +35% |

### प्रोफाइल फ़ील्ड उपनाम

निम्नलिखित जानकारी अंतर्निहित आउटपुट प्रोफाइल के साथ आउटपुट की जा सकती है:

| उपनाम नाम | Hayabusa आउटपुट जानकारी|
| :--- | :--- |
|%AllFieldInfo% | सभी फ़ील्ड जानकारी। |
|%Channel% | लॉग का नाम। `<Event><System><Channel>` फ़ील्ड। |
|%Computer% | `<Event><System><Computer>` फ़ील्ड। |
|%Details% | YML डिटेक्शन नियम में `details` फ़ील्ड, हालांकि, केवल hayabusa नियमों में यह फ़ील्ड होता है। यह फ़ील्ड अलर्ट या इवेंट के बारे में अतिरिक्त जानकारी देता है और इवेंट लॉग में फ़ील्ड से उपयोगी डेटा निकाल सकता है। उदाहरण के लिए, उपयोगकर्ता नाम, कमांड लाइन जानकारी, प्रोसेस जानकारी, आदि... जब कोई प्लेसहोल्डर ऐसे फ़ील्ड की ओर इशारा करता है जो मौजूद नहीं है या कोई गलत उपनाम मैपिंग है, तो इसे `n/a` (उपलब्ध नहीं) के रूप में आउटपुट किया जाएगा। यदि `details` फ़ील्ड निर्दिष्ट नहीं है (अर्थात sigma नियम), तो `./rules/config/default_details.txt` में परिभाषित फ़ील्ड निकालने के लिए डिफ़ॉल्ट `details` संदेश आउटपुट किए जाएंगे। आप `default_details.txt` में `Provider Name`, `EventID` और जिस `details` संदेश को आप आउटपुट करना चाहते हैं उसे जोड़कर अधिक डिफ़ॉल्ट `details` संदेश जोड़ सकते हैं। जब किसी नियम में और न ही `default_details.txt` में कोई `details` फ़ील्ड परिभाषित होता है, तो सभी फ़ील्ड `details` कॉलम में आउटपुट किए जाएंगे। |
|%ExtraFieldInfo% | वह फ़ील्ड जानकारी प्रिंट करें जो %Details% में आउटपुट नहीं की गई थी। |
|%EventID% | `<Event><System><EventID>` फ़ील्ड। |
|%EvtxFile% | वह evtx फ़ाइल नाम जिसके कारण अलर्ट या इवेंट हुआ। |
|%Level% | YML डिटेक्शन नियम में `level` फ़ील्ड। (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [tactics](https://attack.mitre.org/tactics/enterprise/) (उदा: Initial Access, Lateral Movement, आदि...)। |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID और Software ID। |
|%OtherTags% | YML डिटेक्शन नियम में `tags` फ़ील्ड में कोई भी कीवर्ड जो `MitreTactics` या `MitreTags` में शामिल नहीं है। |
|%Provider% | `<Event><System><Provider>` फ़ील्ड में `Name` विशेषता। |
|%RecordID% | `<Event><System><EventRecordID>` फ़ील्ड से Event Record ID। |
|%RuleAuthor% | YML डिटेक्शन नियम में `author` फ़ील्ड। |
|%RuleCreationDate% | YML डिटेक्शन नियम में `date` फ़ील्ड। |
|%RuleFile% | वह डिटेक्शन नियम का फ़ाइल नाम जिसने अलर्ट या इवेंट उत्पन्न किया। |
|%RuleID% | YML डिटेक्शन नियम में `id` फ़ील्ड। |
|%RuleModifiedDate% | YML डिटेक्शन नियम में `modified` फ़ील्ड। |
|%RuleTitle% | YML डिटेक्शन नियम में `title` फ़ील्ड। |
|%Status% | YML डिटेक्शन नियम में `status` फ़ील्ड। |
|%Timestamp% | डिफ़ॉल्ट `YYYY-MM-DD HH:mm:ss.sss +hh:mm` प्रारूप है। इवेंट लॉग में `<Event><System><TimeCreated SystemTime>` फ़ील्ड। डिफ़ॉल्ट टाइमज़ोन स्थानीय टाइमज़ोन होगा लेकिन आप `--UTC` विकल्प के साथ टाइमज़ोन को UTC में बदल सकते हैं। |

#### अतिरिक्त प्रोफाइल फ़ील्ड उपनाम

यदि आपको आवश्यकता हो तो आप अपनी आउटपुट प्रोफाइल में इस अतिरिक्त उपनाम को भी जोड़ सकते हैं:

| उपनाम नाम | Hayabusa आउटपुट जानकारी|
| :--- | :--- |
|%RenderedMessage% | WEC अग्रेषित लॉग में `<Event><RenderingInfo><Message>` फ़ील्ड। |

नोट: यह किसी भी अंतर्निहित प्रोफाइल में शामिल **नहीं** है इसलिए आपको `config/default_profile.yaml` फ़ाइल को मैन्युअल रूप से संपादित करना होगा और निम्नलिखित पंक्ति जोड़नी होगी:

```
Message: "%RenderedMessage%"
```

अन्य फ़ील्ड आउटपुट करने के लिए आप [event key aliases](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) भी परिभाषित कर सकते हैं।
