# अप्रचलित (Deprecated) विशेषताएँ

अप्रचलित विशेष कीवर्ड और `count` एकत्रीकरण (aggregation) अभी भी Hayabusa में समर्थित हैं लेकिन भविष्य में नियमों के अंदर इनका उपयोग नहीं किया जाएगा।

## अप्रचलित विशेष कीवर्ड

वर्तमान में, निम्नलिखित विशेष कीवर्ड निर्दिष्ट किए जा सकते हैं:

- `value`: स्ट्रिंग द्वारा मिलान करता है (वाइल्डकार्ड और पाइप भी निर्दिष्ट किए जा सकते हैं)।
- `min_length`: जब वर्णों की संख्या निर्दिष्ट संख्या के बराबर या उससे अधिक होती है तो मिलान करता है।
- `regexes`: मिलान करता है यदि उस फ़ाइल में मौजूद नियमित अभिव्यक्तियों (regular expressions) में से कोई एक मेल खाती है जिसे आप इस फ़ील्ड में निर्दिष्ट करते हैं।
- `allowlist`: यदि उस फ़ाइल में मौजूद नियमित अभिव्यक्तियों की सूची में कोई मिलान मिलता है, जिसे आप इस फ़ील्ड में निर्दिष्ट करते हैं, तो नियम को छोड़ दिया जाएगा।

नीचे दिए गए उदाहरण में, यदि निम्नलिखित सत्य हों तो नियम मिलान करेगा:

- `ServiceName` को `malicious-service` कहा जाता है या उसमें `./rules/config/regex/detectlist_suspicous_services.txt` की कोई नियमित अभिव्यक्ति शामिल है।
- `ImagePath` में कम से कम 1000 वर्ण हैं।
- `ImagePath` का `allowlist` में कोई मिलान नहीं है।

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### regexes और allowlist कीवर्ड के नमूना फ़ाइलें

Hayabusa में `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml` फ़ाइल के लिए उपयोग की जाने वाली दो अंतर्निहित (built-in) नियमित अभिव्यक्ति फ़ाइलें थीं:

- `./rules/config/regex/detectlist_suspicous_services.txt`: संदिग्ध सेवा नामों का पता लगाने के लिए
- `./rules/config/regex/allowlist_legitimate_services.txt`: वैध सेवाओं को अनुमति देने के लिए

`regexes` और `allowlist` में परिभाषित फ़ाइलों को संपादित किया जा सकता है ताकि उन सभी नियमों के व्यवहार को बदला जा सके जो उन्हें संदर्भित करते हैं, बिना किसी नियम फ़ाइल को स्वयं बदले।

आप अपने द्वारा बनाई गई अलग-अलग detectlist और allowlist टेक्स्ट फ़ाइलों का भी उपयोग कर सकते हैं।

## अप्रचलित एकत्रीकरण शर्तें (`count` नियम)

यह अभी भी Hayabusa में समर्थित है लेकिन भविष्य में इसे Sigma correlation नियमों से बदल दिया जाएगा।

### मूल बातें

ऊपर वर्णित `condition` कीवर्ड न केवल `AND` और `OR` तर्क को लागू करता है, बल्कि घटनाओं की गणना या "एकत्रीकरण" करने में भी सक्षम है।
इस फ़ंक्शन को "एकत्रीकरण शर्त" (aggregation condition) कहा जाता है और इसे एक शर्त को पाइप से जोड़कर निर्दिष्ट किया जाता है।
नीचे दिए गए इस password spray पहचान उदाहरण में, एक सशर्त अभिव्यक्ति का उपयोग यह निर्धारित करने के लिए किया जाता है कि क्या 5 मिनट की समय-सीमा के भीतर एक स्रोत `IpAddress` से 5 या अधिक `TargetUserName` मान हैं।

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

एकत्रीकरण शर्तें निम्नलिखित प्रारूप में परिभाषित की जा सकती हैं:

- `count() {operator} {number}`: पाइप से पहले की पहली शर्त से मेल खाने वाली लॉग घटनाओं के लिए, यदि मेल खाने वाले लॉग की संख्या `{operator}` और `{number}` द्वारा निर्दिष्ट सशर्त अभिव्यक्ति को संतुष्ट करती है तो शर्त मेल खाएगी।

`{operator}` निम्नलिखित में से कोई एक हो सकता है:

- `==`: यदि मान निर्दिष्ट मान के बराबर है, तो इसे शर्त के मिलान के रूप में माना जाता है।
- `>=`: यदि मान निर्दिष्ट मान के बराबर या उससे अधिक है, तो शर्त को पूरा माना जाता है।
- `>`: यदि मान निर्दिष्ट मान से अधिक है, तो शर्त को पूरा माना जाता है।
- `<=`: यदि मान निर्दिष्ट मान के बराबर या उससे कम है, तो शर्त को पूरा माना जाता है।
- `<`: यदि मान निर्दिष्ट मान से कम है, तो इसे शर्त पूरी होने के रूप में माना जाएगा।

`{number}` एक संख्या होनी चाहिए।

`timeframe` को निम्नलिखित में परिभाषित किया जा सकता है:

- `15s`: 15 सेकंड
- `30m`: 30 मिनट
- `12h`: 12 घंटे
- `7d`: 7 दिन
- `3M`: 3 महीने

### एकत्रीकरण शर्तों के चार पैटर्न

1. कोई count तर्क या `by` कीवर्ड नहीं। उदाहरण: `selection | count() > 10`
   > यदि समय-सीमा के भीतर `selection` 10 से अधिक बार मेल खाता है, तो शर्त मेल खाएगी।
   > इन्हें Event Count correlation नियमों से बदल दिया जाता है जो `group-by` फ़ील्ड का उपयोग नहीं करते।
2. कोई count तर्क नहीं लेकिन एक `by` कीवर्ड है। उदाहरण: `selection | count() by IpAddress > 10`
   > **समान** `IpAddress` के लिए `selection` को 10 से अधिक बार सत्य होना होगा।
   > ये #2 नियम #1 नियमों की तुलना में अधिक सामान्य हैं।
   > आप समूहीकरण के लिए कई फ़ील्ड भी निर्दिष्ट कर सकते हैं। उदाहरण के लिए: `by IpAddress, Computer`
   > इन्हें Event Count correlation नियमों से बदल दिया जाता है जो `group-by` फ़ील्ड का उपयोग करते हैं।
3. एक count तर्क है लेकिन कोई `by` कीवर्ड नहीं। उदाहरण: `selection | count(TargetUserName) > 10`
   > यदि `selection` मेल खाता है और `TargetUserName` समय-सीमा के भीतर 10 से अधिक बार **भिन्न** है, तो शर्त मेल खाएगी।
   > इन्हें Value Count correlation नियमों से बदल दिया जाता है जो `group-by` फ़ील्ड का उपयोग नहीं करते।
4. एक count तर्क और `by` कीवर्ड दोनों हैं। उदाहरण: `selection | count(Users) by IpAddress > 10`
   > **समान** `IpAddress` के लिए, शर्त के मेल खाने के लिए 10 से अधिक **भिन्न** `TargetUserName` होने की आवश्यकता होगी।
   > ये #4 नियम #3 नियमों की तुलना में अधिक सामान्य हैं।
   > इन्हें Value Count correlation नियमों से बदल दिया जाता है जो `group-by` फ़ील्ड का उपयोग करते हैं।

### पैटर्न 1 उदाहरण

यह सबसे बुनियादी पैटर्न है: `count() {operator} {number}`। नीचे दिया गया नियम मेल खाएगा यदि `selection` 3 या अधिक बार होता है।

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### पैटर्न 2 उदाहरण

`count() by {eventkey} {operator} {number}`: पाइप से पहले `condition` से मेल खाने वाली लॉग घटनाओं को **समान** `{eventkey}` द्वारा समूहीकृत किया जाता है। यदि प्रत्येक समूहीकरण के लिए मेल खाने वाली घटनाओं की संख्या `{operator}` और `{number}` द्वारा निर्दिष्ट शर्त को संतुष्ट करती है, तो शर्त मेल खाएगी।

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### पैटर्न 3 उदाहरण

`count({eventkey}) {operator} {number}`: गणना करता है कि शर्त पाइप से पहले की शर्त से मेल खाने वाली लॉग घटना में `{eventkey}` के कितने **भिन्न** मान मौजूद हैं। यदि संख्या `{operator}` और `{number}` में निर्दिष्ट सशर्त अभिव्यक्ति को संतुष्ट करती है, तो शर्त को पूरा माना जाता है।

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### पैटर्न 4 उदाहरण

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: शर्त पाइप से पहले की शर्त से मेल खाने वाले लॉग को **समान** `{eventkey_2}` द्वारा समूहीकृत किया जाता है, और प्रत्येक समूह में `{eventkey_1}` के **भिन्न** मानों की संख्या की गणना की जाती है। यदि प्रत्येक समूहीकरण के लिए गणना किए गए मान `{operator}` और `{number}` द्वारा निर्दिष्ट सशर्त अभिव्यक्ति को संतुष्ट करते हैं, तो शर्त मेल खाएगी।

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Count नियम आउटपुट

count नियमों के लिए विवरण आउटपुट निश्चित है और मूल count शर्त को `[condition]` में प्रिंट करेगा, उसके बाद `[result]` में रिकॉर्ड किए गए eventkeys को प्रिंट करेगा।

नीचे दिए गए उदाहरण में, `TargetUserName` उपयोगकर्ता नामों की एक सूची जिन पर bruteforce किया जा रहा था, उसके बाद स्रोत `IpAddress`:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

अलर्ट का टाइमस्टैम्प पहली पहचानी गई घटना का समय होगा।
