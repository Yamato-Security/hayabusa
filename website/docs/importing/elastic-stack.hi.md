- [परिणामों को SOF-ELK (Elastic Stack) में आयात करना](#importing-results-into-sof-elk-elastic-stack)
  - [SOF-ELK इंस्टॉल और शुरू करें](#install-and-start-sof-elk)
    - [Macs पर नेटवर्क कनेक्टिविटी समस्या](#network-connectivity-trouble-on-macs)
  - [SOF-ELK को अपडेट करें!](#update-sof-elk)
  - [Hayabusa चलाएँ](#run-hayabusa)
  - [वैकल्पिक: पुराना आयातित डेटा हटाना](#optional-deleting-old-imported-data)
  - [SOF-ELK में Hayabusa logstash कॉन्फ़िग फ़ाइल को कॉन्फ़िगर करें](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Hayabusa परिणामों को SOF-ELK में आयात करें](#import-hayabusa-results-into-sof-elk)
  - [जांचें कि Kibana में आयात सफल हुआ](#check-that-the-import-worked-in-kibana)
  - [Discover में परिणाम देखें](#view-results-in-discover)
  - [परिणामों का विश्लेषण](#analyzing-results)
    - [कॉलम जोड़ना](#adding-columns)
    - [फ़िल्टरिंग](#filtering)
    - [विवरण टॉगल करना](#toggling-details)
    - [आसपास के दस्तावेज़ देखें](#view-surrounding-documents)
    - [फ़ील्ड पर त्वरित मेट्रिक्स प्राप्त करें](#get-quick-metrics-on-fields)
  - [भविष्य की योजनाएँ](#future-plans)

# परिणामों को SOF-ELK (Elastic Stack) में आयात करना

## SOF-ELK इंस्टॉल और शुरू करें

Hayabusa परिणामों को आसानी से Elastic Stack में आयात किया जा सकता है।
हम [SOF-ELK](https://github.com/philhagen/sof-elk) का उपयोग करने की सलाह देते हैं, जो DFIR जांच पर केंद्रित एक मुफ़्त elastic stack Linux distro है।

सबसे पहले [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README) से SOF-ELK 7-zipped VMware इमेज डाउनलोड करें और अनज़िप करें।

दो संस्करण हैं, Intel CPUs के लिए x86 और Apple M-series कंप्यूटरों के लिए एक ARM संस्करण।

जब आप VM को बूट करेंगे, तो आपको इसके समान एक स्क्रीन मिलेगी:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Kibana URL और SSH सर्वर के IP पते को नोट कर लें।

आप निम्नलिखित क्रेडेंशियल्स के साथ लॉग इन कर सकते हैं:
* Username: `elk_user`
* Password: `forensics`

प्रदर्शित URL के अनुसार किसी वेब ब्राउज़र में Kibana खोलें।
उदाहरण के लिए: http://172.16.23.128:5601/

> Note: Kibana को लोड होने में कुछ समय लग सकता है।

आपको निम्नलिखित जैसा एक वेबपेज दिखाई देना चाहिए:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

हम सलाह देते हैं कि आप VM के अंदर कमांड टाइप करने के बजाय `ssh elk_user@172.16.23.128` के साथ VM में SSH करें।

> Note: डिफ़ॉल्ट कीबोर्ड लेआउट US कीबोर्ड है।

### Macs पर नेटवर्क कनेक्टिविटी समस्या

यदि आप macOS पर हैं और आपको टर्मिनल में `no route to host` त्रुटि मिलती है या आप अपने ब्राउज़र में Kibana तक नहीं पहुँच सकते, तो यह संभवतः macOS के स्थानीय नेटवर्क गोपनीयता नियंत्रणों के कारण है।

`System Settings` में, `Privacy & Security` -> `Local Network` खोलें और सुनिश्चित करें कि आपका ब्राउज़र और टर्मिनल प्रोग्राम आपके स्थानीय नेटवर्क पर उपकरणों के साथ संचार करने में सक्षम होने के लिए सक्षम हैं।

## SOF-ELK को अपडेट करें!

डेटा आयात करने से पहले, `sudo sof-elk_update.sh` कमांड के साथ SOF-ELK को अपडेट करना सुनिश्चित करें।

## Hayabusa चलाएँ

Hayabusa चलाएँ और परिणामों को JSONL में सहेजें।

उदा.: `./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## वैकल्पिक: पुराना आयातित डेटा हटाना

यदि यह पहली बार नहीं है कि आप Hayabusa परिणाम आयात कर रहे हैं और आप सब कुछ साफ़ करना चाहते हैं, तो आप निम्नलिखित के साथ ऐसा कर सकते हैं:

1. जांचें कि वर्तमान में SOF-ELK में कौन से रिकॉर्ड हैं: `sof-elk_clear.py -i list`
2. वर्तमान डेटा हटाएँ: `sof-elk_clear.py -a`
3. logstash निर्देशिका में फ़ाइलें हटाएँ: `rm /logstash/hayabusa/*`

## SOF-ELK में Hayabusa logstash कॉन्फ़िग फ़ाइल को कॉन्फ़िगर करें

SOF-ELK में पहले से ही एक Hayabusa logstash कॉन्फ़िग फ़ाइल शामिल है जो फ़ील्ड नामों को Elastic Common Schema प्रारूप में परिवर्तित करती है।
यदि आप Hayabusa फ़ील्ड नामों के साथ अधिक सहज हैं, तो हम उस फ़ाइल का उपयोग करने की सलाह देते हैं जो हम प्रदान करते हैं।

1. सबसे पहले SOF-ELK में SSH करें: `ssh elk_user@172.16.23.128`
2. वर्तमान logstash कॉन्फ़िग फ़ाइल को हटाएँ या स्थानांतरित करें: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. नई [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) फ़ाइल को `/etc/logstash/conf.d/` पर अपलोड करें: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`।
4. logstash को रीबूट करें: `sudo systemctl restart logstash`

यह कॉन्फ़िग फ़ाइल समेकित `DetailsText` और `ExtraFieldInfoText` फ़ील्ड बनाएगी जो आपको प्रत्येक रिकॉर्ड को एक-एक करके खोलकर सभी फ़ील्ड को देखने में समय लगाने के बजाय सबसे महत्वपूर्ण फ़ील्ड को एक नज़र में जल्दी से देखने देती हैं।

## Hayabusa परिणामों को SOF-ELK में आयात करें

`/logstash` निर्देशिका के अंदर उपयुक्त निर्देशिका में लॉग को कॉपी करके लॉग को SOF-ELK में अंतर्ग्रहण किया जाता है।

सबसे पहले SSH से `exit` करें और फिर, आपके द्वारा बनाई गई Hayabusa परिणाम फ़ाइल को कॉपी करें:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## जांचें कि Kibana में आयात सफल हुआ

सबसे पहले अपने Hayabusa स्कैन के `Results Summary` में `Total detections`, `First Timestamp` और `Last Timestamp` को नोट कर लें।

यदि आप यह जानकारी प्राप्त नहीं कर सकते, तो आप `Total detections` के लिए कुल लाइन गणना प्राप्त करने हेतु *nix पर `wc -l results.jsonl` चला सकते हैं।

डिफ़ॉल्ट रूप से, Hayabusa प्रदर्शन को बेहतर बनाने के लिए परिणामों को क्रमबद्ध नहीं करता है, इसलिए आप पहली और अंतिम टाइमस्टैम्प प्राप्त करने के लिए पहली और अंतिम लाइनों को नहीं देख सकते।
यदि आप सटीक पहली और अंतिम टाइमस्टैम्प नहीं जानते, तो बस Kibana में पहली तारीख को वर्ष 2007 और अंतिम दिन को `now` पर सेट करें ताकि आपके पास सभी परिणाम हों।

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

अब आपको `Total Records` के साथ-साथ आयात किए गए इवेंट्स की पहली और अंतिम टाइमस्टैम्प दिखाई देनी चाहिए।

कभी-कभी सभी इवेंट्स को आयात करने में कुछ समय लगता है, इसलिए जब तक `Total Records` अपेक्षित गणना न हो जाए तब तक बस पेज को रिफ़्रेश करते रहें।

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

आप यह जांचने के लिए कि आयात सफल हुआ या नहीं, टर्मिनल से `sof-elk_clear.py -i list` चलाकर भी जांच कर सकते हैं।
आपको देखना चाहिए कि आपके `evtxlogs` इंडेक्स में अधिक रिकॉर्ड होने चाहिए:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

यदि आयात करते समय आपको कोई पार्सिंग त्रुटि होती है तो कृपया GitHub पर एक issue बनाएँ।
आप `/var/log/logstash/logstash-plain.log` लॉग फ़ाइल के अंत को देखकर इसकी जांच कर सकते हैं।

## Discover में परिणाम देखें

ऊपर-बाईं ओर साइडबार आइकन पर क्लिक करें और `Discover` पर क्लिक करें:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

आपको संभवतः `No results match your search criteria` दिखाई देगा।

ऊपर बाएँ कोने में जहाँ `logstash-*` इंडेक्स लिखा है, उस पर क्लिक करें और इसे `evtxlogs-*` में बदलें।
अब आपको Discover टाइमलाइन दिखाई देनी चाहिए।

## परिणामों का विश्लेषण

डिफ़ॉल्ट Discover दृश्य इसके समान दिखना चाहिए:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

आप शीर्ष पर हिस्टोग्राम को देखकर इस बात का अवलोकन प्राप्त कर सकते हैं कि इवेंट्स कब हुए और इवेंट्स की आवृत्ति क्या थी। 

### कॉलम जोड़ना

बाईं-ओर साइडबार में, आप किसी फ़ील्ड पर होवर करने के बाद प्लस चिह्न पर क्लिक करके वे फ़ील्ड जोड़ सकते हैं जिन्हें आप कॉलम में प्रदर्शित करना चाहते हैं।
चूंकि कई फ़ील्ड हैं, आप खोज बॉक्स में जिस फ़ील्ड नाम की तलाश कर रहे हैं उसका नाम टाइप करना चाह सकते हैं।

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

शुरुआत के लिए, हम निम्नलिखित कॉलम की सलाह देते हैं:
- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

यदि आपका मॉनिटर पर्याप्त चौड़ा है, तो आप `ExtraFieldInfoText` भी जोड़ना चाह सकते हैं ताकि आप सभी फ़ील्ड जानकारी देख सकें।

अब आपका Discover दृश्य इस तरह दिखना चाहिए:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### फ़िल्टरिंग

आप कुछ इवेंट्स और अलर्ट खोजने के लिए KQL(Kibana Query Language) के साथ फ़िल्टर कर सकते हैं। उदाहरण के लिए:
  * `Level: "crit"`: केवल critical अलर्ट दिखाएँ।
  * `Level: "crit" OR Level: "high"`: high और critical अलर्ट दिखाएँ।
  * `NOT Level: info`: सूचनात्मक इवेंट्स न दिखाएँ, केवल अलर्ट दिखाएँ।
  * `MitreTactics: *LatMov*`: lateral movement से संबंधित इवेंट्स और अलर्ट दिखाएँ।
  * `"PW Spray"`: केवल विशिष्ट हमले दिखाएँ जैसे "Password Spray"।
  * `"LID: 0x8724ead"`: Logon ID 0x8724ead से जुड़ी सभी गतिविधि प्रदर्शित करें।
  * `Details_TgtUser: admmig`: उन सभी इवेंट्स को खोजें जहाँ लक्षित उपयोगकर्ता `admmig` है।

### विवरण टॉगल करना

किसी रिकॉर्ड में सभी फ़ील्ड की जांच करने के लिए, बस टाइमस्टैम्प के बगल में आइकन (Toggle dialog with details) पर क्लिक करें:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### आसपास के दस्तावेज़ देखें

यदि आप किसी निश्चित अलर्ट से ठीक पहले और बाद के इवेंट्स देखना चाहते हैं, तो पहले उस अलर्ट के विवरण खोलें और फिर ऊपर दाईं ओर `View surrounding documents` पर क्लिक करें:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

इस उदाहरण में, हम Pass the Hash हमले के अलर्ट से पहले और बाद के इवेंट्स देख रहे हैं:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Note: अधिक इवेंट्स प्राप्त करने के लिए ऊपर `Load x newer documents` या नीचे `Load x older documents` पर संख्याएँ बदलें।

### फ़ील्ड पर त्वरित मेट्रिक्स प्राप्त करें

बाएँ कॉलम में, यदि आप किसी फ़ील्ड नाम पर क्लिक करते हैं तो यह आपको इसके उपयोग पर त्वरित मेट्रिक्स देगा:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> ध्यान दें कि डेटा को गति के लिए सैंपल किया जाता है इसलिए यह 100% सटीक नहीं है।

## भविष्य की योजनाएँ

* CSV के लिए Logstash पार्सर
* पूर्व-निर्मित डैशबोर्ड
