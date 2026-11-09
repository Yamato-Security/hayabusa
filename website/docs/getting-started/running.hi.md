# Hayabusa चलाना

## सावधानी: एंटी-वायरस/EDR चेतावनियाँ और धीमा रनटाइम

जब आप hayabusa चलाने की कोशिश करते हैं या यहाँ तक कि सिर्फ़ `.yml` नियम डाउनलोड करते हैं, तब भी आपको एंटी-वायरस या EDR उत्पादों से एक अलर्ट मिल सकता है क्योंकि डिटेक्शन सिग्नेचर में `mimikatz` और संदिग्ध PowerShell कमांड जैसे कीवर्ड होंगे।
ये false positive हैं इसलिए आपको hayabusa को चलने देने के लिए अपने सुरक्षा उत्पादों में बहिष्करण (exclusions) कॉन्फ़िगर करने होंगे।
यदि आप मैलवेयर या सप्लाई चेन हमलों को लेकर चिंतित हैं, तो कृपया hayabusa स्रोत कोड की जाँच करें और बाइनरी को स्वयं कंपाइल करें।

रीबूट के बाद पहली बार चलाने पर आपको Windows Defender की रियल-टाइम सुरक्षा के कारण विशेष रूप से धीमा रनटाइम अनुभव हो सकता है।
आप रियल-टाइम सुरक्षा को अस्थायी रूप से बंद करके या hayabusa रनटाइम डायरेक्टरी में बहिष्करण जोड़कर इससे बच सकते हैं।
(कृपया ऐसा करने से पहले सुरक्षा जोखिमों पर विचार करें।)

## Windows

किसी Command/PowerShell Prompt या Windows Terminal में, बस उपयुक्त 32-bit या 64-bit Windows बाइनरी चलाएँ।

### पथ में स्पेस वाली फ़ाइल या डायरेक्टरी को स्कैन करने की कोशिश करते समय त्रुटि

Windows में अंतर्निहित Command या PowerShell prompt का उपयोग करते समय, यदि आपके फ़ाइल या डायरेक्टरी पथ में स्पेस है तो आपको एक त्रुटि मिल सकती है कि Hayabusa किसी भी .evtx फ़ाइल को लोड करने में असमर्थ था।
.evtx फ़ाइलों को सही ढंग से लोड करने के लिए, निम्नलिखित अवश्य करें:

1. फ़ाइल या डायरेक्टरी पथ को डबल कोट्स में बंद करें।
2. यदि यह एक डायरेक्टरी पथ है, तो सुनिश्चित करें कि आप अंतिम वर्ण के लिए बैकस्लैश शामिल न करें।

### वर्ण सही ढंग से प्रदर्शित न होना

Windows पर डिफ़ॉल्ट फ़ॉन्ट `Lucida Console` के साथ, लोगो और तालिकाओं में उपयोग किए गए विभिन्न वर्ण सही ढंग से प्रदर्शित नहीं होंगे।
इसे ठीक करने के लिए आपको फ़ॉन्ट को `Consalas` में बदलना चाहिए।

यह समापन संदेशों में जापानी वर्णों के प्रदर्शन को छोड़कर अधिकांश टेक्स्ट रेंडरिंग को ठीक कर देगा:

![Mojibake](../assets/screenshots/Mojibake.png)

इसे ठीक करने के लिए आपके पास चार विकल्प हैं:

1. Command या PowerShell prompt के बजाय [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) का उपयोग करें। (अनुशंसित)
2. `MS Gothic` फ़ॉन्ट का उपयोग करें। ध्यान दें कि बैकस्लैश Yen चिह्नों में बदल जाएँगे।
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. [HackGen](https://github.com/yuru7/HackGen/releases) फ़ॉन्ट इंस्टॉल करें और `HackGen Console NF` का उपयोग करें।
4. जापानी वाले समापन संदेशों को प्रदर्शित न करने के लिए `-q, --quiet` का उपयोग करें।

## Linux

आपको पहले बाइनरी को निष्पादन योग्य बनाना होगा।

```bash
chmod +x ./hayabusa
```

फिर इसे Hayabusa रूट डायरेक्टरी से चलाएँ:

```bash
./hayabusa
```

## macOS

Terminal या iTerm2 से, आपको पहले बाइनरी को निष्पादन योग्य बनाना होगा।

```bash
chmod +x ./hayabusa
```

फिर, इसे Hayabusa रूट डायरेक्टरी से चलाने की कोशिश करें:

```bash
./hayabusa
```

macOS के नवीनतम संस्करण पर, जब आप इसे चलाने की कोशिश करते हैं तो आपको निम्नलिखित सुरक्षा त्रुटि मिल सकती है:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

"Cancel" पर क्लिक करें और फिर System Preferences से, "Security & Privacy" खोलें और General टैब से, "Allow Anyway" पर क्लिक करें।

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

उसके बाद, इसे फिर से चलाने की कोशिश करें।

```bash
./hayabusa
```

निम्नलिखित चेतावनी पॉप अप होगी, इसलिए कृपया "Open" पर क्लिक करें।

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

अब आप hayabusa चला पाने में सक्षम होने चाहिए।

## VHDX इनपुट


सभी इवेंट लॉग विश्लेषण कमांड `--vhdx` के साथ `-f <IMAGE.vhdx>` या `-d <DIR>` स्वीकार करते हैं। इमेज खोज दिए गए फ़ोल्डर और उसके नीचे तीन स्तर तक होती है। इमेज के अंदर सभी पढ़ने योग्य NTFS वॉल्यूम खोजे जाते हैं; वहाँ यह गहराई सीमा लागू नहीं होती।

```bash
./hayabusa dfir-timeline --vhdx -f host.vhdx -w -U -p verbose -o timeline.csv
./hayabusa dfir-timeline --vhdx -d images/ -w -U -p verbose -o timeline.csv
```


Juntei के साथ साझा पोर्टेबल NTFS API से **Linux, macOS और Windows** पर मूल रूप से स्कैन किया जा सकता है। फ़ाइलें सीधे केवल पढ़ने योग्य, सीक करने योग्य स्ट्रीम के रूप में खुलती हैं। FUSE, माउंट ड्राइवर, व्यवस्थापक अधिकार या अस्थायी निष्कर्षण की आवश्यकता नहीं है। मूल इमेज अपरिवर्तित रहती है। साक्ष्य पथ `host.vhdx!/path/log.evtx` रूप में रहते हैं। BitLocker और बाहरी पैरेंट इमेज पर निर्भर इमेज समर्थित नहीं हैं।

[English: VHDX input details and limitations](https://yamato-security.github.io/hayabusa/getting-started/running/#vhdx-inputs).
