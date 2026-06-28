# डाउनलोड

कृपया Hayabusa का नवीनतम स्थिर संस्करण संकलित बाइनरी के साथ डाउनलोड करें या [Releases](https://github.com/Yamato-Security/hayabusa/releases) पृष्ठ से स्रोत कोड संकलित करें।

हम निम्नलिखित आर्किटेक्चर के लिए बाइनरी प्रदान करते हैं:
- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [किसी कारण से Linux ARM MUSL बाइनरी ठीक से नहीं चलती है](https://github.com/Yamato-Security/hayabusa/issues/1332) इसलिए हम वह बाइनरी प्रदान नहीं करते हैं। यह हमारे नियंत्रण से बाहर है, इसलिए जब यह ठीक हो जाएगा तब हम भविष्य में इसे प्रदान करने की योजना बना रहे हैं।

## Windows लाइव रिस्पॉन्स पैकेज

v2.18.0 के रूप में, हम विशेष Windows पैकेज प्रदान करते हैं जो एक ही फ़ाइल में प्रदान किए गए XOR-एन्कोडेड नियमों का उपयोग करते हैं तथा सभी कॉन्फ़िग फ़ाइलें एक ही फ़ाइल में संयोजित होती हैं ([hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules) पर होस्ट की गई)।
बस नाम में `live-response` वाले ज़िप पैकेज डाउनलोड करें।
ज़िप फ़ाइलों में केवल तीन फ़ाइलें शामिल होती हैं: Hayabusa बाइनरी, XOR-एन्कोडेड नियम फ़ाइल और कॉन्फ़िग फ़ाइल।
इन लाइव रिस्पॉन्स पैकेजों का उद्देश्य यह है कि जब क्लाइंट एंडपॉइंट्स पर Hayabusa चलाया जाए, तो हम यह सुनिश्चित करना चाहते हैं कि Windows Defender जैसे एंटी-वायरस स्कैनर `.yml` नियम फ़ाइलों पर गलत पॉज़िटिव न दें।
साथ ही, हम सिस्टम पर लिखी जा रही फ़ाइलों की मात्रा को कम से कम करना चाहते हैं ताकि USN Journal जैसे फोरेंसिक आर्टिफैक्ट ओवरराइट न हों।
