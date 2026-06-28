# Windows Logging & Sysmon

## Windows लॉगिंग की अनुशंसाएँ

Windows मशीनों पर दुर्भावनापूर्ण गतिविधि का सही ढंग से पता लगाने के लिए, आपको डिफ़ॉल्ट लॉग सेटिंग्स में सुधार करना होगा।
हमने एक अलग प्रोजेक्ट बनाया है जो दस्तावेज़ करता है कि कौन-सी लॉग सेटिंग्स को सक्षम करने की आवश्यकता है, साथ ही उचित सेटिंग्स को स्वचालित रूप से सक्षम करने वाली स्क्रिप्ट्स भी, जो [https://github.com/Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) पर उपलब्ध हैं।

हम मार्गदर्शन के लिए निम्नलिखित साइटों की भी अनुशंसा करते हैं:

* [JSCU-NL (Joint Sigint Cyber Unit Netherlands) Logging Essentials](https://github.com/JSCU-NL/logging-essentials)
* [ACSC (Australian Cyber Security Centre) Logging and Fowarding Guide](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)
* [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)

## Sysmon संबंधित प्रोजेक्ट

सबसे अधिक फोरेंसिक साक्ष्य बनाने और उच्चतम सटीकता के साथ पता लगाने के लिए, आपको sysmon इंस्टॉल करने की आवश्यकता है। हम निम्नलिखित साइटों और कॉन्फ़िग फ़ाइलों की अनुशंसा करते हैं:

* [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
* [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
* [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by Neo23x0](https://github.com/Neo23x0/sysmon-config)
* [SwiftOnSecurity Sysmon Config fork by ion-storm](https://github.com/ion-storm/sysmon-config)
