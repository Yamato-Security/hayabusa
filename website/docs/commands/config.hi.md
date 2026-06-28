# Config कमांड्स

## `config-critical-systems` कमांड

यह कमांड स्वचालित रूप से डोमेन कंट्रोलर और फ़ाइल सर्वर जैसे महत्वपूर्ण सिस्टम को खोजने का प्रयास करेगा और उन्हें `./config/critical_systems.txt` कॉन्फ़िग फ़ाइल में जोड़ देगा ताकि सभी अलर्ट एक स्तर बढ़ा दिए जाएं।
यह यह निर्धारित करने के लिए Security 4768 (Kerberos TGT requested) इवेंट्स की खोज करेगा कि क्या यह एक डोमेन कंट्रोलर है।
यह यह निर्धारित करने के लिए Security 5145 (Network Share File Access) इवेंट्स की खोज करेगा कि क्या यह एक फ़ाइल सर्वर है।
`critical_systems.txt` फ़ाइल में जोड़े गए किसी भी होस्टनाम के लिए low से ऊपर के सभी अलर्ट एक स्तर बढ़ा दिए जाएंगे, अधिकतम `emergency` स्तर तक।

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### `config-critical-systems` कमांड के उदाहरण

* डोमेन कंट्रोलर और फ़ाइल सर्वर के लिए `../hayabusa-sample-evtx` डायरेक्टरी की खोज करें:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
