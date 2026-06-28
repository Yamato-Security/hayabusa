# उन्नत: स्रोत से संकलन (वैकल्पिक)

यदि आपके पास Rust इंस्टॉल है, तो आप निम्नलिखित कमांड के साथ स्रोत से संकलित कर सकते हैं:

नोट: संकलित करने के लिए, आपको आमतौर पर Rust के नवीनतम संस्करण की आवश्यकता होती है।

```bash
cargo build --release
```

आप main ब्रांच से नवीनतम अस्थिर संस्करण या [Releases](https://github.com/Yamato-Security/hayabusa/releases) पेज से नवीनतम स्थिर संस्करण डाउनलोड कर सकते हैं।

Rust को समय-समय पर इसके साथ अपडेट करना सुनिश्चित करें:

```bash
rustup update stable
```

संकलित बाइनरी `./target/release` फ़ोल्डर में आउटपुट होगी।

## Rust पैकेज अपडेट करना

आप संकलित करने से पहले नवीनतम Rust crates में अपडेट कर सकते हैं:

```bash
cargo update
```

> कृपया हमें बताएं कि अपडेट करने के बाद यदि कुछ टूटता है।

## 32-बिट Windows बाइनरी का क्रॉस-संकलन

आप 64-बिट Windows सिस्टम पर निम्नलिखित के साथ 32-बिट बाइनरी बना सकते हैं:

```bash
rustup install stable-i686-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup run stable-i686-pc-windows-msvc cargo build --release
```

> **चेतावनी: जब भी Rust का नया स्थिर संस्करण आए तो `rustup install stable-i686-pc-windows-msvc` चलाना सुनिश्चित करें क्योंकि `rustup update stable` क्रॉस संकलन के लिए कंपाइलर को अपडेट नहीं करेगा और आपको बिल्ड त्रुटियाँ मिल सकती हैं।**

## macOS संकलन नोट्स

यदि आपको openssl के बारे में संकलन त्रुटियाँ मिलती हैं, तो आपको [Homebrew](https://brew.sh/) इंस्टॉल करना होगा और फिर निम्नलिखित पैकेज इंस्टॉल करने होंगे:

```bash
brew install pkg-config
brew install openssl
```

## Linux संकलन नोट्स

निम्नलिखित बिल्ड निर्भरताएँ आवश्यक हैं:
* openssl-devel (Fedora-based) / libssl-dev (Ubuntu-based) 
* perl
* musl-gcc

## Linux MUSL बाइनरी का क्रॉस-संकलन

Linux OS पर, पहले target इंस्टॉल करें।

```bash
rustup install stable-x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

इसके साथ संकलित करें:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

> **चेतावनी: जब भी Rust का नया स्थिर संस्करण आए तो `rustup install stable-x86_64-unknown-linux-musl` चलाना सुनिश्चित करें क्योंकि `rustup update stable` क्रॉस संकलन के लिए कंपाइलर को अपडेट नहीं करेगा और आपको बिल्ड त्रुटियाँ मिल सकती हैं।**

MUSL बाइनरी `./target/x86_64-unknown-linux-musl/release/` डायरेक्टरी में बनाई जाएगी।
MUSL बाइनरी GNU बाइनरी की तुलना में लगभग 15% धीमी होती हैं, हालाँकि, वे linux के विभिन्न संस्करणों और वितरणों में अधिक पोर्टेबल होती हैं।
