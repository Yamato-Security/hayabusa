# Config কমান্ডসমূহ

## `config-critical-systems` কমান্ড

এই কমান্ডটি স্বয়ংক্রিয়ভাবে ডোমেইন কন্ট্রোলার এবং ফাইল সার্ভারের মতো গুরুত্বপূর্ণ সিস্টেমগুলো খুঁজে বের করার চেষ্টা করবে এবং সেগুলোকে `./config/critical_systems.txt` কনফিগ ফাইলে যুক্ত করবে যাতে সমস্ত অ্যালার্ট এক স্তর বৃদ্ধি পায়।
এটি ডোমেইন কন্ট্রোলার কিনা তা নির্ধারণ করতে Security 4768 (Kerberos TGT requested) ইভেন্ট অনুসন্ধান করবে।
এটি ফাইল সার্ভার কিনা তা নির্ধারণ করতে Security 5145 (Network Share File Access) ইভেন্ট অনুসন্ধান করবে।
`critical_systems.txt` ফাইলে যুক্ত করা যেকোনো হোস্টনেমের ক্ষেত্রে low-এর উপরের সমস্ত অ্যালার্ট এক স্তর বৃদ্ধি পাবে, সর্বোচ্চ `emergency` স্তর পর্যন্ত।

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

### `config-critical-systems` কমান্ডের উদাহরণ

* ডোমেইন কন্ট্রোলার এবং ফাইল সার্ভারের জন্য `../hayabusa-sample-evtx` ডিরেক্টরি অনুসন্ধান করুন:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
