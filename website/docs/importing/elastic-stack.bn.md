- [SOF-ELK-এ ফলাফল ইম্পোর্ট করা (Elastic Stack)](#importing-results-into-sof-elk-elastic-stack)
  - [SOF-ELK ইনস্টল এবং চালু করা](#install-and-start-sof-elk)
    - [Mac-এ নেটওয়ার্ক সংযোগের সমস্যা](#network-connectivity-trouble-on-macs)
  - [SOF-ELK আপডেট করুন!](#update-sof-elk)
  - [Hayabusa চালানো](#run-hayabusa)
  - [ঐচ্ছিক: পুরনো ইম্পোর্ট করা ডেটা মুছে ফেলা](#optional-deleting-old-imported-data)
  - [SOF-ELK-এ Hayabusa logstash কনফিগ ফাইল কনফিগার করা](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [SOF-ELK-এ Hayabusa ফলাফল ইম্পোর্ট করা](#import-hayabusa-results-into-sof-elk)
  - [Kibana-তে ইম্পোর্ট সফল হয়েছে কিনা যাচাই করা](#check-that-the-import-worked-in-kibana)
  - [Discover-এ ফলাফল দেখা](#view-results-in-discover)
  - [ফলাফল বিশ্লেষণ করা](#analyzing-results)
    - [কলাম যোগ করা](#adding-columns)
    - [ফিল্টারিং](#filtering)
    - [বিস্তারিত টগল করা](#toggling-details)
    - [আশেপাশের ডকুমেন্ট দেখা](#view-surrounding-documents)
    - [ফিল্ডের দ্রুত মেট্রিক্স পাওয়া](#get-quick-metrics-on-fields)
  - [ভবিষ্যৎ পরিকল্পনা](#future-plans)

# SOF-ELK-এ ফলাফল ইম্পোর্ট করা (Elastic Stack)

## SOF-ELK ইনস্টল এবং চালু করা

Hayabusa-এর ফলাফল সহজেই Elastic Stack-এ ইম্পোর্ট করা যায়।
আমরা [SOF-ELK](https://github.com/philhagen/sof-elk) ব্যবহার করার পরামর্শ দিই, যা DFIR তদন্তের উপর ফোকাস করা একটি বিনামূল্যের elastic stack Linux ডিস্ট্রো।

প্রথমে [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README) থেকে SOF-ELK 7-zip করা VMware ইমেজটি ডাউনলোড এবং আনজিপ করুন।

দুটি সংস্করণ রয়েছে, Intel CPU-এর জন্য x86 এবং Apple M-series কম্পিউটারের জন্য একটি ARM সংস্করণ।

আপনি যখন VM বুট আপ করবেন, তখন আপনি এই ধরনের একটি স্ক্রিন পাবেন:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Kibana URL এবং SSH সার্ভারের IP ঠিকানা লক্ষ্য করে রাখুন।

আপনি নিম্নলিখিত শংসাপত্র দিয়ে লগ ইন করতে পারেন:

* ইউজারনেম: `elk_user`
* পাসওয়ার্ড: `forensics`

প্রদর্শিত URL অনুযায়ী একটি ওয়েব ব্রাউজারে Kibana খুলুন।
উদাহরণস্বরূপ: http://172.16.23.128:5601/

> দ্রষ্টব্য: Kibana লোড হতে কিছুটা সময় লাগতে পারে।

আপনি নিম্নলিখিত একটি ওয়েবপেজ দেখতে পাবেন:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

আমরা পরামর্শ দিই যে আপনি VM-এর ভিতরে কমান্ড টাইপ করার পরিবর্তে `ssh elk_user@172.16.23.128` দিয়ে VM-এ SSH করুন।

> দ্রষ্টব্য: ডিফল্ট কীবোর্ড লেআউট হল US কীবোর্ড।

### Mac-এ নেটওয়ার্ক সংযোগের সমস্যা

আপনি যদি macOS-এ থাকেন এবং টার্মিনালে `no route to host` ত্রুটি পান বা আপনি আপনার ব্রাউজারে Kibana অ্যাক্সেস করতে না পারেন, তাহলে এটি সম্ভবত macOS-এর লোকাল নেটওয়ার্ক প্রাইভেসি কন্ট্রোলের কারণে।

`System Settings`-এ, `Privacy & Security` -> `Local Network` খুলুন এবং নিশ্চিত করুন যে আপনার ব্রাউজার এবং টার্মিনাল প্রোগ্রাম আপনার লোকাল নেটওয়ার্কের ডিভাইসগুলোর সাথে যোগাযোগ করতে সক্ষম হওয়ার জন্য সক্রিয় আছে।

## SOF-ELK আপডেট করুন!

ডেটা ইম্পোর্ট করার আগে, `sudo sof-elk_update.sh` কমান্ড দিয়ে SOF-ELK আপডেট করতে ভুলবেন না।

## Hayabusa চালানো

Hayabusa চালান এবং ফলাফল JSONL-এ সংরক্ষণ করুন।

উদাহরণ: `./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## ঐচ্ছিক: পুরনো ইম্পোর্ট করা ডেটা মুছে ফেলা

যদি এটি Hayabusa-এর ফলাফল ইম্পোর্ট করার প্রথমবার না হয় এবং আপনি সবকিছু পরিষ্কার করতে চান, তাহলে আপনি নিম্নলিখিতভাবে তা করতে পারেন:

1. SOF-ELK-এ বর্তমানে কোন রেকর্ডগুলো আছে তা পরীক্ষা করুন: `sof-elk_clear.py -i list`
2. বর্তমান ডেটা মুছে ফেলুন: `sof-elk_clear.py -a`
3. logstash ডিরেক্টরির ফাইলগুলো মুছে ফেলুন: `rm /logstash/hayabusa/*`

## SOF-ELK-এ Hayabusa logstash কনফিগ ফাইল কনফিগার করা

SOF-ELK-এ ইতিমধ্যে একটি Hayabusa logstash কনফিগ ফাইল অন্তর্ভুক্ত আছে যা ফিল্ডের নামগুলোকে Elastic Common Schema ফরম্যাটে রূপান্তর করে।
আপনি যদি Hayabusa ফিল্ডের নামগুলোর সাথে বেশি স্বাচ্ছন্দ্যবোধ করেন, তাহলে আমরা আমাদের প্রদান করা ফাইলটি ব্যবহার করার পরামর্শ দিই।

1. প্রথমে SOF-ELK-এ SSH করুন: `ssh elk_user@172.16.23.128`
2. বর্তমান logstash কনফিগ ফাইলটি মুছে ফেলুন বা সরিয়ে নিন: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. নতুন [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) ফাইলটি `/etc/logstash/conf.d/`-এ আপলোড করুন: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`।
4. logstash রিবুট করুন: `sudo systemctl restart logstash`

এই কনফিগ ফাইলটি একত্রিত `DetailsText` এবং `ExtraFieldInfoText` ফিল্ড তৈরি করবে যা আপনাকে প্রতিটি রেকর্ড একে একে খুলে সমস্ত ফিল্ড দেখার জন্য সময় নেওয়ার পরিবর্তে এক নজরে সবচেয়ে গুরুত্বপূর্ণ ফিল্ডগুলো দ্রুত দেখতে দেয়।

## SOF-ELK-এ Hayabusa ফলাফল ইম্পোর্ট করা

`/logstash` ডিরেক্টরির ভিতরে উপযুক্ত ডিরেক্টরিতে লগগুলো কপি করে লগগুলো SOF-ELK-এ ইনজেস্ট করা হয়।

প্রথমে SSH থেকে `exit` করুন এবং তারপর, আপনার তৈরি করা Hayabusa ফলাফল ফাইলটি কপি করুন:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Kibana-তে ইম্পোর্ট সফল হয়েছে কিনা যাচাই করা

প্রথমে আপনার Hayabusa স্ক্যানের `Results Summary`-তে `Total detections`, `First Timestamp` এবং `Last Timestamp` লক্ষ্য করে রাখুন।

আপনি যদি এই তথ্য না পান, তাহলে আপনি *nix-এ `wc -l results.jsonl` চালিয়ে `Total detections`-এর জন্য মোট লাইন গণনা পেতে পারেন।

ডিফল্টভাবে, Hayabusa কর্মক্ষমতা উন্নত করার জন্য ফলাফলগুলো সাজায় না, তাই আপনি প্রথম এবং শেষ টাইমস্ট্যাম্প পেতে প্রথম এবং শেষ লাইনগুলো দেখতে পারবেন না।
আপনি যদি সঠিক প্রথম এবং শেষ টাইমস্ট্যাম্প না জানেন, তাহলে শুধু Kibana-তে প্রথম তারিখ 2007 সালে সেট করুন এবং শেষ দিন `now` হিসেবে সেট করুন যাতে আপনি সমস্ত ফলাফল পান।

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

এখন আপনি ইম্পোর্ট করা ইভেন্টগুলোর `Total Records` এবং সেইসাথে প্রথম এবং শেষ টাইমস্ট্যাম্প দেখতে পাবেন।

সমস্ত ইভেন্ট ইম্পোর্ট করতে কখনও কখনও কিছুটা সময় লাগে, তাই `Total Records` আপনার প্রত্যাশিত গণনায় না পৌঁছানো পর্যন্ত শুধু পৃষ্ঠাটি রিফ্রেশ করতে থাকুন।

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

ইম্পোর্ট সফল হয়েছে কিনা দেখতে আপনি টার্মিনাল থেকে `sof-elk_clear.py -i list` চালিয়েও পরীক্ষা করতে পারেন।
আপনি দেখতে পাবেন যে আপনার `evtxlogs` ইনডেক্সে আরও বেশি রেকর্ড থাকা উচিত:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

ইম্পোর্ট করার সময় যদি আপনার কোনো পার্সিং ত্রুটি হয়, তাহলে অনুগ্রহ করে GitHub-এ একটি issue তৈরি করুন।
আপনি `/var/log/logstash/logstash-plain.log` লগ ফাইলের শেষ অংশ দেখে এটি পরীক্ষা করতে পারেন।

## Discover-এ ফলাফল দেখা

উপরের-বাম সাইডবার আইকনে ক্লিক করুন এবং `Discover`-এ ক্লিক করুন:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

আপনি সম্ভবত `No results match your search criteria` দেখতে পাবেন।

উপরের-বাম কোণে যেখানে `logstash-*` ইনডেক্স লেখা আছে, সেখানে ক্লিক করুন এবং এটিকে `evtxlogs-*`-এ পরিবর্তন করুন।
এখন আপনি Discover টাইমলাইন দেখতে পাবেন।

## ফলাফল বিশ্লেষণ করা

ডিফল্ট Discover ভিউটি এই ধরনের দেখতে হওয়া উচিত:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

উপরের হিস্টোগ্রামের দিকে তাকিয়ে আপনি ইভেন্টগুলো কখন ঘটেছে এবং ইভেন্টের ফ্রিকোয়েন্সির একটি ওভারভিউ পেতে পারেন।

### কলাম যোগ করা

বাম-পাশের সাইডবারে, একটি ফিল্ডের উপর হোভার করার পর প্লাস চিহ্নে ক্লিক করে আপনি কলামে প্রদর্শন করতে চান এমন ফিল্ডগুলো যোগ করতে পারেন।
যেহেতু অনেক ফিল্ড আছে, আপনি হয়তো সার্চ বক্সে আপনার খুঁজছেন এমন ফিল্ডের নাম টাইপ করতে চাইবেন।

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

শুরু করার জন্য, আমরা নিম্নলিখিত কলামগুলোর পরামর্শ দিই:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

আপনার মনিটর যথেষ্ট প্রশস্ত হলে, আপনি হয়তো `ExtraFieldInfoText`-ও যোগ করতে চাইবেন যাতে আপনি সমস্ত ফিল্ডের তথ্য দেখতে পান।

আপনার Discover ভিউটি এখন এই রকম দেখতে হওয়া উচিত:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### ফিল্টারিং

আপনি নির্দিষ্ট ইভেন্ট এবং অ্যালার্ট খুঁজতে KQL(Kibana Query Language) দিয়ে ফিল্টার করতে পারেন। উদাহরণস্বরূপ:
  * `Level: "crit"`: শুধু critical অ্যালার্ট দেখান।
  * `Level: "crit" OR Level: "high"`: high এবং critical অ্যালার্ট দেখান।
  * `NOT Level: info`: তথ্যমূলক ইভেন্ট দেখাবেন না, শুধু অ্যালার্ট।
  * `MitreTactics: *LatMov*`: lateral movement সম্পর্কিত ইভেন্ট এবং অ্যালার্ট দেখান।
  * `"PW Spray"`: শুধু নির্দিষ্ট আক্রমণ যেমন "Password Spray" দেখান।
  * `"LID: 0x8724ead"`: Logon ID 0x8724ead-এর সাথে সম্পর্কিত সমস্ত কার্যকলাপ প্রদর্শন করুন।
  * `Details_TgtUser: admmig`: টার্গেট ইউজার `admmig` এমন সমস্ত ইভেন্ট খুঁজুন।

### বিস্তারিত টগল করা

একটি রেকর্ডের সমস্ত ফিল্ড পরীক্ষা করতে, শুধু টাইমস্ট্যাম্পের পাশের আইকনে (Toggle dialog with details) ক্লিক করুন:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### আশেপাশের ডকুমেন্ট দেখা

আপনি যদি একটি নির্দিষ্ট অ্যালার্টের ঠিক আগে এবং পরের ইভেন্টগুলো দেখতে চান, তাহলে প্রথমে সেই অ্যালার্টের বিস্তারিত খুলুন এবং তারপর উপরের ডানদিকে `View surrounding documents`-এ ক্লিক করুন:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

এই উদাহরণে, আমরা Pass the Hash আক্রমণ অ্যালার্টের আগে এবং পরের ইভেন্টগুলো দেখছি:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> দ্রষ্টব্য: আরও ইভেন্ট পুনরুদ্ধার করতে উপরের `Load x newer documents` বা নিচের `Load x older documents`-এর সংখ্যা পরিবর্তন করুন।

### ফিল্ডের দ্রুত মেট্রিক্স পাওয়া

বাম কলামে, আপনি যদি একটি ফিল্ডের নামে ক্লিক করেন তাহলে এটি তার ব্যবহারের উপর দ্রুত মেট্রিক্স দেবে:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> লক্ষ্য করুন যে গতির জন্য ডেটা স্যাম্পল করা হয়েছে তাই এটি ১০০% নির্ভুল নয়।

## ভবিষ্যৎ পরিকল্পনা

* CSV-এর জন্য Logstash পার্সার
* প্রি-বিল্ট ড্যাশবোর্ড
