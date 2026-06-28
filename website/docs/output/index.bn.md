# টাইমলাইন আউটপুট

## আউটপুট প্রোফাইল

Hayabusa-তে `config/profiles.yaml`-এ ব্যবহারের জন্য ৫টি পূর্ব-নির্ধারিত আউটপুট প্রোফাইল রয়েছে:

1. `minimal`
2. `standard` (default)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

এই ফাইলটি সম্পাদনা করে আপনি সহজেই আপনার নিজস্ব প্রোফাইল কাস্টমাইজ করতে বা যোগ করতে পারেন।
আপনি `set-default-profile --profile <profile>` দিয়ে ডিফল্ট প্রোফাইলও সহজে পরিবর্তন করতে পারেন।
উপলব্ধ প্রোফাইল এবং তাদের ফিল্ড তথ্য দেখাতে `list-profiles` কমান্ড ব্যবহার করুন।

### 1. `minimal` প্রোফাইল আউটপুট

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard` প্রোফাইল আউটপুট

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose` প্রোফাইল আউটপুট

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info` প্রোফাইল আউটপুট

ন্যূনতম `details` তথ্য আউটপুট করার পরিবর্তে, `EventData` এবং `UserData` বিভাগের সমস্ত ফিল্ড তথ্য তাদের মূল ফিল্ড নামসহ আউটপুট করা হবে।

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose` প্রোফাইল আউটপুট

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose` প্রোফাইল আউটপুট

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal` প্রোফাইল আউটপুট

[Timesketch](https://timesketch.org/)-এ ইম্পোর্ট করার সাথে সামঞ্জস্যপূর্ণ একটি ফরম্যাটে আউটপুট।

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose` প্রোফাইল আউটপুট

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### প্রোফাইল তুলনা

নিম্নলিখিত বেঞ্চমার্কগুলি একটি 2018 Lenovo P51 (Xeon 4 Core CPU / 64GB RAM)-এ 3GB evtx ডেটা এবং 3891টি রুল সক্রিয় রেখে পরিচালিত হয়েছিল। (2023/06/01)

| প্রোফাইল | প্রসেসিং সময় | আউটপুট ফাইলসাইজ | ফাইলসাইজ বৃদ্ধি |
| :---: | :---: | :---: | :---: |
| minimal | 8 minutes 50 seconds | 770 MB | -30% |
| standard (default) | 9 minutes 00 seconds | 1.1 GB | None |
| verbose | 9 minutes 10 seconds | 1.3 GB | +20% |
| all-field-info | 9 minutes 3 seconds | 1.2 GB | +10% |
| all-field-info-verbose | 9 minutes 10 seconds | 1.3 GB | +20% |
| super-verbose | 9 minutes 12 seconds | 1.5 GB | +35% |

### প্রোফাইল ফিল্ড অ্যালিয়াস

নিম্নলিখিত তথ্য বিল্ট-ইন আউটপুট প্রোফাইল দিয়ে আউটপুট করা যেতে পারে:

| অ্যালিয়াস নাম | Hayabusa আউটপুট তথ্য|
| :--- | :--- |
|%AllFieldInfo% | সমস্ত ফিল্ড তথ্য। |
|%Channel% | লগের নাম। `<Event><System><Channel>` ফিল্ড। |
|%Computer% | `<Event><System><Computer>` ফিল্ড। |
|%Details% | YML ডিটেকশন রুলের `details` ফিল্ড, তবে কেবল hayabusa রুলগুলিতেই এই ফিল্ড থাকে। এই ফিল্ডটি অ্যালার্ট বা ইভেন্ট সম্পর্কে অতিরিক্ত তথ্য দেয় এবং ইভেন্ট লগের ফিল্ড থেকে উপযোগী ডেটা নিষ্কাশন করতে পারে। উদাহরণস্বরূপ, ইউজারনেম, কমান্ড লাইন তথ্য, প্রসেস তথ্য, ইত্যাদি... যখন একটি প্লেসহোল্ডার এমন একটি ফিল্ডের দিকে নির্দেশ করে যা বিদ্যমান নেই অথবা একটি ভুল অ্যালিয়াস ম্যাপিং থাকে, তখন এটি `n/a` (not available) হিসাবে আউটপুট হবে। যদি `details` ফিল্ড নির্দিষ্ট করা না থাকে (অর্থাৎ sigma রুল), তাহলে `./rules/config/default_details.txt`-এ সংজ্ঞায়িত ফিল্ড নিষ্কাশনের জন্য ডিফল্ট `details` বার্তা আউটপুট করা হবে। আপনি `default_details.txt`-এ আউটপুট করতে চাওয়া `Provider Name`, `EventID` এবং `details` বার্তা যোগ করে আরও ডিফল্ট `details` বার্তা যোগ করতে পারেন। যখন কোনো রুলে বা `default_details.txt`-এ কোনো `details` ফিল্ড সংজ্ঞায়িত থাকে না, তখন সমস্ত ফিল্ড `details` কলামে আউটপুট করা হবে। |
|%ExtraFieldInfo% | %Details%-এ যে ফিল্ড তথ্য আউটপুট করা হয়নি তা প্রিন্ট করুন। |
|%EventID% | `<Event><System><EventID>` ফিল্ড। |
|%EvtxFile% | যে evtx ফাইলটি অ্যালার্ট বা ইভেন্টের কারণ হয়েছিল তার নাম। |
|%Level% | YML ডিটেকশন রুলের `level` ফিল্ড। (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [tactics](https://attack.mitre.org/tactics/enterprise/) (যেমন: Initial Access, Lateral Movement, ইত্যাদি...)। |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID এবং Software ID। |
|%OtherTags% | YML ডিটেকশন রুলের `tags` ফিল্ডের যেকোনো কীওয়ার্ড যা `MitreTactics` বা `MitreTags`-এ অন্তর্ভুক্ত নয়। |
|%Provider% | `<Event><System><Provider>` ফিল্ডের `Name` অ্যাট্রিবিউট। |
|%RecordID% | `<Event><System><EventRecordID>` ফিল্ড থেকে Event Record ID। |
|%RuleAuthor% | YML ডিটেকশন রুলের `author` ফিল্ড। |
|%RuleCreationDate% | YML ডিটেকশন রুলের `date` ফিল্ড। |
|%RuleFile% | যে ডিটেকশন রুলটি অ্যালার্ট বা ইভেন্ট তৈরি করেছে তার ফাইলনাম। |
|%RuleID% | YML ডিটেকশন রুলের `id` ফিল্ড। |
|%RuleModifiedDate% | YML ডিটেকশন রুলের `modified` ফিল্ড। |
|%RuleTitle% | YML ডিটেকশন রুলের `title` ফিল্ড। |
|%Status% | YML ডিটেকশন রুলের `status` ফিল্ড। |
|%Timestamp% | ডিফল্ট হল `YYYY-MM-DD HH:mm:ss.sss +hh:mm` ফরম্যাট। ইভেন্ট লগে `<Event><System><TimeCreated SystemTime>` ফিল্ড। ডিফল্ট টাইমজোন হবে লোকাল টাইমজোন তবে আপনি `--UTC` অপশন দিয়ে টাইমজোন UTC-তে পরিবর্তন করতে পারেন। |

#### অতিরিক্ত প্রোফাইল ফিল্ড অ্যালিয়াস

প্রয়োজন হলে আপনি আপনার আউটপুট প্রোফাইলে এই অতিরিক্ত অ্যালিয়াসও যোগ করতে পারেন:

| অ্যালিয়াস নাম | Hayabusa আউটপুট তথ্য|
| :--- | :--- |
|%RenderedMessage% | WEC ফরোয়ার্ডেড লগে `<Event><RenderingInfo><Message>` ফিল্ড। |

দ্রষ্টব্য: এটি কোনো বিল্ট-ইন প্রোফাইলে অন্তর্ভুক্ত **নয়** তাই আপনাকে ম্যানুয়ালি `config/default_profile.yaml` ফাইলটি সম্পাদনা করে নিম্নলিখিত লাইনটি যোগ করতে হবে:

```
Message: "%RenderedMessage%"
```

অন্যান্য ফিল্ড আউটপুট করতে আপনি [event key aliases](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases)-ও সংজ্ঞায়িত করতে পারেন।
