# অপ্রচলিত বৈশিষ্ট্যসমূহ

অপ্রচলিত বিশেষ কীওয়ার্ড এবং `count` অ্যাগ্রিগেশন এখনও Hayabusa-তে সমর্থিত, তবে ভবিষ্যতে রুলের ভেতরে ব্যবহার করা হবে না।

## অপ্রচলিত বিশেষ কীওয়ার্ড

বর্তমানে, নিম্নলিখিত বিশেষ কীওয়ার্ডগুলো নির্দিষ্ট করা যেতে পারে:

- `value`: স্ট্রিং দ্বারা মিল খোঁজে (ওয়াইল্ডকার্ড এবং পাইপও নির্দিষ্ট করা যেতে পারে)।
- `min_length`: অক্ষরের সংখ্যা নির্দিষ্ট সংখ্যার সমান বা তার বেশি হলে মিল খোঁজে।
- `regexes`: এই ফিল্ডে আপনি যে ফাইল নির্দিষ্ট করেন তার ভেতরের নিয়মিত এক্সপ্রেশনগুলোর একটি মিলে গেলে মিল খোঁজে।
- `allowlist`: এই ফিল্ডে আপনি যে ফাইল নির্দিষ্ট করেন তার ভেতরের নিয়মিত এক্সপ্রেশনের তালিকায় কোনো মিল পাওয়া গেলে রুলটি এড়িয়ে যাওয়া হবে।

নিচের উদাহরণে, নিম্নলিখিত শর্তগুলো সত্য হলে রুলটি মিলবে:

- `ServiceName`-কে `malicious-service` বলা হয় অথবা এতে `./rules/config/regex/detectlist_suspicous_services.txt`-এর একটি নিয়মিত এক্সপ্রেশন থাকে।
- `ImagePath`-এ ন্যূনতম 1000 অক্ষর আছে।
- `ImagePath`-এর `allowlist`-এ কোনো মিল নেই।

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

### regexes এবং allowlist কীওয়ার্ডের নমুনা ফাইল

Hayabusa-তে `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml` ফাইলের জন্য ব্যবহৃত দুটি অন্তর্নির্মিত নিয়মিত এক্সপ্রেশন ফাইল ছিল:

- `./rules/config/regex/detectlist_suspicous_services.txt`: সন্দেহজনক সার্ভিস নাম শনাক্ত করতে
- `./rules/config/regex/allowlist_legitimate_services.txt`: বৈধ সার্ভিসগুলোকে অনুমতি দিতে

`regexes` এবং `allowlist`-এ সংজ্ঞায়িত ফাইলগুলো সম্পাদনা করা যায়, যাতে কোনো রুল ফাইল নিজেই পরিবর্তন না করেই সেগুলোকে রেফারেন্স করা সকল রুলের আচরণ পরিবর্তন করা যায়।

আপনি নিজের তৈরি করা ভিন্ন detectlist এবং allowlist টেক্সটফাইলও ব্যবহার করতে পারেন।

## অপ্রচলিত অ্যাগ্রিগেশন শর্ত (`count` রুল)

এটি এখনও Hayabusa-তে সমর্থিত, তবে ভবিষ্যতে Sigma correlation রুল দ্বারা প্রতিস্থাপিত হবে।

### মৌলিক বিষয়

উপরে বর্ণিত `condition` কীওয়ার্ড শুধু `AND` এবং `OR` লজিকই বাস্তবায়ন করে না, বরং ইভেন্ট গণনা বা "অ্যাগ্রিগেট" করতেও সক্ষম।
এই ফাংশনকে "অ্যাগ্রিগেশন শর্ত" বলা হয় এবং এটি একটি শর্তকে পাইপ দিয়ে সংযুক্ত করে নির্দিষ্ট করা হয়।
নিচের এই পাসওয়ার্ড স্প্রে শনাক্তকরণ উদাহরণে, একটি শর্তসাপেক্ষ এক্সপ্রেশন ব্যবহার করা হয়েছে যা নির্ধারণ করে 5 মিনিট সময়সীমার মধ্যে একটি উৎস `IpAddress` থেকে 5 বা তার বেশি `TargetUserName` মান আছে কিনা।

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

অ্যাগ্রিগেশন শর্তগুলো নিম্নলিখিত ফরম্যাটে সংজ্ঞায়িত করা যায়:

- `count() {operator} {number}`: পাইপের আগের প্রথম শর্তের সাথে মিলে যাওয়া লগ ইভেন্টগুলোর জন্য, মিলে যাওয়া লগের সংখ্যা `{operator}` এবং `{number}` দ্বারা নির্দিষ্ট শর্ত এক্সপ্রেশন পূরণ করলে শর্তটি মিলবে।

`{operator}` নিম্নলিখিত যেকোনো একটি হতে পারে:

- `==`: মান নির্দিষ্ট মানের সমান হলে, এটি শর্তের সাথে মিলে যাওয়া হিসেবে বিবেচিত হয়।
- `>=`: মান নির্দিষ্ট মানের সমান বা তার বেশি হলে, শর্ত পূরণ হয়েছে বলে বিবেচিত হয়।
- `>`: মান নির্দিষ্ট মানের চেয়ে বেশি হলে, শর্ত পূরণ হয়েছে বলে বিবেচিত হয়।
- `<=`: মান নির্দিষ্ট মানের সমান বা তার কম হলে, শর্ত পূরণ হয়েছে বলে বিবেচিত হয়।
- `<`: মান নির্দিষ্ট মানের চেয়ে কম হলে, এটি শর্ত পূরণ হয়েছে বলে বিবেচিত হবে।

`{number}` অবশ্যই একটি সংখ্যা হতে হবে।

`timeframe` নিম্নলিখিতভাবে সংজ্ঞায়িত করা যায়:

- `15s`: 15 সেকেন্ড
- `30m`: 30 মিনিট
- `12h`: 12 ঘণ্টা
- `7d`: 7 দিন
- `3M`: 3 মাস

### অ্যাগ্রিগেশন শর্তের চারটি প্যাটার্ন

1. কোনো count আর্গুমেন্ট বা `by` কীওয়ার্ড নেই। উদাহরণ: `selection | count() > 10`
   > যদি `selection` সময়সীমার মধ্যে 10 বারের বেশি মেলে, তবে শর্তটি মিলবে।
   > এগুলো Event Count correlation রুল দ্বারা প্রতিস্থাপিত হয় যা `group-by` ফিল্ড ব্যবহার করে না।
2. কোনো count আর্গুমেন্ট নেই কিন্তু একটি `by` কীওয়ার্ড আছে। উদাহরণ: `selection | count() by IpAddress > 10`
   > **একই** `IpAddress`-এর জন্য `selection`-কে 10 বারের বেশি সত্য হতে হবে।
   > এই #2 রুলগুলো #1 রুলের চেয়ে বেশি সাধারণ।
   > আপনি গ্রুপ করার জন্য একাধিক ফিল্ডও নির্দিষ্ট করতে পারেন। উদাহরণস্বরূপ: `by IpAddress, Computer`
   > এগুলো Event Count correlation রুল দ্বারা প্রতিস্থাপিত হয় যা `group-by` ফিল্ড ব্যবহার করে।
3. একটি count আর্গুমেন্ট আছে কিন্তু কোনো `by` কীওয়ার্ড নেই। উদাহরণ: `selection | count(TargetUserName) > 10`
   > যদি `selection` মেলে এবং `TargetUserName` সময়সীমার মধ্যে 10 বারের বেশি **ভিন্ন** হয়, তবে শর্তটি মিলবে।
   > এগুলো Value Count correlation রুল দ্বারা প্রতিস্থাপিত হয় যা `group-by` ফিল্ড ব্যবহার করে না।
4. একটি count আর্গুমেন্ট এবং `by` কীওয়ার্ড উভয়ই আছে। উদাহরণ: `selection | count(Users) by IpAddress > 10`
   > **একই** `IpAddress`-এর জন্য, শর্ত মেলার জন্য 10টির বেশি **ভিন্ন** `TargetUserName` থাকতে হবে।
   > এই #4 রুলগুলো #3 রুলের চেয়ে বেশি সাধারণ।
   > এগুলো Value Count correlation রুল দ্বারা প্রতিস্থাপিত হয় যা `group-by` ফিল্ড ব্যবহার করে।

### প্যাটার্ন 1 উদাহরণ

এটি সবচেয়ে মৌলিক প্যাটার্ন: `count() {operator} {number}`। নিচের রুলটি `selection` 3 বা তার বেশি বার ঘটলে মিলবে।

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### প্যাটার্ন 2 উদাহরণ

`count() by {eventkey} {operator} {number}`: পাইপের আগের `condition`-এর সাথে মিলে যাওয়া লগ ইভেন্টগুলো **একই** `{eventkey}` দ্বারা গ্রুপ করা হয়। প্রতিটি গ্রুপিংয়ের জন্য মিলে যাওয়া ইভেন্টের সংখ্যা `{operator}` এবং `{number}` দ্বারা নির্দিষ্ট শর্ত পূরণ করলে, শর্তটি মিলবে।

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### প্যাটার্ন 3 উদাহরণ

`count({eventkey}) {operator} {number}`: শর্ত পাইপের আগের শর্তের সাথে মিলে যাওয়া লগ ইভেন্টে `{eventkey}`-এর কতটি **ভিন্ন** মান বিদ্যমান তা গণনা করে। সংখ্যাটি `{operator}` এবং `{number}`-এ নির্দিষ্ট শর্তসাপেক্ষ এক্সপ্রেশন পূরণ করলে, শর্ত পূরণ হয়েছে বলে বিবেচিত হয়।

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### প্যাটার্ন 4 উদাহরণ

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: শর্ত পাইপের আগের শর্তের সাথে মিলে যাওয়া লগগুলো **একই** `{eventkey_2}` দ্বারা গ্রুপ করা হয়, এবং প্রতিটি গ্রুপে `{eventkey_1}`-এর **ভিন্ন** মানের সংখ্যা গণনা করা হয়। প্রতিটি গ্রুপিংয়ের জন্য গণনা করা মানগুলো `{operator}` এবং `{number}` দ্বারা নির্দিষ্ট শর্তসাপেক্ষ এক্সপ্রেশন পূরণ করলে, শর্তটি মিলবে।

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Count রুলের আউটপুট

count রুলের বিস্তারিত আউটপুট নির্দিষ্ট এবং `[condition]`-এ মূল count শর্তটি মুদ্রণ করবে, এরপর `[result]`-এ রেকর্ড করা eventkey-গুলো মুদ্রণ করবে।

নিচের উদাহরণে, ব্রুটফোর্স করা হচ্ছিল এমন `TargetUserName` ইউজারনেমের একটি তালিকা এবং তারপর উৎস `IpAddress`:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

অ্যালার্টের টাইমস্ট্যাম্প হবে শনাক্ত হওয়া প্রথম ইভেন্টের সময়।
