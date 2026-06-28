## Event Count নিয়ম

এগুলো হলো এমন নিয়ম যা নির্দিষ্ট কিছু ইভেন্ট গণনা করে এবং যদি একটি নির্দিষ্ট সময়সীমার মধ্যে এই ইভেন্টগুলোর সংখ্যা অত্যধিক বেশি বা যথেষ্ট না হয়, তাহলে সতর্কতা দেয়।
একটি নির্দিষ্ট সময়সীমার মধ্যে অনেক ইভেন্ট শনাক্ত করার সাধারণ উদাহরণ হলো পাসওয়ার্ড অনুমান করার আক্রমণ, পাসওয়ার্ড স্প্রে আক্রমণ এবং পরিষেবা প্রত্যাখ্যান (denial of service) আক্রমণ শনাক্ত করা।
আপনি এই নিয়মগুলো লগ উৎসের নির্ভরযোগ্যতা সংক্রান্ত সমস্যা শনাক্ত করতেও ব্যবহার করতে পারেন, যেমন যখন নির্দিষ্ট ইভেন্ট একটি নির্দিষ্ট থ্রেশহোল্ডের নিচে নেমে যায়।

### Event Count নিয়মের উদাহরণ:

নিম্নলিখিত উদাহরণটি পাসওয়ার্ড অনুমান করার আক্রমণ শনাক্ত করতে দুটি নিয়ম ব্যবহার করে।
যখন রেফারেন্স করা নিয়মটি ৫ মিনিটের মধ্যে ৫ বা তার বেশি বার মিলে যায় এবং সেই ইভেন্টগুলোর জন্য `IpAddress` ক্ষেত্রটি একই থাকে, তখন একটি সতর্কতা থাকবে।

> মনে রাখবেন যে ধারণাটি বোঝার জন্য আমরা শুধুমাত্র প্রয়োজনীয় ক্ষেত্রগুলো অন্তর্ভুক্ত করেছি।
> এই উদাহরণটি যে সম্পূর্ণ নিয়মের উপর ভিত্তি করে তৈরি তা আপনার রেফারেন্সের জন্য [এখানে](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) অবস্থিত।

### Event Count কোরিলেশন নিয়ম:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Failed Logon - Incorrect Password নিয়ম:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### অপ্রচলিত (Deprecated) `count` নিয়মের উদাহরণ:

উপরের কোরিলেশন ও রেফারেন্স করা নিয়মগুলো নিম্নলিখিত নিয়মের মতোই একই ফলাফল প্রদান করে, যা পুরনো `count` মডিফায়ার ব্যবহার করে:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Event Count নিয়মের আউটপুট:

উপরের নিয়মগুলো নিম্নলিখিত আউটপুট তৈরি করবে:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Value Count নিয়ম

এই নিয়মগুলো একটি সময়সীমার মধ্যে একই ইভেন্ট গণনা করে যেখানে একটি প্রদত্ত ক্ষেত্রের **ভিন্ন** মান থাকে।

উদাহরণ:

- নেটওয়ার্ক স্ক্যান যেখানে একটি একক উৎস IP ঠিকানা অনেক ভিন্ন গন্তব্য IP ঠিকানা এবং/অথবা পোর্টের সাথে সংযোগ করার চেষ্টা করে।
- পাসওয়ার্ড স্প্রেয়িং আক্রমণ যেখানে একটি একক উৎস অনেক ভিন্ন ব্যবহারকারীর সাথে প্রমাণীকরণে ব্যর্থ হয়।
- BloodHound-এর মতো টুল শনাক্ত করা যা একটি সংক্ষিপ্ত সময়সীমার মধ্যে অনেক উচ্চ-সুবিধাপ্রাপ্ত AD গ্রুপ গণনা করে।

### Value Count নিয়মের উদাহরণ:

নিম্নলিখিত নিয়মটি শনাক্ত করে যখন একজন আক্রমণকারী ব্যবহারকারীর নাম অনুমান করার চেষ্টা করছে।
অর্থাৎ, যখন **একই** উৎস IP ঠিকানা (`IpAddress`) ৫ মিনিটের মধ্যে ৩টির বেশি **ভিন্ন** ব্যবহারকারীর নাম (`TargetUserName`) দিয়ে লগঅন করতে ব্যর্থ হয়।

> মনে রাখবেন যে ধারণাটি বোঝার জন্য আমরা শুধুমাত্র প্রয়োজনীয় ক্ষেত্রগুলো অন্তর্ভুক্ত করেছি।
> এই উদাহরণটি যে সম্পূর্ণ নিয়মের উপর ভিত্তি করে তৈরি তা আপনার রেফারেন্সের জন্য [এখানে](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) অবস্থিত।

### Value Count কোরিলেশন নিয়ম:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Value Count Logon Failure (Non-existant User) নিয়ম:

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### অপ্রচলিত (Deprecated) `count` মডিফায়ার নিয়ম:

উপরের কোরিলেশন ও রেফারেন্স করা নিয়মগুলো নিম্নলিখিত নিয়মের মতোই একই ফলাফল প্রদান করে, যা পুরনো `count` মডিফায়ার ব্যবহার করে:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Value Count নিয়মের আউটপুট:

উপরের নিয়মগুলো নিম্নলিখিত আউটপুট তৈরি করবে:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Temporal Proximity নিয়ম

rule ক্ষেত্র দ্বারা রেফারেন্স করা নিয়মগুলো দ্বারা সংজ্ঞায়িত সকল ইভেন্ট অবশ্যই timespan দ্বারা সংজ্ঞায়িত সময়সীমার মধ্যে ঘটতে হবে।
`group-by`-তে সংজ্ঞায়িত ক্ষেত্রগুলোর মান সবগুলো অবশ্যই একই মান থাকতে হবে (যেমন: একই হোস্ট, ব্যবহারকারী, ইত্যাদি...)।

### Temporal Proximity নিয়মের উদাহরণ:

উদাহরণ: তিনটি Sigma নিয়মে সংজ্ঞায়িত রিকনেসান্স কমান্ড একই ব্যবহারকারী দ্বারা একটি সিস্টেমে ৫ মিনিটের মধ্যে যেকোনো ক্রমে চালানো হয়।

### Temporal Proximity কোরিলেশন নিয়ম:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Ordered Temporal Proximity নিয়ম

`temporal_ordered` কোরিলেশন টাইপ `temporal`-এর মতো আচরণ করে এবং এর পাশাপাশি প্রয়োজন যে ইভেন্টগুলো `rules` অ্যাট্রিবিউটে প্রদত্ত ক্রমে উপস্থিত হবে।

### Ordered Temporal Proximity নিয়মের উদাহরণ:

উদাহরণ: উপরে সংজ্ঞায়িত অনেক ব্যর্থ লগইনের পরে ১ ঘণ্টার মধ্যে একই ব্যবহারকারী অ্যাকাউন্ট দ্বারা একটি সফল লগইন ঘটে:

### Ordered Temporal Proximity কোরিলেশন নিয়ম:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## কোরিলেশন নিয়ম সম্পর্কে নোট

1. আপনার সকল কোরিলেশন ও রেফারেন্স করা নিয়মগুলো একটি একক ফাইলে অন্তর্ভুক্ত করা উচিত এবং `---` একটি YAML বিভাজক দিয়ে সেগুলো পৃথক করা উচিত।

2. ডিফল্টভাবে, রেফারেন্স করা কোরিলেশন নিয়মগুলো আউটপুট করা হবে না। আপনি যদি রেফারেন্স করা নিয়মগুলোর আউটপুট দেখতে চান, তাহলে আপনাকে `correlation`-এর অধীনে `generate: true` যোগ করতে হবে। কোরিলেশন নিয়ম তৈরি করার সময় এটি চালু করা ও পরীক্ষা করা খুবই উপযোগী।

    উদাহরণ:
    ```
    correlation:
        generate: true
    ```
3. বিষয়গুলো বোঝা সহজ করার জন্য নিয়ম রেফারেন্স করার সময় আপনি রুল ID-এর পরিবর্তে অ্যালিয়াস নাম ব্যবহার করতে পারেন।

4. আপনি একাধিক নিয়ম রেফারেন্স করতে পারেন।

5. আপনি `group-by`-তে একাধিক ক্ষেত্র ব্যবহার করতে পারেন। আপনি যদি তা করেন, তাহলে সেই ক্ষেত্রগুলোর সকল মান একই হতে হবে অন্যথায় আপনি কোনো সতর্কতা পাবেন না। অধিকাংশ সময়, আপনি মিথ্যা পজিটিভ কমানোর জন্য `group-by` দিয়ে নির্দিষ্ট কিছু ক্ষেত্রে ফিল্টার করে নিয়ম লিখবেন, তবে একটি আরও জেনেরিক নিয়ম তৈরি করতে `group-by` বাদ দেওয়াও সম্ভব।

6. কোরিলেশন নিয়মের টাইমস্ট্যাম্প হবে আক্রমণের একদম শুরু, তাই এটি মিথ্যা পজিটিভ কিনা তা নিশ্চিত করতে আপনার সেই সময়ের পরবর্তী ইভেন্টগুলো পরীক্ষা করা উচিত।
