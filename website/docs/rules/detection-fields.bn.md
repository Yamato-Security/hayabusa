# ডিটেকশন ফিল্ড

## সিলেকশন মৌলিক বিষয়সমূহ

প্রথমে, কীভাবে একটি সিলেকশন রুল তৈরি করতে হয় তার মৌলিক বিষয়গুলো ব্যাখ্যা করা হবে।

### কীভাবে AND এবং OR লজিক লিখতে হয়

AND লজিক লিখতে আমরা নেস্টেড ডিকশনারি ব্যবহার করি।
নিচের ডিটেকশন রুলটি সংজ্ঞায়িত করে যে রুলটি ম্যাচ করার জন্য **উভয় শর্ত** সত্য হতে হবে।
- EventID ঠিক `7040` হতে হবে।
- **AND**
- Channel ঠিক `System` হতে হবে।

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

OR লজিক লিখতে আমরা লিস্ট ব্যবহার করি (যে ডিকশনারিগুলো `-` দিয়ে শুরু হয়)।
নিচের ডিটেকশন রুলে, শর্তগুলোর **যেকোনো একটি** সত্য হলেই রুলটি ট্রিগার হবে।
- EventID ঠিক `7040` হতে হবে।
- **OR**
- Channel ঠিক `System` হতে হবে।

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

আমরা নিচে দেখানো অনুযায়ী `AND` এবং `OR` লজিকও একসাথে ব্যবহার করতে পারি।
এই ক্ষেত্রে, রুলটি তখন ম্যাচ করে যখন নিচের দুটি শর্তই সত্য হয়।
- EventID ঠিক `7040` **OR** `7041` হয়।
- **AND**
- Channel ঠিক `System` হয়।

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkey

নিচে একটি Windows ইভেন্ট লগের একটি অংশ দেওয়া হলো, যা মূল XML ফরম্যাটে রয়েছে।
উপরের রুল ফাইলের উদাহরণে থাকা `Event.System.Channel` ফিল্ডটি মূল XML ট্যাগকে নির্দেশ করে: `<Event><System><Channel>System<Channel><System></Event>`
নেস্টেড XML ট্যাগগুলোকে ডট (`.`) দিয়ে পৃথক করা ট্যাগ নাম দিয়ে প্রতিস্থাপন করা হয়।
hayabusa রুলে, ডট দিয়ে যুক্ত এই ফিল্ড স্ট্রিংগুলোকে `eventkeys` বলা হয়।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Eventkey অ্যালিয়াস

অনেক `.` দিয়ে পৃথক করা দীর্ঘ eventkey সাধারণ ব্যাপার, তাই hayabusa এগুলো সহজে ব্যবহার করার জন্য অ্যালিয়াস ব্যবহার করবে। অ্যালিয়াসগুলো `rules/config/eventkey_alias.txt` ফাইলে সংজ্ঞায়িত করা থাকে। এই ফাইলটি একটি CSV ফাইল যা `alias` এবং `event_key` ম্যাপিং দিয়ে গঠিত। আপনি উপরের রুলটি নিচে দেখানো অনুযায়ী অ্যালিয়াস দিয়ে পুনরায় লিখতে পারেন যা রুলটিকে পড়তে সহজ করে তোলে।

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### সতর্কতা: অসংজ্ঞায়িত Eventkey অ্যালিয়াস

সব eventkey অ্যালিয়াস `rules/config/eventkey_alias.txt`-এ সংজ্ঞায়িত করা নেই। যদি আপনি `details` (`Alert details`) মেসেজে সঠিক ডেটা না পান, বরং `n/a` (not available) পান অথবা যদি আপনার ডিটেকশন লজিকের সিলেকশন সঠিকভাবে কাজ না করে, তাহলে আপনাকে `rules/config/eventkey_alias.txt` একটি নতুন অ্যালিয়াস দিয়ে আপডেট করতে হতে পারে।

### কন্ডিশনে XML অ্যাট্রিবিউট কীভাবে ব্যবহার করতে হয়

XML এলিমেন্টে এলিমেন্টের সাথে একটি স্পেস যোগ করে অ্যাট্রিবিউট সেট করা যেতে পারে। উদাহরণস্বরূপ, নিচের `Provider Name`-এ থাকা `Name` হলো `Provider` এলিমেন্টের একটি XML অ্যাট্রিবিউট।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

একটি eventkey-তে XML অ্যাট্রিবিউট নির্দিষ্ট করতে, `{eventkey}_attributes.{attribute_name}` ফরম্যাট ব্যবহার করুন। উদাহরণস্বরূপ, একটি রুল ফাইলে `Provider` এলিমেন্টের `Name` অ্যাট্রিবিউট নির্দিষ্ট করতে, এটি এরকম দেখাবে:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep সার্চ

কোনো eventkey নির্দিষ্ট না করে Hayabusa Windows ইভেন্ট লগ ফাইলে grep সার্চ করতে পারে।

একটি grep সার্চ করতে, নিচে দেখানো অনুযায়ী ডিটেকশন নির্দিষ্ট করুন। এই ক্ষেত্রে, যদি Windows ইভেন্ট লগে `mimikatz` বা `metasploit` স্ট্রিং অন্তর্ভুক্ত থাকে, তাহলে এটি ম্যাচ করবে। ওয়াইল্ডকার্ড নির্দিষ্ট করাও সম্ভব।

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> নোট: Hayabusa ডেটা প্রসেস করার আগে অভ্যন্তরীণভাবে Windows ইভেন্ট লগ ডেটাকে JSON ফরম্যাটে রূপান্তর করে, তাই XML ট্যাগে ম্যাচ করা সম্ভব নয়।

### EventData

Windows ইভেন্ট লগ দুটি অংশে বিভক্ত: `System` অংশ যেখানে মৌলিক ডেটা (Event ID, Timestamp, Record ID, Log name (Channel)) লেখা হয়, এবং `EventData` বা `UserData` অংশ যেখানে Event ID অনুযায়ী যেকোনো ডেটা লেখা হয়।
যে সমস্যাটি প্রায়ই দেখা দেয় তা হলো `EventData`-তে নেস্টেড ফিল্ডগুলোর নাম সবই `Data` বলে ডাকা হয়, তাই এতক্ষণ বর্ণিত eventkey-গুলো `SubjectUserSid` এবং `SubjectUserName`-এর মধ্যে পার্থক্য করতে পারে না।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

এই সমস্যাটি মোকাবিলা করতে, আপনি `Data Name`-এ অ্যাসাইন করা মানটি নির্দিষ্ট করতে পারেন। উদাহরণস্বরূপ, যদি আপনি EventData-তে থাকা `SubjectUserName` এবং `SubjectDomainName` একটি রুলের শর্ত হিসেবে ব্যবহার করতে চান, তাহলে আপনি এটি নিম্নরূপে বর্ণনা করতে পারেন:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventData-তে অস্বাভাবিক প্যাটার্ন

`EventData`-তে নেস্টেড কিছু ট্যাগে `Name` অ্যাট্রিবিউট থাকে না।

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

উপরের মতো একটি ইভেন্ট লগ শনাক্ত করতে, আপনি `Data` নামের একটি eventkey নির্দিষ্ট করতে পারেন।
এই ক্ষেত্রে, নেস্টেড `Data` ট্যাগগুলোর যেকোনো একটি `None`-এর সমান হলেই শর্তটি ম্যাচ করবে।

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### একই নামের একাধিক ফিল্ড নাম থেকে ফিল্ড ডেটা আউটপুট করা

কিছু ইভেন্ট পূর্ববর্তী উদাহরণের মতো তাদের ডেটা `Data` নামের ফিল্ডে সংরক্ষণ করবে।
যদি আপনি `details:`-এ `%Data%` নির্দিষ্ট করেন, তাহলে সমস্ত ডেটা একটি অ্যারেতে আউটপুট হবে।

উদাহরণস্বরূপ:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

যদি আপনি শুধুমাত্র প্রথম `Data` ফিল্ড ডেটা প্রিন্ট করতে চান, তাহলে আপনি আপনার `details:` অ্যালার্ট স্ট্রিংয়ে `%Data[1]%` নির্দিষ্ট করতে পারেন এবং শুধুমাত্র `rundll32.exe` আউটপুট হবে।

## ফিল্ড মডিফায়ার

স্ট্রিং ম্যাচ করার জন্য নিচে দেখানো অনুযায়ী eventkey-এর সাথে একটি পাইপ ক্যারেক্টার ব্যবহার করা যেতে পারে।
এতক্ষণ বর্ণিত সমস্ত শর্ত হুবহু ম্যাচ ব্যবহার করে, কিন্তু ফিল্ড মডিফায়ার ব্যবহার করে আপনি আরও নমনীয় ডিটেকশন রুল বর্ণনা করতে পারেন।
নিচের উদাহরণে, যদি `Data`-এর একটি মান `EngineVersion=2` স্ট্রিং ধারণ করে, তাহলে এটি শর্তটির সাথে ম্যাচ করবে।

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

স্ট্রিং ম্যাচগুলো কেস ইনসেনসিটিভ। তবে, যখনই `|re` বা `|equalsfield` ব্যবহার করা হয় তখন এগুলো কেস সেনসিটিভ হয়ে যায়।

### সমর্থিত Sigma ফিল্ড মডিফায়ার

Hayabusa বর্তমানে একমাত্র ওপেন-সোর্স টুল যা Sigma স্পেসিফিকেশনের সবকিছু সম্পূর্ণভাবে সমর্থন করে।

আপনি সমস্ত সমর্থিত ফিল্ড মডিফায়ারের বর্তমান অবস্থা এবং এই মডিফায়ারগুলো Sigma ও Hayabusa রুলে কতবার ব্যবহৃত হয়েছে তা https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md -এ দেখতে পারেন।
Sigma বা Hayabusa রুলে যখনই কোনো আপডেট হয় তখনই এই ডকুমেন্টটি গতিশীলভাবে আপডেট হয়।

- `'|all':`: এই ফিল্ড মডিফায়ারটি উপরের মডিফায়ারগুলো থেকে আলাদা কারণ এটি একটি নির্দিষ্ট ফিল্ডে প্রয়োগ হয় না বরং সমস্ত ফিল্ডে প্রয়োগ হয়।

    এই উদাহরণে, `Keyword-1` এবং `Keyword-2` উভয় স্ট্রিংই থাকতে হবে কিন্তু যেকোনো ফিল্ডে যেকোনো জায়গায় থাকতে পারে:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: এনকোডেড স্ট্রিংয়ে ডেটার অবস্থান অনুযায়ী এটি তিনটি ভিন্ন উপায়ে base64-এ এনকোড হবে। এই মডিফায়ারটি একটি স্ট্রিংকে তিনটি ভিন্ন রূপেই এনকোড করবে এবং স্ট্রিংটি base64 স্ট্রিংয়ের কোথাও এনকোড করা আছে কিনা তা পরীক্ষা করবে।
- `|cased`: সার্চকে কেস-সেনসিটিভ করে তোলে।
- `|cidr`: একটি ফিল্ড মান IPv4 বা IPv6 CIDR নোটেশনে ম্যাচ করে কিনা তা পরীক্ষা করে। (উদাহরণ: `192.0.2.0/24`)
- `|contains`: একটি ফিল্ড মান একটি নির্দিষ্ট স্ট্রিং ধারণ করে কিনা তা পরীক্ষা করে।
- `|contains|all`: ডেটায় একাধিক শব্দ অন্তর্ভুক্ত আছে কিনা তা পরীক্ষা করে।
- `|contains|all|windash`: `|contains|windash`-এর মতোই কিন্তু সমস্ত কীওয়ার্ড উপস্থিত থাকতে হবে।
- `|contains|cased`: একটি ফিল্ড মান একটি নির্দিষ্ট কেস-সেনসিটিভ স্ট্রিং ধারণ করে কিনা তা পরীক্ষা করে।
- `|contains|expand`: একটি ফিল্ড মান `/config/expand/`-এর ভিতরে `expand` কনফিগ ফাইলের একটি স্ট্রিং ধারণ করে কিনা তা পরীক্ষা করে।
- `|contains|windash`: স্ট্রিংটিকে যেমন আছে তেমন পরীক্ষা করবে, সেইসাথে প্রথম `-` ক্যারেক্টারকে `/`, `–` (en dash), `—` (em dash), এবং `―` (horizontal bar) ক্যারেক্টার পারমুটেশনে রূপান্তর করবে।
- `|endswith`: একটি ফিল্ড মান একটি নির্দিষ্ট স্ট্রিং দিয়ে শেষ হয় কিনা তা পরীক্ষা করে।
- `|endswith|cased`: একটি ফিল্ড মান একটি নির্দিষ্ট কেস-সেনসিটিভ স্ট্রিং দিয়ে শেষ হয় কিনা তা পরীক্ষা করে।
- `|endswith|windash`: স্ট্রিংয়ের শেষ অংশ পরীক্ষা করে এবং ড্যাশের জন্য বিভিন্ন রূপ সম্পাদন করে।
- `|exists`: একটি ফিল্ড বিদ্যমান কিনা তা পরীক্ষা করে।
- `|expand`: একটি ফিল্ড মান `/config/expand/`-এর ভিতরে `expand` কনফিগ ফাইলের একটি স্ট্রিংয়ের সমান কিনা তা পরীক্ষা করে।
- `|fieldref`: দুটি ফিল্ডের মান একই কিনা তা পরীক্ষা করে। যদি আপনি দুটি ফিল্ড ভিন্ন কিনা তা পরীক্ষা করতে চান তাহলে আপনি `condition`-এ `not` ব্যবহার করতে পারেন।
- `|fieldref|contains`: একটি ফিল্ডের মান অন্য একটি ফিল্ডে অন্তর্ভুক্ত আছে কিনা তা পরীক্ষা করে।
- `|fieldref|endswith`: বাম দিকের ফিল্ডটি ডান দিকের ফিল্ডের স্ট্রিং দিয়ে শেষ হয় কিনা তা পরীক্ষা করে। এগুলো ভিন্ন কিনা তা পরীক্ষা করতে আপনি `condition`-এ `not` ব্যবহার করতে পারেন।
- `|fieldref|startswith`: বাম দিকের ফিল্ডটি ডান দিকের ফিল্ডের স্ট্রিং দিয়ে শুরু হয় কিনা তা পরীক্ষা করে। এগুলো ভিন্ন কিনা তা পরীক্ষা করতে আপনি `condition`-এ `not` ব্যবহার করতে পারেন।
- `|gt`: একটি ফিল্ড মান একটি নির্দিষ্ট সংখ্যার চেয়ে বড় কিনা তা পরীক্ষা করে।
- `|gte`: একটি ফিল্ড মান একটি নির্দিষ্ট সংখ্যার চেয়ে বড় বা সমান কিনা তা পরীক্ষা করে।
- `|lt`: একটি ফিল্ড মান একটি নির্দিষ্ট সংখ্যার চেয়ে ছোট কিনা তা পরীক্ষা করে।
- `|lte`: একটি ফিল্ড মান একটি নির্দিষ্ট সংখ্যার চেয়ে ছোট বা সমান কিনা তা পরীক্ষা করে।
- `|re`: কেস-সেনসিটিভ রেগুলার এক্সপ্রেশন ব্যবহার করুন। (আমরা regex crate ব্যবহার করছি তাই কীভাবে সমর্থিত রেগুলার এক্সপ্রেশন লিখতে হয় তা শিখতে অনুগ্রহ করে <https://docs.rs/regex/latest/regex/#syntax>-এর ডকুমেন্টেশন দেখুন।)
    > সতর্কতা: [Sigma রুলে রেগুলার এক্সপ্রেশন সিনট্যাক্স](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) PCRE ব্যবহার করে যেখানে ক্যারেক্টার ক্লাস, lookbehind, atomic grouping ইত্যাদির জন্য কিছু নির্দিষ্ট মেটাক্যারেক্টার অসমর্থিত। Rust regex crate Sigma রুলের সমস্ত রেগুলার এক্সপ্রেশন ব্যবহার করতে সক্ষম হওয়া উচিত কিন্তু অসামঞ্জস্যতার সম্ভাবনা আছে।
- `|re|i`: (Insensitive) কেস-ইনসেনসিটিভ রেগুলার এক্সপ্রেশন ব্যবহার করুন।
- `|re|m`: (Multi-line) একাধিক লাইন জুড়ে ম্যাচ করুন। `^` / `$` লাইনের শুরু/শেষ ম্যাচ করে।
- `|re|s`: (Single-line) ডট (`.`) নিউলাইন ক্যারেক্টার সহ সমস্ত ক্যারেক্টার ম্যাচ করে।
- `|startswith`: একটি ফিল্ড মান একটি নির্দিষ্ট স্ট্রিং দিয়ে শুরু হয় কিনা তা পরীক্ষা করে।
- `|startswith|cased`: একটি ফিল্ড মান একটি নির্দিষ্ট কেস-সেনসিটিভ স্ট্রিং দিয়ে শুরু হয় কিনা তা পরীক্ষা করে।
- `|utf16|base64offset|contains`: একটি নির্দিষ্ট UTF-16 স্ট্রিং একটি base64 স্ট্রিংয়ের ভিতরে এনকোড করা আছে কিনা তা পরীক্ষা করে।
- `|utf16be|base64offset|contains`: একটি নির্দিষ্ট UTF-16 big-endian স্ট্রিং একটি base64 স্ট্রিংয়ের ভিতরে এনকোড করা আছে কিনা তা পরীক্ষা করে।
- `|utf16le|base64offset|contains`: একটি নির্দিষ্ট UTF-16 little-endian স্ট্রিং একটি base64 স্ট্রিংয়ের ভিতরে এনকোড করা আছে কিনা তা পরীক্ষা করে।
- `|wide|base64offset|contains`: `utf16le|base64offset|contains`-এর অ্যালিয়াস, UTF-16 little-endian স্ট্রিংয়ের জন্য পরীক্ষা করে।

### অপ্রচলিত ফিল্ড মডিফায়ার

নিচের মডিফায়ারগুলো এখন অপ্রচলিত এবং Sigma স্পেসিফিকেশন আরও মেনে চলে এমন মডিফায়ার দিয়ে প্রতিস্থাপিত হয়েছে।

- `|equalsfield`: এখন `|fieldref` দিয়ে প্রতিস্থাপিত হয়েছে।
- `|endswithfield`: এখন `|fieldref|endswith` দিয়ে প্রতিস্থাপিত হয়েছে।

### Expand ফিল্ড মডিফায়ার

`expand` ফিল্ড মডিফায়ারগুলো অনন্য কারণ এগুলোই একমাত্র ফিল্ড মডিফায়ার যা ব্যবহার করার আগে কনফিগারেশন প্রয়োজন।
উদাহরণস্বরূপ, এগুলো `%DC-MACHINE-NAME%`-এর মতো প্লেসহোল্ডার ব্যবহার করে এবং `/config/expand/DC-MACHINE-NAME.txt` নামের একটি কনফিগ ফাইল প্রয়োজন যাতে সমস্ত সম্ভাব্য DC মেশিন নাম থাকে।

এটি কীভাবে কনফিগার করতে হয় তা [এখানে](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command) আরও বিস্তারিতভাবে ব্যাখ্যা করা হয়েছে।

## ওয়াইল্ডকার্ড

eventkey-তে ওয়াইল্ডকার্ড ব্যবহার করা যেতে পারে। নিচের উদাহরণে, যদি `ProcessCommandLine` "malware" স্ট্রিং দিয়ে শুরু হয়, তাহলে রুলটি ম্যাচ করবে।
স্পেসিফিকেশনটি মূলত sigma রুল ওয়াইল্ডকার্ডের মতোই তাই এটি কেস ইনসেনসিটিভ হবে।

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

নিচের দুটি ওয়াইল্ডকার্ড ব্যবহার করা যেতে পারে।
- `*`: শূন্য বা একাধিক ক্যারেক্টারের যেকোনো স্ট্রিং ম্যাচ করে। (অভ্যন্তরীণভাবে এটি রেগুলার এক্সপ্রেশন `.*`-এ রূপান্তরিত হয়)
- `?`: যেকোনো একটি ক্যারেক্টার ম্যাচ করে। (অভ্যন্তরীণভাবে রেগুলার এক্সপ্রেশন `.`-এ রূপান্তরিত হয়)

ওয়াইল্ডকার্ড এস্কেপ করা সম্পর্কে:
- ওয়াইল্ডকার্ড (`*` এবং `?`) একটি ব্যাকস্ল্যাশ ব্যবহার করে এস্কেপ করা যেতে পারে: `\*`, `\?`।
- যদি আপনি একটি ওয়াইল্ডকার্ডের ঠিক আগে একটি ব্যাকস্ল্যাশ ব্যবহার করতে চান তাহলে `\\*` বা `\\?` লিখুন।
- যদি আপনি ব্যাকস্ল্যাশ একা ব্যবহার করেন তাহলে এস্কেপ করার প্রয়োজন নেই।

## null কীওয়ার্ড

একটি ফিল্ড বিদ্যমান নেই কিনা তা পরীক্ষা করতে `null` কীওয়ার্ড ব্যবহার করা যেতে পারে।

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

নোট: এটি `ProcessCommandLine: ''` থেকে আলাদা যা একটি ফিল্ডের মান খালি কিনা তা পরীক্ষা করে।

## condition

আমরা উপরে যে নোটেশন ব্যাখ্যা করেছি তা দিয়ে আপনি `AND` এবং `OR` লজিক প্রকাশ করতে পারেন কিন্তু যদি আপনি জটিল লজিক সংজ্ঞায়িত করার চেষ্টা করেন তাহলে এটি বিভ্রান্তিকর হবে।
যখন আপনি আরও জটিল রুল তৈরি করতে চান, তখন আপনার নিচে দেখানো অনুযায়ী `condition` কীওয়ার্ড ব্যবহার করা উচিত।

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

`condition`-এর জন্য নিচের এক্সপ্রেশনগুলো ব্যবহার করা যেতে পারে।
- `{expression1} and {expression2}`: {expression1} এবং {expression2} উভয়ই প্রয়োজন
- `{expression1} or {expression2}`: {expression1} বা {expression2}-এর যেকোনো একটি প্রয়োজন
- `not {expression}`: {expression}-এর লজিক উল্টে দেয়
- `( {expression} )`: {expression}-এর প্রাধান্য সেট করে। এটি গণিতের মতোই একই প্রাধান্য লজিক অনুসরণ করে।

উপরের উদাহরণে, `SELECTION_1`, `SELECTION_2` ইত্যাদির মতো সিলেকশন নাম ব্যবহার করা হয়েছে কিন্তু এগুলোকে যেকোনো নাম দেওয়া যেতে পারে যতক্ষণ পর্যন্ত এগুলোতে কেবল নিচের ক্যারেক্টারগুলো থাকে: `a-z A-Z 0-9 _`
> তবে, যখনই সম্ভব জিনিসগুলো পড়তে সহজ করতে অনুগ্রহ করে `selection_1`, `selection_2`, `filter_1`, `filter_2` ইত্যাদির স্ট্যান্ডার্ড কনভেনশন ব্যবহার করুন।

## not লজিক

অনেক রুল false positive-এর ফলাফল দেবে তাই signature খোঁজার জন্য একটি সিলেকশন থাকা কিন্তু false positive-এ অ্যালার্ট না দেওয়ার জন্য একটি ফিল্টার সিলেকশন থাকা খুবই সাধারণ।
উদাহরণস্বরূপ:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma correlations

আমরা [এখানে](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md) সংজ্ঞায়িত অনুযায়ী Sigma version 2.0.0-এর সমস্ত correlation প্রয়োগ করেছি।

সমর্থিত correlation:
- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

12 সেপ্টেম্বর, 2025-এ Sigma version 2.1.0-তে প্রকাশিত নতুন "metrics" correlation রুল (`value_sum`, `value_avg`, `value_percentile`) বর্তমানে সমর্থিত নয়।
