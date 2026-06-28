# Hayabusa রুলস

Hayabusa ডিটেকশন রুলগুলি একটি sigma-সদৃশ YML ফরম্যাটে লেখা হয় এবং `rules` ফোল্ডারে অবস্থিত।
রুলগুলি [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) এ হোস্ট করা হয়েছে, তাই অনুগ্রহ করে রুল সম্পর্কিত যেকোনো issue এবং pull request মূল Hayabusa রিপোজিটরির পরিবর্তে সেখানে পাঠান।

রুল ফরম্যাট এবং কীভাবে রুল তৈরি করতে হয় তা বোঝার জন্য এই বিভাগে [Creating Rule Files](creating-rules.md), [Detection Fields](detection-fields.md) এবং [Sigma Correlations](correlations.md) দেখুন। (সূত্র: [hayabusa-rules repository](https://github.com/Yamato-Security/hayabusa-rules)।)

hayabusa-rules রিপোজিটরির সমস্ত রুল `rules` ফোল্ডারে স্থাপন করা উচিত।
`informational` লেভেলের রুলগুলিকে `events` হিসাবে বিবেচনা করা হয়, যখন `low` এবং তার উপরের `level` সহ যেকোনো কিছুকে `alerts` হিসাবে বিবেচনা করা হয়।

hayabusa রুল ডিরেক্টরি গঠন ২টি ডিরেক্টরিতে বিভক্ত:

* `builtin`: Windows বিল্ট-ইন ফাংশনালিটি দ্বারা তৈরি করা যেতে পারে এমন লগ।
* `sysmon`: [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) দ্বারা তৈরি করা লগ।

রুলগুলি আরও লগ টাইপ অনুসারে ডিরেক্টরিতে বিভক্ত (উদাহরণ: Security, System, ইত্যাদি...) এবং নিম্নলিখিত ফরম্যাটে নামকরণ করা হয়:

নতুন রুল তৈরিতে টেমপ্লেট হিসাবে ব্যবহার করার জন্য বা ডিটেকশন লজিক যাচাই করার জন্য অনুগ্রহ করে বর্তমান রুলগুলি দেখুন।

## Sigma বনাম Hayabusa (Built-in Sigma Compatible) রুলস

Hayabusa অভ্যন্তরীণভাবে `logsource` ফিল্ডগুলি পরিচালনা করার একটি ব্যতিক্রম সহ Sigma রুলগুলিকে নেটিভভাবে সমর্থন করে।
false positive কমানোর জন্য, Sigma রুলগুলি আমাদের কনভার্টারের মাধ্যমে চালানো উচিত যা [here](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md) ব্যাখ্যা করা হয়েছে।
এটি সঠিক `Channel` এবং `EventID` যোগ করবে এবং `process_creation` এর মতো নির্দিষ্ট ক্যাটাগরির জন্য ফিল্ড ম্যাপিং সম্পাদন করবে।

প্রায় সমস্ত Hayabusa রুল Sigma ফরম্যাটের সাথে সামঞ্জস্যপূর্ণ, তাই আপনি অন্যান্য SIEM ফরম্যাটে রূপান্তর করতে ঠিক Sigma রুলের মতোই সেগুলি ব্যবহার করতে পারেন।
Hayabusa রুলগুলি কেবলমাত্র Windows event log বিশ্লেষণের জন্য ডিজাইন করা হয়েছে এবং নিম্নলিখিত সুবিধাগুলি রয়েছে:

1. লগের শুধুমাত্র দরকারী ফিল্ডগুলি থেকে নেওয়া অতিরিক্ত তথ্য প্রদর্শনের জন্য একটি অতিরিক্ত `details` ফিল্ড।
2. এগুলি সবই নমুনা লগের বিপরীতে পরীক্ষা করা হয়েছে এবং কাজ করে বলে জানা যায়।
3. sigma-তে পাওয়া যায় না এমন অতিরিক্ত aggregator, যেমন `|equalsfield` এবং `|endswithfield`।

আমাদের জানামতে, hayabusa যেকোনো ওপেন সোর্স Windows event log বিশ্লেষণ টুলের মধ্যে sigma রুলের জন্য সর্বাধিক নেটিভ সমর্থন প্রদান করে।
