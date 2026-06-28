# Hayabusa সম্পর্কে

Hayabusa হলো একটি **Windows ইভেন্ট লগ ফাস্ট ফরেনসিক টাইমলাইন জেনারেটর** এবং **থ্রেট হান্টিং টুল** যা জাপানের [Yamato Security](https://yamatosecurity.connpass.com/) গ্রুপ তৈরি করেছে।
জাপানি ভাষায় Hayabusa অর্থ ["peregrine falcon"](https://en.wikipedia.org/wiki/Peregrine_falcon) এবং এটি বেছে নেওয়া হয়েছে কারণ peregrine falcon বিশ্বের দ্রুততম প্রাণী, শিকারে দক্ষ এবং সহজেই প্রশিক্ষণযোগ্য।
এটি মেমরি-সেফ [Rust](https://www.rust-lang.org/) ভাষায় লেখা, যথাসম্ভব দ্রুত হওয়ার জন্য মাল্টি-থ্রেডিং সমর্থন করে এবং এটিই একমাত্র ওপেন-সোর্স টুল যা v2 correlation rules সহ Sigma স্পেসিফিকেশনের সম্পূর্ণ সমর্থন দেয়।
Hayabusa [upstream Sigma](https://github.com/SigmaHQ/sigma) rules পার্সিং সামলাতে পারে, তবে আমরা যে Sigma rules ব্যবহার করি এবং [hayabusa-rules repository](https://github.com/Yamato-Security/hayabusa-rules)-তে হোস্ট করি সেগুলোতে কিছু রূপান্তর করা হয়েছে যাতে rule লোডিং আরও নমনীয় হয় এবং ফলস পজিটিভ কমে।
আপনি এই বিষয়ে বিস্তারিত পড়তে পারেন [sigma-to-hayabusa-converter repository](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) README ফাইলে।
Hayabusa চালানো যায় হয় লাইভ বিশ্লেষণের জন্য একক চলমান সিস্টেমে, একক বা একাধিক সিস্টেম থেকে লগ সংগ্রহ করে অফলাইন বিশ্লেষণের জন্য, অথবা এন্টারপ্রাইজ-ব্যাপী থ্রেট হান্টিং ও ইনসিডেন্ট রেসপন্সের জন্য [Velociraptor](https://docs.velociraptor.app/) দিয়ে [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) চালিয়ে।
আউটপুট একটি একক CSV/JSON/JSONL টাইমলাইনে একত্রিত হবে যাতে [LibreOffice](https://www.libreoffice.org/), [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) [Elastic Stack](../importing/elastic-stack.md), [Timesketch](https://timesketch.org/) ইত্যাদিতে সহজে বিশ্লেষণ করা যায়...
