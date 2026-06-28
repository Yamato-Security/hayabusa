# ডাউনলোড

অনুগ্রহ করে কম্পাইল করা বাইনারিসহ Hayabusa-এর সর্বশেষ স্থিতিশীল সংস্করণটি ডাউনলোড করুন অথবা [Releases](https://github.com/Yamato-Security/hayabusa/releases) পৃষ্ঠা থেকে সোর্স কোড কম্পাইল করুন।

আমরা নিম্নলিখিত আর্কিটেকচারগুলোর জন্য বাইনারি সরবরাহ করি:
- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [কোনো কারণে Linux ARM MUSL বাইনারিটি সঠিকভাবে চলে না](https://github.com/Yamato-Security/hayabusa/issues/1332) তাই আমরা সেই বাইনারিটি সরবরাহ করি না। এটি আমাদের নিয়ন্ত্রণের বাইরে, তাই এটি ঠিক হয়ে গেলে ভবিষ্যতে এটি সরবরাহ করার পরিকল্পনা আমাদের আছে।

## Windows live response প্যাকেজ

v2.18.0 থেকে, আমরা বিশেষ Windows প্যাকেজ সরবরাহ করি যেগুলো একটি একক ফাইলে সরবরাহ করা XOR-এনকোডেড রুল ব্যবহার করে এবং সেই সাথে সমস্ত কনফিগ ফাইল একটি একক ফাইলে সংযুক্ত করা হয় ([hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules)-তে হোস্ট করা)।
শুধু নামে `live-response` থাকা zip প্যাকেজগুলো ডাউনলোড করুন।
zip ফাইলগুলোতে শুধু তিনটি ফাইল থাকে: Hayabusa বাইনারি, XOR-এনকোডেড রুল ফাইল এবং কনফিগ ফাইল।
এই live response প্যাকেজগুলোর উদ্দেশ্য হলো ক্লায়েন্ট এন্ডপয়েন্টে Hayabusa চালানোর সময়, আমরা নিশ্চিত করতে চাই যে Windows Defender-এর মতো অ্যান্টি-ভাইরাস স্ক্যানারগুলো `.yml` রুল ফাইলে কোনো ফলস পজিটিভ না দেয়।
এছাড়াও, আমরা সিস্টেমে লেখা ফাইলের পরিমাণ ন্যূনতম রাখতে চাই যাতে USN Journal-এর মতো ফরেনসিক আর্টিফ্যাক্টগুলো ওভাররাইট না হয়।
