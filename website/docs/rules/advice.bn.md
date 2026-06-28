# রুল তৈরির পরামর্শ

## রুল তৈরির পরামর্শ

1. **যখন সম্ভব হয়, সর্বদা `Channel` বা `ProviderName` নাম এবং `EventID` নম্বর নির্দিষ্ট করুন।** ডিফল্টভাবে, শুধুমাত্র `./rules/config/target_event_IDs.txt`-এ তালিকাভুক্ত ইভেন্ট আইডিগুলো স্ক্যান করা হবে, তাই যদি EID টি ইতিমধ্যে সেখানে না থাকে তবে আপনাকে এই ফাইলে একটি নতুন `EventID` নম্বর যোগ করতে হতে পারে।

2. **প্রয়োজন না হলে দয়া করে একাধিক `selection` বা `filter` ফিল্ড এবং অতিরিক্ত গ্রুপিং ব্যবহার করবেন না।** উদাহরণস্বরূপ:

#### এর পরিবর্তে

```yaml
detection:
    SELECTION_1:
        Channnel: Security
    SELECTION_2:
        EventID: 4625
    SELECTION_3:
        LogonType: 3
    FILTER_1:
        SubStatus: "0xc0000064"   #Non-existent user
    FILTER_2:
        SubStatus: "0xc000006a"   #Wrong password
    condition: SELECTION_1 and SELECTION_2 and SELECTION_3 and not (FILTER_1 or FILTER_2)
```

#### দয়া করে এটি করুন

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        - SubStatus: "0xc0000064"   #Non-existent user
        - SubStatus: "0xc000006a"   #Wrong password
    condition: selection and not filter
```

3. **যখন আপনার একাধিক সেকশনের প্রয়োজন হয়, দয়া করে প্রথম সেকশনটি চ্যানেল এবং ইভেন্ট আইডি তথ্যসহ `section_basic` সেকশনে নাম দিন এবং অন্যান্য সিলেকশনগুলোকে `section_` ও `filter_` এর পরে অর্থপূর্ণ নাম দিন। এছাড়াও, দয়া করে যেকোনো বোঝা কঠিন বিষয় ব্যাখ্যা করার জন্য মন্তব্য লিখুন।** উদাহরণস্বরূপ:

#### এর পরিবর্তে

```yaml
detection:
    Takoyaki:
        Channel: Security
        EventID: 4648
    Naruto:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    Sushi:
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    Godzilla:
        SubjectUserName|endswith: "$"
    Ninja:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$"
        IpAddress: "-"
    Daisuki:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: Takoyaki and Daisuki and not (Naruto and not Godzilla) and not Ninja and not Sushi
```

#### দয়া করে এটি করুন

```yaml
detection:
    selection_basic:
        Channel: Security
        EventID: 4648
    selection_TargetUserIsComputerAccount:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    filter_UsersAndTargetServerAreComputerAccounts:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_SubjectUserIsComputerAccount:
        SubjectUserName|endswith: "$"
    filter_SystemAccounts:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_SuspiciousProcess:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_basic and selection_SuspiciousProcess and not (selection_TargetUserIsComputerAccount
               and not filter_SubjectUserIsComputerAccount) and not filter_SystemAccounts and not filter_UsersAndTargetServerAreComputerAccounts
```

## Sigma রুলগুলোকে Hayabusa ফরম্যাটে রূপান্তর করা

আমরা Sigma থেকে Hayabusa-সামঞ্জস্যপূর্ণ ফরম্যাটে রুল রূপান্তর করার জন্য একটি ব্যাকএন্ড তৈরি করেছি [এখানে](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)।
