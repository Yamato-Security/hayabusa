# نصائح إنشاء القواعد

## نصائح إنشاء القواعد

1. **عند الإمكان، حدد دائمًا اسم `Channel` أو `ProviderName` ورقم `EventID`.** افتراضيًا، سيتم فحص معرّفات الأحداث المدرجة في `./rules/config/target_event_IDs.txt` فقط، لذا قد تحتاج إلى إضافة رقم `EventID` جديد إلى هذا الملف إذا لم يكن معرّف الحدث موجودًا فيه بالفعل.

2. **يُرجى عدم استخدام حقول `selection` أو `filter` متعددة والتجميع المفرط عندما لا يكون ذلك ضروريًا.** على سبيل المثال:

#### بدلًا من

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

#### يُرجى فعل هذا

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

3. **عندما تحتاج إلى أقسام متعددة، يُرجى تسمية القسم الأول بمعلومات القناة ومعرّف الحدث في قسم `section_basic` والتحديدات الأخرى بأسماء ذات معنى بعد `section_` و`filter_`. أيضًا، يُرجى كتابة تعليقات لشرح أي شيء يصعب فهمه.** على سبيل المثال:

#### بدلًا من

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

#### يُرجى فعل هذا

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

## تحويل قواعد Sigma إلى تنسيق Hayabusa

لقد أنشأنا واجهة خلفية لتحويل القواعد من Sigma إلى تنسيق متوافق مع Hayabusa [هنا](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).
