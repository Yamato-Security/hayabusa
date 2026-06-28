# नियम निर्माण सलाह

## नियम निर्माण सलाह

1. **जब भी संभव हो, हमेशा `Channel` या `ProviderName` नाम और `EventID` संख्या निर्दिष्ट करें।** डिफ़ॉल्ट रूप से, केवल `./rules/config/target_event_IDs.txt` में सूचीबद्ध इवेंट ID ही स्कैन किए जाएंगे, इसलिए यदि EID पहले से वहाँ मौजूद नहीं है तो आपको इस फ़ाइल में एक नई `EventID` संख्या जोड़ने की आवश्यकता हो सकती है।

2. **कृपया जब आवश्यकता न हो तो कई `selection` या `filter` फ़ील्ड और अत्यधिक समूहन का उपयोग न करें।** उदाहरण के लिए:

#### इसके बजाय

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

#### कृपया ऐसा करें

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

3. **जब आपको कई अनुभागों की आवश्यकता हो, तो कृपया पहले अनुभाग का नाम `section_basic` अनुभाग में चैनल और इवेंट ID जानकारी के साथ रखें और अन्य चयनों को `section_` और `filter_` के बाद सार्थक नामों के साथ रखें। साथ ही, कृपया समझने में कठिन किसी भी चीज़ को समझाने के लिए टिप्पणियाँ लिखें।** उदाहरण के लिए:

#### इसके बजाय

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

#### कृपया ऐसा करें

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

## Sigma नियमों को Hayabusa प्रारूप में परिवर्तित करना

हमने Sigma से Hayabusa-संगत प्रारूप में नियमों को परिवर्तित करने के लिए एक बैकएंड बनाया है [यहाँ](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)।
