# नियम फ़ाइलें बनाना

## Hayabusa-Rules के बारे में

यह एक रिपॉज़िटरी है जिसमें Windows इवेंट लॉग में हमलों का पता लगाने वाले संकलित sigma नियम शामिल हैं।
इसका मुख्य रूप से [Hayabusa](https://github.com/Yamato-Security/hayabusa) के डिटेक्शन नियमों और कॉन्फ़िग फ़ाइलों के लिए, साथ ही [Velociraptor](https://github.com/Velocidex/velociraptor) के अंतर्निहित sigma डिटेक्शन के लिए उपयोग किया जाता है।
[अपस्ट्रीम sigma रिपॉज़िटरी](https://github.com/SigmaHQ/sigma) की तुलना में इस रिपॉज़िटरी का उपयोग करने का लाभ यह है कि हम केवल वे नियम शामिल करते हैं जिन्हें अधिकांश sigma-native टूल पार्स कर सकें।
हम `logsource` फ़ील्ड को de-abstract भी करते हैं, नियमों में आवश्यक `Channel`, `EventID`, आदि फ़ील्ड जोड़कर, ताकि यह समझना आसान हो जाए कि नियम किस पर फ़िल्टर कर रहा है और इससे भी महत्वपूर्ण रूप से false positives को कम किया जा सके।
हम `process_creation` नियमों और `registry` आधारित नियमों के लिए परिवर्तित फ़ील्ड नामों और मानों के साथ नए नियम भी बनाते हैं ताकि sigma नियम केवल Sysmon लॉग पर ही नहीं, बल्कि अंतर्निहित Windows लॉग पर भी पता लगा सकें।

## नियम फ़ाइलें बनाने के बारे में

Hayabusa डिटेक्शन नियम [YAML](https://en.wikipedia.org/wiki/YAML) प्रारूप में `.yml` फ़ाइल एक्सटेंशन के साथ लिखे जाते हैं। (`.yaml` फ़ाइलों को नज़रअंदाज़ किया जाएगा।)
ये sigma नियमों का एक उपसमुच्चय हैं लेकिन इनमें कुछ अतिरिक्त सुविधाएँ भी शामिल हैं।
हम इन्हें यथासंभव sigma नियमों के करीब बनाने का प्रयास कर रहे हैं ताकि समुदाय को वापस देने के लिए Hayabusa नियमों को sigma में वापस परिवर्तित करना आसान हो।
Hayabusa नियम न केवल सरल स्ट्रिंग मिलान को बल्कि नियमित अभिव्यक्तियों, `AND`, `OR`, और अन्य शर्तों को संयोजित करके जटिल डिटेक्शन नियम व्यक्त कर सकते हैं।
इस अनुभाग में, हम बताएंगे कि Hayabusa डिटेक्शन नियम कैसे लिखें।

### नियम फ़ाइल प्रारूप

उदाहरण:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## Author section

- **author [required]**: लेखक(ओं) का नाम।
- **date [required]**: वह तिथि जब नियम बनाया गया था।
- **modified** [optional]: वह तिथि जब नियम अद्यतन किया गया था।

> ## Alert section

- **title [required]**: नियम फ़ाइल का शीर्षक। यह प्रदर्शित होने वाले अलर्ट का नाम भी होगा इसलिए जितना संक्षिप्त हो उतना बेहतर। (85 वर्णों से अधिक लंबा नहीं होना चाहिए।)
- **details** [optional]: प्रदर्शित होने वाले अलर्ट का विवरण। कृपया Windows इवेंट लॉग में किसी भी ऐसे फ़ील्ड को आउटपुट करें जो विश्लेषण के लिए उपयोगी हों। फ़ील्ड `" ¦ "` द्वारा अलग किए जाते हैं। फ़ील्ड प्लेसहोल्डर `%` से घिरे होते हैं (उदाहरण: `%MemberName%`) और इन्हें `rules/config/eventkey_alias.txt` में परिभाषित किया जाना चाहिए। (नीचे समझाया गया है।)
- **description** [optional]: नियम का विवरण। यह प्रदर्शित नहीं होता इसलिए आप इसे लंबा और विस्तृत बना सकते हैं।

> ## Rule section

- **id [required]**: नियम की विशिष्ट पहचान के लिए एक यादृच्छिक रूप से उत्पन्न संस्करण 4 UUID। आप एक [यहां](https://www.uuidgenerator.net/version4) उत्पन्न कर सकते हैं।
- **level [required]**: [sigma की परिभाषा](https://github.com/SigmaHQ/sigma/wiki/Specification) पर आधारित गंभीरता स्तर। कृपया निम्नलिखित में से एक लिखें: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: [sigma की परिभाषा](https://github.com/SigmaHQ/sigma/wiki/Specification) पर आधारित स्थिति। कृपया निम्नलिखित में से एक लिखें: `deprecated`, `experimental`, `test`, `stable`।
- **logsource [required]**: हालांकि वर्तमान में इसका वास्तव में Hayabusa द्वारा उपयोग नहीं किया जाता, हम sigma नियमों के साथ संगत होने के लिए logsource को sigma के समान ही परिभाषित करते हैं।
- **detection  [required]**: डिटेक्शन लॉजिक यहां जाता है। (नीचे समझाया गया है।)
- **falsepositives [required]**: false positives की संभावनाएं। उदाहरण के लिए: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`। यदि यह अज्ञात है, तो कृपया `unknown` लिखें।
- **tags** [optional]: यदि तकनीक एक [LOLBINS/LOLBAS](https://lolbas-project.github.io/) तकनीक है, तो कृपया `lolbas` टैग जोड़ें। यदि अलर्ट को [MITRE ATT&CK](https://attack.mitre.org/) फ्रेमवर्क में किसी तकनीक से मैप किया जा सकता है, तो कृपया रणनीति ID (उदाहरण: `attack.t1098`) और नीचे दी गई कोई भी लागू रणनीति जोड़ें:
  - `attack.reconnaissance` -> Reconnaissance (Recon)
  - `attack.resource-development` -> Resource Development  (ResDev)
  - `attack.initial-access` -> Initial Access (InitAccess)
  - `attack.execution` -> Execution (Exec)
  - `attack.persistence` -> Persistence (Persis)
  - `attack.privilege-escalation` -> Privilege Escalation (PrivEsc)
  - `attack.stealth` -> Stealth (Stealth)
  - `attack.defense-impairment` -> Defense Impairment (DefImpair)
  - `attack.credential-access` -> Credential Access (CredAccess)
  - `attack.discovery` -> Discovery (Disc)
  - `attack.lateral-movement` -> Lateral Movement (LatMov)
  - `attack.collection` -> Collection (Collect)
  - `attack.command-and-control` -> Command and Control (C2)
  - `attack.exfiltration` -> Exfiltration (Exfil)
  - `attack.impact` -> Impact (Impact)
- **references** [optional]: संदर्भों के लिए कोई भी लिंक।
- **ruletype [required]**: hayabusa नियमों के लिए `Hayabusa`। sigma Windows नियमों से स्वचालित रूप से परिवर्तित नियम `Sigma` होंगे।

> ## Sample XML Event

- **sample-message [required]**: आगे से, हम नियम लेखकों से अनुरोध करते हैं कि वे अपने नियमों के लिए नमूना संदेश शामिल करें। यह वह रेंडर किया गया संदेश है जिसे Windows का Event Viewer प्रदर्शित करता है।
- **sample-evtx [required]**: आगे से, हम नियम लेखकों से अनुरोध करते हैं कि वे अपने नियमों के लिए नमूना XML इवेंट शामिल करें।
