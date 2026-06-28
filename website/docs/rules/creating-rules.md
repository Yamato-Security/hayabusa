# Creating Rule Files

## About Hayabusa-Rules

This is a repository containing curated sigma rules that detect attacks in Windows event logs.
It is mainly used for [Hayabusa](https://github.com/Yamato-Security/hayabusa) detections rules and config files, as well as [Velociraptor](https://github.com/Velocidex/velociraptor)'s built-in sigma detection.
The advantage of using this repository over the [upstream sigma repository](https://github.com/SigmaHQ/sigma) is that we include only rules that most sigma-native tools should be able to parse.
We also de-abstract the `logsource` field by adding the necessary `Channel`, `EventID`, etc... fields to the rules to make it easier to understand what the rule is filtering on and more importantly to reduce false positives.
We also create new rules with converted field names and values for `process_creation` rules and `registry` based rules so that the sigma rules will not only detect on Sysmon logs, but will detect on built-in Windows logs as well.

## About creating rule files

Hayabusa detection rules are written in [YAML](https://en.wikipedia.org/wiki/YAML) format with a file extension of `.yml`. (`.yaml` files will be ignored.)
They are a subset of sigma rules but also contain some added features.
We are trying to make them as close to sigma rules as possible so that it is easy to convert Hayabusa rules back to sigma to give back to the community.
Hayabusa rules can express complex detection rules by combining not only simple string matching but also regular expressions, `AND`, `OR`, and other conditions.
In this section, we will explain how to write Hayabusa detection rules.

### Rule file format

Example:

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

- **author [required]**: Name of the author(s).
- **date [required]**: Date the rule was made.
- **modified** [optional]: Date the rule was updated.

> ## Alert section

- **title [required]**: Rule file title. This will also be the name of the alert that gets displayed so the briefer the better. (Should not be longer than 85 characters.)
- **details** [optional]: The details of the alert that gets displayed. Please output any fields in the Windows event log that are useful for analysis. Fields are seperated by `" ¦ "`. Field placeholders are enclosed with a `%` (Example: `%MemberName%`) and need to be defined in `rules/config/eventkey_alias.txt`. (Explained below.)
- **description** [optional]: A description of the rule. This does not get displayed so you can make this long and detailed.

> ## Rule section

- **id [required]**: A randomly generated version 4 UUID used to uniquely identify the rule. You can generate one [here](https://www.uuidgenerator.net/version4).
- **level [required]**: Severity level based on [sigma's definition](https://github.com/SigmaHQ/sigma/wiki/Specification). Please write one of the following: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: Status based on [sigma's definition](https://github.com/SigmaHQ/sigma/wiki/Specification). Please write one of the following: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [required]**: While this is not actually used by Hayabusa at the moment, we define logsource in the same way as sigma in order to be compatible with sigma rules.
- **detection  [required]**: The detection logic goes here. (Explained below.)
- **falsepositives [required]**: The possibilities for false positives. For example: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. If it is unknown, please write `unknown`.
- **tags** [optional]: If the technique is a [LOLBINS/LOLBAS](https://lolbas-project.github.io/) technique, please add the `lolbas` tag. If the alert can be mapped to a technique in the [MITRE ATT&CK](https://attack.mitre.org/) framework, please add the tactic ID (Example: `attack.t1098`) and any applicable tactics below:
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
- **references** [optional]: Any links to references.
- **ruletype [required]**: `Hayabusa` for hayabusa rules. Rules automatically converted from sigma Windows rules will be `Sigma`.

> ## Sample XML Event

- **sample-message [required]**: Starting forward, we ask rule authors to include sample messages for their rules. This is the rendered message that Windows' Event Viewer displays.
- **sample-evtx [required]**: Starting forward, we ask rule authors to include sample XML events for their rules.
