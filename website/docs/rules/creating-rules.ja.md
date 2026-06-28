# ルールファイルの作成

## Hayabusa-Rulesについて

Windowsのイベントログから攻撃を検出するキュレーションされたSigmaルールをまとめているリポジトリです。
主に[Hayabusa](https://github.com/Yamato-Security/hayabusa)の検知ルールや設定ファイル、[Velociraptor](https://github.com/Velocidex/velociraptor)内蔵のSigma検知などに使用されています。
[上流のSigmaリポジトリ](https://github.com/SigmaHQ/sigma)よりもこのリポジトリを使う利点は、ほとんどのSigmaネイティブツールがパースできるはずのルールだけを含んでいることです。
また、必要な`Channel`、`EventID`等々のフィールドをルールに追加することで、`logsource`フィールドの抽象化を解除し、ルールが何をフィルタリングしているのかを理解しやすくし、さらに重要なこととして、過検出を減らすようにしています。
また、`process_creation`ルールと`registry`ベースのルールのフィールド名と値を変換した新しいルールを作成し、SigmaルールがSysmonのログを検知するだけでなく、組み込みのWindowsログも検知できるようにしています。

## ルールファイル作成について

Hayabusaの検知ルールは[YAML](https://en.wikipedia.org/wiki/YAML)形式で記述され、ファイル拡張子は必ず`.yml`にしてください。(`.yaml`ファイルは無視されます。)
Sigmaルールのサブセットでありながら、いくつかの付加的な機能を含んでいます。
HayabusaのルールをSigmaに修正し、コミュニティに還元しやすいように、できるだけSigmaルールに近いものを作ろうとしています。
単純な文字列のマッチングだけでなく、正規表現や`AND`、`OR`などの条件を組み合わせて複雑な検知ルールを表現することができます。
本節ではHayabusaの検知ルールの書き方について説明します。

### ルールファイル形式

記述例:

```yaml
#作者セクション
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#アラートセクション
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#ルールセクション
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

#XMLイベントのサンプル
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

> ## 作者セクション

- **author [必須]**: 著者名（複数可）。
- **date [必須]**: ルールが作成された日付。
- **modified** [オプション]: ルールが更新された日付。

> ## アラートセクション

- **title [必須]**: ルールファイルのタイトル。これは表示されるアラートの名前にもなるので、簡潔であるほどよいです。(85文字以下でなければなりません。)
- **details** [オプション]: 表示されるアラートの詳細です。Windowsイベントログの中で解析に有効なフィールドがあれば出力してください。フィールドは `" ¦ "` で区切られます。フィールドのプレースホルダは `%` で囲まれ (例: `%MemberName%`) 、`rules/config_eventkey_alias.txt` で定義する必要があります。(以下で説明します)
- **description** [オプション]: ルールの説明。これは表示されないので、長く詳細に記述することができます。

> ## ルールセクション

- **id [必須]**: ルールを一意に識別するために使用される、ランダムに生成されたバージョン4のUUIDです。 [ここ](https://www.uuidgenerator.net/version4) で生成することができます。

- **level [必須]**: [sigmaルールの定義](https://github.com/SigmaHQ/sigma/wiki/Specification)に基づく重要度レベル。いずれかを記述してください: `informational`,`low`,`medium`,`high`,`critical`
- **status[必須]**: [sigmaルールの定義](https://github.com/SigmaHQ/sigma/wiki/Specification)に基づくステータス。いずれかを記述してください: `deprecated`, `experimental`, `test`, `stable`
- **logsource [required]**: Sigmaルールと互換性があるようにSigmaのlogsource定義と同様。
- **detection  [必須]**: 検知ロジックはここに入ります。(以下で説明します。)
- **falsepositives [必須]**: 誤検知の可能性について記載を行います。例: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`。 不明な場合は `unknown` と記述してください。
- **tags** [オプション]: [LOLBINS/LOLBAS](https://lolbas-project.github.io/)という手法を利用している場合、`lolbas` タグを追加してください。アラートを[MITRE ATT&CK](https://attack.mitre.org/) フレームワークにマッピングできる場合は、以下のリストから該当するものを追加してください。戦術ID（例：`attack.t1098`）を指定することも可能です。
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
- **references** [オプション]: 参考文献への任意のリンク。
- **ruletype [必須]**: Hayabusaルールには `Hayabusa` を指定します。SigmaのWindowsルールから自動変換されたルールは `Sigma` になります。

> ## Sample XML Event

- **sample-evtx [required]**: Starting forward, we ask rule authors to include sample XML events for their rules.
