# 建立規則檔案

## 關於 Hayabusa-Rules

這是一個收錄精選 sigma 規則的儲存庫，用於偵測 Windows 事件記錄中的攻擊行為。
它主要用於 [Hayabusa](https://github.com/Yamato-Security/hayabusa) 的偵測規則與設定檔，以及 [Velociraptor](https://github.com/Velocidex/velociraptor) 內建的 sigma 偵測功能。
相較於 [upstream sigma 儲存庫](https://github.com/SigmaHQ/sigma)，使用本儲存庫的優點在於我們只收錄大多數原生 sigma 工具都能夠解析的規則。
我們也透過在規則中加入必要的 `Channel`、`EventID` 等欄位，將 `logsource` 欄位具體化，使其更容易理解規則所過濾的對象，更重要的是可以減少誤報。
我們也會為 `process_creation` 規則與 `registry` 相關規則建立轉換過欄位名稱與值的新規則，讓 sigma 規則不僅能偵測 Sysmon 記錄，也能偵測內建的 Windows 記錄。

## 關於建立規則檔案

Hayabusa 偵測規則以 [YAML](https://en.wikipedia.org/wiki/YAML) 格式撰寫，副檔名為 `.yml`。（`.yaml` 檔案會被忽略。）
它們是 sigma 規則的子集，但也包含一些額外的功能。
我們盡量讓它們與 sigma 規則保持接近，以便輕鬆將 Hayabusa 規則轉換回 sigma 並回饋給社群。
Hayabusa 規則不僅能透過簡單的字串比對，還能結合正規表示式、`AND`、`OR` 及其他條件來表達複雜的偵測規則。
在本節中，我們將說明如何撰寫 Hayabusa 偵測規則。

### 規則檔案格式

範例：

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

> ## 作者區段

- **author [required]**：作者姓名。
- **date [required]**：規則建立的日期。
- **modified** [optional]：規則更新的日期。

> ## 警示區段

- **title [required]**：規則檔案標題。這也會作為顯示的警示名稱，因此越簡潔越好。（不應超過 85 個字元。）
- **details** [optional]：顯示的警示細節。請輸出 Windows 事件記錄中任何對分析有用的欄位。欄位以 `" ¦ "` 分隔。欄位佔位符以 `%` 包夾（範例：`%MemberName%`），且須在 `rules/config/eventkey_alias.txt` 中定義。（下文會說明。）
- **description** [optional]：規則的說明。這不會被顯示，因此可以寫得長而詳細。

> ## 規則區段

- **id [required]**：隨機產生的第 4 版 UUID，用於唯一識別規則。你可以在[此處](https://www.uuidgenerator.net/version4)產生一個。
- **level [required]**：依據 [sigma 的定義](https://github.com/SigmaHQ/sigma/wiki/Specification)的嚴重性等級。請填入下列其中之一：`informational`、`low`、`medium`、`high`、`critical`
- **status[required]**：依據 [sigma 的定義](https://github.com/SigmaHQ/sigma/wiki/Specification)的狀態。請填入下列其中之一：`deprecated`、`experimental`、`test`、`stable`。
- **logsource [required]**：雖然 Hayabusa 目前實際上並未使用此欄位，但我們以與 sigma 相同的方式定義 logsource，以便與 sigma 規則相容。
- **detection  [required]**：偵測邏輯寫在這裡。（下文會說明。）
- **falsepositives [required]**：誤報的可能性。例如：`system administrator`、`normal user usage`、`normal system usage`、`legacy application`、`security team`、`none`。若未知，請填寫 `unknown`。
- **tags** [optional]：若該技術屬於 [LOLBINS/LOLBAS](https://lolbas-project.github.io/) 技術，請加入 `lolbas` 標籤。若該警示可對應至 [MITRE ATT&CK](https://attack.mitre.org/) 框架中的某項技術，請加入戰術 ID（範例：`attack.t1098`）以及下列任何適用的戰術：
  - `attack.reconnaissance` -> 偵察 (Recon)
  - `attack.resource-development` -> 資源開發 (ResDev)
  - `attack.initial-access` -> 初始存取 (InitAccess)
  - `attack.execution` -> 執行 (Exec)
  - `attack.persistence` -> 持久化 (Persis)
  - `attack.privilege-escalation` -> 權限提升 (PrivEsc)
  - `attack.stealth` -> 隱匿 (Stealth)
  - `attack.defense-impairment` -> 防禦削弱 (DefImpair)
  - `attack.credential-access` -> 憑證存取 (CredAccess)
  - `attack.discovery` -> 探索 (Disc)
  - `attack.lateral-movement` -> 橫向移動 (LatMov)
  - `attack.collection` -> 蒐集 (Collect)
  - `attack.command-and-control` -> 命令與控制 (C2)
  - `attack.exfiltration` -> 資料外洩 (Exfil)
  - `attack.impact` -> 影響 (Impact)
- **references** [optional]：任何參考資料的連結。
- **ruletype [required]**：hayabusa 規則填 `Hayabusa`。從 sigma Windows 規則自動轉換而來的規則則為 `Sigma`。

> ## 範例 XML 事件

- **sample-message [required]**：自此之後，我們要求規則作者為其規則附上範例訊息。這是 Windows 事件檢視器所顯示的呈現訊息。
- **sample-evtx [required]**：自此之後，我們要求規則作者為其規則附上範例 XML 事件。
