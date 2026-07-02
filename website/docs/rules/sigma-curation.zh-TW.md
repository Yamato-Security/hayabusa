# 整理適用於 Windows 事件記錄的 Sigma 規則

本頁說明 Yamato Security 如何透過將 `logsource` 欄位去抽象化，並篩除無法使用或難以使用的規則，將上游 [Sigma](https://github.com/SigmaHQ/sigma) 適用於 Windows 事件記錄的規則整理成更易於使用的形式。這是透過 [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) 工具完成的，該工具主要用於建立託管在 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 的精選 Sigma 規則集。該規則集由 [Hayabusa](https://github.com/Yamato-Security/hayabusa) 與 [Velociraptor](https://github.com/Velocidex/velociraptor) 使用。

!!! info "來源"
    本文件與轉換工具一起維護，位於 [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)。我們希望這些資訊對於其他想要使用 Sigma 規則來偵測 Windows 事件記錄中攻擊的專案也有幫助。另請參閱 [建立規則檔案](creating-rules.md) 與 [欄位修飾子](field-modifiers.md)。

## TL;DR

* 將 `logsource` 欄位去抽象化，並為內建規則以及原始的 Sysmon 基礎規則建立新的 `.yml` 規則檔案，可讓 Sigma 規則更容易完整支援內建事件，也讓分析人員更容易閱讀規則。
* 在為 Windows 事件記錄撰寫 Sigma 規則時，了解原始 Sysmon 基礎記錄與相容的內建記錄之間的差異非常重要，最理想的情況是撰寫能同時相容兩者的規則。
* 許多組織無法或不願意在所有 Windows 端點上安裝並維護 Sysmon 代理程式，因為他們沒有專門的資源來處理，或是想要避免 Sysmon 造成任何速度變慢或當機的風險。因此，盡可能啟用越多內建事件記錄，並使用能夠在這些內建記錄中偵測攻擊的工具，就顯得相當重要。

## 上游 Sigma 規則在 Windows 事件記錄上的挑戰

根據我們的經驗，為 Windows 事件記錄建立原生 Sigma 規則剖析器的主要挑戰，一直是支援 `logsource` 欄位。目前這是 Hayabusa 少數尚未原生支援的功能之一，因為它仍然非常複雜且正在開發中。目前我們透過將上游規則轉換為更易於使用的格式來解決此問題，詳細說明如下。

### 關於 `logsource` 欄位

在適用於 Windows 事件記錄的 Sigma 規則中，`product` 欄位設定為 `windows`，接著是 `service` 欄位或 `category` 欄位。

`service` 欄位範例：

```yaml
logsource:
    product: windows
    service: application
```

`category` 欄位範例：

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Service 欄位

`service` 欄位相對容易處理，它會告訴使用該 Sigma 規則的任何後端，根據 Windows XML 事件記錄中的 `Channel` 欄位搜尋單一通道或多個通道。

**單一通道範例**

`service: application` 等同於在 Sigma 規則中加入 `Channel: Application` 的選擇條件。

**多重通道範例**

`service: applocker` 目前產生最多需要搜尋的通道，因為 AppLocker 會將資訊儲存在四個不同的記錄中。為了正確地僅搜尋 AppLocker 記錄，需要在 Sigma 規則邏輯中加入以下條件：

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**目前的 service 對應清單**

| 服務                                        | 通道                                                                                                                                 |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**Service 對應來源**

我們建立了將服務對應到通道名稱的 YAML 對應檔案，並定期維護、託管在轉換器儲存庫中。它們是根據 [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) 中的服務對應資訊而來：雖然這似乎不是供人使用的官方通用設定檔，但它似乎是最新的。

#### Category 欄位

大多數 `category` 欄位只是在搜尋特定 `Channel` 之外，額外加入一個條件來檢查 `EventID` 欄位中的特定事件 ID。這些類別名稱大多以 [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) 事件為基礎，並針對內建的 PowerShell 記錄與 Windows Defender 增加了一些額外的類別。

**Category 欄位範例**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**目前的 category 對應清單**

有些類別會對應到多個 service/EventID（以**粗體**顯示）。

| 類別                       | 服務                | 事件 ID                                                                |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**Category 欄位的挑戰**

如上所示，同一個 `category` 可以使用多個服務與事件 ID（以**粗體**標示）。這表示，如果規則所使用的欄位也存在於內建事件記錄中，就有可能將某些為 `sysmon` 設計的 Sigma 規則用於類似的內建 Windows `security` 事件記錄。在這種情況下，可能需要轉換欄位名稱——有時也包括值——以符合內建 `security` 事件記錄的欄位名稱與值。雖然對某些類別來說這可能只是重新命名一些欄位名稱那麼簡單，但對其他類別而言，可能還需要對欄位值進行各種轉換。我們如何進行這項轉換，以及 `sysmon` 記錄與 `security` 記錄之間的相容性，將在[下方](#sysmon-builtin-comparison)詳細說明。

**Category 對應來源**

類別的 YAML 對應檔案同樣託管在轉換器儲存庫中，也是根據 [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) 中的資訊而來。

## 抽象化記錄來源的優點與挑戰

在後端抽象化記錄來源，並為不同的 `Channel`、`EventID` 與欄位建立對應，既有優點也有挑戰。

### 優點

1. 在將 Sigma 規則轉換為其他後端查詢時，將 `Channel` 與 `EventID` 欄位名稱轉換為適當的後端欄位名稱可能會更容易。
2. 可以將兩條規則整合為一條。例如，處理程序建立事件可以記錄在 `Sysmon 1` 以及 `Security 4688` 中。與其撰寫兩條查看不同通道、事件 ID 與欄位但邏輯相同的規則，不如將欄位標準化為 Sysmon 所使用的形式，然後讓後端轉換器加入 `Channel` 與 `EventID` 欄位，並在必要時轉換其他欄位資訊。這讓規則的維護更容易，因為需要維護的規則數量減少了。
3. 雖然非常罕見，但如果某個記錄來源開始將其資料記錄在不同的 `Channel` 或 `EventID` 中，只需要更新對應邏輯，而不必更新所有 Sigma 規則，讓維護更容易。

### 挑戰

1. 如果原始基於 Sysmon 的 Sigma 規則使用了某個內建記錄中不存在的欄位來過濾誤報，會發生什麼事？你應該還是建立該規則，以偵測能力為優先；還是忽略它，以減少誤報為優先？理想情況下，需要建立兩條具有不同 `severity`、`status` 與誤報資訊的規則，讓使用者能更好地處理。
2. 這會讓篩選規則變得更困難，因為如果檔案尚未建立，你就無法僅根據 `.yml` 檔案中的 `Channel` 或 `EventID` 欄位，或規則的檔案路徑來篩選——因為它是針對內建記錄的衍生規則，而非原始的 Sysmon 規則。此外，由於規則 ID 相同，你也無法根據規則 ID 進行篩選。
3. 當警示來自由 Sysmon 記錄衍生而來、針對內建記錄的規則時，這會讓確認警示變得更困難。欄位名稱與值無法對應，因此分析人員需要理解這個略為複雜的轉換過程。
4. 這會讓後端邏輯的建立更複雜。

對於第一個問題，除了在有值得投入心力的重要使用情境時建立並維護新規則之外，我們無能為力；但為了解決第 2 到第 4 個問題，我們決定將 `logsource` 欄位去抽象化，並為任何能夠產生多條規則的規則建立兩套規則。能夠在內建記錄中偵測攻擊的規則會輸出到 `builtin` 目錄，而針對 Sysmon 的規則則輸出到 `sysmon` 目錄。

## 轉換範例

以下是一個簡單的範例，以便更好地理解轉換過程。

**轉換前** — 原始的 Sigma 規則：

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**轉換後** — 適用於 Sysmon 記錄的 Hayabusa 相容規則：

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

……以及適用於 Windows 內建記錄的 Hayabusa 相容規則：

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

如你所見，已建立兩條規則：一條用於 Sysmon 1 記錄，一條用於內建的 Security 4688 記錄。新增了一個帶有通道與事件 ID 資訊的 `process_creation` 條件，並將它加入 `condition` 欄位以要求符合此條件。此外，原本的 `Image` 欄位名稱已變更為 `NewProcessName`。

## 轉換的共通處理

在詳細說明我們如何轉換特定類別之前，以下是適用於所有規則的轉換部分。

1. 任何 ID 出現在 `ignore-uuid-list.txt` 中的規則都會被忽略。目前我們只會忽略那些因為含有 `mimikatz` 之類關鍵字而在 Windows Defender 上造成誤報的規則。
2. 「Placeholder」（佔位）規則會被忽略，因為它們無法直接使用。這些是放在 Sigma 儲存庫中 [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) 資料夾內的規則。
3. 使用不相容欄位修飾子的規則會被捨棄。Hayabusa 支援大多數的欄位修飾子，因此為了避免剖析錯誤，轉換器不會輸出任何使用下列以外修飾子的規則（請參閱 [欄位修飾子](field-modifiers.md)）：

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. 含有語法錯誤的規則不會被轉換。
5. `deprecated` 與 `unsupported` 規則中的標籤會從 V1 格式更新為 V2 格式，V2 格式使用 `-` 而非 `_`，以保持一致並讓 Hayabusa 更容易處理縮寫。例如：`initial_access` 會變成 `initial-access`。
6. 由於我們會在規則中加入 `Channel` 與 `EventID` 資訊，因此我們會使用原始 ID 的 MD5 雜湊值建立一個新的 UUIDv4 ID，在 `related` 欄位中指定原始 ID，並將 `type` 標記為 `derived`。對於可以轉換成多條規則（`sysmon` 與 `builtin`）的規則，我們也需要為衍生的 `builtin` 規則建立新的規則 ID。為此，我們會計算 `sysmon` 規則 ID 的 MD5 雜湊值，並將其用於 UUIDv4 ID。例如：

    原始的 Sigma 規則：

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    新的 `sysmon` 規則：

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    新的 `builtin` 規則：

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. 在內建 Windows 事件記錄中進行偵測的規則會輸出到 `builtin` 目錄，而依賴 Sysmon 記錄的規則則輸出到 `sysmon` 目錄，其子目錄與上游 Sigma 儲存庫中的目錄相符。

## 轉換的限制

目前只有一個[已知的錯誤](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2)：Sigma 規則中的註解行不會被包含在輸出規則中，除非這些註解跟在某些原始碼之後。

## Sysmon 與內建事件的比較及規則轉換 { #sysmon-builtin-comparison }

### 處理程序建立

* 類別：`process_creation`
* Sysmon
    * 通道：`Microsoft-Windows-Sysmon/Operational`
    * 事件 ID：`1`
* 內建記錄
    * 通道：`Security`
    * 事件 ID：`4688`

**比較**

![處理程序建立比較](../assets/rules-doc/process_creation_comparison.png)

**轉換注意事項**

1. `User` 欄位資訊需要拆分為 `SubjectUserName` 與 `SubjectDomainName` 兩個欄位。
2. `LogonId` 欄位名稱變更為 `SubjectLogonId`，且十六進位值中的任何字母都需要轉為小寫。
3. `ProcessId` 欄位名稱變更為 `NewProcessId`，且值需要轉換為十六進位。
4. `Image` 欄位名稱變更為 `NewProcessName`。
5. `ParentProcessId` 欄位名稱變更為 `ProcessId`，且值需要轉換為十六進位。
6. `ParentImage` 欄位名稱變更為 `ParentProcessName`。
7. `IntegrityLevel` 欄位名稱變更為 `MandatoryLabel`，且需要進行以下值的轉換：
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. 如果規則包含以下僅存在於 `Security 4688` 事件中的欄位，我們就不會建立 `Sysmon 1` 規則：
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. 如果規則包含以下僅存在於 `Sysmon 1` 事件中的欄位，我們就不會建立 `Security 4688` 規則：
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. 第 8 點與第 9 點有一個例外：即使使用了僅存在於某一種記錄事件中的欄位，只要該欄位位於 `OR` 條件中，你仍然應該建立該規則。例如，以下規則**不應**產生 `Security 4688` 規則，因為 `OriginalFileName` 欄位是必要的（選擇項內為 `AND` 邏輯）：

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    然而，具有以下條件的規則**應該**建立 `Security 4688` 規則，因為 `OriginalFileName` 是選用的（選擇項內為 `OR` 邏輯）：

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    困難之處在於，你的剖析器不僅要理解選擇項內部的邏輯，還要理解 `condition` 欄位內部的邏輯。例如，以下規則**不應**建立 `Security 4688` 規則，因為它使用 `AND` 邏輯：

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    然而，以下規則**應該**建立 `Security 4688` 規則，因為它使用 `OR` 邏輯：

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**其他注意事項**

* `Security 4688` 中的 `SubjectUserSid` 欄位顯示 SID；然而，在轉譯後的事件記錄 `Message` 中，它會被轉換為 `DOMAIN\User`。
* 視設定而定，`Security 4688` 事件的 `CommandLine` 中可能不包含命令列選項資訊。
* `TokenElevationType` 在 `Message` 中會原樣顯示，不會被轉譯。
* `MandatoryLabel` 中的 `S-1-16-4096` 等值，在轉譯後的 `Message` 中會被轉換為 `Mandatory Label\Low Mandatory Level` 等。

**內建記錄設定**

!!! warning "預設未啟用"
    重要的內建 `Security 4688` 處理程序建立事件記錄預設並未啟用。你需要同時啟用 `4688` 事件與命令列選項記錄，才能使用大多數的 Sigma 規則。

*透過群組原則啟用：*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*透過命令列啟用：*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### 網路連線

* 類別：`network_connection`
* Sysmon
    * 通道：`Microsoft-Windows-Sysmon/Operational`
    * 事件 ID：`3`
* 內建記錄
    * 通道：`Security`
    * 事件 ID：`5156`

**比較**

![網路連線比較](../assets/rules-doc/network_connection_comparison.png)

**轉換注意事項**

1. `ProcessId` 欄位名稱變更為 `ProcessID`。
2. `Image` 欄位名稱變更為 `Application`，且 `C:\` 變更為 `\device\harddiskvolume?\`。（注意：由於我們不知道硬碟磁碟區編號，因此以單一字元萬用字元 `?` 取代。）
3. `Protocol` 欄位值 `tcp` 變更為 `6`，`udp` 變更為 `17`。
4. `Initiated` 欄位名稱變更為 `Direction`，且值 `true` 變更為 `%%14593`，`false` 變更為 `%%14592`。
5. `SourceIp` 欄位名稱變更為 `SourceAddress`。
6. `DestinationIp` 欄位名稱變更為 `DestAddress`。
7. `DestinationPort` 欄位名稱變更為 `DestPort`。

**內建記錄設定**

!!! warning "預設未啟用"
    內建的 `Security 5156` 網路連線記錄預設並未啟用。它們會產生大量記錄，可能覆寫 `Security` 事件記錄中的其他重要記錄，並在系統有大量網路連線時可能拖慢系統。請確保 `Security` 記錄的最大檔案大小夠大，並進行測試以確認不會對系統造成不良影響。

*透過群組原則啟用：*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*透過命令列啟用：*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

……如果你使用非英文的地區設定，則使用以下命令：

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "另請參閱"
    如需更多關於啟用這些規則所依賴之證據所需的內建 Windows 事件記錄的資訊，請參閱 [Windows 記錄與 Sysmon](../resources/logging.md) 以及 [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) 專案。

## Sigma 規則撰寫建議

!!! tip
    如果你使用了任何存在於 `sysmon` 記錄但不存在於 `builtin` 記錄中的欄位，請務必將該欄位設為選用，這樣仍然可以將該規則用於 `builtin` 記錄。

例如：

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

此選擇項會尋找處理程序（`Image`）名稱為 `addinutil.exe` 的情況。問題在於攻擊者只要重新命名檔案就能繞過該規則。僅存在於 Sysmon 記錄中的 `OriginalFileName` 欄位，是在編譯時嵌入二進位檔的檔名。即使攻擊者重新命名檔案，嵌入的名稱也不會改變，因此在使用 Sysmon 時，此規則能夠偵測攻擊者已重新命名檔案的攻擊；而在使用標準內建記錄時，也能偵測未變更檔名的攻擊。

## 預先轉換的 Sigma 規則

以本頁所述方式——透過將 `logsource` 欄位去抽象化——所整理的 Sigma 規則，託管在 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 儲存庫的 `sigma` 資料夾下。

## 工具環境

如果你想在本機將 Sigma 規則轉換為 Hayabusa 相容格式，首先需要安裝 [Poetry](https://python-poetry.org/)。請參閱官方 Poetry [安裝文件](https://python-poetry.org/docs/#installation)。

## 工具使用方式

`sigma-to-hayabusa-converter.py` 是我們用來將 Sigma 規則的 `logsource` 欄位轉換為 Hayabusa 相容格式的主要工具。執行以下步驟來運行它：

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

執行上述命令後，轉換為 Hayabusa 相容格式的規則會輸出到 `./converted_sigma_rules` 目錄。
