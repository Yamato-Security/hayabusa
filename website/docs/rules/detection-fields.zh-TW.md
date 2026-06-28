# 偵測欄位

## Selection 基礎

首先，將說明如何建立 selection 規則的基礎概念。

### 如何撰寫 AND 與 OR 邏輯

要撰寫 AND 邏輯，我們會使用巢狀字典。
下方的偵測規則定義了**兩個條件**都必須為真，規則才會比對成功。
- EventID 必須剛好為 `7040`。
- **AND**
- Channel 必須剛好為 `System`。

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

要撰寫 OR 邏輯，我們會使用清單（以 `-` 開頭的字典）。
在下方的偵測規則中，**任一個**條件成立都會觸發規則。
- EventID 必須剛好為 `7040`。
- **OR**
- Channel 必須剛好為 `System`。

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

我們也可以如下所示結合 `AND` 與 `OR` 邏輯。
在這個情況下，當以下兩個條件都為真時，規則才會比對成功。
- EventID 剛好為 `7040` **OR** `7041`。
- **AND**
- Channel 剛好為 `System`。

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

以下是一段 Windows 事件日誌的擷取內容，以原始 XML 格式呈現。
上方規則檔範例中的 `Event.System.Channel` 欄位指的是原始的 XML 標籤：`<Event><System><Channel>System<Channel><System></Event>`
巢狀的 XML 標籤會以點（`.`）分隔的標籤名稱來取代。
在 hayabusa 規則中，這些以點連接在一起的欄位字串稱為 `eventkeys`。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Eventkey 別名

帶有許多 `.` 分隔的長 eventkey 很常見，因此 hayabusa 會使用別名讓它們更容易使用。別名定義在 `rules/config/eventkey_alias.txt` 檔案中。這個檔案是一個由 `alias` 與 `event_key` 對應關係組成的 CSV 檔案。你可以如下所示以別名改寫上方的規則，讓規則更易於閱讀。

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### 注意：未定義的 Eventkey 別名

並非所有的 eventkey 別名都定義在 `rules/config/eventkey_alias.txt` 中。如果你在 `details`（`Alert details`）訊息中沒有取得正確的資料，反而得到 `n/a`（not available），或是你偵測邏輯中的 selection 無法正常運作，那麼你可能需要在 `rules/config/eventkey_alias.txt` 中更新一個新的別名。

### 如何在條件中使用 XML 屬性

XML 元素可以透過在元素中加入空格來設定屬性。例如，下方 `Provider Name` 中的 `Name` 就是 `Provider` 元素的一個 XML 屬性。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

要在 eventkey 中指定 XML 屬性，請使用 `{eventkey}_attributes.{attribute_name}` 格式。例如，要在規則檔中指定 `Provider` 元素的 `Name` 屬性，看起來會像這樣：

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep 搜尋

Hayabusa 可以透過不指定任何 eventkey 來在 Windows 事件日誌檔案中執行 grep 搜尋。

要執行 grep 搜尋，請如下所示指定偵測內容。在這個情況下，如果 Windows 事件日誌中包含字串 `mimikatz` 或 `metasploit`，就會比對成功。也可以指定萬用字元。

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> 注意：Hayabusa 在處理資料之前，會在內部將 Windows 事件日誌資料轉換成 JSON 格式，因此無法針對 XML 標籤進行比對。

### EventData

Windows 事件日誌分為兩個部分：寫入基本資料（Event ID、Timestamp、Record ID、Log name（Channel））的 `System` 部分，以及依據 Event ID 寫入任意資料的 `EventData` 或 `UserData` 部分。
經常出現的一個問題是，巢狀於 `EventData` 中的欄位名稱全都叫做 `Data`，因此目前為止所描述的 eventkey 無法區分 `SubjectUserSid` 與 `SubjectUserName`。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

為了解決這個問題，你可以指定 `Data Name` 中所賦予的值。例如，如果你想在規則條件中使用 EventData 裡的 `SubjectUserName` 與 `SubjectDomainName`，可以如下所示描述：

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventData 中的異常模式

巢狀於 `EventData` 中的某些標籤沒有 `Name` 屬性。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

要偵測像上面這樣的事件日誌，你可以指定一個名為 `Data` 的 eventkey。
在這個情況下，只要任何一個巢狀的 `Data` 標籤等於 `None`，條件就會比對成功。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### 從多個同名欄位輸出欄位資料

某些事件會將其資料儲存到全都叫做 `Data` 的欄位名稱中，就像前面的範例一樣。
如果你在 `details:` 中指定 `%Data%`，所有的資料都會以陣列的形式輸出。

例如：
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

如果你只想印出第一個 `Data` 欄位的資料，可以在你的 `details:` 警示字串中指定 `%Data[1]%`，這樣就只會輸出 `rundll32.exe`。

## 欄位修飾子

如下所示，可以將管線字元與 eventkey 一起使用來進行字串比對。
目前為止我們所描述的所有條件都使用完全比對，但透過使用欄位修飾子，你可以描述更彈性的偵測規則。
在以下範例中，如果 `Data` 的值包含字串 `EngineVersion=2`，就會符合條件。

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

字串比對不區分大小寫。然而，只要使用 `|re` 或 `|equalsfield`，就會變成區分大小寫。

### 支援的 Sigma 欄位修飾子

Hayabusa 目前是唯一完整支援所有 Sigma 規格的開源工具。

你可以在 https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md 查看所有支援的欄位修飾子的目前狀態，以及這些修飾子在 Sigma 和 Hayabusa 規則中被使用了多少次。
這份文件會在每次 Sigma 或 Hayabusa 規則更新時動態更新。

- `'|all':`：這個欄位修飾子與上述的不同，因為它不是套用到某個特定欄位，而是套用到所有欄位。

    在這個範例中，字串 `Keyword-1` 與 `Keyword-2` 都需要存在，但可以存在於任何欄位的任何位置：
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`：資料會依據其在編碼字串中的位置，以三種不同的方式編碼為 base64。這個修飾子會將字串編碼成全部三種變體，並檢查該字串是否被編碼於 base64 字串中的某處。
- `|cased`：使搜尋區分大小寫。
- `|cidr`：檢查欄位值是否符合 IPv4 或 IPv6 CIDR 表示法。（例如：`192.0.2.0/24`）
- `|contains`：檢查欄位值是否包含某個字串。
- `|contains|all`：檢查資料中是否包含多個字詞。
- `|contains|all|windash`：與 `|contains|windash` 相同，但所有的關鍵字都需要存在。
- `|contains|cased`：檢查欄位值是否包含某個區分大小寫的字串。
- `|contains|expand`：檢查欄位值是否包含 `/config/expand/` 內 `expand` 設定檔中的某個字串。
- `|contains|windash`：會原封不動地檢查字串，同時也會將第一個 `-` 字元轉換為 `/`、`–`（en dash）、`—`（em dash）以及 `―`（horizontal bar）字元的排列組合。
- `|endswith`：檢查欄位值是否以某個字串結尾。
- `|endswith|cased`：檢查欄位值是否以某個區分大小寫的字串結尾。
- `|endswith|windash`：檢查字串的結尾並對破折號執行各種變體。
- `|exists`：檢查欄位是否存在。
- `|expand`：檢查欄位值是否等於 `/config/expand/` 內 `expand` 設定檔中的某個字串。
- `|fieldref`：檢查兩個欄位中的值是否相同。如果你想檢查兩個欄位是否不同，可以在 `condition` 中使用 `not`。
- `|fieldref|contains`：檢查一個欄位的值是否被包含在另一個欄位中。
- `|fieldref|endswith`：檢查左側欄位是否以右側欄位的字串結尾。如果你想檢查它們是否不同，可以在 `condition` 中使用 `not`。
- `|fieldref|startswith`：檢查左側欄位是否以右側欄位的字串開頭。如果你想檢查它們是否不同，可以在 `condition` 中使用 `not`。
- `|gt`：檢查欄位值是否大於某個數字。
- `|gte`：檢查欄位值是否大於或等於某個數字。
- `|lt`：檢查欄位值是否小於某個數字。
- `|lte`：檢查欄位值是否小於或等於某個數字。
- `|re`：使用區分大小寫的正規表示式。（我們使用的是 regex crate，因此請參閱位於 <https://docs.rs/regex/latest/regex/#syntax> 的文件，以了解如何撰寫支援的正規表示式。）
    > 注意：[Sigma 規則中的正規表示式語法](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression)使用 PCRE，其中字元類別、後行斷言、原子分組等的某些中繼字元並不受支援。Rust regex crate 應該能夠使用 Sigma 規則中所有的正規表示式，但仍有不相容的可能性。
- `|re|i`：（Insensitive，不區分大小寫）使用不區分大小寫的正規表示式。
- `|re|m`：（Multi-line，多行）跨多行比對。`^` / `$` 比對行的開頭/結尾。
- `|re|s`：（Single-line，單行）點（`.`）比對所有字元，包括換行字元。
- `|startswith`：檢查欄位值是否以某個字串開頭。
- `|startswith|cased`：檢查欄位值是否以某個區分大小寫的字串開頭。
- `|utf16|base64offset|contains`：檢查某個 UTF-16 字串是否被編碼於 base64 字串內。
- `|utf16be|base64offset|contains`：檢查某個 UTF-16 big-endian 字串是否被編碼於 base64 字串內。
- `|utf16le|base64offset|contains`：檢查某個 UTF-16 little-endian 字串是否被編碼於 base64 字串內。
- `|wide|base64offset|contains`：`utf16le|base64offset|contains` 的別名，用於檢查 UTF-16 little-endian 字串。

### 已棄用的欄位修飾子

以下修飾子現已棄用，並由更符合 sigma 規格的修飾子取代。

- `|equalsfield`：現已由 `|fieldref` 取代。
- `|endswithfield`：現已由 `|fieldref|endswith` 取代。

### Expand 欄位修飾子

`expand` 欄位修飾子之所以獨特，在於它們是唯一在使用前需要進行設定的欄位修飾子。
例如，它們使用如 `%DC-MACHINE-NAME%` 這樣的預留位置，並且需要一個名為 `/config/expand/DC-MACHINE-NAME.txt` 的設定檔，其中包含所有可能的 DC 機器名稱。

如何設定這個部分在[此處](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command)有更詳細的說明。

## 萬用字元

eventkey 中可以使用萬用字元。在下方範例中，如果 `ProcessCommandLine` 以字串 "malware" 開頭，規則就會比對成功。
其規格基本上與 sigma 規則的萬用字元相同，因此會不區分大小寫。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

可以使用以下兩種萬用字元。
- `*`：比對零個或多個字元組成的任何字串。（在內部會被轉換為正規表示式 `.*`）
- `?`：比對任何單一字元。（在內部會被轉換為正規表示式 `.`）

關於跳脫萬用字元：
- 萬用字元（`*` 與 `?`）可以使用反斜線來跳脫：`\*`、`\?`。
- 如果你想在萬用字元前面直接使用反斜線，請寫成 `\\*` 或 `\\?`。
- 如果你只是單獨使用反斜線，則不需要跳脫。

## null 關鍵字

`null` 關鍵字可以用來檢查欄位是否不存在。

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

注意：這與 `ProcessCommandLine: ''` 不同，後者檢查的是欄位的值是否為空。

## condition

透過我們上面說明的表示法，你可以表達 `AND` 與 `OR` 邏輯，但如果你試圖定義複雜的邏輯，就會變得令人困惑。
當你想要製作更複雜的規則時，應該如下所示使用 `condition` 關鍵字。

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

`condition` 可以使用以下運算式。
- `{expression1} and {expression2}`：同時需要 {expression1} AND {expression2}
- `{expression1} or {expression2}`：需要 {expression1} OR {expression2} 其中之一
- `not {expression}`：反轉 {expression} 的邏輯
- `( {expression} )`：設定 {expression} 的優先順序。它遵循與數學相同的優先順序邏輯。

在上面的範例中，使用了如 `SELECTION_1`、`SELECTION_2` 等 selection 名稱，但只要它們只包含以下字元，就可以命名為任何名稱：`a-z A-Z 0-9 _`
> 然而，請盡可能使用 `selection_1`、`selection_2`、`filter_1`、`filter_2` 等標準慣例，讓內容易於閱讀。

## not 邏輯

許多規則會導致誤報，因此非常常見的做法是除了用來搜尋特徵碼的 selection 之外，再設置一個 filter selection 以避免對誤報發出警示。
例如：

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma 關聯

我們已實作[此處](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md)所定義的所有 Sigma 2.0.0 版關聯。

支援的關聯：
- Event Count（`event_count`）
- Value Count（`value_count`）
- Temporal Proximity（`temporal`）
- Ordered Temporal Proximity（`temporal_ordered`）

於 2025 年 9 月 12 日在 Sigma 2.1.0 版發布的新「metrics」關聯規則（`value_sum`、`value_avg`、`value_percentile`）目前尚不支援。
