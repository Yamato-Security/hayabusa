# 時間軸輸出

## 輸出設定檔

Hayabusa 在 `config/profiles.yaml` 中有 5 個預先定義的輸出設定檔可供使用:

1. `minimal`
2. `standard` (預設)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

您可以透過編輯此檔案輕鬆自訂或新增您自己的設定檔。
您也可以使用 `set-default-profile --profile <profile>` 輕鬆變更預設設定檔。
使用 `list-profiles` 指令來顯示可用的設定檔及其欄位資訊。

### 1. `minimal` 設定檔輸出

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard` 設定檔輸出

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose` 設定檔輸出

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info` 設定檔輸出

不會輸出最精簡的 `details` 資訊,而是會將 `EventData` 與 `UserData` 區段中的所有欄位資訊連同其原始欄位名稱一併輸出。

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose` 設定檔輸出

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose` 設定檔輸出

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal` 設定檔輸出

輸出為與匯入 [Timesketch](https://timesketch.org/) 相容的格式。

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose` 設定檔輸出

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 設定檔比較

以下基準測試是在 2018 年的 Lenovo P51 (Xeon 4 核心 CPU / 64GB RAM) 上,使用 3GB 的 evtx 資料並啟用 3891 條規則所進行。(2023/06/01)

| 設定檔 | 處理時間 | 輸出檔案大小 | 檔案大小增幅 |
| :---: | :---: | :---: | :---: |
| minimal | 8 分 50 秒 | 770 MB | -30% |
| standard (預設) | 9 分 00 秒 | 1.1 GB | 無 |
| verbose | 9 分 10 秒 | 1.3 GB | +20% |
| all-field-info | 9 分 3 秒 | 1.2 GB | +10% |
| all-field-info-verbose | 9 分 10 秒 | 1.3 GB | +20% |
| super-verbose | 9 分 12 秒 | 1.5 GB | +35% |

### 設定檔欄位別名

以下資訊可透過內建的輸出設定檔輸出:

| 別名名稱 | Hayabusa 輸出資訊 |
| :--- | :--- |
|%AllFieldInfo% | 所有欄位資訊。 |
|%Channel% | 記錄檔的名稱。`<Event><System><Channel>` 欄位。 |
|%Computer% | `<Event><System><Computer>` 欄位。 |
|%Details% | YML 偵測規則中的 `details` 欄位,然而,只有 hayabusa 規則才有此欄位。此欄位提供有關警示或事件的額外資訊,並可從事件記錄檔的欄位中擷取有用的資料。例如使用者名稱、命令列資訊、處理程序資訊等等。當預留位置指向不存在的欄位,或別名對應不正確時,將會輸出為 `n/a` (無法取得)。如果未指定 `details` 欄位 (即 sigma 規則),則會輸出在 `./rules/config/default_details.txt` 中定義用於擷取欄位的預設 `details` 訊息。您可以在 `default_details.txt` 中加入您想要輸出的 `Provider Name`、`EventID` 和 `details` 訊息,以新增更多預設 `details` 訊息。當規則中與 `default_details.txt` 中均未定義 `details` 欄位時,所有欄位都會輸出到 `details` 欄。 |
|%ExtraFieldInfo% | 列印未在 %Details% 中輸出的欄位資訊。 |
|%EventID% | `<Event><System><EventID>` 欄位。 |
|%EvtxFile% | 造成警示或事件的 evtx 檔案名稱。 |
|%Level% | YML 偵測規則中的 `level` 欄位。(`informational`、`low`、`medium`、`high`、`critical`) |
|%MitreTactics% | MITRE ATT&CK [戰術](https://attack.mitre.org/tactics/enterprise/) (例如:Initial Access、Lateral Movement 等等)。 |
|%MitreTags% | MITRE ATT&CK 群組 ID、技術 ID 和軟體 ID。 |
|%OtherTags% | YML 偵測規則的 `tags` 欄位中未包含於 `MitreTactics` 或 `MitreTags` 內的任何關鍵字。 |
|%Provider% | `<Event><System><Provider>` 欄位中的 `Name` 屬性。 |
|%RecordID% | 來自 `<Event><System><EventRecordID>` 欄位的事件記錄 ID。 |
|%RuleAuthor% | YML 偵測規則中的 `author` 欄位。 |
|%RuleCreationDate% | YML 偵測規則中的 `date` 欄位。 |
|%RuleFile% | 產生該警示或事件的偵測規則檔案名稱。 |
|%RuleID% | YML 偵測規則中的 `id` 欄位。 |
|%RuleModifiedDate% | YML 偵測規則中的 `modified` 欄位。 |
|%RuleTitle% | YML 偵測規則中的 `title` 欄位。 |
|%Status% | YML 偵測規則中的 `status` 欄位。 |
|%Timestamp% | 預設為 `YYYY-MM-DD HH:mm:ss.sss +hh:mm` 格式。事件記錄檔中的 `<Event><System><TimeCreated SystemTime>` 欄位。預設時區為本機時區,但您可以使用 `--UTC` 選項將時區變更為 UTC。 |

#### 額外的設定檔欄位別名

如果您需要,也可以將此額外別名加入您的輸出設定檔:

| 別名名稱 | Hayabusa 輸出資訊 |
| :--- | :--- |
|%RenderedMessage% | WEC 轉送記錄檔中的 `<Event><RenderingInfo><Message>` 欄位。 |

注意:此別名**不**包含於任何內建設定檔中,因此您需要手動編輯 `config/default_profile.yaml` 檔案並加入以下行:

```
Message: "%RenderedMessage%"
```

您也可以定義 [事件鍵別名](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) 來輸出其他欄位。
