# DFIR 時間軸指令

## 掃描精靈

`csv-timeline` 與 `json-timeline` 指令現在預設啟用掃描精靈。
此功能旨在協助使用者依據自身需求與偏好，輕鬆選擇要啟用哪些偵測規則。
要載入的偵測規則集合是依據 Sigma 專案的官方清單而定。
詳細說明請參閱[這篇部落格文章](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81)。
您可以加上 `-w, --no-wizard` 選項，輕鬆關閉精靈並以傳統方式使用 Hayabusa。

### Core 規則

`core` 規則集會啟用狀態為 `test` 或 `stable`、且等級為 `high` 或 `critical` 的規則。
這些是高品質、高可信度與高相關性的規則，不應產生太多誤判。
規則狀態為 `test` 或 `stable`，代表超過 6 個月未回報任何誤判。
規則會比對攻擊者技術、一般可疑活動或惡意行為。
這與使用 `--exclude-status deprecated,unsupported,experimental --min-level high` 選項相同。

### Core+ 規則

`core+` 規則集會啟用狀態為 `test` 或 `stable`、且等級為 `medium` 或更高的規則。
`medium` 規則通常需要額外調校，因為可能比對到某些應用程式、組織中正當的使用者行為或指令稿。
這與使用 `--exclude-status deprecated,unsupported,experimental --min-level medium` 選項相同。

### Core++ 規則

`core++` 規則集會啟用狀態為 `experimental`、`test` 或 `stable`、且等級為 `medium` 或更高的規則。
這些規則屬於最新前沿。
它們會針對 SigmaHQ 專案提供的基準 evtx 檔案進行驗證，並由多位偵測工程師審查。
除此之外，它們一開始幾乎未經測試。
若您希望盡早偵測威脅，並願意承擔管理較高誤判門檻的代價，則可使用這些規則。
這與使用 `--exclude-status deprecated,unsupported --min-level medium` 選項相同。

### Emerging Threats (ET) 附加規則

`Emerging Threats (ET)` 規則集會啟用帶有 `detection.emerging_threats` 標籤的規則。
這些規則針對特定威脅，對於目前資訊尚不充足的當前威脅尤其有用。
這些規則不應有太多誤判，但其相關性會隨時間下降。
未啟用這些規則時，等同於使用 `--exclude-tag detection.emerging_threats` 選項。
以傳統方式不使用精靈執行 Hayabusa 時，這些規則會預設包含在內。

### Threat Hunting (TH) 附加規則

`Threat Hunting (TH)` 規則集會啟用帶有 `detection.threat_hunting` 標籤的規則。
這些規則可能偵測到未知的惡意活動，但通常會有較多誤判。
未啟用這些規則時，等同於使用 `--exclude-tag detection.threat_hunting` 選項。
以傳統方式不使用精靈執行 Hayabusa 時，這些規則會預設包含在內。

## 以 Channel 為基礎的事件記錄與規則過濾

自 Hayabusa v2.16.0 起，我們在載入 `.evtx` 檔案與 `.yml` 規則時啟用以 Channel 為基礎的過濾器。
其目的是只載入必要的內容，使掃描盡可能有效率。
雖然單一事件記錄中可能存在多個 provider，但單一 evtx 檔案中存在多個 channel 的情況並不常見。
（我們唯一見過的情況，是有人為了 [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) 專案而人為地將兩個不同的 evtx 檔案合併在一起。）
我們可以善用這一點，先檢查每個指定要掃描的 `.evtx` 檔案中第一筆記錄的 `Channel` 欄位。
我們也會檢查各個 `.yml` 規則在規則的 `Channel` 欄位中所指定的 channel。
有了這兩份清單，我們便只載入使用了 `.evtx` 檔案中實際存在之 channel 的規則。

舉例來說，若使用者想掃描 `Security.evtx`，則只會使用指定 `Channel: Security` 的規則。
載入其他偵測規則並無意義，例如只在 `Application` 記錄中尋找事件的規則等等。
請注意，channel 欄位（例如：`Channel: Security`）並未在原始 Sigma 規則中**明確**定義。
在 Sigma 規則中，channel 與 event ID 欄位是透過 `logsource` 下的 `service` 與 `category` 欄位**隱含**定義的。（例如：`service: security`）
當我們在 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 儲存庫中整理 Sigma 規則時，會將 `logsource` 欄位去抽象化，並明確定義 channel 與 event ID 欄位。
我們在[此處](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)深入說明我們為何以及如何這麼做。

目前只有以下兩條偵測規則未定義 `Channel`，並設計為掃描所有 `.evtx` 檔案：
- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

若您想使用這兩條規則並對載入的 `.evtx` 檔案掃描所有規則，則需要在 `csv-timeline` 與 `json-timeline` 指令中加上 `-A, --enable-all-rules` 選項。
在我們的基準測試中，規則過濾通常會帶來 20% 到 10 倍的速度提升，這取決於掃描的檔案，當然也會使用較少的記憶體。

Channel 過濾在載入 `.evtx` 檔案時也會使用。
舉例來說，若您指定一條尋找 channel 為 `Security` 之事件的規則，那麼載入並非來自 `Security` 記錄的 `.evtx` 檔案便毫無意義。
在我們的基準測試中，這在一般掃描下帶來約 10% 的速度優勢，而以單一規則掃描時，效能提升可達 60% 以上。
若您確定單一 `.evtx` 檔案中使用了多個 channel，例如有人使用工具將多個 `.evtx` 檔案合併在一起，則可在 `csv-timeline` 與 `json-timeline` 指令中以 `-a, --scan-all-evtx-files` 選項停用此過濾。

> 注意：Channel 過濾僅適用於 `.evtx` 檔案；若您嘗試以 `-J, --json-input` 從 JSON 檔案載入事件記錄並同時指定 `-A` 或 `-a`，將會收到錯誤。

## `csv-timeline` 指令

`csv-timeline` 指令會以 CSV 格式建立事件的鑑識時間軸。

```
Usage: csv-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -M, --multiline                    Output event field information in multiple rows
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in CSV format (ex: results.csv)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)
  -S, --tab-separator                Separate event field information by tabs

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `csv-timeline` 指令範例

* 以預設 `standard` 設定檔對單一 Windows 事件記錄檔案執行 hayabusa：

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* 以 verbose 設定檔對包含多個 Windows 事件記錄檔案的 sample-evtx 目錄執行 hayabusa：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* 匯出為單一 CSV 檔案，以便使用 LibreOffice、Timeline Explorer、Elastic Stack 等進行進一步分析，並包含所有欄位資訊（警告：使用 `super-verbose` 設定檔時，您的檔案輸出大小會變得相當大！）：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* 啟用 EID（Event ID）過濾器：

> 注意：在我們的測試中，啟用 EID 過濾器會將分析速度提升約 10-15%，但有可能遺漏部分警示。

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* 只執行 hayabusa 規則（預設是執行 `-r .\rules` 中的所有規則）：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* 只針對 Windows 上預設啟用之記錄執行 hayabusa 規則：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* 只針對 sysmon 記錄執行 hayabusa 規則：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* 只執行 sigma 規則：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* 啟用已淘汰規則（`status` 標記為 `deprecated` 者）以及吵雜規則（其規則 ID 列於 `.\rules\config\noisy_rules.txt` 者）：

> 注意：近來已淘汰規則改放在 sigma 儲存庫中的獨立目錄，因此 Hayabusa 不再預設包含這些規則。
> 因此，您大概不需要啟用已淘汰規則。

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* 只執行用於分析登入的規則，並以 UTC 時區輸出：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* 在運作中的 Windows 機器上執行（需要系統管理員權限），並只偵測警示（潛在的惡意行為）：

```
hayabusa.exe csv-timeline -l -m low
```

* 列印詳細資訊（有助於判斷哪些檔案需要較長時間處理、剖析錯誤等等）：

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* 詳細輸出範例：

載入規則：

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

掃描期間的錯誤：
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* 輸出為相容於匯入 [Timesketch](https://timesketch.org/) 的 CSV 格式：

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* 安靜錯誤模式：
預設情況下，hayabusa 會將錯誤訊息儲存到錯誤記錄檔案。
若您不想儲存錯誤訊息，請加上 `-Q`。

### 進階 - GeoIP 記錄擴充

您可以利用免費的 GeoLite2 地理位置資料，將 GeoIP（ASN 組織、城市與國家）資訊加入 SrcIP（來源 IP）欄位與 TgtIP（目標 IP）欄位。

步驟：
1. 首先在[此處](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)註冊 MaxMind 帳號。
2. 從[下載頁面](https://www.maxmind.com/en/accounts/current/geoip/downloads)下載三個 `.mmdb` 檔案並儲存到某個目錄。檔名應分別為 `GeoLite2-ASN.mmdb`、	`GeoLite2-City.mmdb` 與 `GeoLite2-Country.mmdb`。
3. 執行 `csv-timeline` 或 `json-timeline` 指令時，加上 `-G` 選項，後接含有 MaxMind 資料庫的目錄。

* 使用 `csv-timeline` 時，會額外輸出以下 6 個欄位：`SrcASN`、`SrcCity`、`SrcCountry`、`TgtASN`、`TgtCity`、`TgtCountry`。
* 使用 `json-timeline` 時，同樣的 `SrcASN`、`SrcCity`、`SrcCountry`、`TgtASN`、`TgtCity`、`TgtCountry` 欄位會加入 `Details` 物件中，但僅在它們含有資訊時才加入。

* 當 `SrcIP` 或 `TgtIP` 為 localhost（`127.0.0.1`、`::1` 等等）時，`SrcASN` 或 `TgtASN` 會輸出為 `Local`。
* 當 `SrcIP` 或 `TgtIP` 為私有 IP 位址（`10.0.0.0/8`、`fe80::/10` 等等）時，`SrcASN` 或 `TgtASN` 會輸出為 `Private`。

#### GeoIP 設定檔

含有來源與目標 IP 位址、並用於在 GeoIP 資料庫中查詢的欄位名稱，定義於 `rules/config/geoip_field_mapping.yaml`。
必要時您可以新增至此清單。
此檔案中還有一個過濾區段，用於決定要從哪些事件擷取 IP 位址資訊。

#### GeoIP 資料庫的自動更新

MaxMind GeoIP 資料庫每 2 週更新一次。
您可以在[此處](https://github.com/maxmind/geoipupdate)安裝 MaxMind `geoipupdate` 工具，以便自動更新這些資料庫。

macOS 上的步驟：
1. `brew install geoipupdate`
2. 編輯 `/usr/local/etc/GeoIP.conf` 或 `/opt/homebrew/etc/GeoIP.conf`：填入您登入 MaxMind 網站後建立的 `AccountID` 與 `LicenseKey`。確認 `EditionIDs` 那一行為 `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`。
3. 執行 `geoipupdate`。
4. 當您想加入 GeoIP 資訊時，加上 `-G /usr/local/var/GeoIP` 或 `-G /opt/homebrew/var/GeoIP`。

Windows 上的步驟：
1. 從 [Releases](https://github.com/maxmind/geoipupdate/releases) 頁面下載最新的 Windows 二進位檔（例如：`geoipupdate_4.10.0_windows_amd64.zip`）。
2. 編輯 `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`：填入您登入 MaxMind 網站後建立的 `AccountID` 與 `LicenseKey`。確認 `EditionIDs` 那一行為 `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`。
3. 執行 `geoipupdate` 執行檔。

### `csv-timeline` 指令設定檔

`./rules/config/channel_abbreviations.txt`：channel 名稱與其縮寫的對應。

`./rules/config/default_details.txt`：用於設定在規則未指定 `details:` 行時，應輸出何種預設欄位資訊（`%Details%` 欄位）的設定檔。
此設定以 provider 名稱與 event ID 為基礎。

`./rules/config/eventkey_alias.txt`：此檔案含有欄位簡稱別名與其原始較長欄位名稱的對應。

範例：
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

若某個欄位未在此處定義，Hayabusa 會自動在 `Event.EventData` 下檢查該欄位。

`./rules/config/exclude_rules.txt`：此檔案含有會被排除使用的規則 ID 清單。
通常是因為某條規則取代了另一條，或該規則本身就無法使用。
與防火牆和 IDS 一樣，任何以特徵為基礎的工具都需要一些調校以符合您的環境，因此您可能需要永久或暫時排除某些規則。
您可以將規則 ID（例如：`4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`）加入 `./rules/config/exclude_rules.txt`，以忽略任何您不需要或無法使用的規則。

`./rules/config/noisy_rules.txt`：此檔案含有預設停用的規則 ID 清單，但可透過 `-n, --enable-noisy-rules` 選項啟用吵雜規則來開啟。
這些規則通常本質上吵雜，或是因為誤判而吵雜。

`./rules/config/target_event_IDs.txt`：若啟用 EID 過濾器，則只會掃描此檔案中指定的 event ID。
預設情況下，Hayabusa 會掃描所有事件，但若您想提升效能，請使用 `-E, --EID-filter` 選項。
這通常可帶來 10~25% 的速度提升。

## `json-timeline` 指令

`json-timeline` 指令會以 JSON 或 JSONL 格式建立事件的鑑識時間軸。
輸出為 JSONL 會比 JSON 更快且檔案大小更小，因此若您只是要將結果匯入像 Elastic Stack 這類的其他工具，這會很合適。
若您要以文字編輯器手動分析結果，JSON 會比較好。
CSV 輸出適合將較小的時間軸（通常小於 2GB）匯入像 LibreOffice 或 Timeline Explorer 這類工具。
JSON 最適合搭配像 `jq` 這類工具，對資料（包括大型結果檔案）進行更詳細的分析，因為 `Details` 欄位是分開的，較易於分析。
（在 CSV 輸出中，所有事件記錄欄位都集中在一個龐大的 `Details` 欄中，使得資料排序等操作較為困難。）

```
Usage: json-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -L, --JSONL-output                 Save the timeline in JSONL format (ex: -L -o results.jsonl)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in JSON format (ex: results.json)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `json-timeline` 指令範例與設定檔

`json-timeline` 的選項與設定檔和 `csv-timeline` 相同，但多了一個額外選項 `-L, --JSONL-output`，用於輸出為 JSONL 格式。

## `level-tuning` 指令

`level-tuning` 指令可讓您調校規則的警示等級，依您的需要調高或調低風險等級。
此指令使用設定檔來覆寫 `rules` 資料夾中規則的風險等級（`level` 欄位）。

> 警告：每次您執行 `update-rules` 指令時，風險等級都會回復為原始值，因此之後您需要再次執行 `level-tuning` 指令。

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` 指令範例

* 一般用法：`hayabusa.exe level-tuning`
* 依您的自訂設定檔調校規則警示等級：`hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` 設定檔

Hayabusa 與 Sigma 規則作者在撰寫規則時，會估計警示適當的風險等級。
然而，有時風險等級並不一致，且實際風險等級也可能依您的環境而有所不同。
Yamato Security 提供並維護一個位於 `./rules/config/level_tuning.txt` 的設定檔，您也可以用它來調校您的規則。

`./rules/config/level_tuning.txt` 範例：

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

在此情況下，規則目錄中 `id` 為 `570ae5ec-33dc-427c-b815-db86228ad43e` 的規則，其 `level` 會被改寫為 `informational`。
可設定的等級為 `critical`、`high`、`medium`、`low` 與 `informational`。

> 警告：每次您執行 `update-rules` 時，`./rules/config/level_tuning.txt` 設定檔也會更新為 hayabusa-rules 儲存庫上的最新版本。
> 因此，若您對此檔案做了變更，這些變更將會遺失！
> 若您想為自己保留一份設定檔，請在 `./config/level_tuning.txt` 建立一個設定檔，並執行 `hayabusa.exe level-tuning -f ./config/level_tuning.txt`。
> 您也可以先以 Yamato Security 提供的設定檔進行等級調校，再以您自己的設定檔進一步調校。

## `list-profiles` 指令

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` 指令

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` 指令範例

* 將預設設定檔設為 `minimal`：`hayabusa.exe set-default-profile minimal`
* 將預設設定檔設為 `super-verbose`：`hayabusa.exe set-default-profile super-verbose`

## `update-rules` 指令

`update-rules` 指令會將 `rules` 資料夾與 [Hayabusa rules github 儲存庫](https://github.com/Yamato-Security/hayabusa-rules)同步，更新規則與設定檔。

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` 指令範例

您通常只要執行這個：`hayabusa.exe update-rules`
