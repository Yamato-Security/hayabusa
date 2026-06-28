- [將結果匯入 SOF-ELK（Elastic Stack）](#importing-results-into-sof-elk-elastic-stack)
  - [安裝並啟動 SOF-ELK](#install-and-start-sof-elk)
    - [Mac 上的網路連線問題](#network-connectivity-trouble-on-macs)
  - [更新 SOF-ELK！](#update-sof-elk)
  - [執行 Hayabusa](#run-hayabusa)
  - [選用：刪除舊的已匯入資料](#optional-deleting-old-imported-data)
  - [在 SOF-ELK 中設定 Hayabusa logstash 設定檔](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [將 Hayabusa 結果匯入 SOF-ELK](#import-hayabusa-results-into-sof-elk)
  - [在 Kibana 中確認匯入是否成功](#check-that-the-import-worked-in-kibana)
  - [在 Discover 中檢視結果](#view-results-in-discover)
  - [分析結果](#analyzing-results)
    - [新增欄位](#adding-columns)
    - [篩選](#filtering)
    - [切換詳細資訊](#toggling-details)
    - [檢視周邊文件](#view-surrounding-documents)
    - [取得欄位的快速統計指標](#get-quick-metrics-on-fields)
  - [未來計畫](#future-plans)

# 將結果匯入 SOF-ELK（Elastic Stack）

## 安裝並啟動 SOF-ELK

Hayabusa 的結果可以輕鬆匯入 Elastic Stack。
我們建議使用 [SOF-ELK](https://github.com/philhagen/sof-elk)，這是一個免費的、專注於 DFIR 調查的 Elastic Stack Linux 發行版。

首先從 [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README) 下載並解壓縮以 7-zip 壓縮的 SOF-ELK VMware 映像檔。

有兩個版本，分別是適用於 Intel CPU 的 x86 版本，以及適用於 Apple M 系列電腦的 ARM 版本。

當你啟動 VM 時，會看到類似下列的畫面：

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

請記下 Kibana 的 URL 以及 SSH 伺服器的 IP 位址。

你可以使用下列憑證登入：
* 使用者名稱：`elk_user`
* 密碼：`forensics`

依照顯示的 URL 在網頁瀏覽器中開啟 Kibana。
例如：http://172.16.23.128:5601/

> 注意：Kibana 可能需要一段時間才能載入完成。

你應該會看到如下的網頁：

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

我們建議你使用 `ssh elk_user@172.16.23.128` 以 SSH 連入 VM，而不要直接在 VM 內輸入指令。

> 注意：預設的鍵盤配置為美式鍵盤。

### Mac 上的網路連線問題

如果你使用的是 macOS，且在終端機中出現 `no route to host` 錯誤，或是無法在瀏覽器中存取 Kibana，這很可能是由於 macOS 的本機網路隱私控制所致。

在 `System Settings` 中，開啟 `Privacy & Security` -> `Local Network`，並確認你的瀏覽器與終端機程式已啟用，能夠與本機網路上的裝置通訊。

## 更新 SOF-ELK！

在匯入資料之前，請務必使用 `sudo sof-elk_update.sh` 指令更新 SOF-ELK。

## 執行 Hayabusa

執行 Hayabusa 並將結果儲存為 JSONL。

例如：`./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## 選用：刪除舊的已匯入資料

如果這不是你第一次匯入 Hayabusa 結果，而且你想要清除所有內容，可以透過下列方式進行：

1. 確認 SOF-ELK 中目前有哪些記錄：`sof-elk_clear.py -i list`
2. 刪除目前的資料：`sof-elk_clear.py -a`
3. 刪除 logstash 目錄中的檔案：`rm /logstash/hayabusa/*`

## 在 SOF-ELK 中設定 Hayabusa logstash 設定檔

SOF-ELK 已內建一個 Hayabusa logstash 設定檔，可將欄位名稱轉換為 Elastic Common Schema 格式。
如果你比較習慣 Hayabusa 的欄位名稱，我們建議使用我們提供的版本。

1. 首先以 SSH 連入 SOF-ELK：`ssh elk_user@172.16.23.128`
2. 刪除或移動目前的 logstash 設定檔：`sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. 將新的 [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) 檔案上傳到 `/etc/logstash/conf.d/`：`sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`。
4. 重新啟動 logstash：`sudo systemctl restart logstash`

這個設定檔會建立整合的 `DetailsText` 與 `ExtraFieldInfoText` 欄位，讓你可以一眼快速看到最重要的欄位，而不必逐筆開啟每個記錄、花時間逐一查看所有欄位。

## 將 Hayabusa 結果匯入 SOF-ELK

要將日誌匯入 SOF-ELK，是透過將日誌複製到 `/logstash` 目錄內適當的目錄來完成。

首先 `exit` 退出 SSH，然後複製你建立的 Hayabusa 結果檔：
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## 在 Kibana 中確認匯入是否成功

首先記下 Hayabusa 掃描的 `Results Summary` 中的 `Total detections`、`First Timestamp` 與 `Last Timestamp`。

如果你無法取得這些資訊，可以在 *nix 上執行 `wc -l results.jsonl` 來取得總行數，作為 `Total detections`。

預設情況下，Hayabusa 為了提升效能不會將結果排序，因此你無法藉由查看第一行與最後一行來取得第一個與最後一個時間戳記。
如果你不知道確切的第一個與最後一個時間戳記，只要在 Kibana 中將起始日期設為 2007 年、結束日期設為 `now`，這樣你就能取得所有結果。

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

你現在應該會看到 `Total Records`，以及已匯入事件的第一個與最後一個時間戳記。

匯入所有事件有時需要一段時間，因此請持續重新整理頁面，直到 `Total Records` 達到你預期的數量。

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

你也可以從終端機執行 `sof-elk_clear.py -i list` 來確認匯入是否成功。
你應該會看到你的 `evtxlogs` 索引擁有更多記錄：
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

如果你在匯入時遇到任何剖析錯誤，請在 GitHub 上建立一個 issue。
你可以查看 `/var/log/logstash/logstash-plain.log` 日誌檔的結尾來進行確認。

## 在 Discover 中檢視結果

點選左上角的側邊欄圖示，然後點選 `Discover`：

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

你很可能會看到 `No results match your search criteria`。

在左上角顯示 `logstash-*` 索引的地方，點選它並將其變更為 `evtxlogs-*`。
你現在應該會看到 Discover 時間軸。

## 分析結果

預設的 Discover 檢視畫面看起來應該類似這樣：

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

你可以查看頂部的直方圖，以總覽事件發生的時間與頻率。 

### 新增欄位

在左側的側邊欄中，你可以將游標移到某個欄位上後點選加號，以新增你想顯示為欄位的內容。
由於欄位很多，你可能會想在搜尋框中輸入你要尋找的欄位名稱。

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

一開始，我們建議使用下列欄位：
- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

如果你的螢幕夠寬，你可能也會想新增 `ExtraFieldInfoText`，以便看到所有欄位資訊。

你的 Discover 檢視畫面現在看起來應該像這樣：

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### 篩選

你可以使用 KQL（Kibana Query Language）進行篩選，以搜尋特定的事件與警示。例如：
  * `Level: "crit"`：只顯示嚴重（critical）警示。
  * `Level: "crit" OR Level: "high"`：顯示高（high）與嚴重（critical）警示。
  * `NOT Level: info`：不顯示資訊性事件，只顯示警示。
  * `MitreTactics: *LatMov*`：顯示與橫向移動相關的事件與警示。
  * `"PW Spray"`：只顯示特定攻擊，例如「Password Spray」。
  * `"LID: 0x8724ead"`：顯示與登入 ID 0x8724ead 相關的所有活動。
  * `Details_TgtUser: admmig`：搜尋目標使用者為 `admmig` 的所有事件。

### 切換詳細資訊

要查看某筆記錄中的所有欄位，只要點選時間戳記旁邊的圖示（Toggle dialog with details）：

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### 檢視周邊文件

如果你想檢視某個警示前後緊鄰的事件，先開啟該警示的詳細資訊，然後在右上角點選 `View surrounding documents`：

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

在這個範例中，我們正在檢視 Pass the Hash 攻擊警示前後的事件：

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> 注意：變更頂部 `Load x newer documents` 或底部 `Load x older documents` 的數字，可擷取更多事件。

### 取得欄位的快速統計指標

在左欄中，如果你點選某個欄位名稱，它會提供該欄位使用情況的快速統計指標：

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> 請注意，為了加快速度，資料是經過抽樣的，因此並非 100% 準確。

## 未來計畫

* 適用於 CSV 的 Logstash 剖析器
* 預先建構的儀表板
