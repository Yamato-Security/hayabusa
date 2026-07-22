# 使用 Timesketch 分析 Hayabusa 結果

## 關於

「[Timesketch](https://timesketch.org/) 是一套用於協作式鑑識時間軸分析的開源工具。透過 sketch，您與您的協作者可以輕鬆組織您的時間軸並同時進行分析。利用豐富的註記、留言、標籤與星號標記，為您的原始資料賦予意義。」

對於只分析數百 MB 大小的 CSV 檔案且獨自作業的小型調查而言，Timeline Explorer 已足夠勝任；然而，當您處理較大的資料或與團隊協作時，像 Timesketch 這樣的工具會好得多。

Timesketch 提供以下優點：

1. 它非常快速，能夠處理大量資料
2. 它是一套協作工具，多位使用者可以同時使用
3. 它提供進階資料分析、直方圖與視覺化
4. 它不限於 Windows
5. 它支援進階查詢

還有許多其他優點，例如 CTI 支援、各種分析器、互動式筆記本等等……
請參閱[使用者指南](https://timesketch.org/guides/user/upload-data/)與 [YouTube 頻道](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ)以取得更多資訊。

唯一的缺點是您必須在您的實驗環境中架設一台 Timesketch 伺服器，但幸運的是，這非常容易做到。

## 安裝
### Docker
請依照[此處](https://docs.docker.com/compose/install)的官方說明操作。

### Ubuntu
**注意：** 在繼續之前必須先安裝 Docker。如果您尚未安裝 Docker，請依照[上方的 Docker 安裝說明](#docker)操作。
我們建議使用最新的 Ubuntu LTS Server 版本，並至少配置 8GB 記憶體。
您可以在[此處](https://ubuntu.com/download/server)下載。
設定時請選擇最小安裝。
設定作業系統時請勿安裝 docker。
您將無法使用 `ifconfig`，因此請以 `sudo apt install net-tools` 安裝它。

之後，執行 `ifconfig` 以找出 VM 的 IP 位址，並可選擇性地透過 ssh 連入。

執行以下指令：
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**注意：** 在繼續之前，請確認您的系統上已安裝並執行 [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/)。
複製 Timesketch 儲存庫並切換至該目錄。
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
依照以下步驟啟動 Docker 容器。

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## 登入

以 `ifconfig` 找出 Timesketch 伺服器的 IP 位址，並以網頁瀏覽器開啟它。
您將被重新導向至登入頁面。
使用您新增使用者時所用的使用者憑證登入。

## 建立新的 sketch

在 `Start a new investigation` 下，點擊 `BLANK SKETCH`。
為該 sketch 命名一個與您的調查相關的名稱。

## 上傳您的時間軸

當您點擊 `+ ADD TIMELINE` 後，您會看到一個對話框要求您上傳 Plaso、JSONL 或 CSV 檔案。
可惜的是，Timesketch 目前無法匯入 Hayabusa 的 `JSONL` 格式，因此請使用以下指令建立並上傳 CSV 時間軸：

```shell
hayabusa-x.x.x-win-x64.exe dfir-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --iso-8601
```

> 注意：必須選擇 `timesketch*` 設定檔，並以 `--iso-8601`（UTC）或 `--rfc-3339`（當地時間）指定時間戳記。如果您願意，可以加入其他 Hayabusa 選項，但請勿加入 `-M, --multiline` 選項，因為換行字元會破壞匯入。

在「Select file to upload」對話框中，將您的時間軸命名為類似 `hayabusa` 的名稱，選擇 `Comma (,)` CSV 分隔符號，然後點擊 `SUBMIT`。

> 如果您的 CSV 檔案過大而無法上傳，您可以使用 Takajo 的 [split-dfir-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-dfir-timeline-command) 指令將檔案分割成多個 CSV 檔案。

在檔案匯入期間，您會看到一個旋轉的圓圈，因此請等待直到完成並看到 `hayabusa` 出現。

## 分析技巧

### 顯示時間軸

**注意：即使匯入已成功完成，它仍會顯示 `Your search did not match any events`，且 `hayabusa` 時間軸中會有 `0` 筆事件。**

搜尋 `*`，事件就會如下所示出現：

![Timesketch results](../assets/doc/TimesketchImport/TimesketchResults.png)

### 警示詳細資訊

如果您點擊 `message` 欄位下的某個警示規則標題，您將取得有關該警示的詳細資訊：

![Alert details](../assets/doc/TimesketchImport/AlertDetails.png)

如果您想了解 sigma 規則邏輯，查看其描述與參考資料等等……請在 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 儲存庫中查詢該規則。

#### 欄位篩選

在點擊某事件的規則標題開啟其詳細資訊後，您可以將滑鼠停留在任何欄位上，輕鬆地篩選保留或排除該值：

![Filter In Out](../assets/doc/TimesketchImport/FilterInOut.png)

#### 彙總分析

將滑鼠停留時，如果您點擊最左邊的 `Aggregation dialog` 圖示，您會取得關於該欄位非常出色的事件資料分析：

![Event Data Analytics](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### 使用者留言

當您點擊某個警示以取得詳細資訊時，右側會顯示一個新的留言對話框圖示，如下所示：

![Comment Icon](../assets/doc/TimesketchImport/CommentIcon.png)

在此，使用者可以開始聊天並針對調查撰寫留言。

> 如果您在團隊中作業，您應該為每位成員建立不同的使用者帳戶，以便您知道誰寫了什麼。

![Comment chat](../assets/doc/TimesketchImport/CommentChat.png)

> 如果您將滑鼠停留在某則留言上，您可以輕鬆地編輯與刪除訊息。

### 修改欄位

預設情況下，只會顯示時間戳記與警示規則標題，因此請點擊 `Modify columns` 圖示以自訂欄位：

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

這將開啟以下對話框：

![Select columns](../assets/doc/TimesketchImport/SelectColumns.png)

我們建議至少**依序**加入以下欄位：

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

欄位的順序會依您加入它們的順序而變動，因此請先加入較重要的欄位。

如果您的螢幕還有空間，我們建議也加入 `Details`，如下所示：

![Details](../assets/doc/TimesketchImport/Details.png)

如果您的螢幕還有空間，我們建議也加入 `ExtraFieldInfo`，然而，如您在此處所見，如果您加入太多欄位，`message` 欄位就會變得太窄，您將無法再閱讀警示標題：

![Too much details](../assets/doc/TimesketchImport/TooMuchDetails.png)

### 頂部圖示

#### 省略符號圖示

如果您點擊 `···` 圖示，您可以讓列變得更緊湊，並移除 `Timeline name` 以為結果騰出更多空間：

![More room](../assets/doc/TimesketchImport/MoreRoom.png)

#### 事件直方圖

您可以開啟事件直方圖以將時間軸視覺化：

![Event Histogram](../assets/doc/TimesketchImport/EventHistogram.png)

如果您點擊其中一個長條，它會建立一個時間篩選器，僅顯示該時間段內的結果。

#### 儲存目前搜尋

如果您點擊時間戳記正上方、`Toggle Event Histogram` 圖示左側的 `Save current search` 圖示，您可以將目前的搜尋查詢以及欄位設定儲存至 `Saved Searches`。
之後，您可以從左側側邊欄輕鬆地存取您喜愛的搜尋。

### 搜尋列

以下是一些方便的查詢，可作為起點，僅顯示具有特定嚴重性等級的警示：

1. `Level:crit` 僅顯示嚴重 (critical) 警示。
2. `Level:crit OR Level:high` 顯示高 (high) 與嚴重 (critical) 警示
3. `NOT Level:info` 隱藏資訊性 (informational) 警示

您可以輕鬆地透過輸入欄位名稱加上 `:` 再加上值來進行篩選。
您可以使用 `AND`、`OR` 與 `NOT` 組合篩選條件。
支援萬用字元與正規表示式。

請參閱[此處](https://timesketch.org/guides/user/search-query-guide/)的使用者指南以了解更進階的查詢。

#### 搜尋歷史

如果您點擊搜尋列左側的時鐘圖示，您可以顯示先前輸入過的查詢。
您也可以點擊左右箭頭圖示來執行上一個與下一個查詢。

![Search History](../assets/doc/TimesketchImport/SearchHistory.png)

### 垂直省略符號

如果您點擊時間戳記左側的垂直省略符號並點擊 `Context search`，您可以看到某個事件前後所發生的警示：

![Vertical elipsis](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

這將會顯示以下內容：

![Context Search](../assets/doc/TimesketchImport/ContextSearch.png)

在上述範例中，顯示的是前後 60 秒（`60S`）的事件，但您可以將其從 +- 1 秒（`1S`）調整至 +- 60 分鐘（`60M`）。

如果您想進一步深入檢視所顯示的事件，請點擊 `Replace Search` 以在標準時間軸中顯示這些事件。

### 星號與標籤

您可以點擊時間戳記左側的星號圖示來為其加上星號標記，並將其註記為重要事件。

您也可以為事件加上標籤。
這對於向他人表明您已確認某事件為可疑、惡意、誤判等等很有用……
如果您在團隊中作業，您可以建立像是 `under investigation by xxx` 這樣的標籤，以表明某人目前正在調查該警示。

![Stars and tags](../assets/doc/TimesketchImport/StarsAndTags.png)
