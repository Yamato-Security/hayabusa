# 使用 Timeline Explorer 分析 Hayabusa 結果

## 關於

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) 是一款免費但閉源的工具，用於在 DFIR 用途中分析 CSV 檔案時取代 Excel。
它是一款以 C# 撰寫、僅適用於 Windows 的 GUI 工具。
這款工具非常適合單一分析師進行的小型調查，也適合剛開始學習 DFIR 分析的人，然而其介面一開始可能不容易理解，因此請使用本指南來了解各項不同的功能。

## 安裝與執行

不需要安裝此應用程式。
只要從 [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) 下載最新版本，解壓縮後執行 `TimelineExplorer.exe` 即可。
如果您沒有適當的 .NET runtime，會跳出訊息告訴您需要安裝它。
在撰寫本文時（2025/2/14），最新版本為 `2.1.0`，執行於 .NET 版本 `9` 上。

## 載入 CSV 檔案

只要從選單點選 `File` -> `Open` 即可載入 CSV 檔案。

您會看到類似這樣的畫面：

![First Start](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

在最底部，您可以看到檔名、`Total lines` 與 `Visible lines`。

除了 CSV 檔案中的欄位之外，左側還有兩個由 Timeline Explorer 新增的欄位：`Line` 與 `Tag`。
`Line` 顯示行號，但對調查通常沒有用處，因此您可能會想隱藏這個欄位。
`Tag` 讓您為想要記下以供後續分析等用途的事件打上勾選標記……
不幸的是，由於 CSV 檔案是以唯讀模式開啟以防止資料被覆寫，因此無法為事件新增自訂標籤，也無法針對事件寫下註解。

## 資料篩選

如果您將滑鼠游標移到標頭的右上方，會看到一個黑色的篩選圖示出現。

![Basic Data Filtering](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

您可以在嚴重程度等級上打勾，先對 `high` 與 `crit`（`critical`）警示進行分流。
這種篩選對於過濾掉雜訊警示也非常有用，方法是勾選 `Rule Title` 下的全部項目，然後取消勾選那些雜訊規則。

如下所示，如果您點選 `Text Filters`，可以建立更進階的篩選：

![Advanced Data Filtering](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

不過，與其在這裡建立篩選，通常更簡單的做法是點選標頭下方的 `ABC` 圖示並在此套用篩選：

![ABC Filtering](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

不幸的是，這兩個地方提供的篩選選項略有不同，因此您應該同時了解這兩個篩選資料的地方。

舉例來說，如果您有太多想要過濾掉的 `Proc Exec` 事件，可以選擇 `Does not contain` 並輸入 `Proc Exec` 來忽略這些事件：

![Rule Filtering](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

如果您往底部看，可以看到篩選規則以不同顏色顯示。
如果您想暫時停用篩選，只要取消勾選即可。
如果您想清除所有篩選，點選 `X` 按鈕。

如果您想忽略另一個雜訊規則，應該點選右下角的 `Edit Filter` 來開啟 `Filter Editor`：

![Filter Editor](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

複製 `Not Contains([Rule Title], 'Proc Exec')` 文字，加上 `and`，貼上同樣的篩選並將 `Proc Exec` 改為 `Possible LOLBIN`，現在您就可以忽略這兩個規則：

![Multiple Filters](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

組合多個篩選最簡單的方法是先從 `ABC` 圖示建立篩選語法，然後複製、貼上並編輯該文字，並用 `and`、`or` 與 `not` 組合這些篩選。

您也可以點選任何彩色文字以取得一個下拉方塊，列出可用的選項來編輯您的篩選：

![Dropdown editing](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## 標頭選項

如果您在任何標頭上點按右鍵，會取得以下選項：

![Header Options](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

這些選項大多不言自明。

* 在您隱藏一個欄位之後，可以再次顯示它，方法是開啟 `Column Chooser`，在欄位名稱上點按右鍵並點選 `Show Column`。
* `Group By This Column` 的效果與將欄位標頭拖曳到上方以進行群組相同。（稍後會更詳細說明。）
* `Hide Group By Box` 只會隱藏 `Drag a column header here to group by that column` 文字，並將搜尋列移過去。

### 條件式格式設定

您可以透過點選 `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...` 來為文字設定顏色、粗體字型等格式：

![Conditional Formatting](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

舉例來說，如果您想以 `Red Fill` 顯示 `critical` 警示，只要輸入 `crit` 並從選項中選擇 `Red Fill`，勾選 `Apply formatting to an entire row` 並按下 `OK`。

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

現在 `critical` 警示將會以紅色顯示，如下所示：

![Red fill](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

您可以繼續這麼做，也為 `low`、`medium` 與 `high` 警示新增顏色。

## 搜尋

預設情況下，當您在搜尋列中輸入一些文字時，它會執行篩選，只顯示資料列中某處包含該文字的結果。
您可以透過檢查底部的 `Visible lines` 欄位來查看有多少筆符合的結果。

您可以透過點選最右下角的 `Search options` 來改變這個行為。
這會顯示以下內容：

![Search Options](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

如果您將 `Behavior` 從 `Filter` 改為 `Search`，就可以正常地搜尋文字。

> 注意：切換行為通常需要一些時間，Timeline Explorer 會卡住一陣子，因此點選後請耐心等待。

預設的 `Match criteria` 是 `Mixed`，但可以改為 `Or`、`And` 或 `Exact`。
如果您將它改為 `Mixed` 以外的任何選項，接著就可以將 `Condition` 從 `Contains` 設定為 `Starts with`、`Like` 或 `Equals`。

`Mixed` 的 `Match criteria` 較為複雜，因為它有時使用 `AND` 邏輯，有時使用 `OR`，但一旦學會後就可以非常靈活。
其運作方式如下：

* 如果您用空格分隔字詞，會被視為 `OR` 邏輯。
* 如果您想在搜尋中包含空格，則需要加上引號。
* 在條件前加上 `+` 表示 `AND` 邏輯。
* 在條件前加上 `-` 表示排除結果。
* 以 `ColumnName:FilterString` 格式對特定欄位進行篩選。
* 如果您對特定欄位進行篩選並同時包含一個獨立的關鍵字，則會是 `AND` 邏輯。

範例：

| 搜尋條件                  | 說明                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | 選取在任何搜尋欄位中包含 `mimikatz` 字串的記錄。                                                                        |
| one two three                    | 選取在任何搜尋欄位中包含 `one` OR `two` OR `three` 的記錄。                                                             |
| "hoge hoge"                      | 選取在任何搜尋欄位中包含 `hoge hoge` 的記錄。                                                                  |
| mimikatz +"Bad Guy"              | 選取在任何搜尋欄位中同時包含 `mimikatz` AND `Bad Guy` 的記錄。                                                                |
| EventID:4624 kali                | 選取在以 `EventID` 開頭的欄位中包含 `4624` 且在任何搜尋欄位中包含 `kali` 的記錄。                          |
| data +entry -mark                | 選取在任何搜尋欄位中同時包含 `data` AND `entry` 的記錄，並排除包含 `mark` 的記錄。                               |
| manu mask -file                  | 選取包含 `menu` OR `mask` 的記錄，並排除包含 `file` 的記錄。                                                           |
| From:Roller Subj:"currency mask" | 選取在以 `From` 開頭的欄位中包含 `Roller` 且在以 `Subj` 開頭的欄位中包含 `currency mask` 的記錄。 |
| import -From:Steve               | 選取在任何搜尋欄位中包含 `import` 的記錄，並排除在以 `From` 開頭的欄位中包含 `Steve` 的記錄。       |

## 凍結欄位

雖然這不是搜尋選項，但您可以在 `Search options` 選單下設定 `First scrollable column`。
大多數分析師會將此設定為 `Timestamp`，這樣他們就能隨時看到特定事件發生的時間。

## 拖曳欄位標頭以進行群組

如果您將欄位標頭拖曳到 `Drag a column header here to group by that column`，Timeline Explorer 會依該欄位進行群組。
常見的做法是依 `Level` 進行群組，這樣您就可以依嚴重程度為警示排定優先順序：

![Group by](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

如果您的結果中有多台電腦，您可以進一步依 `Computer` 進行群組，以便針對每台電腦的不同嚴重程度等級進行分流。

## 檢查欄位

預設情況下，Hayabusa 會用斷線豎線符號分隔欄位資料：`¦`。
當欄位資料位於同一水平線上時，由於此字元在日誌中不常出現，因此可以很容易地分辨多個欄位：

![Field Information](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

然而有時候，日誌中會有太多欄位資訊，無法將所有內容塞進一個畫面。
在這種情況下，您可以雙擊儲存格以取得一個顯示所有欄位資訊的彈出視窗：

![Cell Contents](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

問題在於 Timeline Explorer 只允許您依換行字元（`CRLF`、`CR`、`LF`）、逗號與定位字元來格式化欄位資料。

如果您使用 `-M, --multiline` 選項，可以用換行字元分隔欄位，當您雙擊開啟儲存格內容時，它會被正確地格式化：

![Multi-line formatting](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

問題在於現在時間軸中只會顯示第一個欄位，因此每次您想要檢查其他欄位資料時，都必須雙擊並開啟一個新視窗：

![Multiline single fiels](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

不幸的是，Timeline Explorer 在時間軸檢視中不支援多行顯示。

為了解決這個問題，自 Hayabusa `v3.1.0` 起，您可以用定位字元分隔欄位：

![Tab separation](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

要分辨一個欄位在哪裡結束、下一個欄位從哪裡開始會稍微困難一些。
此外，當您雙擊並開啟儲存格內容時，欄位不會自動被格式化：

![Tab separation not formatted](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

不過，如果您點選底部的 `Tab` 然後點選 `Format`，就可以將欄位格式化為易於閱讀的檢視：

![Tab separation formatted](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## 外觀主題

如果您偏好深色模式等，可以從 `Tools` -> `Skins` 變更色彩主題……

## 工作階段

如果您自訂了欄位、外觀、新增了篩選等，並想要儲存這些設定以供日後使用，請務必從 `File` -> `Session` -> `Save` 儲存您的工作階段。
