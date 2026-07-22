# 命令清單

## 分析命令：
* `computer-metrics`: 根據電腦名稱列印事件數量。
* `eid-metrics`: 根據 Event ID 列印事件的數量與百分比。
* `expand-list`: 從 `rules` 資料夾擷取 `expand` 佔位符。
* `extract-base64`: 從事件中擷取並解碼 base64 字串。
* `log-metrics`: 列印記錄檔指標。
* `logon-summary`: 列印登入事件的摘要。
* `pivot-keywords-list`: 列印可供樞紐分析的可疑關鍵字清單。
* `search`: 以關鍵字或正規表示式搜尋所有事件

## 設定命令：
* `config-critical-systems`: 尋找網域控制站與檔案伺服器等關鍵系統。

## DFIR 時間軸命令：
* `dfir-timeline`: 以 CSV 格式儲存時間軸。
* `dfir-timeline`: 以 JSON/JSONL 格式儲存時間軸。
* `level-tuning`: 自訂調整警示的 `level`。
* `list-profiles`: 列出可用的輸出設定檔。
* `set-default-profile`: 變更預設設定檔。
* `update-rules`: 將規則同步至 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) GitHub 儲存庫中的最新規則。

## 一般命令：
* `help`: 列印此訊息或所指定子命令的說明
* `list-contributors`: 列印貢獻者清單
