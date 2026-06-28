# Hayabusa 規則

Hayabusa 偵測規則以類似 sigma 的 YML 格式撰寫，並位於 `rules` 資料夾中。
這些規則託管於 [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)，因此關於規則的任何 issue 與 pull request 請發送至該處，而非主要的 Hayabusa 儲存庫。

請參閱本章節中的[建立規則檔案](creating-rules.md)、[偵測欄位](detection-fields.md)與 [Sigma 關聯](correlations.md)，以瞭解規則格式以及如何建立規則。（來源：[hayabusa-rules 儲存庫](https://github.com/Yamato-Security/hayabusa-rules)。）

hayabusa-rules 儲存庫中的所有規則都應放置於 `rules` 資料夾中。
`informational` 等級的規則被視為 `events`，而 `level` 為 `low` 或更高的任何規則則被視為 `alerts`。

hayabusa 規則目錄結構分為 2 個目錄：

* `builtin`：可由 Windows 內建功能產生的記錄檔。
* `sysmon`：由 [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) 產生的記錄檔。

規則會進一步依記錄檔類型（例如：Security、System 等）分入各目錄，並以下列格式命名：

請查閱目前的規則，以作為建立新規則時的範本，或用於檢查偵測邏輯。

## Sigma 與 Hayabusa（內建相容 Sigma）規則

Hayabusa 原生支援 Sigma 規則，唯一的例外是在內部處理 `logsource` 欄位。
為了減少誤判，Sigma 規則應透過我們的轉換器執行，相關說明請見[此處](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md)。
這將會加入適當的 `Channel` 與 `EventID`，並針對某些類別（例如 `process_creation`）執行欄位對應。

幾乎所有 Hayabusa 規則都與 Sigma 格式相容，因此您可以像使用 Sigma 規則一樣使用它們，以轉換為其他 SIEM 格式。
Hayabusa 規則專為 Windows 事件記錄檔分析而設計，並具有下列優點：

1. 額外的 `details` 欄位，可顯示僅取自記錄檔中有用欄位的額外資訊。
2. 它們全都經過範例記錄檔測試，並已知可正常運作。
3. Sigma 中沒有的額外彙整器，例如 `|equalsfield` 與 `|endswithfield`。

據我們所知，hayabusa 在所有開源 Windows 事件記錄檔分析工具中，提供對 sigma 規則最完整的原生支援。
