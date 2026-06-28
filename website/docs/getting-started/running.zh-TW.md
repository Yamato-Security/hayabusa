# 執行 Hayabusa

## 注意：防毒軟體/EDR 警告與執行緩慢

當你嘗試執行 hayabusa，甚至只是下載 `.yml` 規則時，可能會收到防毒軟體或 EDR 產品的警示，因為偵測特徵碼中會含有像 `mimikatz` 這類的關鍵字以及可疑的 PowerShell 指令。
這些都是誤判，因此你需要在資安產品中設定排除項目，以允許 hayabusa 執行。
如果你擔心惡意軟體或供應鏈攻擊，請檢視 hayabusa 的原始碼並自行編譯執行檔。

特別是在重新開機後第一次執行時，由於 Windows Defender 的即時防護，你可能會遇到執行緩慢的情況。
你可以透過暫時關閉即時防護，或將 hayabusa 的執行目錄加入排除項目來避免這種情況。
（在這麼做之前，請考量其中的資安風險。）

## Windows

在命令提示字元/PowerShell 提示字元或 Windows Terminal 中，只要執行對應的 32 位元或 64 位元 Windows 執行檔即可。

### 掃描路徑中含有空格的檔案或目錄時發生錯誤

在 Windows 中使用內建的命令提示字元或 PowerShell 提示字元時，如果你的檔案或目錄路徑中含有空格，你可能會收到 Hayabusa 無法載入任何 .evtx 檔案的錯誤。
為了正確載入 .evtx 檔案，請務必執行以下步驟：
1. 用雙引號將檔案或目錄路徑括起來。
2. 如果是目錄路徑，請確保最後一個字元不包含反斜線。

### 字元無法正確顯示

在 Windows 上使用預設字型 `Lucida Console` 時，標誌與表格中使用的各種字元將無法正確顯示。
你應該將字型變更為 `Consalas` 以修正此問題。

這將修正大部分的文字呈現問題，但結尾訊息中的日文字元顯示除外：

![Mojibake](../assets/screenshots/Mojibake.png)

你有四個選項可以修正此問題：
1. 使用 [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) 取代命令提示字元或 PowerShell 提示字元。（建議）
2. 使用 `MS Gothic` 字型。請注意反斜線會變成日圓符號。
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. 安裝 [HackGen](https://github.com/yuru7/HackGen/releases) 字型並使用 `HackGen Console NF`。
4. 使用 `-q, --quiet` 來不顯示含有日文的結尾訊息。

## Linux

你首先需要讓執行檔可被執行。

```bash
chmod +x ./hayabusa
```

然後從 Hayabusa 根目錄執行它：

```bash
./hayabusa
```

## macOS

在 Terminal 或 iTerm2 中，你首先需要讓執行檔可被執行。

```bash
chmod +x ./hayabusa
```

然後，嘗試從 Hayabusa 根目錄執行它：

```bash
./hayabusa
```

在最新版本的 macOS 上，當你嘗試執行它時，可能會收到以下安全性錯誤：

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

點選「Cancel」，然後從「系統偏好設定」開啟「安全性與隱私權」，並在「一般」分頁中點選「仍要允許」。

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

之後，再次嘗試執行它。

```bash
./hayabusa
```

接著會彈出以下警告，請點選「打開」。

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

現在你應該可以執行 hayabusa 了。
