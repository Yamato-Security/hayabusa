# 使用 jq 分析 Hayabusa 結果

# 作者

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# 關於

能夠在日誌中識別、擷取出重要欄位並針對其建立統計指標，是 DFIR 與威脅獵捕分析師不可或缺的技能。
Hayabusa 的結果通常會儲存為 `.csv` 檔案，以便匯入 Excel 或 Timeline Explorer 等程式進行時間軸分析。
然而，當同一種事件有數百筆以上時，要手動逐一檢查就變得不切實際或根本不可能。
在這些情況下，分析師通常會排序並計算相似類型的資料，尋找異常值。
這也被稱為長尾分析（long tail analysis）、堆疊排名（stack ranking）、頻率分析（frequency analysis）等等……
這可以透過將 Hayabusa 的結果輸出為 `.json` 或 `.jsonl` 檔案，然後用 `jq` 分析來達成。

舉例來說，分析師可以比較一個組織內所有工作站上安裝的服務。
雖然某種惡意軟體有可能被安裝到每一台工作站上，但更可能的情況是它只存在於少數幾個系統上。
在這種情況下，安裝在所有系統上的服務較可能是良性的，而罕見的服務則往往較為可疑，應該定期檢查。

另一個使用案例是協助判斷某件事的可疑程度。
舉例來說，分析師可以分析 `4625` 登入失敗的日誌，以判斷某個 IP 位址登入失敗了多少次。
如果只有少數幾次登入失敗，那麼很可能只是管理員打錯了密碼。
然而，如果某個 IP 位址在短時間內有數百次以上的登入失敗，那麼這個 IP 位址很可能是惡意的。

學習如何使用 `jq` 不僅能幫助你精通分析 Windows 事件日誌，也能精通分析所有 JSON 格式的日誌。
如今 JSON 已成為非常普遍的日誌格式，而且大多數雲端供應商都用它來儲存日誌，因此能夠用 `jq` 來解析它們，已成為現代資安分析師不可或缺的技能。

在本指南中，我會先為從未使用過 `jq` 的人說明如何使用它，然後再透過真實世界的範例說明更複雜的用法。
我建議使用 linux、macOS 或在 Windows 上的 linux，以便將 `jq` 與其他實用指令結合使用，例如 `sort`、`uniq`、`grep`、`sed` 等等……

# 安裝 jq

請參考 [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) 並安裝 `jq` 指令。

# 關於 JSON 格式

JSON 日誌是一連串包含在大括號 `{` `}` 內的物件。
這些物件內部是以冒號分隔的鍵值對（key-value pairs）。
鍵必須是字串，但值可以是以下其中之一：
  * 字串（例如：`"string"`）
  * 數字（例如：`10`）
  * 另一個物件（例如：`{ xxxx }`）
  * 陣列（例如：`["string", 10]`）
  * 布林值（例如：`true`、`false`）
  * `null`

你可以在物件內部任意巢狀嵌套任意多個物件。

在這個範例中，`Details` 是一個巢狀於根物件內的物件：
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# 關於 Hayabusa 的 JSON 與 JSONL 格式

在較早的版本中，Hayabusa 會使用傳統的 JSON 格式，將所有 `{ xxx }` 日誌物件放入一個巨大的陣列中。

範例：
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

這有兩個問題。
第一個問題是 `jq` 查詢會變得更繁瑣，因為所有東西都必須以額外的 `.[]` 開頭，以告訴它要查看那個陣列。
更大的問題是，為了讓任何程式解析這類日誌，必須先載入陣列中的所有資料。
如果你有非常大的 JSON 檔案而記憶體又不充裕，這就會成為一個問題。
為了降低所需的 CPU 與記憶體使用量，不把所有東西放進一個巨大陣列的 JSONL（JSON Lines）格式變得更受歡迎。
Hayabusa 會以 JSON 與 JSONL 格式輸出，不過 JSON 格式不再被儲存在陣列內。
唯一的差別在於，JSON 格式在文字編輯器或主控台上較容易閱讀，而 JSONL 格式則將每個 JSON 物件儲存在單獨一行上。
JSONL 格式速度會稍快一些、檔案大小也較小，因此如果你只打算將日誌匯入 SIEM 等系統而不會去查看它們，這是理想的選擇……
而 JSON 格式則適合在你也要進行一些手動檢查的情況下使用。

# 建立 JSON 結果檔案

在目前的 Hayabusa 2.x 版本中，你可以用 `hayabusa dfir-timeline -t json -d <directory> -o results.json` 將結果儲存為 JSON，或用 `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` 儲存為 JSONL 格式。

Hayabusa 會使用預設的 `standard` 設定檔，並只在 `Details` 物件中儲存最少量的分析資料。
如果你想儲存 .evtx 日誌中所有原始欄位資訊，你可以使用 `all-field-info` 設定檔搭配 `--profile all-field-info` 選項。
這會將所有欄位資訊儲存到 `AllFieldInfo` 物件中。
如果你為了保險起見想同時儲存 `Details` 與 `AllFieldInfo` 兩個物件，你可以使用 `super-verbose` 設定檔。

## 使用 Details 而非 AllFieldInfo 的好處

使用 `Details` 而非 `AllFieldInfo` 的第一個好處是只會儲存重要的欄位，而且欄位名稱已被縮短以節省檔案空間。
缺點是有可能會遺漏掉你實際上在意、但卻被略過的資料。
第二個好處是 Hayabusa 會透過正規化欄位名稱，以更一致的方式儲存欄位。
舉例來說，在原始的 Windows 日誌中，使用者名稱通常位於 `SubjectUserName` 或 `TargetUserName` 欄位。
然而，有時使用者名稱會位於 `AccountName` 欄位，有時目標使用者實際上會位於 `SubjectUserName` 欄位，等等……
很遺憾地，Windows 事件日誌中有許多不一致的欄位名稱。
Hayabusa 嘗試正規化這些欄位，因此分析師只需要解析出一個共通的名稱，而不必去理解 Windows 中各事件 ID 之間數不清的怪異之處與不一致。

以下是使用者欄位的範例。
Hayabusa 會以下列方式正規化 `SubjectUserName`、`TargetUserName`、`AccountName` 等等……
  * `SrcUser`（來源使用者）：當某個動作是**從**某個使用者發起時。（通常是遠端使用者。）
  * `TgtUser`（目標使用者）：當某個動作是**對**某個使用者執行時。（例如，登入**到**某個使用者。）
  * `User`：當某個動作是由目前已登入的使用者執行時。（該動作沒有特定的方向。）

另一個範例是處理程序。
在原始的 Windows 事件日誌中，處理程序欄位有多種命名慣例：`ProcessName`、`Image`、`processPath`、`Application`、`WindowsDefenderProcessName` 等等……
若沒有欄位正規化，分析師就必須先熟知所有不同的欄位名稱，然後擷取出所有具有這些欄位名稱的日誌，再將它們合併在一起。

分析師只要使用 Hayabusa 在 `Details` 物件中提供的正規化單一 `Proc` 欄位，就能省下大量的時間與麻煩。

# jq 課程／實用範例

我現在會列出幾個可能對你工作有幫助的實用範例課程／配方。

## 1. 用 jq 與彩色 Less 進行手動檢查

這是用來理解日誌中有哪些欄位的首要步驟之一。
你可以單純執行 `less results.json`，但更好的方法如下：
`cat results.json | jq -C | less -R`

透過傳遞給 `jq`，即使欄位一開始沒有整齊地格式化，它也會為你把所有欄位整齊地排版好。
透過搭配使用 `jq` 的 `-C`（color，彩色）選項與 `less` 的 `-R`（raw output，原始輸出）選項，你就能以彩色上下捲動。

## 2. 統計指標

Hayabusa 本身已具備依事件 ID 列印事件數量與百分比的功能，不過知道如何用 `jq` 做到這件事也很有幫助。
這能讓你自訂想要建立統計指標的資料。

我們先用以下指令擷取出一份事件 ID 清單：

`cat results.json | jq '.EventID'`

這會從每筆日誌中只擷取出事件 ID 數字。
在 `jq` 之後，於單引號內只要輸入一個 `.` 加上你想擷取的欄位名稱。
你應該會看到一長串像這樣的清單：

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

現在，把結果透過管道傳給 `sort` 與 `uniq -c` 指令，以計算各事件 ID 出現的次數：

`cat results.json | jq '.EventID' | sort | uniq -c`

`uniq` 的 `-c` 選項會計算某個不重複事件 ID 出現了多少次。

你應該會看到類似這樣的結果：

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 左邊是次數，右邊是事件 ID。
 如你所見，它並未經過排序，因此很難看出哪些事件 ID 出現最多次。

 你可以在結尾加上 `sort -n` 來解決這個問題：

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

`-n` 選項會告訴 `sort` 依數字排序。

你應該會看到類似這樣的結果：
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

我們可以看到 `4688`（處理程序建立）事件被記錄得最多。
記錄次數第二多的事件是 `4625`（登入失敗）。

如果你想把記錄次數最多的事件列印在最上方，你可以用 `sort -n -r` 或 `sort -nr` 反向排序。
你也可以把結果透過管道傳給 `head -n 10`，只列印記錄次數最多的前 10 個事件。

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

這會給你：
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

重要的是要考慮到 EID（事件 ID）並不是唯一的，因此你可能會有具有相同事件 ID 的完全不同事件。
因此，同時檢查 `Channel` 也很重要。

我們可以像這樣加入這個欄位資訊：

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

我們為 `jq` 加上 `-j`（join，合併）選項，將所有欄位以逗號分隔並以 `\n` 換行字元結尾合併在一起。

這會給我們：
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 注意：`Security` 被縮寫為 `Sec`、`System` 為 `Sys`，而 `PowerShell` 為 `PwSh`。

我們可以像這樣加入規則標題：

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

這會給我們：
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

你現在可以自由地從日誌中擷取任何資料並計算其出現次數。

## 3. 篩選特定資料

很多時候你會想針對特定的事件 ID、使用者、處理程序、LID（登入 ID）等等進行篩選……
你可以在 `jq` 查詢內使用 `select` 來做到這件事。

舉例來說，讓我們擷取出所有 `4624` 成功登入事件：

`cat results.json | jq 'select ( .EventID == 4624 ) '`

這會傳回所有 EID `4624` 的 JSON 物件：
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

如果你想針對多個條件篩選，你可以使用 `and`、`or` 與 `not` 等關鍵字。

舉例來說，讓我們搜尋類型為 `3`（網路登入）的 `4624` 事件。

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

這會傳回所有 `EventID` 為 `4624` 且巢狀的 `"Details": { "Type" }` 欄位為 `3` 的物件。

不過這裡有個問題。
你可能會注意到出現了 `jq: error (at <stdin>:10636): Cannot index string with string "Type"` 之類的錯誤。
每當你看到 `Cannot index string with string` 錯誤時，代表你正要求 `jq` 輸出一個不存在或型別錯誤的欄位。
你可以藉由在欄位結尾加上 `?` 來消除這些錯誤。
這會告訴 `jq` 忽略這些錯誤。

範例：`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

現在，在針對特定條件篩選之後，我們可以在 `jq` 查詢內使用 `|` 來進一步選取感興趣的特定欄位。

舉例來說，讓我們擷取出目標使用者名稱 `TgtUser` 與來源 IP 位址 `SrcIP`：

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

同樣地，我們為 `jq` 加上 `-j`（join，合併）選項以選取多個欄位來輸出。
接著你可以像先前的範例一樣執行 `sort`、`uniq -c` 等等……以找出某個 IP 位址透過類型 3 網路登入登入某個使用者多少次。

## 4. 將輸出儲存為 CSV 格式

很遺憾地，Windows 事件日誌中的欄位會根據事件類型而完全不同，因此若不產生數百個欄，就無法輕易地依欄位建立逗號分隔的時間軸。
然而，針對單一類型的事件，建立以欄位分隔的時間軸是可行的。
兩個常見的範例是 Security `4624`（成功登入）與 `4625`（登入失敗），用以檢查橫向移動以及密碼猜測／噴灑攻擊。

在這個範例中，我們只擷取出 Security 4624 日誌，並輸出時間戳記、電腦名稱以及所有 `Details` 資訊。
我們透過使用 `| @csv` 將其儲存為 CSV 檔案，不過我們需要以陣列的形式傳遞資料。
我們可以像先前那樣選取想輸出的欄位，並用 `[ ]` 方括號將它們括起來，使其轉換成陣列來做到這件事。

範例：`cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

注意：
  * 若要選取 `Details` 物件中的所有欄位，我們加上 `[]`。
  * 有些情況下 `Details` 是字串而非陣列，會出現 `Cannot iterate over string` 錯誤，所以你需要加上 `?`。
  * 我們為 `jq` 加上 `-r`（Raw output，原始輸出）選項，以避免對雙引號加上反斜線轉義。

結果：
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

如果我們只是要檢查誰有成功登入，我們可能不需要最後的 `LID`（登入 ID）欄位。
你可以用 `del` 函式刪除任何不需要的欄。

範例：`cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

陣列從 `0` 開始計數，所以要移除第 7 個欄位，我們使用 `6`。

你現在可以藉由加上 `> 4624-logs.csv` 來儲存 CSV 檔案，然後將它匯入 Excel 或 Timeline Explorer 進行進一步分析。

請注意，你需要加上一列標題才能進行篩選。
雖然可以在 `jq` 查詢內加入標題，但通常最簡單的做法就是在儲存檔案後手動加上最上面一列。

## 5. 找出警示最多的日期

預設情況下，Hayabusa 會依嚴重程度等級告訴你警示最多的日期。
然而，你可能也會想找出警示第二多、第三多……的日期。
我們可以對時間戳記做字串切片，依你需求按年、月或日來分組來做到這件事。

範例：`cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` 告訴 `jq` 只從 `Timestamp` 擷取前 10 個位元組。

這會給我們事件最多的日期：
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

如果你想知道事件最多的月份，你只要把 `.[:10]` 改成 `.[:7]` 來擷取前 7 個位元組即可。

如果你想列出 `high` 警示最多的日期，你可以這樣做：

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

你可以依你的需求，根據電腦名稱、事件 ID 等等，持續在 `select` 函式中加入篩選條件……

## 6. 重建 PowerShell 日誌

關於 PowerShell 日誌有一件令人遺憾的事，那就是日誌經常會被拆分成多筆日誌，使其難以閱讀。
我們可以藉由只擷取出攻擊者所執行的指令，讓日誌變得容易閱讀許多。

舉例來說，如果你有 EID `4104` ScriptBlock 日誌，你可以只擷取出那個欄位，以建立易於閱讀的時間軸。

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

這會產生如下的時間軸：
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. 找出可疑的網路連線

你可以先用以下指令取得所有目標 IP 位址的清單：

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

如果你有威脅情資，你可以檢查是否有任何 IP 位址已知為惡意。

你可以用以下指令計算某個目標 IP 位址被連線的次數：

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

藉由把 `TgtIP` 改成 `SrcIP`，你可以根據來源 IP 位址對惡意 IP 位址進行相同的威脅情資檢查。

假設你發現環境中有連線到惡意 IP 位址 `93.184.220.29`。
你可以用以下查詢取得那些事件的詳細資訊：

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

這會給你如下的 JSON 結果：
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

如果你想列出被連線過的網域，你可以使用以下指令：

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> 注意：我加了一個針對 `.` 的 grep 篩選，用以移除 NETBIOS 主機名稱。

## 8. 擷取執行檔的二進位雜湊值

在 Sysmon EID `1` 處理程序建立日誌中，sysmon 可以被設定為計算二進位檔的雜湊值。
資安分析師可以透過威脅情資，將這些雜湊值與已知的惡意雜湊值進行比對。
你可以用以下指令擷取出 `Hashes` 欄位：

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

這會給你一份如下的雜湊值清單：

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon 通常會計算多個雜湊值，例如 `MD5`、`SHA1` 與 `IMPHASH`。
你可以用 `jq` 中的正規表示式擷取出這些雜湊值，或者為了更好的效能而直接使用字串切片。

舉例來說，你可以用以下指令擷取出 MD5 雜湊值並移除重複項：

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. 擷取 PowerShell 日誌

PowerShell Scriptblock 日誌（EID：4104）通常會被拆分成許多筆日誌，而且在輸出為 CSV 格式時，Hayabusa 會刪除定位符與換行字元以使輸出更精簡。
然而，最容易分析 PowerShell 日誌的方式，是保留原本的定位符與換行字元格式，並把日誌合併在一起。
以下是一個範例，從 `COMPUTER-A` 擷取出 PowerShell EID 4104 日誌，並將它們儲存到 `.ps1` 檔案，以便用 VSCode 等工具開啟並分析。
在擷取出 ScriptBlock 欄位後，我們使用 `awk` 將 `\r\n` 與 `\n` 替換為換行字元，並將 `\t` 替換為定位符。

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

在分析師分析完日誌中的惡意 PowerShell 指令後，他們接著通常會需要查詢那些指令是何時執行的。
以下是一個將時間戳記與 PowerShell 日誌輸出到 CSV 檔案的範例，以便查詢某個指令的執行時間：

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

注意：使用的字串分隔符是 `¦`，因為單引號與雙引號經常出現在 PowerShell 日誌中，會破壞 CSV 輸出。
當你匯入 CSV 檔案時，你需要向應用程式指定字串分隔符為 `¦`。
