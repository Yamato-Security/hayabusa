## 事件計數規則（Event Count rules）

這類規則會計算特定事件的數量，並在某個時間範圍內這些事件發生次數過多或不足時發出警報。
在特定時間範圍內偵測到大量事件的常見範例，包括偵測密碼猜測攻擊、密碼噴灑攻擊以及阻斷服務攻擊。
您也可以使用這類規則來偵測日誌來源的可靠性問題，例如當某些事件低於特定門檻時。

### 事件計數規則範例：

以下範例使用兩條規則來偵測密碼猜測攻擊。
當所參照的規則在 5 分鐘內比對到 5 次以上，且這些事件的 `IpAddress` 欄位相同時，就會發出警報。

> 請注意，我們僅納入了理解此概念所需的必要欄位。
> 此範例所依據的完整規則位於[此處](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml)，供您參考。

### 事件計數關聯規則：

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### 登入失敗 - 密碼錯誤規則：

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### 已棄用的 `count` 規則範例：

上述關聯規則與所參照的規則所提供的結果，與以下使用較舊 `count` 修飾符的規則相同：

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### 事件計數規則輸出：

上述規則將產生以下輸出：
```
% ./hayabusa dfir-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## 數值計數規則（Value Count rules）

這類規則會計算在某個時間範圍內，具有特定欄位**不同**數值的相同事件。

範例：

- 網路掃描，即單一來源 IP 位址嘗試連線至許多不同的目的地 IP 位址與／或連接埠。
- 密碼噴灑攻擊，即單一來源以許多不同的使用者驗證失敗。
- 偵測像 BloodHound 這類在短時間內列舉許多高權限 AD 群組的工具。

### 數值計數規則範例：

以下規則會偵測攻擊者試圖猜測使用者名稱的情況。
也就是說，當**相同**的來源 IP 位址（`IpAddress`）在 5 分鐘內以超過 3 個**不同**的使用者名稱（`TargetUserName`）登入失敗時。

> 請注意，我們僅納入了理解此概念所需的必要欄位。
> 此範例所依據的完整規則位於[此處](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml)，供您參考。

### 數值計數關聯規則：

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### 數值計數登入失敗（不存在的使用者）規則：

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### 已棄用的 `count` 修飾符規則：

上述關聯規則與所參照的規則所提供的結果，與以下使用較舊 `count` 修飾符的規則相同：

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### 數值計數規則輸出：

上述規則將產生以下輸出：
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## 時間鄰近性規則（Temporal Proximity rules）

由 rule 欄位所參照的規則所定義的所有事件，都必須發生在 timespan 所定義的時間範圍內。
`group-by` 中所定義欄位的值必須全部相同（例如：相同主機、相同使用者等等）。

### 時間鄰近性規則範例：

範例：定義於三條 Sigma 規則中的偵察指令，由同一名使用者在 5 分鐘內以任意順序在某個系統上被執行。

### 時間鄰近性關聯規則：

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## 有序時間鄰近性規則（Ordered Temporal Proximity rules）

`temporal_ordered` 關聯類型的行為類似於 `temporal`，但額外要求這些事件依照 `rules` 屬性中所提供的順序出現。

### 有序時間鄰近性規則範例：

範例：在 1 小時內，發生上述定義的多次登入失敗後，隨即由同一個使用者帳戶成功登入：

### 有序時間鄰近性關聯規則：

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## 關聯規則的注意事項

1. 您應將所有的關聯規則與所參照的規則放在同一個檔案中，並以 YAML 分隔符 `---` 加以區隔。

2. 預設情況下，被參照的關聯規則不會被輸出。若您想查看被參照規則的輸出，則需要在 `correlation` 下方加入 `generate: true`。在建立關聯規則時，開啟此選項並進行檢查非常有用。

    範例：
    ```
    correlation:
        generate: true
    ```
3. 您可以在參照規則時使用別名來取代規則 ID，以便讓內容更容易理解。

4. 您可以參照多條規則。

5. 您可以在 `group-by` 中使用多個欄位。若這麼做，那些欄位中的所有值都必須相同，否則您將不會收到警報。大多數情況下，您會撰寫以 `group-by` 對特定欄位進行篩選的規則，以減少誤報，然而，您也可以省略 `group-by` 以建立更通用的規則。

6. 關聯規則的時間戳記會是攻擊的最起始時間點，因此您應檢查該時間點之後的事件，以確認是否為誤報。
