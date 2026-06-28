# Sigma相関ルール

[こちら](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md)に定義されているSigmaバージョン2.0.0の相関ルールのすべてを実装しています。

サポートされている相関ルール:

- イベントカウント (`event_count`)
- 値カウント (`value_count`)
- 時間的近接性 (`temporal`)
- 順序付き時間的近接性 (`temporal_ordered`)

2025年9月12日にSigmaバージョン2.1.0で追加された新しい「metrics」相関ルール（`value_sum`、`value_avg`、`value_percentile`）には、現在まだ対応していません。

## イベントカウントルール

これらは特定のイベントをカウントし、一定の時間内にそのイベントが多すぎるか、または少なすぎる場合にアラートを発するルールです。
一定の時間内に多数のイベントを検知する一般的な例として、パスワード推測攻撃、パスワードスプレー攻撃、サービス拒否攻撃の検出が挙げられます。
また、これらのルールを使用して、特定のイベントが特定の閾値を下回った場合など、ログソースの信頼性に関する問題を検出することも可能です。

### イベントカウントルールの例:

次の例では、パスワード推測攻撃を検出するために2つのルールを使用しています。
参照されるルールが5分以内に5回以上一致し、これらのイベントのIpAddressフィールドが同じ場合にアラートが発生します。

> 概念を理解するために必要なフィールドのみを含めています。
> この例に基づく完全なルールは[こちら](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) にありますので、ご参照ください。

### イベントカウント相関ルール:

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

### ログオン失敗 - 誤ったパスワード ルール:

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

### 非推奨の`count`ルールの例:

上記の相関ルールおよび参照されているルールは、従来の`count`修飾子を使用した以下のルールと同じ結果を提供します。

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
### イベントカウントルールの出力:

上記のルールは次の結果を出力します:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## 値カウントルール

これらのルールは、指定されたフィールドの**異なる**値を持つ同じイベントを一定の時間枠内でカウントします。

例:

- 1つの送信元IPアドレスが多数の異なる宛先IPアドレスやポートに接続しようとするネットワークスキャンの検知
- 1つの送信元が多数の異なるユーザーに対して認証に失敗するパスワードスプレー攻撃の検知
- 短時間で多数の高権限ADグループを列挙するBloodHoundのようなツールの検知

### 値カウントルールの例:

次のルールは、攻撃者がユーザー名を推測しようとしている場合を検出します。
つまり、**同じ**送信元IPアドレス (`IpAddress`) が5分以内に3つ以上の**異なる**ユーザー名 (`TargetUserName`) でログオンに失敗した場合です。

> 概念を理解するために必要なフィールドのみを含めています。
> この例に基づく完全なルールは[こちら](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml)にありますので、ご参照ください。

### 値カウント相関ルール:

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

### 値カウント ログオン失敗 (存在しないユーザー) ルール:

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

### 非推奨の`count`ルール:

上記の相関ルールおよび参照されているルールは、従来の`count`修飾子を使用した以下のルールと同じ結果を提供します:

```yaml
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

### 値カウントルールの出力:

上記のルールは次の結果を出力します:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Temporal Proximityルール

ルールフィールドで参照されるルールで定義されたすべてのイベントは、`timespan`で定義された時間内に発生しなければならない。
`group-by` で定義されたフィールドの値はすべて同じ値でなければならない（例：同じホスト、ユーザーなど）。

### Temporal Proximityルールの例:

例: 3つのSigmaルールで定義された偵察コマンドが、同一ユーザーによってシステム上で5分以内に任意の順序で起動される

### Temporal Proximity相関ルール:

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

## Ordered Temporal Proximityルール

`temporal_ordered` 相関タイプは `temporal` と同じように振る舞い、さらに `rules` 属性で指定された順番でイベントが現れることを要求する

### Ordered Temporal Proximityルールの例:

例：上記で定義されたログイン失敗が多数あり、その後1時間以内に同じユーザーアカウントでログインが成功した場合：

### Ordered Temporal Proximity相関ルール:

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

## 相関ルールの注意点

1. すべての相関ルールおよび参照されているルールを1つのファイルに含め、YAMLの区切り文字である`---`で区切ってください

2. デフォルトでは、参照された相関ルールの出力は行われません。参照ルールの出力を確認したい場合は、`correlation`の下に`generate: true`を追加する必要があります。相関ルールを作成する際に有効にして結果を確認すると非常に便利です。
    例:
    ```yaml
    correlation:
        generate: true
    ```
3. ルールを参照する際に、ルールIDの代わりにエイリアス名を使用して、より理解しやすくすることができます

4. 複数のルールを参照することができます

5. `group-by`で複数のフィールドを使用することができます。その場合、これらのフィールドのすべての値が同じでないと、アラートは発生しません。多くの場合、誤検知を減らすために特定のフィールドを`group-by`でフィルタリングするルールを作成しますが、より汎用的なルールを作成するために `group-by`を省略することも可能です

6. 相関ルールのタイムスタンプは攻撃の開始時点になるので、それ以降のイベントを確認し、過検知かどうかを判断する必要があります。
