# 分析コマンド

## `computer-metrics`コマンド

`computer-metrics`コマンドを使うと、`<System><Computer>`フィールドで定義された各コンピュータに応じたイベントの数をチェックすることができます。
`Computer`フィールドを完全に頼りにしてイベントを元のコンピュータ別に分けることはできないことに注意してください。
Windows 11ではイベントログに保存するときにまったく異なる`Computer`の名前を使うことがあります。
また、Windows 10では`Computer`の名前がすべて小文字で記録されることもあります。
このコマンドは検知ルールを使わないので、すべてのイベントを分析します。
このコマンドは、どのコンピュータに最も多くのログが記録されているかを素早く確認するのに適しています。
この情報があれば、タイムラインを生成する際に`--include-computer`または`--exclude-computer`オプションを使い、コンピュータ別に複数のタイムラインを生成したり、特定のコンピュータからのイベントを除外したりすることで、タイムライン生成をより効率的にすることができます。

```
Usage: computer-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>      1つの.evtxファイルに対して解析を行う
  -l, --live-analysis    ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する

General Options:
  -C, --clobber                        結果ファイルを上書きする
  -h, --help                           ヘルプメニューを表示する
  -J, --JSON-input                     .evtxファイルの代わりにJSON形式のログファイル(.jsonまたは.jsonl)をスキャンする
  -Q, --quiet-errors                   Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>             ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>               スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>  evtx以外の拡張子を解析対象に追加する。 (例１: evtx_data 例２: evtx1,evtx2)

Filtering:
      --time-offset <OFFSET>      オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)

Output:
  -o, --output <FILE>  イベントIDに基づくイベントの合計と割合の集計を出力する (例: computer-metrics.csv)

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する               
```

### `computer-metrics`コマンドの使用例

* ディレクトリに対してイベントIDの統計情報を出力する: `hayabusa.exe computer-metrics -d ../logs`
* 結果をCSVファイルに保存する: `hayabusa.exe computer-metrics -d ../logs -o computer-metrics.csv`

### `computer-metrics`のスクリーンショット

![computer-metrics screenshot](../assets/screenshots/ComputerMetrics.png)

## `eid-metrics`コマンド

`eid-metrics`コマンドを使用すると、イベントID(`<System><EventID>`フィールド)の総数や割合をチャンネルごとに分けて表示することができます。
このコマンドは検知ルールを使用しないので、すべてのイベントをスキャンします。

```
Usage: eid-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>        .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>            1つの.evtxファイルに対して解析を行う
  -l, --live-analysis          ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する

General Options:
  -C, --clobber                        結果ファイルを上書きする
  -h, --help                           ヘルプメニューを表示する
  -J, --JSON-input                     .evtxファイルの代わりにJSON形式のログファイル(.jsonまたは.jsonl)をスキャンする
  -Q, --quiet-errors                   Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>             ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>               スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>  evtx以外の拡張子を解析対象に追加する。 (例１: evtx_data 例２: evtx1,evtx2)

Filtering:
      --exclude-computer <COMPUTER...>  特定のコンピュータ名をスキャンしない (例: ComputerA) (例: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  特定のコンピュータ名のみをスキャンする (例: ComputerA) (例: ComputerA,ComputerB)
      --time-offset <OFFSET>            オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)

Output:
  -b, --disable-abbreviations 省略機能を無効にする
  -o, --output <FILE>  イベントIDに基づくイベントの合計と割合の集計を出力する (例: eid-metrics.csv)

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する

Time Format:
      --European-time     ヨーロッパ形式で日付と時刻を出力する (例: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          ISO-8601形式で日付と時刻を出力する (例: 2022-02-22T10:10:10.1234567Z) (UTC時刻)
      --RFC-2822          RFC 2822形式で日付と時刻を出力する (例: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          RFC 3339形式で日付と時刻を出力する (例: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  24時間制(ミリタリータイム)のアメリカ形式で日付と時刻を出力する (例: 02-22-2022 22:00:00.123 -06:00)
      --US-time           アメリカ形式で日付と時刻を出力する (例: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               UTC形式で日付と時刻を出力する (デフォルト: 現地時間)
```

### `eid-metrics`コマンドの使用例

* 一つのファイルに対してイベントIDの統計情報を出力する: `hayabusa.exe eid-metrics -f Security.evtx`
* ディレクトリに対してイベントIDの統計情報を出力する: `hayabusa.exe eid-metrics -d ../logs`
* 結果をCSVファイルに保存する: `hayabusa.exe eid-metrics -f Security.evtx -o eid-metrics.csv`

### `eid-metrics`コマンドの設定ファイル

チャンネル名、イベントID、イベントのタイトルは、`rules/config/channel_eid_info.txt`で定義されています。

例:
```
Channel,EventID,EventTitle
Microsoft-Windows-Sysmon/Operational,1,Process Creation.
Microsoft-Windows-Sysmon/Operational,2,File Creation Timestamp Changed. (Possible Timestomping)
Microsoft-Windows-Sysmon/Operational,3,Network Connection.
Microsoft-Windows-Sysmon/Operational,4,Sysmon Service State Changed.
```

### `eid-metrics`のスクリーンショット

![eid-metrics screenshot](../assets/screenshots/EID-Metrics.png)

## `expand-list`コマンド

ルールフォルダから`expand`プレースホルダーを抽出します。
これは、`expand`フィールド修飾子を使用するルールで利用する設定ファイルを作成する際に役立ちます。
`expand`ルールを使用するには、`./config/expand/`ディレクトリ内に`expand`フィールド修飾子の名前を持つ.txtファイルを作成し、そのファイル内に確認したい値をすべて入力するだけです。

例えば、ルールの`detection`ロジックが次のような場合:
```yaml
detection:
    selection:
        EventID: 5145
        RelativeTargetName|contains: '\winreg'
    filter_main:
        IpAddress|expand: '%Admins_Workstations%'
    condition: selection and not filter_main
```

テキストファイル `./config/expand/Admins_Workstations.txt` を作成し、次のような値を入力します:
```
AdminWorkstation1
AdminWorkstation2
AdminWorkstation3
```

これは本質的に次のロジックと同じ内容を確認します:
```
- IpAddress: 'AdminWorkstation1'
- IpAddress: 'AdminWorkstation2'
- IpAddress: 'AdminWorkstation3'
```

設定ファイルが存在しない場合でも、Hayabusaは`expand`ルールを読み込みますが、それを無視します。

```
Usage:  expand-list <INPUT> [OPTIONS]

General Options:
  -h, --help              ヘルプメニューを表示する
  -r, --rules <DIR/FILE>  ルールファイルまたはルールファイルを持つディレクトリ (デフォルト: ./rules)

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
```

### `expand-list`コマンドの使用例

* デフォルトの`rules`ディレクトリから`expand`フィールド修飾子を抽出する：`hayabusa.exe expand-list`
* `sigma`ディレクトリから`expand`フィールド修飾子を抽出する：`hayabusa.exe eid-metrics -r ../sigma`

### `expand-list`結果

```
5 unique expand placeholders found:
Admins_Workstations
DC-MACHINE-NAME
Workstations
internal_domains
domain_controller_hostnames
```

## `extract-base64`コマンド

このコマンドは、次のイベントからBase64文字列を抽出し、それをデコードして、どのようなエンコードが使用されているかを判別します。
* Security 4688 CommandLine
* Sysmon 1 CommandLine, ParentCommandLine
* System 7045 ImagePath
* PowerShell Operational 4104
* PowerShell Operational 4103

```
Usage:  extract-base64 <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>      1つの.evtxファイルに対して解析を行う
  -l, --live-analysis    ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する

General Options:
  -C, --clobber                        結果ファイルを上書きする
  -h, --help                           ヘルプメニューを表示する
  -J, --JSON-input                     .evtxファイルの代わりにJSON形式のログファイル(.jsonまたは.jsonl)をスキャンする
  -Q, --quiet-errors                   Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>             ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>               スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>  evtx以外の拡張子を解析対象に追加する。 (例１: evtx_data 例２: evtx1,evtx2)

Filtering:
      --exclude-computer <COMPUTER...>  特定のコンピュータ名をスキャンしない (例: ComputerA) (例: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  特定のコンピュータ名のみをスキャンする (例: ComputerA) (例: ComputerA,ComputerB)
      --time-offset <OFFSET>            オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)

Output:
  -o, --output <FILE>  Base64文字列を抽出する

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する

Time Format:
      --European-time     ヨーロッパ形式で日付と時刻を出力する (例: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          ISO-8601形式で日付と時刻を出力する (例: 2022-02-22T10:10:10.1234567Z) (UTC時刻)
      --RFC-2822          RFC 2822形式で日付と時刻を出力する (例: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          RFC 3339形式で日付と時刻を出力する (例: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  24時間制(ミリタリータイム)のアメリカ形式で日付と時刻を出力する (例: 02-22-2022 22:00:00.123 -06:00)
      --US-time           アメリカ形式で日付と時刻を出力する (例: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               UTC形式で日付と時刻を出力する (デフォルト: 現地時間)
```

### `extract-base64`コマンドの使用例

* ディレクトリをスキャンし、結果をターミナルに出力します: `hayabusa.exe  extract-base64 -d ../hayabusa-sample-evtx`
* ディレクトリをスキャンし、結果をCSVファイルに出力します: `hayabusa.exe eid-metrics -r ../sigma -o base64-extracted.csv`

### `extract-base64`の結果

ターミナルに出力する際、スペースに制限があるため、次のフィールドのみが表示されます：
  * Timestamp
  * Computer
  * Base64 String
  * Decoded String (if not binary)

CSVファイルに保存する際、次のフィールドが保存されます：
  * Timestamp
  * Computer
  * Base64 String
  * Decoded String (if not binary)
  * Original Field
  * Length
  * Binary (`Y/N`)
  * Double Encoding (`Y`の場合、それは通常悪意があります。)
  * Encoding Type
  * File Type
  * Event
  * Record ID
  * File Name

## `log-metrics`コマンド

`log-metrics`コマンドを使うと、イベントログ内の以下のメタデータを出力することができる:
* ファイル名
* コンピュータ名
* イベント数
* 最初のタイムスタンプ
* 最後のタイムスタンプ
* チャネル
* プロバイダー

このコマンドは検知ルールを使用しないので、すべてのイベントをスキャンする。

```
Usage: log-metrics <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>        .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>            1つの.evtxファイルに対して解析を行う
  -l, --live-analysis          ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する

General Options:
  -C, --clobber                        結果ファイルを上書きする
  -h, --help                           ヘルプメニューを表示する
  -J, --JSON-input                     .evtxファイルの代わりにJSON形式のログファイル(.jsonまたは.jsonl)をスキャンする
  -Q, --quiet-errors                   Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>             ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>               スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>  evtx以外の拡張子を解析対象に追加する。 (例１: evtx_data 例２: evtx1,evtx2)

Filtering:
      --exclude-computer <COMPUTER...>  特定のコンピュータ名をスキャンしない (例: ComputerA) (例: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  特定のコンピュータ名のみをスキャンする (例: ComputerA) (例: ComputerA,ComputerB)
      --time-offset <OFFSET>            オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)

Output:
  -b, --disable-abbreviations  省略機能を無効にする
  -M, --multiline              イベントフィールド情報を複数の行に出力する
  -o, --output <FILE>          メトリクスをCSV形式で保存する (例: metrics.csv)
  -S, --tab-separator          フィールドをタブ区切りにする

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する

Time Format:
      --European-time     ヨーロッパ形式で日付と時刻を出力する (例: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          ISO-8601形式で日付と時刻を出力する (例: 2022-02-22T10:10:10.1234567Z) (UTC時刻)
      --RFC-2822          RFC 2822形式で日付と時刻を出力する (例: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          RFC 3339形式で日付と時刻を出力する (例: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  24時間制(ミリタリータイム)のアメリカ形式で日付と時刻を出力する (例: 02-22-2022 22:00:00.123 -06:00)
      --US-time           アメリカ形式で日付と時刻を出力する (例: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               UTC形式で日付と時刻を出力する (デフォルト: 現地時間)
```

### `log-metrics`コマンドの使用例

* ファイルからログファイルのメトリクスを出力する: `hayabusa.exe log-metrics -f Security.evtx`
* ディレクトリからログファイルのメトリクスを出力する: `hayabusa.exe log-metrics -d ../logs`
* 結果をCSVファイルに保存: `hayabusa.exe log-metrics -d ../logs -o eid-metrics.csv`

### `log-metrics`のスクリーンショット

![log-metricsスクリーンショット](../assets/screenshots/LogMetrics.png)

## `logon-summary`コマンド

`logon-summary`コマンドを使うことでログオン情報の要約(ユーザ名、ログイン成功数、ログイン失敗数)の画面出力ができます。
単体のevtxファイルを解析したい場合は`-f`オプションを利用してください。複数のevtxファイルを対象としたい場合は`-d`オプションを合わせて使うことでevtxファイルごとのログイン情報の要約を出力できます。

ログオン成功は、以下のイベントから取得される:
* `Security 4624` (ログオン成功)
* `RDS-LSM 21` (リモートデスクトップサービス ローカルセッションマネージャーのログオン)
* `RDS-GTW 302` (リモートデスクトップサービス ゲートウェイのログオン)

ログオン失敗は、`Security 4625`イベントから取得される

```
Usage: logon-summary <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>        .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>            1つの.evtxファイルに対して解析を行う
  -l, --live-analysis          ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する

General Options:
  -C, --clobber                        結果ファイルを上書きする
  -h, --help                           ヘルプメニューを表示する
  -J, --JSON-input                     .evtxファイルの代わりにJSON形式のログファイル(.jsonまたは.jsonl)をスキャンする
  -Q, --quiet-errors                   Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>             ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>               スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>  evtx以外の拡張子を解析対象に追加する (例１: evtx_data 例２:evtx1,evtx2)

Filtering:
      --exclude-computer <COMPUTER...>  特定のコンピュータ名をスキャンしない (例: ComputerA) (例: ComputerA,ComputerB)
      --include-computer <COMPUTER...>  特定のコンピュータ名のみをスキャンする (例: ComputerA) (例: ComputerA,ComputerB)
      --timeline-end <DATE>             解析対象とするイベントログの終了時刻 (例: "2022-02-22 23:59:59 +09:00")
      --time-offset <OFFSET>            オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)
      --timeline-start <DATE>           解析対象とするイベントログの開始時刻 (例: "2020-02-22 00:00:00 +09:00")

Output:
  -o, --output <FILENAME-PREFIX>  ログオンサマリをCSV形式で２つのファイルに保存する (例: -o logon-summary.csv)

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する

Time Format:
      --European-time     ヨーロッパ形式で日付と時刻を出力する (例: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          ISO-8601形式で日付と時刻を出力する (例: 2022-02-22T10:10:10.1234567Z) (UTC時刻)
      --RFC-2822          RFC 2822形式で日付と時刻を出力する (例: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          RFC 3339形式で日付と時刻を出力する (例: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  24時間制(ミリタリータイム)のアメリカ形式で日付と時刻を出力する (例: 02-22-2022 22:00:00.123 -06:00)
      --US-time           アメリカ形式で日付と時刻を出力する (例: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               UTC形式で日付と時刻を出力する (デフォルト: 現地時間)
```

### `logon-summary`コマンドの使用例

* ログオンサマリの出力: `hayabusa.exe logon-summary -f Security.evtx`
* ログオンサマリ結果を保存する: `hayabusa.exe logon-summary -d ../logs -o logon-summary.csv`

### `logon-summary`のスクリーンショット

![logon-summary successful logons screenshot](../assets/screenshots/LogonSummarySuccessfulLogons.png)

![logon-summary failed logons screenshot](../assets/screenshots/LogonSummaryFailedLogons.png)

## `pivot-keywords-list`コマンド

`pivot-keywords-list`コマンドを使用すると、異常なユーザ、ホスト名、プロセスなどを迅速に特定し、イベントを関連付けるための固有のピボットキーワードのリストを作成することができます。

重要：デフォルトでは、Hayabusaはすべてのイベント（informationalおよびそれ以上）から結果を返すので、`pivot-keywords-list`コマンドと`-m, --min-level`オプションを組み合わせることを強くお勧めします。
例えば、まず`-m critical`で`critical`アラートのみのキーワードを作成し、次に`-m high`、`-m medium`等々と続けていきます。
検索結果には、多くの通常のイベントと一致する共通のキーワードが含まれている可能性が高いので、検索結果を手動でチェックし、固有のキーワードのリストを1つのファイルに作成した後、`grep -f keywords.txt timeline.csv`といったコマンドで疑わしい活動のタイムラインを絞り込み作成することが可能です。

```
Usage: pivot-keywords-list <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>        .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>            1つの.evtxファイルに対して解析を行う
  -l, --live-analysis          ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する

General Options:
  -C, --clobber                        結果ファイルを上書きする
  -h, --help                           ヘルプメニューを表示する
  -J, --JSON-input                     .evtxファイルの代わりにJSON形式のログファイル(.jsonまたは.jsonl)をスキャンする
  -w, --no-wizard                      質問はしない。すべてのイベントとアラートをスキャンする
  -Q, --quiet-errors                   Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>             ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>               スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>  evtx以外の拡張子を解析対象に追加する。 (例１: evtx_data 例２: evtx1,evtx2)

Filtering:
  -E, --EID-filter                      速度を上げるため主なEIDだけスキャンする (コンフィグファイル: ./rules/config/target_event_IDs.txt)
  -D, --enable-deprecated-rules         ステータスがdeprecatedのルールを有効にする
  -n, --enable-noisy-rules              Noisyルールを有効にする
  -u, --enable-unsupported-rules        ステータスがunsupportedのルールを有効にする
  -e, --exact-level <LEVEL>             特定のレベルだけスキャンする (informational, low, medium, high, critical)
      --exclude-computer <COMPUTER...>  特定のコンピュータ名をスキャンしない (例: ComputerA) (例: ComputerA,ComputerB)
      --exclude-eid <EID...>            高速化のために特定のEIDをスキャンしない (例: 1) (例: 1,4688)
      --exclude-status <STATUS...>      読み込み対象外とするルール内でのステータス (例１: experimental) (例２: stable,test)
      --include-computer <COMPUTER...>  特定のコンピュータ名のみをスキャンする (例: ComputerA) (例: ComputerA,ComputerB)
      --exclude-tag <TAG...>            特定のタグを持つルールをロードしない (例: sysmon)
      --include-eid <EID...>            指定したEIDのみをスキャンして高速化する (例 1) (例: 1,4688)
      --include-status <STATUS...>      特定のステータスを持つルールのみをロードする (例: expermimental) (例: stable,test)
      --include-tag <TAG...>            特定のタグを持つルールのみをロードする (例１: attack.execution,attack.discovery) (例２: wmi)
  -m, --min-level <LEVEL>               結果出力をするルールの最低レベル (デフォルト: informational)
      --timeline-end <DATE>             解析対象とするイベントログの終了時刻 (例: "2022-02-22 23:59:59 +09:00")
      --time-offset <OFFSET>            オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)
      --timeline-start <DATE>           解析対象とするイベントログの開始時刻 (例: "2020-02-22 00:00:00 +09:00")

Output:
  -o, --output <FILENAME-PREFIX>  ピボットキーワードの一覧を複数ファイルに出力する (例: PivotKeywords)

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する               
```

### `pivot-keywords-list`コマンドの使用例

* ピボットキーワードを画面に出力します: `hayabusa.exe pivot-keywords-list -d ../logs -m critical`
* 重要なアラートからピボットキーワードのリストを作成し、その結果を保存します。(結果は、`keywords-Ip Addresses.txt`、`keywords-Users.txt`等に保存されます):

```
hayabusa.exe pivot-keywords-list -d ../logs -m critical -o keywords
```

### `pivot-keywords-list`の設定ファイル

検索キーワードは、`./rules/config/pivot_keywords.txt`を編集することでカスタマイズすることができます。
デフォルト設定は[こちらのページ](https://github.com/Yamato-Security/hayabusa-rules/blob/main/config/pivot_keywords.txt)です。

フォーマットは、`キーワード名.フィールド名`です。例えば、`Users`のリストを作成する場合、Hayabusaは、`SubjectUserName`、`TargetUserName`、`User`フィールドにあるすべての値をリストアップします。

## `search`コマンド

`search`コマンドは、すべてのイベントのキーワード検索が可能です。
(※Hayabusaの検知結果だけではありません。）
Hayabusaの検知ルールでなにかの痕跡を検知できなくても、検索機能で検知できる可能性があるので、便利です。

```
Usage: hayabusa.exe search <INPUT> <--keywords "<KEYWORDS>" OR --regex "<REGEX>"> [OPTIONS]

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない
  -v, --verbose   詳細な情報を出力する

General Options:
  -C, --clobber                          結果ファイルを上書きする
  -h, --help                             ヘルプメニューを表示する
  -Q, --quiet-errors                     Quiet errorsモード: エラーログを保存しない
  -x, --recover-records                  空ページからevtxレコードをカービングする (デフォルト: 無効)
  -c, --rules-config <DIR>               ルールフォルダのコンフィグディレクトリ (デフォルト: ./rules/config)
  -t, --threads <NUMBER>                 スレッド数 (デフォルト: パフォーマンスに最適な数値)
      --target-file-ext <FILE-EXT...>    evtx以外の拡張子を解析対象に追加する (例１: evtx_data 例２:evtx1,evtx2)
  -s, --sort                             ファイル保存前にイベントをソートする (警告: これは多くのメモリを使用する!)

Input:
  -d, --directory <DIR>        .evtxファイルを持つディレクトリのパス
  -f, --file <FILE>            1つの.evtxファイルに対して解析を行う
  -l, --live-analysis          ローカル端末のC:\Windows\System32\winevt\Logsフォルダを解析する
  
Filtering:
  -a, --and-logic                    ANDロジックでキーワード検索を行う (デフォルト: OR)
  -F, --filter <FILTER...>           特定のフィールドでフィルタする
  -i, --ignore-case                  大文字と小文字を区別しない
  -k, --keywords <KEYWORD...>        キーワードでの検索
  -r, --regex <REGEX>                正規表現での検索
      --time-offset <OFFSET>         オフセットに基づく最近のイベントのスキャン (例: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             解析対象とするイベントログの終了時刻 (例: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           解析対象とするイベントログの開始時刻 (例: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        省略機能を無効にする
  -J, --JSON-output                  JSON形式で検索結果を保存する (例: -J -o results.json)
  -L, --JSONL-output                 JSONL形式で検索結果を保存 (例: -L -o results.jsonl)
  -M, --multiline                    イベントフィールド情報を複数の行に出力する
  -o, --output <FILE>                ログオンサマリをCSV形式で保存する (例: search.csv)
  -S, --tab-separator                フィールドをタブ区切りにする

Time Format:
      --European-time     ヨーロッパ形式で日付と時刻を出力する (例: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          ISO-8601形式で日付と時刻を出力する (例: 2022-02-22T10:10:10.1234567Z) (UTC時刻)
      --RFC-2822          RFC 2822形式で日付と時刻を出力する (例: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          RFC 3339形式で日付と時刻を出力する (例: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  24時間制(ミリタリータイム)のアメリカ形式で日付と時刻を出力する (例: 02-22-2022 22:00:00.123 -06:00)
      --US-time           アメリカ形式で日付と時刻を出力する (例: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               UTC形式で日付と時刻を出力する (デフォルト: 現地時間)
```

### `search`コマンドの使用例

* `../hayabusa-sample-evtx`ディレクトリで`mimikatz`のキーワードを検索する:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz"
```

> 注意: `mimikatz`のキーワードがデータ内のどこかに存在する場合にマッチする。完全一致しなくても良い。

* `../hayabusa-sample-evtx`ディレクトリで`mimikatz`または`kali`のキーワードを検索する:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -k "kali"
```

* `../hayabusa-sample-evtx`ディレクトリで大文字小文字を区別せずに`mimikatz`のキーワードを検索する:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -k "mimikatz" -i
```

* `../hayabusa-sample-evtx`ディレクトリで正規表現を使用し、IPアドレスを検索する:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
```

* `../hayabusa-sample-evtx`ディレクトリで`WorkstationName`フィールドが`kali`の条件で、全イベントを表示する:

```
hayabusa.exe search -d ../hayabusa-sample-evtx -r ".*" -F WorkstationName:"kali"
```

> ※ `.*`の正規表現を使用すると、すべてのイベントが表示される。

### `search`の設定ファイル

`./rules/config/channel_abbreviations.txt`: チャンネル名とその略称のマッピング。
