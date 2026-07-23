# DFIRタイムラインコマンド

## スキャンウィザード

`dfir-timeline`コマンドは、デフォルトでスキャンウィザードが有効になりました。
これは、ユーザのニーズや好みに応じて、どの検知ルールを有効にするかを簡単に選択できるようにするためのものであります。
読み込む検知ルールのセットは、Sigmaプロジェクトの公式リストに基づいています。
詳細は[このブログ記事](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81)で説明されています。
`w, --no-wizard`オプションを追加することで、簡単にウィザードを無効にし、従来の方法でHayabusaを使用できます。

### Core ルール

`core`ルールセットは、ステータスが`test`または`stable`かつ、レベルが`high`または`critical`のルールを有効にします。
これらは高品質のルールで、多くの誤検知は発生しないはずです。
ルールのステータスが`test`または`stable`であるため、6ヶ月以上の間に誤検知が報告されていません。
ルールは攻撃者の戦術、一般的な不審なアクティビティ、または悪意のある振る舞いに一致します。
これは`--exclude-status deprecated,unsupported,experimental --min-level high`オプションを使用した場合と同じです。

### Core+ ルール

`core+`ルールセットは、ステータスが`test`または`stable`かつ、レベルが`medium`以上のルールを有効にします。
`medium`ルールは、しばしば特定のアプリケーション、正当なユーザーの行動、または組織のスクリプトと一致するため、追加のチューニングが必要です。
これは`--exclude-status deprecated,unsupported,experimental --min-level medium`オプションを使用した場合と同じです。

### Core++ ルール

`core++`ルールセットは、ステータスが`experimental`、`test`、`stable`のいずれかかつ、レベルが`medium`以上のルールを有効にします。
これらのルールは最先端のものです。
これらはSigmaHQプロジェクトで提供されているベースラインのevtxファイルに対して検証され、複数のエンジニアによってレビューされています。
それ以外最初は、ほとんどテストされていません。
これらは、できるだけ早く脅威を検出できる場合に使用しますが、誤検知のしきい値を高く保つのにコストがかかります。
これは`--exclude-status deprecated,unsupported --min-level medium`オプションを使用した場合と同じです。

### Emerging Threats (ET) アドオンルール

`Emerging Threats (ET)`ルールセットは、`detection.emerging_threats`のタグを持つルールを有効にします。
これらのルールは特定の脅威を対象とし、情報がまだほとんど入手できていない現在の脅威に特に役立ちます。
これらのルールは多くの誤検知を生成しないはずですが、時間とともに関連性が低下します。
これらのルールが無効になっている場合、`--exclude-tag detection.emerging_threats`オプションを使用した場合と同じです。
ウィザードを無効にしてHayabusaを従来の方法で実行する場合、これらのルールはデフォルトで含まれます。

### Threat Hunting (TH) アドオンルール

`Threat Hunting (TH)`ルールセットは、`detection.threat_hunting`のタグを持つルールを有効にします。
これらのルールは未知の悪意のあるアクティビティを検出するかもしれませんが、通常は誤検知が多くなります。
これらのルールが無効になっている場合、`--exclude-tag detection.threat_hunting`オプションを使用した場合と同じです。
ウィザードを無効にしてHayabusaを従来の方法で実行する場合、これらのルールはデフォルトで含まれます。

## Channelベースのイベントログとルールフィルタリング

Hayabusa v2.16.0以降、`.evtx`ファイルと`.yml`ルールを読み込む際にチャンネルベースのフィルタを有効にしています。
これは、必要なものだけを読み込むことで、スキャンを可能な限り効率的に行うことを目的としています。
単一のイベントログ内に複数のプロバイダが存在することはありますが、単一の.evtxファイル内に複数のチャンネルが含まれることは一般的ではありません。
（これまで見かけた唯一の例は、異なる2つの.evtxファイルを人工的に結合した[sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)プロジェクトです。）
この特性を利用して、スキャン対象のすべての`.evtx`ファイルの最初のレコードで`Channel`フィールドを確認します。
また、ルールの`Channel`フィールドに指定されたチャンネルを使用する`.yml`ルールも確認します。
この2つのリストを基に、実際に`.evtx`ファイル内に存在するチャンネルを使用するルールだけを読み込みます。

例えば、ユーザーが`Security.evtx`をスキャンしたい場合、`Channel: Security`を指定しているルールのみが使用されます。
他の検出ルール、例えば`Application`ログのイベントのみを検出するルールなどを読み込む意味はありません。
なお、チャンネルフィールド（例: `Channel: Security`）は、元のSigmaルールには**明示的**に定義されていません。
Sigmaルールでは、`logsource`の`service`や`category`フィールドでチャンネルやイベントIDが**暗黙的**に定義されています（例: `service: security`）
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)リポジトリでSigmaルールを管理する際には、`logsource`フィールドを具体化し、チャンネルやイベントIDフィールドを明示的に定義しています。
これをどのように、そしてなぜ行うのかについては、[こちら](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)で詳しく説明しています。

現在、`Channel`が定義されておらず、すべての`.evtx`ファイルをスキャンするためのルールは以下の2つだけです：

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

これらの2つのルールを使用して、読み込んだすべての`.evtx`ファイルに対してルールをスキャンしたい場合は、`dfir-timeline`コマンドで`-A, --enable-all-rules`オプションを追加する必要があります。
ベンチマークでは、ルールフィルタリングにより、スキャンするファイルに応じて、速度が20%から10倍に向上することが確認されています。

チャンネルフィルタリングは、`.evtx`ファイルを読み込む際にも使用されます。
例えば、`Security`チャンネルのイベントを探すルールを指定している場合、`Security`ログではない`.evtx`ファイルを読み込む意味はありません。
ベンチマークでは、通常のスキャンで約10%、単一のルールでスキャンする場合には最大60%以上の性能向上が見られました。
1つの.evtxファイル内に複数のチャンネルが使用されている場合、例えば複数の`.evtx`ファイルがツールを使って結合された場合は、`dfir-timeline`コマンドで`-a, --scan-all-evtx-files`オプションを使用してこのフィルタリングを無効にできます。

> 注意: チャンネルフィルタリングは.evtxファイルでのみ動作します。-J, --json-inputでJSONファイルからイベントログを読み込み、さらに-Aや-aを指定した場合、エラーが発生します。

## `dfir-timeline`コマンド

`dfir-timeline`コマンドはイベントのフォレンジックタイムラインを作成します。出力形式は`-t, --output-type`で選択します: `csv`（デフォルト）、`json`、`jsonl`のいずれかです。値は大文字・小文字を区別しません（例: `-t JSONL`）。

- **CSV**は、比較的小さいタイムライン（通常2GB以下）をLibreOfficeやTimeline Explorer等のツールにインポートするのに適しています（すべてのイベントフィールドが1つの大きな`Details`カラムにまとめられます）。
- **JSON**は、`Details`フィールドが分離されているため、`jq`等のツールで大きな結果をより詳細に分析する場合に最適です。
- **JSONL**は、JSONよりも高速でファイルサイズも小さいため、Elastic Stack等のツールにインポートするのに理想的です。

**CSV Output**（CSV出力）のオプション`-M, --multiline`、`-S, --tab-separator`、`-R, --remove-duplicate-data`はCSV出力にのみ適用され、CSV以外の`-t`と組み合わせるとエラーになります。

```
  hayabusa.exe dfir-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort results before saving the file (warning: this uses much more memory!)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)
      --threads <NUMBER>               Number of threads (default: optimal number for performance)
  -V, --validate-checksums             Enable checksum validation

Filtering:
  -E, --eid-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

CSV Output:
  -M, --multiline              Separate event field information by newline characters (CSV output only)
  -R, --remove-duplicate-data  Duplicate field data will be replaced with "DUP" (CSV output only, sort required)
  -S, --tab-separator          Separate event field information by tabs (CSV output only)

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --geo-ip <MAXMIND-DB-DIR>      Add GeoIP (ASN, city, country) info to IP addresses
  -H, --html-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline to a file (ex: results.csv)
  -t, --output-type <OUTPUT_FORMAT>  Output format: csv (default), json, or jsonl
  -p, --profile <PROFILE>            Specify output profile
  -X, --remove-duplicate-detections  Remove duplicate detections (sort required)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode, sort required)

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
  -U, --utc               Output time in UTC format (default: local time)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
```

### `dfir-timeline`コマンドの使用例

* デフォルトの`standard`プロファイルで１つのWindowsイベントログファイルに対してHayabusaを実行する:

```
hayabusa.exe dfir-timeline -f eventlog.evtx 
```

* `verbose`プロファイルで複数のWindowsイベントログファイルのあるsample-evtxディレクトリに対して、Hayabusaを実行する:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* 全てのフィールド情報も含めて１つのCSVファイルにエクスポートして、LibreOffice、Timeline Explorer、Elastic Stack等でさらに分析することができる(注意: `super-verbose`プロファイルを使すると、出力するファイルのサイズがとても大きくなる！):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* CSVの代わりにJSON形式で出力する（`jq`等での分析用）:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* JSONL形式で出力する（Elastic Stack等へのインポート用。`-t`は大文字・小文字を区別しない）:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* EID(イベントID)フィルタを有効にし、タイムラインをJSON形式で保存する:

> 注意: EIDフィルタを有効にすると、私達のテストでは処理時間が約10〜15%速くなりますが、アラートを見逃す可能性があります。

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Hayabusaルールのみを実行する（デフォルトでは`-r .\rules`にあるすべてのルールが利用される）:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Windowsでデフォルトで有効になっているログに対してのみ、Hayabusaルールを実行する:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Sysmonログに対してのみHayabusaルールを実行する:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Sigmaルールのみを実行する:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* 廃棄(deprecated)されたルール(`status`が`deprecated`になっているルール)とノイジールール(`.\rules\config\noisy_rules.txt`にルールIDが書かれているルール)を有効にする:

> 注意: 最近、廃止されたルールはSigmaリポジトリで別のディレクトリに置かれるようになり、Hayabusaではもうデフォルトでは含まれないようになりました。
> 従って、廃止されたルールを有効にする必要はないでしょう。

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* ログオン情報を分析するルールのみを実行し、UTCタイムゾーンで出力する:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* 起動中のWindows端末上で実行し（Administrator権限が必要）、アラート（悪意のある可能性のある動作）のみを検知する:

```
hayabusa.exe dfir-timeline -l -m low
```

* 詳細なメッセージを出力する(処理に時間がかかるファイル、パースエラー等を特定するのに便利):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Verbose出力の例:

ルールファイルの読み込み:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

スキャン中のエラー:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* 結果を[Timesketch](https://timesketch.org/)にインポートできるCSV形式に保存する:

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* エラーログの出力をさせないようにする:
デフォルトでは、Hayabusaはエラーメッセージをエラーログに保存します。
エラーメッセージを保存したくない場合は、`-Q`を追加してください。

### アドバンス - GeoIPのログエンリッチメント

無償のGeoLite2のジオロケーションデータで、SrcIP（ソースIPアドレス）フィールドとTgtIP（ターゲットIPアドレス）フィールドにGeoIP（ASN組織、都市、国）情報を追加することができます。

手順:

1. まずMaxMindのアカウントを[こちら](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)で登録してください。
2. [ダウンロードページ](https://www.maxmind.com/en/accounts/current/geoip/downloads)から3つの`.mmdb`ファイルをダウンロードし、ディレクトリに保存してください。ファイル名は、`GeoLite2-ASN.mmdb`、`GeoLite2-City.mmdb`、`GeoLite2-Country.mmdb`であることをご確認ください。
3. `dfir-timeline`コマンドを実行する際には、`-G`オプションの後にMaxMindデータベースのあるディレクトリを追加してください。

* CSV出力では、次の6つのカラムが追加で出力されます: `SrcASN`、`SrcCity`、`SrcCountry`、`TgtASN`、`TgtCity`、`TgtCountry`
* JSON/JSONL出力では、同じ`SrcASN`、`SrcCity`、`SrcCountry`、`TgtASN`、`TgtCity`、`TgtCountry`フィールドが`Details`オブジェクトに追加されますが、情報を含む場合のみとなります。

* `SrcIP`または`TgtIP`がlocalhost (`127.0.0.1`、`::1`等々)の場合、`SrcASN`または`TgtASN`は、`Local`として出力されます。
* `SrcIP`または`TgtIP`がプライベートIPアドレス (`10.0.0.0/8`、`fe80::/10`等々)の場合、`SrcASN`または`TgtASN`は、`Private`として出力されます。

#### GeoIPの設定ファイル

GeoIPデータベースで検索される送信元と送信先のIPアドレスを含むフィールド名は、`rules/config/geoip_field_mapping.yaml`で定義されています。
必要であれば、このリストに追加することができます。
また、このファイルには、どのイベントからIPアドレス情報を抽出するかを決定するフィルタセクションもあります。

#### GeoIPデータベースの自動アップデート

MaxMind GeoIP データベースは、2 週間ごとに更新されます。
これらのデータベースを自動的に更新するために、[こちら](https://github.com/maxmind/geoipupdate)からMaxMindの`geoipupdate`のツールをインストールすることができます。

macOSでの手順:

1. `brew install geoipupdate`
2. `/usr/local/etc/GeoIP.conf`または`/opt/homebrew/etc/GeoIP.conf`を編集する: MaxMindのウェブサイトにログインした後に作成した`AccountID`と`LicenseKey`を入れる。`EditionIDs`の行に、`EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`とあることを確認する。
3. `geoipupdate`を実行する。
4. GeoIP情報を追加する場合は、`-G /usr/local/var/GeoIP`または`-G /opt/homebrew/var/GeoIP`を追加する。

Windowsでの手順:

1. [Releases](https://github.com/maxmind/geoipupdate/releases)ページからWindowsバイナリの最新版(例: `geoipupdate_4.10.0_windows_amd64.zip`)をダウンロードする。
2. `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`を編集する: MaxMindのウェブサイトにログインした後に作成した`AccountID`と`LicenseKey`を入れる。`EditionIDs`の行に、`EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`とあることを確認する。
3. `geoipupdate`を実行する。

Linuxでの手順:

1. `sudo apt install geoip-update`でインストールする。
2. `sudo nano /etc/GeoIP.conf`で設定ファイルを編集する。
3. `sudo geoipupdate`でデータベースファイルを更新する。
4. GeoIP情報を追加する場合は、`-G /var/lib/GeoIP/`を追加する。

### `dfir-timeline`コマンドの設定ファイル

`./rules/config/channel_abbreviations.txt`: チャンネル名とその略称のマッピング。

`./rules/config/default_details.txt`: ルールに`details:`行が指定されていない場合に、どのようなデフォルトのフィールド情報 (`%Details%`フィールド)を出力するかを設定するファイルです。
プロバイダー名とイベントIDを元に作成されます。

`./rules/config/eventkey_alias.txt`: このファイルには、フィールドの短い名前のエイリアスと、元の長いフィールド名のマッピングがあります。

例:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

ここでフィールドが定義されていない場合、Hayabusaは自動的に`Event.EventData`にあるフィールドを使用してみます。

`./rules/config/exclude_rules.txt`: このファイルには、使用から除外されるルールIDのリストがあります。
通常は、あるルールが別のルールに置き換わったか、そもそもそのルールが使用できないことが原因です。
ファイアウォールやIDSと同様に、シグネチャベースのツールは、自身の環境に合わせてチューニングする必要があるため、特定のルールを恒久的または一時的に除外する必要があるかもしれません。
`./rules/config/exclude_rules.txt`にルールID (例:`4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`)を追加すると、不要なルールや使用できないルールを無視できます。

`./rules/config/noisy_rules.txt`: このファイルには、デフォルトでは無効になっているルールのIDが入っています。`-n, --enable-noisy-rules`オプションでノイジールールを有効にできます。
これらのルールは通常、性質上ノイズが多いか、誤検出があるためです。

`./rules/config/target_event_IDs.txt`: EIDフィルターが有効な場合、このファイルで指定されたイベントIDのみがスキャンされます。
デフォルトでは、Hayabusaはすべてのイベントをスキャンしますが、パフォーマンスを向上させたい場合は、`-E, --eid-filter`オプションを使用してください。
これにより、通常10〜25％の速度向上があります。

## `level-tuning`コマンド

`level-tuning`コマンドを使用すると、環境に応じてリスクレベルを上げたり下げたりして、ルールのアラートレベルを調整できます。
このコマンドは、`rules`フォルダ内のルールのリスクレベル(`level`フィールド)を上書きするために、設定ファイルを使用します。

> 注意: `update-rules`を実行するたびに、アラートレベルが元の設定に上書きされるので、レベルを変更したい場合は、`level-tuning`コマンドも実行する必要があります。

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color      カラーで出力しない
  -q, --quiet         Quietモード: 起動バナーを表示しない

General Options:
  -f, --file <FILE>   ルールlevelのチューニング (デフォルト: ./rules/config/level_tuning.txt)
  -h, --help          ヘルプメニューを表示する
```

### `level-tuning`コマンドの使用例

* 通常使用: `hayabusa.exe level-tuning`
* カスタム設定ファイルに基づくルールのアラートレベルの調整: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning`の設定ファイル

HayabuaとSigmaのルール作成者は、ルールを作成する際にアラートの適切なリスクレベルを見積もります。
しかし、リスクレベルが一貫していない場合や、実際のリスクレベルが環境によって異なる場合があります。
Yamato Securityは、`./rules/config/level_tuning.txt`に設定ファイルを提供し、ルールを調整することができます。

`./rules/config/level_tuning.txt`の一例:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

この場合、ルールディレクトリ内の`id`が`570ae5ec-33dc-427c-b815-db86228ad43e`のルールのリスクレベルは、`informational`に書き換えられます。
設定可能なレベルは、`critical`、`high`、`medium`、`low`、`informational`です。

> 注意: `./rules/config/level_tuning.txt`設定ファイルは、`update-rules`を実行するたびに、hayabusa-rulesリポジトリの最新バージョンに更新されます。
> したがって、このファイルを変更した場合、変更内容は失われます！
> 自分用の設定ファイルを保持したい場合は、`./config/level_tuning.txt`に設定ファイルを作成し、`hayabusa.exe level-tuning -f ./config/level_tuning.txt`を実行してください。
> また、Yamato Securityが提供する設定ファイルを使用して最初にレベル調整を行い、その後独自の設定ファイルでさらに調整することもできます。

## `list-profiles`コマンド

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color   カラーで出力しない
  -q, --quiet      Quietモード: 起動バナーを表示しない
  
General Options:
  -h, --help       ヘルプメニューを表示する
```

## `set-default-profile`コマンド

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color           カラーで出力しない
  -q, --quiet              Quietモード: 起動バナーを表示しない

General Options:
  -h, --help               ヘルプメニューを表示する
  -p, --profile <PROFILE>  利用する出力プロファイル名を指定する
```

### `set-default-profile`コマンドの使用例

* デフォルトプロファイルを`minimal`に設定する: `hayabusa.exe set-default-profile minimal`
* デフォルトプロファイルを`super-verbose`に設定する: `hayabusa.exe set-default-profile super-verbose`

# `update-rules`コマンド

`update-rules`コマンドは、`rules`フォルダを[HayabusaルールのGitHubリポジトリ](https://github.com/Yamato-Security/hayabusa-rules)と同期し、ルールと設定ファイルを更新します。

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない

General Options:
  -h, --help              ヘルプメニューを表示する
  -r, --rules <DIR/FILE>  ルールファイルまたはルールファイルを持つディレクトリ (デフォルト: ./rules)
```

## `update-rules`コマンドの使用例

普段は次のように実行します: `hayabusa.exe update-rules`
