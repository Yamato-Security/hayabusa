<div align="center">
 <p>

  ![Hayabusa Logo](hayabusa-logo.png)
 
 </p>
</div>

# Hayabusa について
Hayabusaは、日本の[Yamato Security](https://yamatosecurity.connpass.com/)グループによって作られた**Windowsイベントログのファストフォレンジックタイムライン生成**および**スレットハンティングツール**であります。 Hayabusaは日本語で[「ハヤブサ」](https://en.wikipedia.org/wiki/Peregrine_falcon)を意味し、ハヤブサが世界で最も速く、狩猟(hunting)に優れ、とてもしつけやすい動物であることから選ばれました。[Rust](https://www.rust-lang.org/) で開発され、マルチスレッドに対応し、可能な限り高速に動作するよう配慮されています。[Sigma](https://github.com/SigmaHQ/Sigma)ルールをHayabusaルール形式に変換する[ツール](https://github.com/Yamato-Security/hayabusa/tree/main/tools/Sigmac)も提供しています。Hayabusaの検知ルールもSigmaと同様に、できるだけ簡単にカスタマイズや拡張ができるようにYMLで書かれています。稼働中のシステムで実行してライブ調査することも、複数のシステムからログを収集してオフライン調査することも可能です。(※現時点では、リアルタイムアラートや定期的なスキャンには対応していません。) 出力は一つの CSV タイムラインにまとめられ、Excelや[Timeline Explorer](https://ericzimmerman.github.io/#!index.md)で簡単に分析できるようになります。

## 主な目的

### 脅威ハンティング
Hayabusa には現在、1000以上のSigmaルールと約50のHayabusa検知ルールがあり、定期的にルールが追加されています。 最終的な目標はインシデントの後で、または定期的な脅威ハンティングのために、HayabusaエージェントをすべてのWindows端末にプッシュして、中央サーバーにアラートを返すことができるようにすることです。

### フォレンジックタイムラインの高速生成
Windowsのイベントログは、
  1）解析が困難なデータ形式であること
  2）データの大半がノイズであり調査に有用でないこと
から、従来は非常に長い時間と手間がかかる解析作業となっていました。 Hayabusa は、有用なデータのみを抽出し、専門的なトレーニングを受けた分析者だけでなく、Windowsのシステム管理者であれば誰でも利用できる読みやすい形式で提示することを主な目的としています。
[Evtx Explorer](https://ericzimmerman.github.io/#!index.md)や[Event Log Explorer](https://eventlogxp.com/)のような、より深く掘り下げた分析を行うツールの代替となることは意図していませんが、分析者が20%の時間で80%の作業を行えるようにすることを目的としています。

# 開発について
[DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)というWindowsイベントログ解析ツールに触発されて、2020年に[RustyBlue](https://github.com/Yamato-Security/RustyBlue)プロジェクト用にRustに移植することから始めました。その後、YMLで書かれたSigmaのような柔軟な検知シグネチャを作り、Sigmaルールを我々のHayabusaルール形式へ変換するサポートをSigmaへのバックエンドとして追加しています。

# スクリーンショット
## 起動画面:

![Hayabusa 起動画面](/screenshots/Hayabusa-Startup.png)

## ターミナル出力画面:

![Hayabusa ターミナル出力画面](/screenshots/Hayabusa-Results.png)

## 結果サマリ画面:

![Hayabusa 結果サマリ画面](/screenshots/HayabusaResultsSummary.png)

## Excelでの解析:

![Hayabusa Excelでの解析](/screenshots/ExcelScreenshot.png)

## Timeline Explorerでの解析:

![Hayabusa Timeline Explorerでの解析](screenshots/TimelineExplorer-ColoredTimeline.png)

## Criticalアラートのフィルタリングとコンピュータごとのグルーピング:

![Timeline ExplorerでCriticalアラートのフィルタリングとコンピュータグルーピング](screenshots/TimelineExplorer-CriticalAlerts-ComputerGrouping.png)

# 特徴
* クロスプラットフォーム対応: Windows, Linux, macOS
* Rustで開発され、メモリセーフでハヤブサよりも高速です！
* マルチスレッド対応により、最大5倍のスピードアップを実現!
* フォレンジック調査やインシデントレスポンスのために、分析しやすいCSVタイムラインを作成します。
* 読みやすい/作成/編集可能なYMLベースのHayabusaルールで作成されたIoCシグネチャに基づく脅威ハンティング 
* SigmaルールをHayabusaルールに変換するためのSigmaルールのサポートがされています。
* 現在、他の類似ツールに比べ最も多くのSigmaルールをサポートしており、カウントルールにも対応しています。
* イベントログの統計（どのような種類のイベントがあるのかを把握し、ログ設定のチューニングに有効です。）
* 不良ルールやノイズの多いルールを除外するルールチューニング設定が可能です。

# 予定されている機能
* すべてのエンドポイントでの企業全体の脅威ハンティング
* 日本語対応
* MITRE ATT&CK とのマッピング
* MITRE ATT&CK ヒートマップ生成機能
* ユーザーログオンと失敗したログオンのサマリー
* JSONログからの入力
* JSONへの出力→Elastic Stack/Splunkへのインポート

# ダウンロード
以下の`git clone`コマンドでレポジトリをダウンロードできます:

```bash
git clone https://github.com/Yamato-Security/hayabusa.git
```

または、手動で[https://github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa)からHayabusaをダウンロードすることもできます。

その後、Windows、Linux、macOS用のコンパイル済みバイナリを[Releases](https://github.com/Yamato-Security/Hayabusa/releases)からダウンロードして、`hayabusa`のディレクトリに置く必要があります。

# ソースコードからのコンパイル（任意）
rustがインストールされている場合、以下のコマンドでソースコードからコンパイルすることができます:

```bash
cargo build --release
```

## アドバンス: パッケージに更新
コンパイル前に最新のRust crateにアップデートすることで、最新のライブラリを取得することができます:

```bash
cargo update
```

※ アップデート後、何か不具合がありましたらお知らせください。

## サンプルevtxファイルでHayabusaをテストする
Hayabusaをテストしたり、新しいルールを作成したりするためのサンプルevtxファイルをいくつか提供しています: [https://github.com/Yamato-Security/Hayabusa-sample-evtx](https://github.com/Yamato-Security/Hayabusa-sample-evtx)

以下のコマンドで、サンプルのevtxファイルを新しいサブディレクトリ `hayabusa-sample-evtx` にダウンロードすることができます:
```bash
git clone https://github.com/Yamato-Security/hayabusa-sample-evtx.git
```

> ※ 以下の例でHayabusaを試したい方は、上記コマンドをhayabusaのルートフォルダから実行してください。

# 使用方法
## コマンドラインオプション
```bash
USAGE:
    -d --directory=[DIRECTORY] 'Directory of multiple .evtx files'
    -f --filepath=[FILEPATH] 'File path to one .evtx file'
    -r --rules=[RULEDIRECTORY] 'Rule file directory (default: ./rules)'
    -o --output=[CSV_TIMELINE] 'Save the timeline in CSV format. Example: results.csv'
    -v --verbose 'Output verbose information'
    -D --enable-deprecated-rules 'Enable sigma rules marked as deprecated'
    -n --enable-noisy-rules 'Enable rules marked as noisy'
    -m --min-level=[LEVEL] 'Minimum level for rules (default: informational)'
    --start-timeline=[STARTTIMELINE] 'Start time of the event to load from event file. Example: '2018/11/28 12:00:00 +09:00''
    --end-timeline=[ENDTIMELINE] 'End time of the event to load from event file. Example: '2018/11/28 12:00:00 +09:00''
    --rfc-2822 'Output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600'
    --rfc-3339 'Output date and time in RFC 3339 format. Example: 2006-08-07T12:34:56.485214 -06:00'
    -u --utc 'Output time in UTC format (default: local time)'
    -t --thread-number=[NUMBER] 'Thread number (default: optimal number for performance)'
    -s --statistics 'Prints statistics of event IDs'
    -q --quiet 'Quiet mode. Do not display the launch banner'
    --contributors 'Prints the list of contributors'
```

## 使用例
* 1 つのWindowsイベントログファイルに対してHayabusaを実行します:
```bash
hayabusa.exe -f eventlog.evtx
```

* 複数のWindowsイベントログファイルのあるsample-evtxディレクトリに対して、Hayabusaを実行します:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx
```

* 1 つのCSVファイルにエクスポートして、EXCELやTimeline Explorerでさらに分析することができます:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -o results.csv
```

* Hayabusaルールのみを実行します（デフォルトでは `-r .\rules` にあるすべてのルールが利用されます）:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv
```

* Windowsでデフォルトで有効になっているログに対してのみ、Hayabusaルールを実行します:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa\default -o results.csv
```

* Sysmonログに対してのみHayabusaルールを実行します:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv
```

* Sigmaルールのみを実行します:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv
```

* 廃棄(deprecated)されたルール(`status`が`deprecated`になっているルール)とノイジールール(`.\config\noisy-rules.txt`にルールIDが書かれているルール)を有効にします:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx --enable-deprecated-rules --enable-noisy-rules -o results.csv
```

* ログオン情報を分析するルールのみを実行し、UTCタイムゾーンで出力します:
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -r ./rules/Hayabusa/default/events/Security/Logons -u -o results.csv
```

* 起動中のWindows端末上で実行し（Administrator権限が必要）、アラート（悪意のある可能性のある動作）のみを検知します:
```bash
hayabusa.exe -d C:\Windows\System32\winevt\Logs -m low
```

* イベントIDの統計情報を取得します:
```bash
hayabusa.exe -f Security.evtx -s
```

* 詳細なメッセージを出力します(処理に時間がかかるファイル等を特定するのに便利):
```bash
hayabusa.exe -d .\hayabusa-sample-evtx -v
```

* Verbose出力の例:
```bash
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1027.004_Obfuscated Files or Information\u{a0}Compile After Delivery/sysmon.evtx"
1 / 509 [>-------------------------------------------------------------------------------------------------------------------------------------------] 0.20 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1558.004_Steal or Forge Kerberos Tickets AS-REP Roasting/Security.evtx"
2 / 509 [>-------------------------------------------------------------------------------------------------------------------------------------------] 0.39 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1558.003_Steal or Forge Kerberos Tickets\u{a0}Kerberoasting/Security.evtx"
3 / 509 [>-------------------------------------------------------------------------------------------------------------------------------------------] 0.59 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1197_BITS Jobs/Windows-BitsClient.evtx"
4 / 509 [=>------------------------------------------------------------------------------------------------------------------------------------------] 0.79 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1218.004_Signed Binary Proxy Execution\u{a0}InstallUtil/sysmon.evtx"
5 / 509 [=>------------------------------------------------------------------------------------------------------------------------------------------] 0.98 % 1s
```

# Hayabusaの出力
Hayabusaの出力を画面に表示しているとき（デフォルト）は、以下の情報を表示します:

* `Timestamp`: デフォルトでは`YYYY-MM-DD HH:mm:ss.sss +hh:mm`形式になっています。イベントログの`<Event><System><TimeCreated SystemTime>`フィールドから来ています。デフォルトのタイムゾーンはローカルのタイムゾーンになりますが、`--utc` オプションで UTC に変更することができます。
* `Computer`: イベントログの`<Event><System><Computer>`フィールドから来ています。
* `Event ID`: イベントログの`<Event><System><EventID>`フィールドから来ています。
* `Level`: YML検知ルールの`level`フィールドから来ています。(例：`informational`, `low`, `medium`, `high`, `critical`) デフォルトでは、すべてのレベルのアラートとイベントが出力されますが、`-m`オプションで最低のレベルを指定することができます。例えば`-m high`オプションを付けると、`high`と`critical`アラートしか出力されません。
* `Title`: YML検知ルールの`title`フィールドから来ています。
* `Details`: YML検知ルールの`output`フィールドから来ていますが、このフィールドはHayabusaルールにしかありません。このフィールドはアラートとイベントに関する追加情報を提供し、ログの`<Event><System><EventData>`部分から有用なデータを抽出することができます。

CSVファイルとして保存する場合、以下の2つのフィールドが追加されます:
* `Rule Path`: アラートまたはイベントを生成した検知ルールへのパス。
* `File Path`: アラートまたはイベントを起こしたevtxファイルへのパス。

## プログレスバー
プログレス・バーは、複数のevtxファイルに対してのみ機能します。
解析したevtxファイルの数と割合をリアルタイムで表示します。

# Hayabusa ルール
Hayabusa検知ルールはSigmaのようなYML形式で記述されています。`rules`ディレクトリに入っていますが、将来的人[https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)のレポジトリで管理する予定なので、ルールのissueとpull requestはhayabusaのレポジトリではなく、ルールレポジトリへお願いします。

ルールの作成方法については、[AboutRuleCreation-Japanase.md](./doc/AboutRuleCreation-Japanase.md) をお読みください。

[hayabusa-rulesレポジトリ](https://github.com/Yamato-Security/hayabusa-rules)にあるすべてのルールは、`rules`フォルダに配置する必要があります。

情報レベルのルールは `events` とみなされ、`level`が`low` 以上のものは `alerts` とみなされます。

Hayabusaルールのディレクトリ構造は、3つのディレクトリに分かれています。
 * `default`: Windows OSでデフォルトで記録されるログ
 * `non-default`: グループポリシーやセキュリティベースラインの適用でオンにする必要があるログ
 * `sysmon`: [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)によって生成されるログ。
 * `testing`: 現在テストしているルールを配置するための一時ディレクトリ

ルールはさらにログタイプ（例：Security、Systemなど）によってディレクトリに分けられ、次の形式で名前が付けられます。
 * アラート形式: `<イベントID>_<MITRE ATT&CKの攻撃手法名>_<詳細>.yml`
 * アラート例: `1102_IndicatorRemovalOnHost-ClearWindowsEventLogs_SecurityLogCleared.yml`
 * イベント形式: `<イベントID>_<詳細>.yml`
 * イベント例: `4776_NTLM-LogonToLocalAccount.yml`

現在のルールをご確認いただき、新規作成時のテンプレートとして、また検知ロジックの確認用としてご利用ください。

## Hayabusa v.s. 変換されたSigmaルール
Sigmaルールは、最初にHayabusaルール形式に変換する必要があります。変換のやり方は[ここ](https://github.com/Yamato-Security/Hayabusa/blob/main/tools/Sigmac/README-Japanese.md)で説明されています。Hayabusaルールは、Windowsのイベントログ解析専用に設計されており、以下のような利点があります:
1. ログの有用なフィールドのみから抽出された追加情報を表示するための `output` フィールドを追加しています。
2. Hayabusaルールはすべてサンプルログに対してテストされ、検知することが確認されています。
   > 変換処理のバグ、サポートされていない機能、実装の違い(正規表現など)により、一部のSigmaルールは意図したとおりに動作しない可能性があります。
   
**制限事項**: 私たちの知る限り、Hayabusa はオープンソースの Windows イベントログ解析ツールの中でSigmaルールを最も多くサポートしていますが、まだサポートされていないルールもあります。
1. [Rust正規表現クレート](https://docs.rs/regex/1.5.4/regex/)では機能しない正規表現を使用するルール。
2. [Sigmaルール仕様](https://github.com/SigmaHQ/Sigma/wiki/Specification)の`count`以外の集計式。

> 注意：この制限はSigmaルールの変換ツールにあり、Hayabusa自身にあるわけではありません。

## 検知ルールのチューニング
ファイアウォールやIDSと同様に、シグネチャベースのツールは、環境に合わせて調整が必要になるため、特定のルールを永続的または一時的に除外する必要がある場合があります。

ルールID(例: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) を `config/exclude-rules.txt`に追加すると、不要なルールや利用できないルールを無視することができます。

ルールIDを `config/noisy-rules.txt`に追加して、デフォルトでルールを無視することもできますが、` -n`または `--enable-noisy-rules`オプションを指定してルールを使用することもできます。

## イベントIDフィルタリング
`config/target_eventids.txt`にイベントID番号を追加することで、イベントIDでフィルタリングすることができます。
これはパフォーマンスを向上させるので、特定のIDだけを検索したい場合に推奨されます。

すべてのルールの`EventID`フィールドと実際のスキャン結果で見られるIDから作成したIDフィルタリストのサンプルを`config/target_eventids_sample.txt`で提供しています。

最高のパフォーマンスを得たい場合はこのリストを使用してください。ただし、誤検出の可能性が若干あることにご注意ください。

# その他のWindowsイベントログ解析ツールおよび関連プロジェクト
「すべてを統治する1つのツール」というものはなく、それぞれにメリットがあるため、これらの他の優れたツールやプロジェクトをチェックして、どれが気に入ったかを確認することをお勧めします。

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Pythonで開発された攻撃検知ツール。
- [Chainsaw](https://github.com/countercept/chainsaw) - Rustで開発された同様のSigmaベースの攻撃検知ツール。
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - [Eric Conrad](https://twitter.com/eric_conrad) によってPowershellで開発された攻撃検知ツール。
- [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Elastic StackにEvtxデータを送信するPythonツール。
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - [SBousseaden](https://twitter.com/SBousseaden) によるEVTX攻撃サンプルイベントログファイル。
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - ATT&CKにマッピングされたEVTX攻撃サンプルログのもう一つの素晴らしいレポジトリ。
- [EVTX parser](https://github.com/omerbenamram/evtx) - [@OBenamram](https://twitter.com/obenamram) によって書かれた、私たちが使用したRustライブラリ。.
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - [JPCERTCC](https://twitter.com/jpcert_en) による、横方向の動きを検知するためにログオンを視覚化するグラフィカルなインターフェースです。
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - 大和セキュリティによるDeepBlueCLIのRust版。
- [Sigma](https://github.com/SigmaHQ/Sigma) - コミュニティベースの汎用SIEMルール。
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtxファイルをSecurityOnionにインポートします。
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) による最高のCSVタイムラインアナライザーです。
- [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - Forward DefenseのSteve Ansonによるものです。
- [Zircolite](https://github.com/wagga40/Zircolite) - Pythonで書かれたSigmaベースの攻撃検知ツール。

## Sigmaをサポートする他の類似ツールとの比較
対象となるサンプルデータ、コマンドラインオプション、ルールのチューニング等によって結果が異なるため、完全な比較はできませんが、ご了承ください。
我々のテストでは、Hayabusaはすべてのツールの中で最も多くのSigmaルールをサポートしながらも、非常に高速な速度を維持し、大量のメモリを必要としないことが分かっています。

以下のベンチマークは、2021/12/19に [sample-evtx repository](https://github.com/Yamato-Security/Hayabusa-sample-evtx) から約500個のevtxファイル（130MB）を基に、Lenovo P51で計測したものです。

| | 経過時間 | メモリ使用量 | 利用可能のSigmaルール数 |
| :---: | :---: | :---: | :---: |
| Chainsaw | 7.5 seconds | 70 MB | 170 |
| Hayabusa | 7.5 seconds | 340 MB | 267 |
| Zircolite | 34 seconds | 380 MB (通常、ログファイルの3倍のサイズが必要) | 237 |

* Hayabusaルールも有効にすると、約300のユニークなアラートとイベントを検知します。
* 合計7.5GBの多数のイベントログファイルでテストしたところ、7分以内に終了し、1GB以上のメモリを使用しませんでした。
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md)などのツールで解析するために、結果を1つのCSVタイムラインにまとめる唯一のツールです。

# ライセンス

Hayabusaは[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)で公開され、すべてのルールは[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)で公開されています。

# 貢献

どのような形でも構いませんので、ご協力をお願いします。プルリクエスト、ルール作成、evtxログのサンプルなどがベストですが、機能リクエスト、バグの通知なども大歓迎です。

少なくとも、私たちのツールを気に入っていただけたなら、Githubで星を付けて、あなたのサポートを表明してください。
