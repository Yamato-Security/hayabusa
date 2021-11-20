<div align="center">
 <p>

  ![Hayabusa Logo](hayabusa-logo.png)
 </p>
</div>

# Hayabusa
Hayabusaは非常に高速なWindowsイベントアナライザで、フォレンジックタイムラインの作成や、HayabusaまたはSIGMAルールで記述されたIoCに基づいた脅威のハンティングを行うために使用されます。ライブでもオフラインでも実行でき、インシデント後に企業内のエンドポイントで実行されるエージェントとしてプッシュアウトすることもできます。

# Hayabusaについて
Hayabusaは日本のYamato Securityグループによって書かれました。最初にDeepblueCLI Windowsイベントログアナライザに触発され、2020年にRustyBlueプロジェクトのためにRustに移植することから始まり、SIGMAのようなYAMLベースの柔軟なシグネチャを作成し、SIGMAのルールをhayabusaのルールに変換することをサポートするためにSIGMAにバックエンドを追加しました。マルチスレッドをサポートし、（我々の知る限り）現在最速のフォレンジックタイムラインジェネレータと脅威探索ツールであり、SIGMAの最も多くの機能をサポートしています。複数のWindowsイベントログを分析し、分析しやすいように結果を一つのタイムラインに集約することができます。また、CSV形式で出力されるので、Timeline ExplorerやExcelなどのツールに取り込んで分析することができます。

# スクリーンショット
screenshotを入れる

# 機能
* 複数のOSに対応: Windows, Linux, macOS (Intel + ARM)
* ハヤブサよりも速い！
* 英語と日本語に対応
* マルチスレッド
* フォレンジック調査用のイベントタイムライン作成
* 作成・編集しやすいYAML形式のhayabusaルールでIoCシグネチャーを作成し、攻撃検知(スレットハンティング)を行う
* SIGMAルールをhayabusaルールに自動変換
* イベントログの集計(どのようなイベントがあるかを把握するためやログ設定のチューニングに便利)

# ダウンロード
[Releases](https://github.com/Yamato-Security/hayabusa/releases)からコンパイル済みの実行ファイルをダウンロードできます。

# 使い方
## コマンドラインオプション
````
USAGE:
    hayabusa.exe [FLAGS] [OPTIONS]

FLAGS:
        --credits       コントリビューターの一覧表示
    -h, --help          ヘルプ画面の表示
        --rfc-2822      日付と時間をRFC 2822形式で表示する。例： Mon, 07 Aug 2006 12:34:56 -0600
    -s, --statistics    イベントログの集計
    -u, --utc           時間をUTCで出力する（デフォルトはローカル時間）
    -V, --version       バージョン情報を出力する

OPTIONS:
        --csv-timeline <CSV_TIMELINE>                          タイムラインをCSVに保存する
    -d, --directory <DIRECTORY>                                イベントログファイルが入っているディレクトリ
    -f, --filepath <FILEPATH>                                  イベントファイルのパス
        --human-readable-timeline <HUMAN_READABLE_TIMELINE>    読みやすいタイミングを出力
    -l, --lang <LANG>                                          出力する言語
    -t, --threadnum <NUM>                                      スレッド数（デフォルトではCPUコア数）
````

## 使い方の例
* Windowsイベントログを一つ指定する:
````
hayabusa.exe --filepath=eventlog.evtx
````

* Windowsイベントログが格納されているフォルダを指定する:
````
hayabusa.exe --directory=.\evtx
````

* 結果をCSVファイルに出力する:
````
hayabusa.exe --directory=.\evtx --csv-timeline kekka.csv
````

# ルールファイル
HayabusaではWindowsEventログを検知するルールをYAML形式で定義します。

ルールの記載方法については[AboutRuleCreation-Japanese.md](./doc/AboutRuleCreation-Japanese.md)を参照してください。

ルールファイルはrulesフォルダ内に設置します。
rulesフォルダには組み込みルールファイルも設置されていますので、参考にしてください。

# ソースコードからのコンパイル
下記のコマンドでビルドできます。

````
cargo build --release
````

# 関連するWindowsイベントログのスレットハンティングプロジェクト
まだ完璧なWindowsイベントログ解析ツールは存在していなくて、それぞれ長所短所があるので、以下のツールとプロジェクトもチェックして、好きなツールを使ってくださいね！

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Pythonで書かれた攻撃検知ツール。
- [Chainsaw](https://github.com/countercept/chainsaw)　- 他のRustで書かれたSIGMAベースの攻撃検知ツール。
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) Powershellで書かれた攻撃検知ツール。
- [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - EvtxデータをElastic Stackにインポートするツール。
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - 攻撃の痕跡が入っているEVTXサンプルファイルのリポジトリ。作者：[SBousseaden](https://twitter.com/SBousseaden)。
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - もう一つの素晴らしい攻撃の痕跡が入っているEVTXサンプルファイルのリポジトリ。攻撃はMITE ATT&CKにマッピングされている。
- [EVTXパーサ](https://github.com/omerbenamram/evtx) - Hayabusaが使っているRustライブラリ。作者：[@OBenamram](https://twitter.com/obenamram)。
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - 横展開を検知するためのEVTX可視化ツール。作者：[JPCERTCC](https://twitter.com/jpcert)。
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - DeepBlueCLIをRustに書き換えたツール。
- [SIGMA](SIGMA: https://github.com/SigmaHQ/sigma) - SIEM等のジェネリックな攻撃検知ルール。
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtxファイルをSecurity Onionにインポートするコマンド。
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - CSV形式のタイムラインの最高な解析ツール。作者：[Eric Zimmerman](https://twitter.com/ericrzimmerman)。
- [Zircolite](https://github.com/wagga40/Zircolite) - Pythonで書かれたSIGMAベースの攻撃検知ツール。

## ライセンス

HayabusaのライセンスはGPLv3で、ルールはすべてDetection Rule License (DRL) 1.1でリリースしています。

## 貢献

コントリビューターは大募集中です！プルリクエストやルール作成が一番ですが、機能リクエストやバグのお知らせなども大歓迎です。

hayabusaを気に入って頂けたら、Githubで星をつけて応援してくださいね！