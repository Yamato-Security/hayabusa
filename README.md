# Lagotto
Aiming to be the world's greatest Windows event log analysis tool!

世界一のWindowsイベントログ解析ツールを目指しています！


# Platforms
Lagottoは下記のプラットフォーム上で実行できます。
* Windows
* Linux
* macOS

# Downloads
[Releases](https://github.com/Yamato-Security/YamatoEventAnalyzer/releases)からコンパイル済みの実行ファイルをダウンロードできます。

# Usage
## Commnad line option
````
USAGE:
    lagotto.exe [FLAGS] [OPTIONS]

FLAGS:
        --credits       Prints credits
    -h, --help          Prints help information
        --rfc-2822      Output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600
        --slack         Slack notification
    -s, --statistics    Prints statistics for event logs
    -u, --utc           Output time in UTC format(default: local time)
    -V, --version       Prints version information

OPTIONS:
        --csv-timeline <CSV_TIMELINE>                          Csv output timeline
    -d, --directory <DIRECTORY>                                Event log files directory
    -f, --filepath <FILEPATH>                                  Event file path
        --human-readable-timeline <HUMAN_READABLE_TIMELINE>    Human readable timeline
    -l, --lang <LANG>                                          Output language
    -t, --threadnum <NUM>                                      Thread number
````

## Usage examples
* Windowsイベントログを一つ指定する
````
lagotto.exe --filepath=eventlog.evtx
````

* Windowsイベントログが格納されているフォルダを指定する
````
lagotto.exe --directory=.\evtx
````

* 結果をCSVファイルに出力する。
````
lagotto.exe --directory=.\evtx --csv-timeline lagotto.csv
````

# Rule files
LagottoではWindowsEventログを検知するルールをYAML形式で定義します。

ルールの記載方法については[RULEFILE.md](./doc/RULEFILE.md)を参照してください。

ルールファイルはrulesフォルダ内に設置します。
rulesフォルダには組み込みルールファイルも設置されていますので、参考にしてください。

# How to compile from source files
下記のコマンドでビルドできます。

````
cargo build
````

# How to notify to Slack channel

Slackチャンネルへの通知にはSlackでのWEBHOOKURLの設定と実行マシンの環境変数(WEBHOOKURL、CHANNEL)への追加が必要です。

1. 通知先のSlackのワークスペースに対して「Incoming Webhook」をSlackに追加してください。
2. 「チャンネルへの投稿」で投稿するチャンネルを選択し 「Incoming Webhookインテグレーションの追加」をクリックします。
3. 遷移後のぺージの「Webhook URL」の内容(https:hooks.slack.com/services/xxx...)を環境変数の`WEBHOOK_URL` に代入してください。
4. 投入するchannelを#付きで環境変数の`CHANNEL`に代入してください。
5. 以下のコマンドで実行をするとCHANNELで指定したチャンネルに検知情報の通知が送付されます。

````
lagotto.exe --slack
````
