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

ルールの記載方法については[RULEFILE.md](./RULEFILE.md)を参照してください。

ルールファイルはrulesフォルダ内に設置します。
rulesフォルダには組み込みルールファイルも設置されていますので、参考にしてください。

# How to compile from source files
下記のコマンドでビルドできます。

````
cargo build
````