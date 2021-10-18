# Lagotto
Aiming to be the world's greatest Windows event log analysis tool!

世界一のWindowsイベントログ解析ツールを目指しています！


# Platforms
* Windows
* Linux
* macOS

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

# Configuration File
## config\eventkey_alias.txt

## regexes.txt
ルールファイルのregexというキーワードに指定するファイルのサンプルです。
regexes.txtの1行目はヘッダであり、2行目以降に正規表現を記載します。
記載された正規表現のいずれかひとつにマッチする場合、一致したものとして処理されます。

regexesキーワードは下記のように使用します。
下記の例では、regexes.txtに記載された正規表現の内ひとつでもImagePathの値に一致していた場合、ImagePathは一致したものとして処理されます。
``````
detection:
    selection_img:
        Channel: Security
        EventID: 7045
        ImagePath:
            regexes: ./regexes.txt
``````

上記の例では組み込みで用意されているregexes.txtを参照していますが、ユーザーが独自に作成したファイルを指定することも可能です。

## whitelist.txt
ルールファイルのwhitelistというキーワードに指定するファイルであり、一部の組み込みのルールファイル(rulesフォルダに設置されているファイル)が参照しています。
whitelist.txtのフォーマットは、1行目はヘッダであり、2行目以降に正規表現を記載します。
記載された正規表現のいずれかひとつにマッチする場合、一致してないものとして処理されます。

whiltelistキーワードは下記のように使用します。
下記の例では、whitelist.txtに記載された正規表現の内ひとつでもImagePathの値に一致していた場合、ImagePathは一致していないものとして処理されます。
``````
detection:
    selection_img:
        Channel: Security
        EventID: 7045
        ImagePath:
            whitelist: ./whitelist.txt
``````

上記の例では組み込みで用意されているwhitelist.txtを参照していますが、ユーザーが独自に作成したファイルを指定することも可能です。


# How to compile from source files
下記のコマンドでビルドできます。

````
cargo build
````