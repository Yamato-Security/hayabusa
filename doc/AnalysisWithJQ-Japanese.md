# Hayabusaの結果をjqで分析する

# 目次

- [Hayabusaの結果をjqで分析する](#hayabusaの結果をjqで分析する)
- [目次](#目次)
- [著者](#著者)
- [翻訳者](#翻訳者)
- [この文書について](#この文書について)
- [jqのインストール](#jqのインストール)
- [JSON形式について](#json形式について)
- [HayabusaのJSON/JSONL形式について](#hayabusaのjsonjsonl形式について)
- [JSON結果ファイルの作成](#json結果ファイルの作成)
  - [AllFieldInfoではなくDetailsを使う利点](#allfieldinfoではなくdetailsを使う利点)
- [jqレッスン/レシピ](#jqレッスンレシピ)
  - [1. jqとlessのカラーモードによる手動チェック](#1-jqとlessのカラーモードによる手動チェック)
  - [2. 集計](#2-集計)
  - [3. 特定データのフィルタリング](#3-特定データのフィルタリング)
  - [4. 出力をCSV形式で保存する](#4-出力をcsv形式で保存する)
  - [5. アラートがもっとも多い日付の検索](#5-アラートがもっとも多い日付の検索)
  - [6. PowerShellログの再構築](#6-powershellログの再構築)
  - [7. 疑わしいネットワーク接続の検出](#7-疑わしいネットワーク接続の検出)
  - [8. 実行可能なバイナリのハッシュ値の抽出](#8-実行可能なバイナリのハッシュ値の抽出)
  - [9. PowerShellログの抽出](#9-powershellログの抽出)

# 著者

田中ザック ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# 翻訳者

Fukusuke Takahashi (@fukusuket)

# この文書について

ログ内の重要なフィールドを特定、抽出、集計ができることは、DFIRおよび脅威ハンティングアナリストにとって不可欠なスキルです。
Hayabusaは、通常`.csv`形式で結果を保存します。これはExcelやTimeline Explorerなどのプログラムにインポートし、タイムラインを分析するためです。
ただし、同じイベントが数百件以上ある場合、それらを手動で確認することは非現実的または不可能です。
このような状況では、アナリストは通常​​、類似したタイプのデータを並べ替えてカウントし、外れ値を探します。
この手法は、ロングテール分析、スタックランキング、頻度分析などとも呼ばれます。
Hayabusaでは、結果を`.json` または `.jsonl` で出力し、`jq`を使うことで、これらの分析を実現できます。

たとえば、アナリストは、組織内のすべてのワークステーションにインストールされているサービスを比較できます。
特定のマルウェアがすべてのワークステーションにインストールされる可能性はありますが、少数のシステムにしか存在しない可能性は高いです。
この場合、すべてのシステムにインストールされているサービスは無害である可能性が高く、まれなサービスは疑わしい傾向があり、定期的にチェックする必要があります。

他のユースケースでは、何がどれほど疑わしいかを判断するのに役立ちます。
たとえば、アナリストは`4625`失敗ログオンログを分析して、特定のIPアドレスがログオンに失敗した回数を判断できます。
ログオンの失敗が数回しかない場合は、管理者がパスワードを誤って入力した可能性があります。
しかし、特定のIPアドレスによるログオン失敗が短期間に数百回以上あった場合は、そのIPアドレスが悪意のあるものである可能性があります。

`jq`の使い方を学ぶことは、Windowsイベントログ分析だけでなく、すべてのJSON形式のログ分析に役立ちます。
昨今、JSONが非常に一般的なログ形式になり、ほとんどのクラウド プロバイダーがログにJSONを使用するようになりました。このため、`jq`を使用してJSONを分析できることは、現代のセキュリティアナリストにとって不可欠なスキルです。

このガイドでは、最初に`jq`を使用したことがない人のために使用方法を説明し、次に実際の例とともにより複雑な使用方法を説明します。
`jq`と他の便利なコマンド`sort`、`uniq`、 `grep`、 `sed`などを組み合わせられるよう、LinuxやmacOS、Linux on Windowsで作業することをお勧めします。

# jqのインストール

[https://stedolan.github.io/jq/](https://stedolan.github.io/jq/)を参照し、`jq`コマンドをインストールしてください。

# JSON形式について

JSONログは、中括弧 `{` `}`で囲まれたオブジェクトのリストです。
これらのオブジェクト内には、コロンで区切られたキーと値のペアがあります。
キーは文字列でなければなりませんが、値は次のいずれかになります。
  * 文字列 (Ex: `"string"`)
  * 数値 (Ex: `10`)
  * オブジェクト (Ex: `{ xxxx }`)
  * 配列 (Ex: `["string", 10]`)
  * 真偽値 (Ex: `true`, `false`)
  * `null`

オブジェクト内にオブジェクトをいくつでもネストできます。

この例は、 `Details` はルートオブジェクト内でネストされたオブジェクトです:
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

# HayabusaのJSON/JSONL形式について

以前のバージョンでは、Hayabusaはすべての`{ xxx }`ログオブジェクトを1つの巨大な配列に格納する従来のJSON形式を使用していました。

例:
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

これには2つの問題があります。
最初の問題は、配列を走査するためにすべての`jq`クエリは`.[]`ではじまる必要があり、手間がかかる点です。
さらに大きな問題は、そのようなログをパースするには、はじめに配列内のすべてのデータをロードする必要があることです。
これは、非常に大きなJSONファイルがあり、十分なメモリがない場合に問題となります。
そこで、必要なCPUとメモリの使用量を減らすために、巨大な配列にすべてを入れないJSONL(JSON Lines) 形式が一般的になりました。
HayabusaはJSONおよびJSONL形式で出力しますが、JSON形式は配列で出力されなくなりました。
唯一の違いは、JSON形式はテキスト エディターまたはコンソールで読みやすいのに対し、JSONL形式はすべてのJSONオブジェクトを1行に格納することです。
JSONL形式はわずかに高速でサイズが小さいため、ログをSIEMなどにインポートするだけで、ログを見ない場合に最適です。
一方JSON形式は手動チェックを行うときに最適です。

# JSON結果ファイルの作成

現在バージョン2.xのHayabusaでは、`hayabusa json-timeline -d <directory> -o results.json`でJSON、`hayabusa json-timeline -d <directory> -J -o results.jsonl` でJSONLに結果を保存できます。

Hayabusaはデフォルトのstandardプロファイルを使用し、分析用に最小限のデータのみをDetailsオブジェクトに保存します。
evtxログの全フィールド情報を保存する場合は、`--profile all-field-info`で`all-field-info`プロファイルを指定します。
これにより、すべてのフィールド情報が`AllFieldInfo`オブジェクトに保存されます。
念のため、`Details` と `AllFieldInfo`オブジェクトの両方を保存したい場合、`super-verbose`プロファイルを使用できます。

## AllFieldInfoではなくDetailsを使う利点

`AllFieldInfo`より`Details`を使う1つ目の利点は、重要なフィールドのみが保存され、ファイルスペースを節約するためにフィールド名が短縮されていることです。
欠点は、実際には気にしていたデータの欠落可能性があることです。
2つ目の利点は、Hayabusaがフィールド名を正規化することで、より画一的な方法でフィールドを保存できることです。
たとえば、通常元のWindowsログでは、ユーザー名は`SubjectUserName`か`TargetUserName`にあります。
しかし、ユーザー名が`AccountName`にある場合もあれば、ターゲットユーザ名が`SubjectUserName`にある場合もあります。
残念ながらWindowsイベントログには、一貫性のないフィールド名が多くあります。
Hayabusaはこれらのフィールドを正規化します。これによりアナリストは、イベントID間の無数の癖や不一致を理解する必要がなくなり、共通の名前を分析するだけで済みます。

ユーザーフィールドの例を次に示します。
Hayabusaは、`SubjectUserName`, `TargetUserName`, `AccountName`などのフィールドを以下の方法で正規化します:
  * `SrcUser` (ソースユーザー): ユーザー **から** アクションが発生したとき。（通常はリモートユーザー）
  * `TgtUser` (ターゲットユーザー): ユーザー **への** アクションが発生したとき。 (たとえば、 ユーザー **への** ログオン)
  * `User`: 現在ログインしているユーザーによってアクションが発生したとき。（アクションにとくに方向がないとき）

他の例はプロセスです。
元のWindowsイベントログでは、プロセスフィールドは複数の命名規則で参照されます:`ProcessName`、 `Image`、 `processPath`、 `Application`、 `WindowsDefenderProcessName`など。
フィールドの正規化がなければ、アナリストは、まずこれらのフィールド名の違いに精通する必要があり、またこれらのフィールドをログからすべて抽出、結合しなければなりません。

Hayabusaが提供する`Details` オブジェクト内で正規化された1つの`Proc`フィールドを使うことで、多くの時間と手間を節約できます。

# jqレッスン/レシピ

ここでは、分析に役立つかもしれない実用的ないくつかのレッスン/レシピを列挙します。

## 1. jqとlessのカラーモードによる手動チェック

これは、ログ中のフィールドを理解するため、最初に行うことの1つです。
単純に `less results.json` を実行することもできますが、より良い方法は次の通りです:
`cat results.json | jq -C | less -R`

`jq`にわたすことで、最初から適切にフォーマットされていない場合でも、すべてのフィールドが適切にフォーマットされます。
`jq`の`-C` (color)オプションと`less`の`-R` (raw-control-chars)を使用すると、カラーで上下にスクロールできます。

## 2. 集計

Hayabusaには、イベントIDに基づいてイベント数と比率を出力する機能がすでにありますが、`jq`のやり方も知っておくと便利です。
これにより、統計情報を取得するデータをカスタマイズできます。

最初に、次のコマンドを使用してイベントIDのリストを抽出しましょう:

`cat results.json | jq '.EventID'`

各ログからイベントIDだけが抽出されます。
`jq`につづけて、シングルクォーテーションで囲み、ドットと抽出したいフィールド名を入力します。
これで、次のような長いリストが出力されます:

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

この結果を`sort` と `uniq -c`コマンドにパイプして、イベントIDが発生した回数をカウントします:

`cat results.json | jq '.EventID' | sort | uniq -c`

`uniq`の`-c`オプションは、一意のイベントIDが発生した回数をカウントします。

この結果は、次のように出力されます:

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

左が件数、右がイベントIDです。
ご覧のとおり、どのイベントIDがもっとも多く発生したかを判断するのはそれほど難しくありません。

これを整えるには、`sort -n` を末尾に追加します:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

`-n`オプションは`sort`に数値で並び替えるように指示します。

この結果は、次のように出力されます:
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

`4688`(プロセス作成)イベントがもっとも多く記録されていることがわかります。
2番目に多く記録されたイベントは`4625`(ログオンの失敗)でした。

もっとも多く記録されたイベントを一番上に出力したい場合は、`sort -n -r`または`sort -nr`で並べ替え順序を逆にできます。
結果を`head -n 10`にパイプすることで、もっとも多く記録された上位10イベントを出力できます。

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

これにより、次の出力が得られます:
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

EID (イベントID) は一意でないことを考慮することが重要です。同じイベントIDでもまったく異なるイベントが発生し得えます。
そのため`Channel`も確認することが重要です。

このフィールド情報は、次のように追加できます:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

`-j`(join)オプションを`jq`に追加して、コンマで区切られ、改行文字`\n`で終わるすべてのフィールドを結合します。
これにより、次の出力が得られます:
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

注釈: `Security`は`Sec`に、 `System`は`Sys`に、`PowerShell`は`PwSh`に省略されます。

次のようにすることで、ルールタイトルも追加できます:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

これにより、次の出力が得られます:
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

ログから任意のデータを自由に抽出し、発生件数をカウントできるようになりました。


## 3. 特定データのフィルタリング

多くの場合、特定のイベントID、ユーザー、プロセス、LID (ログオンID) などでフィルター処理を行う必要があります。
これは、`jq`クエリ内の`select`で実現できます。

`4624`成功ログオンイベントをすべて抽出する例です:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

これにより、EID `4624`のすべてのJSONオブジェクトが返されます:
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

複数の条件でフィルタリングする場合は、`and`、`or`、`not`などのキーワードを使えます。

たとえば`4624`、タイプが`3`(ネットワークログオン)であるイベントを検索してみましょう。

`cat results.json | jq 'select ( (.EventID == 4624) and (.Details.Type == 3) )'`

これにより、`EventID`が`4624`かつネストされた`"Details": { "Type" }`フィールドは`3`であるすべてのオブジェクトが返されます。

しかし、この方法には問題があります。
`jq: error (at <stdin>:10636): Cannot index string with string "Type"`というエラーが出力される場合もあります。
`Cannot index string with string`エラーが出力されるときは、`jq`に存在しないフィールドの出力を指示しているか、間違ったタイプであることを意味します。
このエラーは、フィールドの末尾に`?`を追加することで取り除くことができます。
エラーを無視するには、以下のように`jq`に指示します。

例: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

特定の条件でフィルタリングした後、`jq`クエリの中で`|`を使うことで、関心のある特定のフィールドを選択できます。

たとえば、ターゲットユーザー名`TgtUser`とソースIPアドレス`SrcIP`を抽出します:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

ここでも、複数のフィールドを選択して出力するため、`jq`に`-j` (join) オプションを追加します。
その後、例のように特定IPアドレスがタイプ3ネットワークログオンでログオンした回数を探すために `sort`、 `uniq -c`などを実行できます。

## 4. 出力をCSV形式で保存する

残念ながら、Windowsイベントログのフィールドはイベント種類によって完全に異なるため、何百もの列を持たずにフィールド毎コンマ区切りのタイムラインを作成することは難しいです。
ただし、単一タイプのイベントでフィールドが分離されたタイムラインを作成することは可能です。
一般的な2つの例は、セキュリティ`4624`(ログオンの成功)と`4625`(ログオンの失敗)で、ラテラルムーブメントとパスワード類推/スプレー攻撃をチェックします。

この例では、セキュリティ`4624`ログのみを抽出し、タイムスタンプ、コンピューター名などすべての`Details`情報を出力しています。
`| @csv`を使用してCSVファイルに保存できますが、データを配列として渡す必要があります。
これはこれまでに行ったように、出力したいフィールドを`[ ]`角括弧で囲み、配列に変換することで実現できます。

例: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

注釈:
  * `Details` オブジェクトの全フィールドを選択するためには、`[]`を追加します。
  * `Details`が配列ではなく文字列の場合があり、`Cannot iterate over string` エラーを引き起こすため、`?`を追加する必要があります。
  * ダブルクォーテーションのバックスラッシュエスケープをさせないために、`jq`に`-r` (Raw output)オプションを追加します。

結果:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

誰がログオンに成功したかを確認するだけであれば、最後の`LID` (ログオンID) フィールドは必要ないかもしれません。
`del`関数を使用して、不要な列を削除できます。

例: `cat results.json | jq 'select ( (.Channel == "Sec") and (.EventID == 4624) ) | [.Timestamp, .Computer, .Details[]?] | del(.[6]) | @csv' -r`

配列は`0`からカウントされるため、7番目のフィールドを削除するには、`6`を指定します。

末尾に`> 4624-logs.csv`を追加することで、CSV形式でファイルに保存、さらに分析するためにExcelやTimeline Explorerにインポートできます。

フィルタリングを行うには、ヘッダーを追加する必要があることに注意してください。`jq`クエリでヘッダーを追加することは可能ですが、通常は、ファイルを保存した後に先頭行を手動で追加するのがもっとも簡単です。


## 5. アラートがもっとも多い日付の検索

Hayabusaはデフォルトで、重大度に応じてアラートがもっとも多かった日付を通知します。
しかし、2番目や3番目にアラートが多かった日付を探したいこともあります。
タイムスタンプの文字列をスライスし、年、月、日などを必要に応じてグループ化することでこれを実現できます。

例: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]`は`jq`に`Timestamp`の最初の10バイトを抽出するように指示しています。

これにより、イベントのもっとも多い日付が得られます:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

イベントがもっとも多い月を知りたい場合は、`.[:10]`を`.[:7]`に変更し、最初の7バイトを抽出します。

`high`アラートがもっとも多い日付を一覧表示する場合は、次のようにします:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

必要に応じて、`select`関数にコンピューター名、イベントIDなどの条件を追加していくこともできます。

## 6. PowerShellログの再構築

PowerShellログの残念な点は、複数のログに分割されることが多く、読みにくいことです。
攻撃者が実行したコマンドだけを抽出することで、ログを読みやすくできます。

たとえば、EID`4104`のスクリプトブロックログの場合、そのフィールドだけを抽出して、読みやすいタイムラインを作成できます。

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

これにより、タイムラインは次のようになります:
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

## 7. 疑わしいネットワーク接続の検出

次のコマンドを使用して、最初にすべてのターゲットIPアドレスのリストを取得できます:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

脅威インテリジェンスがある場合は、IPアドレスが悪意のあるものとして知られているかどうかを確認できます。

また、特定のターゲットIPアドレスが接続された回数を以下のようにカウントできます:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

`TgtIP` を `SrcIP` に変更することで、ソースIPアドレスに対しても、脅威インテリジェンスを用いた同様なチェックを実行できます。

ある環境から`93.184.220.29`という悪意のあるIPアドレスへ接続されていたことを発見したとします。
次のクエリを使用して、これらのイベントの詳細を取得できます:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

これにより、次のような結果のJSONが得られます:
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

通信されたドメインをリストアップしたい場合は、以下のコマンドを使用できます:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> ※ NETBIOSホスト名を削除するために、`.`のgrepフィルタが追加されています。

## 8. 実行可能なバイナリのハッシュ値の抽出

Sysmon EID `1` プロセス生成ログで、バイナリのハッシュを計算するようにsysmonを設定できます。
セキュリティアナリストは、脅威インテリジェンスを使用して、これらのハッシュを既知の悪意のあるハッシュと比較できます。
次のように `Hashes` フィールドを抽出できます:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

これにより、このようなハッシュのリストが得られます:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmonは通常、`MD5`、`SHA1`、`IMPHASH`など複数のハッシュを計算します。
これらのハッシュは、`jq` の正規表現か、より良い性能のために文字列スライスを使うことで、抽出できます。

たとえば、次のようにMD5ハッシュを抽出して重複を削除できます:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. PowerShellログの抽出

PowerShellのScriptblockログ（EID: 4104）は、通常多くのログに分割されており、CSV形式で出力する際、Hayabusaはタブやリターン文字を削除して簡潔に出力します。
しかし、PowerShellログは、本来のタブとリターン文字の書式で、ログを組み合わせて解析するのが最も簡単です。
ここでは、VSCode等で開いて分析するために、`COMPUTER-A`からPowerShell EID 4104のログを抽出して、`.txt`ファイルに保存する例を紹介します。
ScriptBlockフィールドを抽出した後、`awk`を使って`\r\n`と`\n`をリターン文字に、`\t`をタブに置き換えています。

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.txt
```

アナリストは、PowerShellログを分析して悪意のあるコマンドが無いかを確認した後、通常、これらのコマンドがいつ実行されたかを調べる必要があります。
以下は、コマンドの実行時間を調べるために、TimestampとPowerShellのコマンド履歴をCSVファイルに出力する例です:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

注：PowerShellのログにはシングルクォートやダブルクォートが多く、CSVの出力を壊してしまうため、文字列の区切りを`¦`にしています。
CSVファイルをインポートする際に、`¦`の文字列の区切りをアプリケーションに指定する必要があります。