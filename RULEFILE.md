# ルールファイル
LagottoはWindowsEventログの検知ルールをファイルにYAML形式のファイルに記載します。
単なる文字列一致だけでなく、正規表現やANDやOR等の条件を組み合わせることができ、複雑な検知ルールも表現できるようになっています。
ここではその検知ルールの書き方について説明します。

# ルールファイルのフォーマット
ルールファイルのフォーマットは下記の通りです。
``````
title: PowerShell Execution Pipeline
description: This rule detect powershell execution pipeline.
author: Zach Mathis
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
falsepositives:
    - unknown
output: 'command=%CommandLine%'
creation_date: 2020/11/8
updated_date: 2020/11/8
``````

* title [required]: ルールファイルのタイトルを入力します。
* description [optional]: ルールファイルの説明を入力します。
* author [optional]: ルールファイルの作者を入力します。
* detection  [required]: 検知ルールを入力します。
* falsepositives [optional]: 誤検知に関する情報を入力します。
* output [required]: イベントログが検知した場合に表示されるメッセージを入力します。
* creation_date [optional]: ルールファイルの作成日を入力します。
* updated_date [optional]: ルールファイルの更新日を入力します。

# detectionの記法について
## detectionの基本
まず、下記の例を用いて、detectionの基本的な書き方について説明します。
``````
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
``````

### AND条件とOR条件の書き方
上記のようにdetectionを記載すると、Lagottoは以下両方の条件を満たすイベントログを検知します。
* EventIDが`7040`に完全一致する
* Channelが`System`に完全一致する

今回の例のようにAND条件を記載する場合はYAMLのハッシュを用いて記載します。OR条件を記載する場合は配列を利用します。

``````
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
``````

また、複数のEventIDをOR条件でつなげたい場合は、下記のように記載します。
``````
detection:
    selection:
        Event.System.EventID: 
          - 7040
          - 7041
        Event.System.Channel: System
``````

### eventkeyについて
WindowsイベントログをXML形式で一部抜粋で出力すると、下記のようになります。ルールファイルの例に含まれる`Event.System.Channel`というのは、XMLの`<Event><System><Channel>System<Channel><System></Event>`を指しています。今回の例のように、XML形式のWindowsイベントログについて、入れ子になったXMLのタグに含まれる値をルールの条件に指定する場合、`.`でつなげて指定します。ルールファイルでは、この`.`でつなげた文字列をeventkeyと読んでいます。

``````
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>自動的な開始</Data>
    </EventData>
</Event>
``````

### eventkeyのaliasについて
`.`でつなげたeventkeyは長い文字列になってしまうことがあるため、Lagottoではeventkeyに対するエイリアスを使用できます。エイリアスは`config\eventkey_alias.txt`というファイルに定義されています。ファイルはCSV形式であり、aliasとevent_keyという列から構成されています。aliasにはエイリアスを定義し、event_keyには`.`でつなげたeventkeyを指定します。このエイリアスを用いると、最初に例に挙げたdetectionは以下のように書き換えることができます。

``````
detection:
    selection:
        EventID: 7040
        Channel: System
``````

## パイプについて
eventkeyにはパイプを指定することができます。ここまで説明した書き方では完全一致しか表現できましたんでしが、パイプを使うことでより柔軟な検知ルールを記載できるようになります。下記の例ではCommandLineの値が`yamato.*lagotto`という正規表現にマッチする場合、条件に一致したものとして処理されます。
``````
detection:
    selection:
        EventID: 7040
        Channel: System
        CommandLine|re: yamato.*lagotto
``````

使用できるパイプの一覧です。なお、v1.0.0時点では、複数のパイプをつなげて使用することはできません。
* startswith: 先頭一致
* endswith: 後方一致
* contains: 部分一致
* re: 正規表現(正規表現の処理にはregexクレートを使用しています。正規表現の詳細記法についてはhttps://docs.rs/regex/1.5.4/regex/を参照してください。)

## ワイルドカードについて
eventkeyに対する値にはワイルドカードを指定することができます。下記の例ではCommandLineがlagottoという文字列で始まっていれば、条件に一致したものとして処理されます。
``````
detection:
    selection:
        EventID: 7040
        Channel: System
        CommandLine: lagotto*
``````

使用できるワイルドカードの一覧です。
* `*`: 任意の0文字以上の文字列にマッチします。(内部的には`.*`という正規表現に変換されます。)
* `?`: 任意の1文字にマッチします。(内部的には`.`という正規表現に変換されます。)

ワイルドカードを使用する場合、下記のルールに則って解釈されます。
* ワイルドカード(`*`と`?`)をエスケープするにはバックスラッシュ(`/`)を使用します。
* ワイルドカードの直前に文字としてのバックスラッシュ(`/`)を使用する場合、`\\*`又は`\\?`と記載してください。
* バックスラッシュを単体で使う分にはエスケープ不要です。

## eventkeyにネストできるキーワード
eventkeyには特定のキーワードをネストさせることができます。下記の例ではCommandLineの値が`aa*bb`というワイルドカードにマッチした上で文字列長が10以上である場合、条件に一致したものと処理されます。
``````
detection:
    selection:
        EventID: 7040
        Channel: System
        CommandLine:
            value: aa*bb
            min_length: 10
``````

現状では下記のキーワードを指定できます。
* value: 文字列による一致(ワイルドカードやパイプを指定することもできます)
* min_length: 指定した文字数以上である場合、条件に一致したものとして処理されます。
* regexes: 指定したファイルに記載された正規表現のリストにひとつでも一致すれば、`条件に一致した`ものとして処理されます。
* whitelist: 指定したファイルに記載された正規表現のリストにひとつでも一致すれば、`条件に一致していない`ものとして処理されます。

### regexes.txtとwhitelist.txt
lagottoではregexesやwhitelistを使用した組み込みのルールを用意しており、それらのルールはregexes.txtとwhitelist.txtを参照しています。regexes.txtとwhitelist.txtを書き換えることで、参照する全てのルールの挙動を一度に変更することが可能です。

また、regexesやwhitelistに指定するファイルは、ユーザーが独自に作成することも可能です。作成する場合、regexes.txtとwhitelist.txtを参考にしてください。

## condition
これまでの記法を用いると、AND条件やOR条件を表現することができますが、ANDやOR等が複雑に入り組んだ条件を定義することは難しい場合があります。その場合、conditionというキーワードを使用することで、複雑な条件式を定義することができます。

``````
detection:
    selection_1:
        EventID: 7040
    selection_2:
        EventID: 7041
    selection_3:
        Channel: System
    selection_4:
        CommandLine: lsass.exe
    selection_5:
        CommandLine: svchost.exe
    condition: ( selection_1 or selection_2 ) and selection_3 and ( not ( selection_4 or selection_5 ) )
``````

conditionには以下のキーワードを使用することができます。
* and: and条件を表します。
* or: or条件を表します。
* not: 条件を否定します。
* ( {selection_name} ) : {selection_name}の真偽を逆転させます。

なお、上記の例では、条件式をグルーピングするためにselection_1やselection_2といった名前を使用していますが、selectionというprefixを付ける必要はなく、ユーザーが任意の名前を定義できます。ただし、使用可能な文字は`\w`という正規表現にマッチする文字のみです。

## aggregation condition
上記で説明したconditionには、andやor条件だけでなく、検知したイベントログを集計するような機能も実装されています。この機能をaggregation conditionと呼んでおり、conditionの後にパイプでつなげて指定します。下記の例では、DestinationIpの値が3種類以上あるかどうかをSubjectUserName毎に判定する条件式になります。

``````
detection:
    selection:
        EventID: 7040
        Channel: System
    condition: selection | count(DestinationIp) by SubjectUserName >= 3
``````

aggregation conditionは下記の形式で定義できます。なお、{number}には数値を指定します。
* `count() {operator} {number}`: conditionのパイプ以前の条件に一致したログについて、{operator}と{number}で指定した条件式を満たす場合に、条件に一致したものとして処理されます。
* `count({eventkey}) {operator} {number}`: conditionのパイプ以前の条件に一致したログについて、{eventkey}の値が何種類存在するか数えます。その数が{operator}と{number}で指定した条件式を満たす場合に、条件に一致したものとして処理されます。
* `count({eventkey_1}) by {eventkey_2} {operator} {number}`: conditionのパイプ以前の条件に一致したログを{eventkey_2}毎にグルーピングし、そのグループ毎に{eventkey_1}の値が何種類存在するか数えます。そのグルーピング毎に数えた値が{operator}と{number}で指定した条件式を満たす場合に、条件に一致したものとして処理されます。

また、上記のoperatorには下記を指定できます。
* `==`: 指定された値と等しい場合、条件に一致したものと処理されます。
* `>=`: 指定された値以上である場合、条件に一致したものと処理されます。
* `>`: 指定された値より大きい場合、条件に一致したものと処理されます。
* `<=`: 指定された値以下である場合、条件に一致したものと処理されます。
* `<`: 指定された値より小さい場合、条件に一致したものと処理されます。