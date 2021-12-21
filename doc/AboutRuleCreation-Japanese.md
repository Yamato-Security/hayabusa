# ルールファイル
Hayabusaの検知ルールは、[YAML](https://en.wikipedia.org/wiki/YAML) 形式で記述されています。
単純な文字列のマッチングだけでなく、正規表現や`AND`、`OR`などの条件を組み合わせて複雑な検知ルールを表現することができます。
本節では、Hayabusaの検知ルールの書き方について説明します。

# ルールファイル形式
記述例:

```yaml
#Author section
author: Eric Conrad, Zach Mathis
creation_date: 2020/11/08
updated_date: 2021/11/26

#Alert section
title: User added to local Administrators group
title_jp: ユーザがローカル管理者グループに追加された
output: 'User: %MemberName%  :  SID: %MemberSid%  :  Group: %TargetUserName%'
output_jp: 'ユーザ: %MemberName%  :  SID: %MemberSid%  :  グループ名: %TargetUserName%'
description: A user was added to the local Administrators group.
description_jp: ユーザがローカル管理者グループに追加された。

#Rule section
id: 611e2e76-a28f-4255-812c-eb8836b2f5bb
level: high
status: stable
detection:
    selection:
        Channel: Security
        EventID: 4732
        TargetUserName: Administrators
    condition: selection
falsepositives:
    - system administrator
tags:
    - attack.persistence
    - attack.t1098
references:
    - https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4732
sample-evtx: ./sample-evtx/EVTX-to-MITRE-Attack/TA0003-Persistence/T1098.xxx-Account manipulation/ID4732-User added to local admin groups.evtx
logsource: default
ruletype: Hayabusa
```

> ## 著者名欄
* **author [必須]**: 著者名（複数可）。
* **contributor** [オプション]: 寄稿者の名前（細かい修正をした人）。
* **creation_date [必須]**: ルールが作成された日付。
* **updated_date** [オプション]: ルールが更新された日付。

> ## アラートセクション
* **title [必須]**: ルールファイルのタイトル。これは表示されるアラートの名前にもなるので、簡潔であるほどよいです。(85文字以下でなければなりません。)
* **title_jp** [オプション]: 日本語のタイトルです。
* output [オプション]: 表示されるアラートの詳細です。Windowsイベントログの中で解析に有効なフィールドがあれば出力してください。フィールドは `" : "` で区切られます（両側ともスペース2つ）。フィールドのプレースホルダは `%` で囲まれ (例: `%MemberName%`) 、`config_eventkey_alias.txt` で定義する必要があります。(以下で説明します)
* **output_jp** [オプション]: 日本語の出力メッセージ。
* **description** [オプション]: ルールの説明。これは表示されないので、長く詳細に記述することができます。
* **description_jp** [オプション]: 日本語の説明文です。

> ## ルールセクション
* **id [必須]**: ルールを一意に識別するために使用される、ランダムに生成されたバージョン4のUUIDです。 [ここ](https://www.uuidgenerator.net/version4) で生成することができます。
* **level [必須]**: [sigmaルールの定義](https://github.com/SigmaHQ/sigma/wiki/Specification)に基づく重要度レベル。 以下のいずれかを記述してください。 `informational`,`low`,`medium`,`high`,`critical`
* **status[必須]**: テスト済みのルールには `stable` を、テストが必要なルールには `testing` を指定します。
* **detection  [必須]**: 検知ロジックはここに入ります。(以下で説明します。)
* **falsepositives [必須]**: 誤検知の可能性について記載を行います。例: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`。 不明な場合は `unknown` と記述してください。
* **tags** [オプション]: もしその技術が[LOLBINS/LOLBAS](https://lolbas-project.github.io/)の技術であれば、`lolbas` タグを追加してください。アラートを[MITRE ATT&CK](https://attack.mitre.org/) フレームワークにマッピングできる場合は、戦術ID（例：`attack.t1098`）や以下に該当する戦術を追加してください。
    * `attack.impact` -> Impact
    * `attack.initial_access` -> Initial Access
    * `attack.execution` -> Execution
    * `attack.lateral_movement` -> Lateral Movement
    * `attack.persistence` -> Persistence
    * `attack.privilege_escalation` -> Privilege Escalation
    * `attack.reconnaissance` -> Reconnaissance
    * `attack.collection` -> Collection
    * `attack.command_and_control` -> Command and Control
    * `attack.credential_access` -> Credential Access
    * `attack.defense_evasion` -> Defense Evasion
    * `attack.discovery` -> Discovery
    * `attack.exfiltration` -> Exfiltration
    * `attack.resource_development` -> Resource Development 
* **references** [オプション]: 参考文献への任意のリンク。
* **sample-evtx [必須]**: このルールが検知するイベントログファイルへのファイルパスまたはURL。
* **logsource [必須]**: ログの出所。以下のいずれかを指定してください。
  * `default`: Windowsでデフォルトで有効になっているログの場合等
  * `non-default`: グループポリシーやセキュリティベースラインなどで有効にする必要があるログ用。
  * `sysmon`: sysmonのインストールが必要なログ。
* **non-default-setting** [オプション]: `non-default` のログソースのログ設定をオンにする方法の説明です。
* **ruletype [必須]**: Hayabusaルールには `Hayabusa` を指定します。SigmaのWindowsルールから自動変換されたルールは `Sigma` になります。

# 検知フィールド
## 検知の基礎知識
まず、検知の作り方の基本を説明します。


### AND論理とOR論理の書き方
ANDロジックを書くには、ネストされた辞書を使用します。
以下の検知ルールでは、ルールがマッチするためには、**両方の条件**が真でなければならないと定義しています。

* イベントIDは `7040` であること。
* チャンネルは `System` であること。

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

OR論理を記述するには、リスト（`- `で始まる辞書）を使用します。
以下の検知ルールでは、**片方**の条件がトリガーされることになります。

* イベントIDは `7040` であること。
  
**または**
* チャンネルは `System` であること。

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection 
```

また、以下のように「AND」と「OR」の論理を組み合わせることも可能です。
この場合、以下の2つの条件が両方成立したときにルールがマッチします。

* イベントID が `7040` **または** `7041` のどちらかであること。
* チャンネルが `System` であること。

```yaml
detection:
    selection:
        Event.System.EventID: 
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### イベントキー
以下は、Windowsイベントログの抜粋で、オリジナルのXMLでフォーマットしたものです。上記のルールファイルの例の  `Event.System.Channel` フィールドは、オリジナルのXMLタグを参照しています。 

`<Event><System><Channel>System<Channel><System></Event>`

ネストされたXMLタグはドット(`.`)で区切られたタグ名で置き換えられます。Hayabusaのルールでは、ドットでつながれたこれらのフィールド文字列は `eventkeys` と呼ばれます。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### イベントキーエイリアス
`.`の区切りが多くて長いイベントキーが一般的であるため、Hayabusaはエイリアスを使って簡単に扱えるようにします。エイリアスは `config\eventkey_alias.txt`ファイルで定義されています。このファイルは `alias` と `event_key` のマッピングで構成される CSV  ファイルです。以下に示すように、エイリアスを使用して上記のルールを書き直し、ルールを読みやすくすることができます。

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### 注意: 未定義のイベントキーエイリアスについて
すべてのイベントキーエイリアスが `config\eventkey_alias.txt`で定義されているわけではありません。`output`（アラートの詳細）メッセージで正しいデータを取得しておらず、代わりに`%EventID%`のような結果を取得している場合、または検知ロジックの選択が正しく機能していない場合は、新しいエイリアスを使用して `config\eventkey_alias.txt`を更新する必要があります。

### 条件におけるXML属性の使用方法
XML要素には、スペースを入れることで属性を設定することができます。例えば、以下の `Provider Name` の `Name` は `Provider` 要素のXML属性です。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```
イベントキーのXML属性を指定するには、`{eventkey}_attributes.{attribute_name}`という形式を使います。例えば、ルールファイルの `Provider` 要素の `Name` 属性を指定する場合は、以下のようになります。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep検索
Hayabusaではeventkeyを指定せず、WindowsEventログに含まれる文字列にマッチするかどうかを判定する機能も用意されています。この機能をHayabusaではgrep検索と呼んでいます。

grep検索をするには下記のようにdetectionを指定します。この場合、`mimikatz`または`metasploit`という文字列がWindowsEventログに含まれる場合に、条件に一致したものとして条件に一致したものとして処理されます。また、grep検索にはワイルドカードを指定することも可能です。

```yaml
detection:
    selection:
        - `mimikatz`
        - `metasploit`
```

> ※ Hayabusaでは内部的にWindowsEventログをJSON形式に変換して上で処理を行っています。そのため、XMLのタグをgrep検索でマッチさせることはできません。

### イベントデータ
Windowsのイベントログは、基本データ（イベントID、タイムスタンプ、レコードID、ログ名（チャンネル））が書き込まれる`System`部分と、イベントIDに応じて任意のデータが書き込まれる`EventData`部分の2つに分けられます。問題は、`EventData` にネストされたタグの名前がすべて `Data` であるため、これまで説明したイベントキーでは `SubjectUserSid` と `SubjectUserName` を区別できないことです。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>Hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-Hayabusa</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

この問題に対処するために、`Data Name`で割り当てられた値を指定することができます。例えば、EventData に含まれる `SubjectUserName` と `SubjectDomainName` をルールの条件として利用したい場合、以下のように記述することが可能です。

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: Hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventDataの異常なパターン
`EventData` にネストされたいくつかのタグは `Name` 属性を持ちません。

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None SequenceNumber=9 HostName=ConsoleHost HostVersion=2.0 HostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c EngineVersion=2.0 RunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1 PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine=</Data>
    </EventData>
</Event>
```

上記のようなイベントログを検知するには、`EventData`という名前のイベントキーを指定します。この場合、`Name`属性を持たないネストされたタグのいずれかがマッチする限り、条件はマッチします。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        EventData: None
    condition: selection
```

## パイプ
パイプは、以下のようにイベントキーと組み合わせて、文字列のマッチングに使用することができます。これまで説明した条件はすべて完全一致ですが、パイプを使うことで、より柔軟な検知ルールを記述することができます。以下の例では、`EventData`の値が正規表現 `[\s\S]*EngineVersion=2.0[\s\S]*` にマッチする場合、条件にマッチすることになります。

```yaml
detection:
    selection:
        Channel: Microsoft-Windows-PowerShell/Operational
        EventID: 400
        EventData|re: '[\s\S]*EngineVersion=2\.0[\s\S]*'
    condition: selection
```

パイプの後に指定できるものの一覧です。現時点では、Hayabusa は複数のパイプを連結することはサポートしていません。
* startswith: 文字列を先頭からチェックします。
* endswith: 文字列の末尾をチェックします。
* contains: ある単語がデータ内に含まれているかどうかをチェックします。
* re: 正規表現を使用します。(私たちは regex crate を使っているので、正しい正規表現の書き方については https://docs.rs/regex/1.5.4/regex/ のドキュメントを参照してください)。 
  > 注意: 正規表現を使用するSigmaルールの中には、Rustが正規表現を使用する方法の違いにより、 検知に失敗するものがあります。

## ワイルドカード
イベントキーにワイルドカードを使用することができます。以下の例では、`ProcessCommandLine` が "malware" という文字列で始まる場合、このルールはマッチします。
この仕様は、Sigmaルールのワイルドカードと基本的に同じです。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

以下の2つのワイルドカードを使用することができます。
* `*`: 0文字以上の任意の文字列にマッチします。(内部的には正規表現 `.*` に変換されます)。
* `?`: 任意の1文字にマッチします。(内部的には正規表現 `. ` に変換されます)。

ワイルドカードのエスケープについて
* ワイルドカード(`*` and `?`)は、バックスラッシュでエスケープできます: `\*` と `\?`.
* もし、ワイルドカードの直前にバックスラッシュを使用したい場合は、 `\\*` または `\\?` と記述してください。
* バックスラッシュを単独で使用する場合は、エスケープは必要ありません。

## イベントキー内のキーワードのネスト
イベントキーは、特定のキーワードでネストすることができます。
以下の例では、以下の場合にルールがマッチします。
* `ServiceName` が `malicious-service` であるか、または `./config/regex/regexes_suspicous_service.txt` にある正規表現を含んでいる場合。
* `ImagePath` は1000文字以上であること。
* `ImagePath` は `allowlist` にマッチするものが一つもありません。

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./config/regex/allowlist_legitimate_services.txt
    condition: selection
```

現在、指定できるキーワードは以下の通りです。
* `value`: 文字列によるマッチング (ワイルドカードやパイプも指定可能)。
* `min_length`: 指定された文字数以上の場合にマッチします。
* `regexes`: このフィールドで指定したファイル内の正規表現のいずれかにマッチする場合にマッチします。
* `allowlist`: このフィールドで指定したファイル内の正規表現のリストにマッチするものがある場合、ルールはスキップされます。

### regexesとallowlistキーワード
Hayabusaに`.\rules\hayabusa\default\alerts\System\7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml`のルールのために使う2つの正規表現ファイルが用意されています。
* `./config/regex/detectlist_suspicous_services.txt`: 怪しいサービス名を検知するためのものです。
* `./config/regex/allowlist_legitimate_services.txt`: 正規のサービスを許可するためのものです。
  
`regexes` と `allowlist` で定義されたファイルは、ルールファイル自体を変更することなく、それらを参照するすべてのルールの動作を変更するために編集することが可能です。

また、自分で作成した異なる regexes と allowlist テキストファイルを使用することもできます。
デフォルトの `./config/detectlist_suspicous_services.txt` と `./config/allowlist_legitimate_services.txt` を参考にして、独自のファイルを作成してください。

## condition (条件)
上記で説明した表記法では、`AND`や`OR`の論理を表現することができますが、複雑な論理を定義しようとすると混乱してしまうでしょう。
より複雑なルールを作りたい場合は、以下のように `condition` キーワードを使用します。

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

 `condition`には、以下の式を用いることができます。
* `{expression1} and {expression2}`: {expression1} と {expression2} の両方を必要とする。
* `{expression1} or {expression2}`: {expression1} または {expression2} のどちらかを必要とする
* `not {expression}`: {expression} の論理を反転させる
* `( {expression} )`: {expression} の優先順位を設定する。数学と同じ優先順位の論理に従う。

上記の例では、 `SELECTION_1`、` SELECTION_2`などの選択名が使用されていますが、次の文字 `a-z A-Z 0-9 _`のみが含まれている限り、任意の名前を付けることができます。
> ただし、可能な限り読みやすくするために、 `selection_1`、` selection_2`、 `filter_1`、` filter_2`などの標準的な規則を使用してください。

## notロジック
多くのルールは誤検知を引き起こすので、検索するシグネチャーの選択と同時に、誤検知が無いようにフィルターの選択をすることはよくあります。

例えば

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter: 
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

## aggregation condition (集計条件) (別名: カウントルール)
### 基本事項
上記の `condition` キーワードは `AND` や `OR` ロジックを実装しているだけでなく、イベントをカウントしたり、「aggregate(集約)」したりすることも可能です。
この機能は「集計条件」と呼ばれ、条件をパイプでつないで指定をします。
以下のパスワードスプレー攻撃の例では、5分以内に同じ送信元の`IpAddress`で5個以上の `TargetUserName`があるかどうかを判断するために条件式が使用されています。

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

集計条件は以下の形式で定義することができます。
* `count() {operator} {number}`: パイプの前の最初の条件にマッチするログイベントに対して、マッチしたログの数が `{operator}` と `{number}` で指定した条件式を満たす場合に条件がマッチします。 

`{operator}` は以下のいずれかになります。
* `==`: 指定された値と等しい場合、条件にマッチしたものとして扱われる。
* `>=`: 指定された値以上であれば、条件にマッチしたものとして扱われる。
* `>`: 指定された値以上であれば、条件にマッチしたものとして扱われる。
* `<=`: 指定された値以下の場合、条件にマッチしたものとして扱われる。
* `<`: 指定された値より小さい場合、条件にマッチしたものとして扱われる。

`{number}` は数値である必要があります。

`timeframe` は以下のように定義することができます。
* `15s`: 15秒
* `30m`: 30分
* `12h`: 12時間
* `7d`: 7日間
* `3M`: 3ヶ月
> `timeframe` は必須ではありませんが、パフォーマンスとメモリ効率のために、可能な限り定義することが強く推奨されます。


### 集計条件として4パターン:
1. count 引数または `by` キーワードを指定しない。例: `selection | count() > 10`
   > もし `selection` が時間枠内に10回以上マッチすれば、条件にマッチします。
2. count 引数はないが、`by` キーワードはある。例: `selection | count() by IpAddress > 10`
   > `selection` は**同じ**`IpAddress` に対して10回以上 true になる必要があります。
3. count 引数があるが、`by` キーワードがない場合。例:  `selection | count(TargetUserName) > 10`
   > `selection` がマッチし、かつ `TargetUserName` が時間枠内で10回以上**異なる**場合であれば、条件にマッチします。
4. count 引数と `by` キーワードの両方が存在する。例: `selection | count(TargetUserName) by IpAddress > 10`
   > **同じ**「日付」に対して、条件が一致するためには、10人以上の**異なる**「ユーザ」が存在する必要があります。


### パターン1の例：
これは最も基本的なパターンです：`count() {operator} {number}`. 以下のルールは、`selection`が3回以上発生した場合にマッチします。

![](CountRulePattern-1-JP.png)

### パターン2の例：
`count() by {eventkey} {operator} {number}`： パイプの前の `condition` にマッチするログイベントは、**同じ**`{eventkey}`でグループ化されます。各グループ化において、マッチしたイベントの数が`{operator}`と`{number}`で指定した条件を満たした場合、条件にマッチすることになります。

![](CountRulePattern-2-JP.png)

### パターン3の例：
`count({eventkey}) {operator} {number}`： 条件パイプの前に、条件にマッチする `{eventkey}` の**異なる**値がいくつログイベント内に存在するかを数えます。その数が`{operator}`と`{number}`で指定された条件式を満たす場合、条件を満たしたものとみなします。

![](CountRulePattern-3-JP.png)

### パターン4の例：
`count({eventkey_1}) by {eventkey_2} {operator} {number}`： 条件パイプの前にある条件にマッチしたログを**同じ**`{eventkey_2}`でグループ化し、各グループに含まれる`{eventkey_1}`の**異なる**値の数をカウントしています。各グループでカウントされた値が`{operator}`と`{number}`で指定された条件式を満たした場合、条件にマッチすることになります。

![](CountRulePattern-4-JP.png)

### Countルールの出力:
CountルールのDetails出力は固定で、`[condition]`にcount条件と`[result]`に記録されたイベントキーが出力されます。

以下の例では、ブルートフォースされた`TargetUserName`のユーザ名のリストと送信元の`IpAddress`が出力されます：
```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

# ルール作成のアドバイス
1. **可能な場合は、常に `Channel`と`EventID`を指定してください。** 将来的には、チャネル名とイベンドIDでフィルタリングする可能性があるため、適切な` Channel`と`EventID`が設定されていない場合はルールが無視される可能性があります。
   
2. **不要な場合は複数の `selection`と`filter`セクションを使用しないでください。**

### 悪い例： 
```yaml
detection:
detection:
    SELECTION_1:
        Channnel: Security
    SELECTION_2:
        EventID: 4625
    SELECTION_3:
        LogonType: 3
    FILTER_1:
        SubStatus: "0xc0000064" 
    FILTER_2:
        SubStatus: "0xc000006a"  
    condition: SELECTION_1 and SELECTION_2 and SELECTION_3 and not (FILTER_1 or FILTER_2)
```

### 良い例：
```yaml
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        - SubStatus: "0xc0000064"   #Non-existent user
        - SubStatus: "0xc000006a"   #Wrong password
    condition: selection and not filter
```

3. **複数のセクションが必要な場合は、チャンネル名とイベントIDの情報を記入する最初のセクションを `section_basic_info` セクションに、その他のセクションを `section_` と `filter_` の後に意味のある名前を付けるか、または `section_1`, `filter_1` などの記法を用いてください。また、分かりにくいところはコメントを書いて説明してください。**

### 悪い例： 
```yaml
detection:
    Takoyaki:
        Channel: Security
        EventID: 4648
    Naruto:
        TargetUserName|endswith: "$"  
        IpAddress: "-"
    Sushi: 
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    Godzilla:
        SubjectUserName|endswith: "$" 
    Ninja:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" 
        IpAddress: "-"                                  
    Daisuki:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: Takoyaki and Daisuki and not (Naruto and not Godzilla) and not Ninja and not Sushi
```

### OKな例：
```yaml
detection:
    selection_1:
        Channel: Security
        EventID: 4648
    selection_2:
        TargetUserName|endswith: "$"  
        IpAddress: "-"
    filter_1:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_2:
        SubjectUserName|endswith: "$" 
    filter_3:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_4:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_1 and selection_4 and not (selection_2 and not filter_2) and not filter_3 and not filter_1
```

### 良い例：
```yaml
detection:
    selection_basic_info:
        Channel: Security
        EventID: 4648
    selection_TargetUserIsComputerAccount:
        TargetUserName|endswith: "$"  
        IpAddress: "-"
    filter_UsersAndTargetServerAreComputerAccounts:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_SubjectUserIsComputerAccount:
        SubjectUserName|endswith: "$" 
    filter_SystemAccounts:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_SuspiciousProcess:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_basic and selection_SuspiciousProcess and not (selection_TargetUserIsComputerAccount 
               and not filter_SubjectUserIsComputerAccount) and not filter_SystemAccounts and not filter_UsersAndTargetServerAreComputerAccounts
```

# SigmaルールからHayabusaルール形式への自動変換
SigmaルールからHayabusaルール形式への自動変換を行うsigmacのバックエンドを[こちら](https://github.com/Yamato-Security/hayabusa/tree/main/tools/sigmac)で作成しました。

使い方のReadmeは[こちら](https://github.com/Yamato-Security/hayabusa/blob/main/tools/sigmac/README-Japanese.md)です。