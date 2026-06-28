# detectionフィールド

## selectionの基礎知識

まず、selectionの作り方の基本を説明します。

### 論理積(AND)と論理和(OR)の書き方

ANDを表現するには辞書（YAMLでは辞書を`:`で表します）を使用します。
このルールでログが検知されるには、**両方の条件**が真である必要があります。

- イベントIDが `7040` であること。
- チャンネルが `System` であること。

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

ORを表現するには、配列（YAMLでは配列を`-`で表します）を使用します。
このルールでログが検知されるには、**片方の条件**が真である必要があります。

- イベントIDが `7040` であること。
- チャンネルが `System` であること。

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

また、以下のように「AND」と「OR」を組み合わせることも可能です。
この場合、以下の2つの条件が両方成立したときに、このルールでログが検知されます。

- イベントIDが `7040` **または** `7041` のどちらかであること。
- チャンネルが `System` であること。

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

WindowsイベントログをXML形式で出力すると下記のようになります。
上記のルールファイルの例にある`Event.System.Channel`フィールドは、元々のXMLタグを参照しています： `<Event><System><Channel>System<Channel><System></Event>`
ネストされたXMLタグはドット(`.`)で区切られたタグ名で置き換えられます。
Hayabusaのルールでは、このドットでつながれた文字列のことをイベントキーと呼んでいます。

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

`.`の区切りが多くて長いイベントキーが一般的であるため、Hayabusaはエイリアスを使って簡単に扱えるようにします。エイリアスは `rules/config/eventkey_alias.txt`ファイルで定義されています。このファイルは `alias` と `event_key` のマッピングで構成されるCSVファイルです。以下に示すように、エイリアスを使用して上記のルールを書き直し、ルールを読みやすくすることができます。

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### 注意: 未定義のイベントキーエイリアスについて

すべてのイベントキーエイリアスが `rules/config/eventkey_alias.txt`に定義されているわけではありません。検知するはずのルールが検知しない場合や、`details`（アラートの詳細）メッセージに`n/a` (not available)が表示されている場合、`rules/config/eventkey_alias.txt`の設定を確認してください。

### XML属性を条件に使用する方法

XMLのタグにはタグ名とは別に属性を設定できます。例えば、以下の `Provider Name` の `Name` は `Provider` タグの属性です。

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

イベントキーでXMLの属性を指定するには、`{eventkey}_attributes.{attribute_name}`という形式で記述します。例えば、ルールファイルの `Provider` 要素の `Name` 属性を指定する場合は、以下のようになります。

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

grep検索をするには下記のようにdetectionを指定します。この場合、`mimikatz`または`metasploit`という文字列がWindowsEventログに含まれる場合に、ルールが検知されます。また、grep検索にはワイルドカードを指定することも可能です。

```yaml
detection:
    selection:
        - `mimikatz`
        - `metasploit`
```

> ※ Hayabusaでは内部的にWindowsEventログをJSON形式に変換しています。そのため、grep検索ではXMLのタグをマッチさせることはできません。

### EventData

Windowsのイベントログは、基本データ（イベントID、タイムスタンプ、レコードID、ログ名（チャンネル））が書き込まれる`System`タグと、イベントIDに応じて任意のデータが書き込まれる`EventData`もしくは`UserData`タグの2つに分けられます。
その内、`EventData`もしくは`UserData`タグはネストされたタグの名前がすべて`Data`であり、これまで説明したイベントキーでは`SubjectUserSid`と`SubjectUserName`を区別できません。

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

この問題に対処するため、`Data`タグの`Name`属性に指定された値をイベントキーとして利用できます。例えば、`EventData`の`SubjectUserName`と`SubjectDomainName` を条件として利用する場合、以下のように記述することが可能です。

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: Hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### EventDataの例外的なパターン

`EventData`タグにネストされたいくつかのタグは`Name`属性を持ちません。

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
        <Data>NewEngineState=Available PreviousEngineState=None (省略)</Data>
    </EventData>
</Event>
```

上記のようなイベントログを検知するには、`Data`というイベントキーを指定します。
この場合、`EventData`にネストされたタグの内、`Data`フィールドが`None`になっている場合は、条件にマッチすることになります。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### 同じ名前の複数のフィールド名からフィールドデータを出力する

いくつかのイベントは、前の例のように、データをすべて`Data`というフィールド名で保存します。
`details:`に`%Data%`を指定すると、すべてのデータが配列として出力されます。

例えば：
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

もし、最初の`Data`フィールドのデータだけを出力したい場合は、`details:`に `%Data[1]%` を指定すると `rundll32.exe`のみが出力されます。

## フィールド修飾子 (Field Modifiers)

イベントキーにはフィールド修飾子を指定することができます。
ここまで説明した書き方では完全一致しか表現できませんでしたが、パイプを使うことでより柔軟な検知ルールを記載できるようになります。
以下の例では、ある`Data`フィールドの値に`EngineVersion=2`という文字列が入っている場合、条件にマッチすることになります。

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

通常は大文字小文字を区別しませんが、`|re`もしくは`|equalsfield`のキーワードを指定した場合は大文字小文字を区別します。

### 対応しているSigmaのフィールド修飾子

Hayabusaは現在、Sigma仕様のすべてを完全にサポートする唯一のオープンソースツールです。

サポートされているフィールド修飾子、サポートされていないフィールド修飾子、およびこれらの修飾子がSigmaとはHayabusaのルールで使用されている回数の現在の状況は、https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md で確認できます。
この文書は、SigmaやHayabusaのルールが更新されるたびに更新されます。

- `'|all':`: このフィールド修飾子は、特定のフィールドに適用されるのではなく、すべてのフィールドに適用されるので、他の修飾子とは異なります

    この例では、`Keyword-1`と`Keyword-2`という文字列の両方が存在する必要がありますが、任意のフィールドのどこにでも存在できます:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: データは、エンコードされた文字列内の位置によって、3つの異なる方法でbase64にエンコードされます。この修飾子は、文字列を3つのバリエーションにエンコードし、その文字列がbase64文字列のどこかにエンコードされているかどうかをチェックします。
- `|cased`: 大文字と小文字を区別して検索します。
- `|cidr`: IPv4またはIPv6のCIDR表記をチェックします。（例：`192.0.2.0/24`）
- `|contains`: 指定された文字列が含まれることをチェックします。
- `|contains|all`: 指定された複数の文字列が含まれることをチェックします。
- `|contains|all|windash`: `contains|windash`と同じですが、すべてのキーワードが存在する必要があります。
- `|contains|cased`: フィールドの値が指定された大文字小文字を区別する文字列を含むかをチェックします。
- `|contains|expand`: フィールドの値に、`/config/expand/`内の`expand`設定ファイルに定義された文字列が含まれているかをチェックします。
- `|contains|windash`: 文字列をそのままチェックするだけでなく、最初の`-`文字を`/`文字に変換し、そのバリエーションもチェックします。
- `|endswith`: 指定された文字列で終わることをチェックします。
- `|endswith|cased`: フィールドの値が指定された大文字小文字を区別する文字列で終わることをチェックします。
- `|endswith|windash`: 指定された文字列で終わることをチェックし、最初の`-`文字を`/`、`–` (en dash)、`—` (em dash)、`―` (horizontal bar)文字のバリエーションに変換し、チェックします。
- `|exists`: フィールドが存在するかをチェックします。
- `|expand`: フィールドの値が、`/config/expand/`内の`expand`設定ファイルに定義された文字列と一致するかをチェックします。
- `|fieldref`: 2つのフィールドの値が同じかどうかをチェックする。これは `|equalsfield` 修飾子と同じです。
- `|fieldref|contains`: 一方のフィールドの値がもう一方のフィールドに含まれているかどうかをチェックします。
- `|fieldref|endswith`: 左側のフィールドが右側のフィールドの文字列で終わっているかどうかをチェックします。`condition` で `not` を使用することで、それらが異なるかどうかをチェックできます。
- `|fieldref|startswith`: 左側のフィールドが右側のフィールドの文字列で始まっているかどうかをチェックします。`condition` で `not` を使用することで、それらが異なるかどうかをチェックできます。
- `|gt`: フィールドの値が指定した数値より大きいかどうかをチェックします。
- `|gte`: フィールドの値が指定した数値以上かどうかをチェックします。
- `|lt`: フィールドの値が指定した数値より小さいかどうかをチェックします。
- `|lte`: フィールドの値が指定した数値以下かどうかをチェックします。
- `|re`: 大文字と小文字を区別する正規表現を使用する。 (regexクレートを使用しているので、サポートされている正規表現の書き方は以下のドキュメントを参照してください。 <https://docs.rs/regex/latest/regex/#syntax>)
    > 注意: [Sigma ルールにおける正規表現の構文](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) PCREを使用しており、文字クラス、ルックビハインド、アトミック・グルーピングなどの特定のメタ文字はサポートされていません。Rust regex crateはSigmaルールですべての正規表現を使用できるはずですが、互換性がない可能性があります。
- `|re|i`: (Insensitive) 大文字小文字を区別しない正規表現を使用する。
- `|re|m`: (Multi-line) 複数行にまたがってマッチする。`^` / `$` は行頭/行末にマッチする。
- `|re|s`: (Single-line) ドット (`.`) は改行文字を含むすべての文字にマッチする。
- `|startswith`: 指定された文字列で始まることをチェックします。
- `|startswith|cased`: フィールドの値が指定された大文字小文字を区別する文字列で始まるかをチェックします。
- `|utf16|base64offset|contains`: UTF-16文字列がBase64文字列内にエンコードされているかどうかをチェックします。
- `|utf16be|base64offset|contains`: UTF-16ビッグエンディアンの文字列がBase64文字列内にエンコードされているかどうかをチェックします。
- `|utf16le|base64offset|contains`: UTF-16リトルエンディアン文字列がBase64文字列内にエンコードされているかどうかをチェックします。
- `|wide|base64offset|contains`: `utf16le|base64offset|contains` のエイリアスで、UTF-16リトルエンディアンの文字列をチェックします。

### 非推奨のフィールド修飾子

以下の修飾子は非推奨となり、Sigma仕様の修飾子に置き換えられました。

- `|equalsfield`: 現在は`|fieldref`に置き換えられています。
- `|endswithfield`: 現在は `|fieldref|endswith`に置き換えられています。

### Expandフィールド修飾子

`expand`フィールド修飾子はユニークなもので、使用するために事前に設定を必要とする唯一のフィールド修飾子です。
例えば、`%DC-MACHINE-NAME%`のようなプレースホルダーを使用し、すべてのDCマシン名を含む`/config/expand/DC-MACHINE-NAME.txt`という名前の設定ファイルを必要とします。

この設定方法については、[こちら](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command)でさらに詳しく説明しています。

## ワイルドカード

Hayabusaルールではワイルドカードを使用することができます。以下の例では、`ProcessCommandLine` が "malware" という文字列で始まる場合、このルールでログが検知されます。この仕様はSigmaルールのワイルドカードと同じく、大文字小文字を区別しません。

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

以下の2つのワイルドカードを使用することができます。

- `*`: 0文字以上の任意の文字列にマッチします。(内部的には`.*`という正規表現に変換されます)。
- `?`: 任意の1文字にマッチします。(内部的には`.`という正規表現に変換されます)。

ワイルドカードのエスケープについて

- ワイルドカード(`*`と`?`)はバックスラッシュでエスケープできます: `\*` と `\?`.
- ワイルドカードの直前にバックスラッシュを使用する場合、 `\\*` または `\\?` と記述してください。
- バックスラッシュを単独で使用する場合、エスケープは不要です。

## null keyword

`null`を値に入れることで、フィールドが存在しないことを条件とすることができます。

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

注意: フィールド自体は存在するが、値がヌルであることを確認したい場合は、`ProcessCommandLine: ''`のように定義します。

## condition (条件)

これまで説明した記法では簡単な`AND`や`OR`であれば表現可能ですが、複雑な条件は定義できません。そのような場合、`condition` キーワードを使用します。

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

- `{expression1} and {expression2}`: {expression1} と {expression2} の両方が真である場合にマッチします。
- `{expression1} or {expression2}`: {expression1} または {expression2} のどちらかが真である場合にマッチします。
- `not {expression}`: {expression} の真偽を反転させます。
- `( {expression} )`: `()`で囲まれた {expression} を先に評価します。数学と同じ優先順位に従います。

上記の例では、 `SELECTION_1`、`SELECTION_2`などの名前が使用されていますが、名前には `a-z A-Z 0-9 _`の文字を使用可能です。ただし、`selection_1`、`selection_2`、 `filter_1`、`filter_2`などの標準的な規則の利用を推奨します。

## notロジック

ルールを作成する場合、誤検知を減らすためにフィルターを作成することはよくあります。以下に利用例を示します。

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
