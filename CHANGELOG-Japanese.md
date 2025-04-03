# 変更点

## x.x.x [xxxx/xx/xx]

**改善:**

- ファイルサイズを1024ベースで出力するようにした。（例:`KiB`, `MiB`, `GiB`等） (#1648) (@fukusuket)

## 3.2.0 [2025/04/02] - Vegemite Release

**改善:**

- `computer-metrics`コマンドにアップタイムとタイムゾーン情報を追加した。 (#1638) (@fukusuket)
- 無効なルールのチェックとロギングを改善した。 (#1601) (@fukusuket)
- デフォルトの出力に最初と最後のタイムスタンプを追加した。 (#1616) (@fukusuket)

**バグ修正:**

- `.evtx`ファイルが開けない場合、スキャンは失敗していた。 (#1634) (@fukusuket)
- 経過時間と保存されたファイル情報がHTMLレポートに出力されていなかった。 (#1643) (@fukusuket)

## 3.1.1 [2025/03/12] - Laksa Release

**改善:**

- Rustエディションを2024に更新した。(@fukusuket)
- `computer-metrics`コマンドにOS情報を追加した。 (#1629) (@fukusuket)

**バグ修正:**

- `expand`ルールの数がターミナルに正しく表示されていなかった。 (#1598) (@fukusuket)
- `status`フィールドが定義されていないルールは、スキャンウィザードで `status: test, stable` などを指定しても読み込まれた。(#1602) (@fukusuket)
- `expand`ルールが設定なしでロードされていた。 (#1606) (@fukusuket)
- `extract-base64`コマンドでダブルBase64エンコーディングの検出が正しく動作していなかった。 (#1607) (@fukusuket)
- エラーメッセージの後、端末の文字が赤くなることがあった。 (#1610) (@fukusuket)
- いくつかのコマンドで`-d`オプションが使用され、`-o`オプションが使用されなかった場合、プログレスバーが表示されなかった。 (#1617) (@fukusuket)
- `pivot-keywords-list`コマンドが壊れていた。(#1619) (@fukusuket)
- `details`が未定義の場合、フィールドデータマッピングが正常に機能しなかった。 (#1614) (@fukusuket)
- `details`フィールドが設定されていない場合、`Details`列と`ExtraFieldInfo`列の両方に重複したデータが出力されていた。現在は`Details`列だけに出力される。 (#1623) (@fukusuket)

## 3.1.0 [2025/02/22] - Ninja Day Release

**新機能:**

- `eid-metrics`と`logon-summary`コマンドに`-X, --remove-duplicate-detections`オプションを追加した。 (#1552) (@fukusuket)
- 新しい「緊急アラート 」と重要なシステムに基づく重大度レベルの調整。`config/critical_systems.txt`に重要なシステム（例: ドメインコントローラ、ファイルサーバ等々）のコンピュータ名のリストを追加すると、`low`以上のすべてのアラートが1つ高く調整される。つまり、`low`は`medium`に、`medium`は`high`に、`critical`アラートは新しい`emergency`アラートになる。 (#1551) (@fukusuket)
- `./config/critical_systems.txt`ファイルに追加するドメインコントローラーとファイルサーバーを自動的に見つける`config-critical-systems`コマンドを追加した。 (#1570) (@fukusuket)
- `csv-timeline`、`search`、`log-metrics`コマンドに、フィールド情報をタブで区切る`-S, --tab-separator`オプションを追加した。 (#1587) (@fukusuket)

**改善:**

- `search`コマンドに`--timeline-start/--timeline-end`オプションを追加した。 (#1543) (@fukuseket)
- チャンネルフィルタリングで `logon-summary` コマンドの速度を大幅に改善した。 (#1544) (@fukusuket)
- `extract-base64`コマンドが`PowerShell Classic EID 400`イベントも対象するようになった。 (#1549) (@fukusuket)
- `extract-base64`コマンドがPowerShell Coreログにも対応した。 (#1558) (@fukusuket)
- `extract-base64`コマンドが`System 7045` (サービス作成)イベントにも対応した。 (#1583) (@fukusuket)
- `search`コマンドは、デフォルトでは結果をソートしないので、メモリ使用量が大幅に減り、より高速になった。新しい`-s, --sort`オプションを使えば、以前と同じように結果をソートできる。(#1475) (@hach1yon)

**バグ修正:**

- `logon-summary`と`pivot-keywords-list`コマンドが不要なファイルを出力していた。 (#1553) (@fukusuket)
-  JSON出力では、いくつかのルールでMITRE戦術の一貫性がなかった。 (#1573) (@fukusuket)
- バージョンv3.0.x`ではルール作者情報がHTMLレポートに出力されていなかった。 (#1571) (@fukusuket)
- ライブ調査用のエンコードされたルールが使用されている場合、相関ルールのルールファイル名がJSONタイムラインに出力されていなかった。 (#1572) (@fukusuket)
- `level-tuning`コマンドが正しく動いていなかった。 (#1584) (@fukusuket)

**その他:**

- `-s, --sort-events`オプションが`-s, --sort`に名前変更された。 (@YamatoSecurity)
- `minimal`以外のプロファイルに`RuleID`を追加した。 (@YamatoSecurity)
- コードのリファクタリング: StoredStaticの不要な初期化コードを減らすためにデフォルトのtraitを使用することにした。 (#1588) (@fukusuket)

## 3.0.1 [2024/12/29] - 3rd Year Anniversary Release

**バグ修正:**

- Hayabusaはバックエンドで`expand`ルールのパースチェックに失敗していた。 (#1537) (@fukusuket)

## 3.0.0 [2024/12/25] - 3rd Year Anniversary Release

**新機能:**

- Base64文字列を抽出して、デコードする`extract-base64`コマンドを追加した。(#1512) (@fukusuket)
- `expand`修飾子が入っているルールで使用されるプレースホルダー名を出力する`expand-list`コマンドを追加した。(#1513) (@fukuseket)
- `expand`フィールド修飾子に対応した。 (#1434) (@fukusuket)
- Temporal Proximity（`temporal`）の相関ルールに対応した。 (#1446) (@fukusuket)
- Temporal Ordered Proximity (`temporal_ordered`) の相関ルールに対応した。 (#1447) (@fukusuket)

**改善:**

- `log-metrics`コマンドにファイルサイズを追加した。 (#1528) (@fukusuket)

**バグ修正:**

- レコードIDが出力されるとき、`csv-timeline`によるソートが完璧に行われなかった。 (#1519) (@fukusuket)
- `J, --JSON-input`は、`.json`ファイルしか対応していなかったので、`.jsonl`ファイルにも対応した。 (#1530) (@fukusuket)

## 2.19.0 [2024/11/26] - "Every Day Is A Good Day" Release

**新機能:**

- `gt`、`gte`、`lt`、`lte`のフィールド修飾子に対応した。(#1433) (@fukusuket)
- 新しい`log-metrics`コマンドで`.evtx`ファイルの情報を取得できるようになった。(コンピュータ名、イベント数、最初のタイムスタンプ、最後のタイムスタンプ、チャネル、プロバイダ) (#1474) (@fukusuket)
- 以下のコマンドに`Channel`と`Provider`の略称を無効にする`-b, --disable-abbreviations`オプションを追加した。元の値を確認したい時に便利。 (#1485) (@fukusuket)
  * `csv-timeline`
  * `json-timeline`
  * `eid-metrics`
  * `log-metrics`
  * `search`
- `utf16/utf16be/utf16le/wide`フィールド修飾子が`base64offset|contains`フィールド修飾子と一緒に使えるようになった。 (#1432) (@fukusuket)
  * `utf16|base64offset|contains`
  * `utf16be|base64offset|contains`
  * `utf16le|base64offset|contains`
  * `wide|base64offset|contains`

**改善:**

- `yaml-rust`クレートを`yaml-rust2`に更新した。(#461) (@yamatosecurity)
- `windash`文字が、`rules/config/windash_characters.txt`から動的に読み込まれるようになった。(#1440) (@fukusuket)
- `logon-summary`コマンドがRDPイベントからのログオン情報を表示するようになった。注意: ファイルに保存する場合、Hayabusaはより詳細な情報を出力する。(#1468) (@fukusuket)
- 見やすくなるように色を更新した。 (#1480) (@yamatosecurity)
- 実行開始と終了のメッセージを出力するようにした。 (#1492) (@fukusuket)
- 出力に新しい配色を追加した。 (#1491) (@fukusuket)
- ファイルサイズがプログレスバーの下のファイル名の横に表示されるようになった。 (#1471) (@fukusuket)

**バグ修正:**

- logon-summary`コマンドが破損したログでクラッシュすることがあった。(#1477) (@fukusuket)
- `csv-timeline`と`json-timeline`コマンドで、結果をターミナルに出力すると、プログレスバーの後にいくつかの結果が表示されていた。(#1459) (@fukusuket)
- 集計ルールのアラートの詳細フィールド値の結果がソートされていないため、`csv-timeline`と`json-timeline`は、毎回完全に正確な結果を出力しなかった。 (#1466) (@fukusuket)
- `hayabusa-evtx`クレートをバージョン`0.8.12`に更新した。(@yamatosecurity)
  - JSONフィールドの出力順序が元のXMLに従って保持されるようになった。(omerbenamram/evtx #241)
  - 属性と同じ名前を持つ複数のサブノードは上書きされ、最後の1つだけが出力されていた。(omerbenamram/evtx #245)
- `logon-summary`と`eid-metrics`が複数のプログレスバーを出力することがあった。 #1479 (@fukusuket)
- ターミナルに出力し、イベントをソートしない場合、プログレスバーは不要なため削除された。 #1508 (@fukusuket)

**その他:**

- `timeline-offset`オプションは、`--time-offset`に名前変更された。 (#1490) (@yamatosecurity)

## 2.18.0 [2024/10/23] - SecTor Release

**新機能:**

- `fieldref`修飾子(`equalsfield`修飾子のエリアス)に対応した。(#1409) (@hitenkoku)
- `fieldref|startswith`と`fieldref|contains`修飾子に対応した。 (#1439) (@fukusuket)
- `fieldref|endswith`修飾子は、`endswithfield`をリプレースするためのエイリアスとして作成された。(#1437) (@fukusuket)
- XORエンコードされたルールをサポートし、端末に置かれるファイルを最小限に抑えるとともに、ルールに過検知するアンチウイルス製品を回避する。(#1419) (@fukusuket)
  - リリースページで、この機能を設定済みのパッケージを含める予定。手動で設定したい場合は、[encoded_rules.yml](https://github.com/Yamato-Security/hayabusa-encoded-rules/raw/refs/heads/main/encoded_rules.yml)をダウンロードして、Hayabusaのルートフォルダに置いてください。このファイルは、hayabusa-rulesリポジトリ内のルールから作成されており、ルールが更新されるたびに自動的にアップデートされる。configディレクトリ以外のrulesフォルダ内のファイルは、まだ単一ファイルに含まれていないので削除してください。
  - 注意: -Hオプションで生成されるレポートは、ルールへのリンクを作成せず、ルール名だけが出力される。
- `rules/config`の設定ファイルが単一のファイル[rules_config_files.txt](https://github.com/Yamato-Security/hayabusa-encoded-rules/raw/refs/heads/main/rules_config_files.txt)からロードされるようになり、ライブ調査のためにターゲットシステムに保存する必要があるファイル数が減った。(#1420) (@fukusuket)

**バグ修正:**

- `search`コマンドの`-o`オプションを使用した際に不要な改行が出力されていた。(#1425) (@fukusuket)
- Sigma相関ルールの`group-by`フィールドは、必須だったが任意に変えた。(#1442) (@fukusuket)
- Hayabusaは、相関ルールで参照されているルールが見つからない場合、エラーメッセージを表示するようにした。 (#1444) (@fukusuket)
- `all-field-info`プロファイルを使用した場合、フィールド情報が出力されなかった。 (#1450) (@fukusuket)

**その他:**

- ライセンスをGPL-3.0からAGPL-3.0に変えた。(@yamatosecurity)

## 2.17.0 [2024/08/23] "HITCON Community Release"

**新機能:**

- Sigma V2の`|re:`のサブ修飾子に対応した。 submodifers. (#1399) (@fukusuket)
  - 参考: https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md
    * `|re|i:`: (insensitive) 大文字小文字を区別しないマッチングを無効にする。
    * `|re|m:`: (multi-line) 複数行にまたがってマッチする。`^` /`$` は行頭/行末にマッチする。
    * `|re|s:`: (single-line) ドット文字 (`.`) は改行文字を含むすべての文字にマッチする。
- Sigma V2の`|exists:`修飾子に対応した。 (#1400) (@hitenkoku)
- Sigma V2の`|cased:`修飾子に対応した。 (#1401) (@hitenkoku)

**改善:**

- `cidr-utils`クレートを新バージョン0.6.xに対応した。 (#1366) (@hitenkoku)
- Sigma相関ルールの`name`ルックアップに対応した。 (#1363) (@fukusuket)
- デフォルトで低メモリモードを有効にした。`-s, --low-memory-mode`は、`-s, --sort-events` - 出力/保存する前に結果をソートする。(注意: より多くのメモリを消費する。）(#1361) (@hitenkoku)
  - 注意: `-R, --remove-duplicate-data`または`-X, --remove-duplicate-detections`を使用するには、ソートを有効にする必要がある。
- Sigma相関ルールが参照しているルールは、デフォルトで結果を出力しないようにした。ルールに`generate: true`を指定すると、出力される。 (#1367) (@fukusuket)
- `Data`フィールドは、すべて`Data`フィールドとして、またはJSONの配列としてではなく、インデックス化された文字列として表示されるようになった。(#1371) (@fukusuket)
  - 前: `"Data": ["17514", "Multiprocessor Free", "Service Pack 1"]`
  - 後: `"Data[3]": "17514", "Data[4]": "Multiprocessor Free", "Data[5]": "Service Pack 1"`
- リリースパッケージのファイル数を減らすために、`config`フォルダ内の設定ファイルもバイナリに埋め込まれるようにした。 (#1370) (@hitenkoku)
  - 注意: `set-default-profile`コマンドは、`config/default_profile.yaml`に依存しているので、`config`ディレクトリファイルがないと実行できない。
- 集計ルールのアラートに、複数の結果がある場合でも`Channel`と`EventID`の情報が表示されるようにした。 (#1342) (@fukusuket)
- JSONタイムラインで`Details`フィールドに情報がない場合、JSONがパースしやすくなるように、デフォルトで出力される`"-"`を`{}`に変更した。(#1386) (@hitenkoku)
- シグネチャーバイパスを防ぐため、`-` (エンダッシュ)、`-` (エムダッシュ)、`―` (水平バー) 文字を `windash` 修飾子でサポートするようにした。(#1392) (@hitenkoku)
- MITRE ATT&CKタグをSigmaバージョン2の形式に対応させた。(例: `defense_evasion` => `defense-evasion`) (@fukusuket)
- `evtx`クレートを最新のものに更新し、機能改善とバグ修正を行った。

**バグ修正:**
- Sigmaの相関ルールのカウントが`Events with hits`に表示されていなかった。(#1373) (@fukusuket)
- 相関ルールのカウントが`Events with hits`に表示されていなかった。(#1374) (@fukusuket)
- 集計ルールのカウントが`Events with hits`に表示されていなかった。(#1375) (@fukusuket)
- まれに、ルール作成者の一覧が表示されないことがあった。 (#1383) (@fukusuket)

## 2.16.0 [2024/06/11]

**新機能:**

- デフォルトでは、`.evtx`ファイルに適用可能なルールのみ有効になる。これは、`.evtx`ファイルと`.yml`ルールの`Channel`フィールドに基づく。例えば、`Security.evtx`がスキャンされている場合、`Channel: Security`が定義されているルールのみがこのファイルに対して使用される。ベンチマークでは、単一の`evtx`ファイルをスキャンする場合、パフォーマンスが約20％向上される。1つの`.evtx`ファイルで複数のチャネルが使用されている場合や、チャネルが定義されていないルールを使用して、チャネルに関係なくすべての`.evtx`ファイルをスキャンしたい場合は、`csv-timeline` と `json-timeline` の `-A、--enable-all-rules` オプションでこのフィルタリングをオフにすることができる。（#1317）(@fukusuket)
  - 現在のところ、`Channel`が定義されておらず、すべての`.evtx`ファイルをスキャンすることを意図している検知ルールは以下の2つだけ:
    - [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
    - [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)
- デフォルトでは、適用可能なルールを持つ`.evtx`ファイルのみ読み込む。たとえば、さまざまなイベントログのディレクトリをスキャンしている場合でも、 `Channel: Security` を探すルールのみを有効にした場合、Hayabusaは`Security`以外のすべてのイベントログを無視します。ベンチマークでは、通常のスキャンで約10％、単一のルールでスキャンする場合は最大60％以上のパフォーマンス向上が得られる。チャネルに関係なくすべての`.evtx`ファイルを読み込みたい場合は、`csv-timeline` と `json-timeline` の `-a、--scan-all-evtx-files` オプションでこのフィルタリングをオフにすることができる。(#1318) (@fukusuket)
- 注意: チャンネルフィルタリングは .evtx ファイルにのみ適用され、`-J, --json-input`オプションを使用してイベントログをJSONファイルから読み込む際に`-A`または`-a`を指定するとエラーが発生する。(#1345) (@fukusuket)
- Sigma相関ルールのEvent Countに対応した。 (#1337) (@fukusuket)
- Sigma相関ルールのValue Countに対応した。 (#1338) (@fukusuket)

**改善:**

- `-d, --directory`オプションで複数のフォルダを指定できるようにした。 (#1335) (@hitenkoku)
- REST APIからエクスポートされたSplunkログを分析できるようになった。 (#1083) (@hitenkoku)
- `count`で複数のグループを指定できるようにした。例: `count() by IpAddress,SubStatus,LogonType >= 2`。また、出力される結果を更新した。例: `[condition] count(TargetUserName) by IpAddress > 3 in timeframe [result] count: 4 TargetUserName:tanaka/Administrator/adsyncadmin/suzuki IpAddress:- timeframe:5m` -> `Count: 4 ¦ TargetUserName: tanaka/Administrator/adsyncadmin/suzuki ¦ IpAddress: -` (#1339) (@fukusuket)
- フィールドデータマッピングファイル(`rules/config/data_mapping/*.yaml`)で任意の`Provider_Name`フィールドを指定できるようにし、`Data[x]`表記に対応した。(#1350) (@fukusuket)
- カウントルールのJSON出力で、フィールド情報が分離されるようになった。 (#1342) (@fukusuket)
  - 以前: `"Details": "[condition] count() by IpAddress >= 5 in timeframe [result] count:3558 IpAddress:192.168.198.149 timeframe:5m"`
  - 現在: `"Details": { "Count": 3558, "IpAddress": "192.168.198.149" }`

## 2.15.0 [2024/04/20] "Sonic Release"

**改善:**

- Sigmaルールの `windash`フィールド修飾子 (例: `|contains|windash:`と`|contains|all|windash:`)に対応した。 (#1319) (@hitenkoku)
  - https://sigmahq.io/docs/basics/modifiers.html#windash
  - 注意: 現在、バックエンドでは、以前のバージョンのHayabusaと互換性があるようにルール内の`windash`の使用を変換しているが、5月末ごろには、`windash`の使用をそのままにする予定なので、それまでにこのバージョンにアップデートしてください。

**バグ修正:**

- バージョン2.14.0では、`-T`の検知頻度タイムライン出力は使用できなかった。 (#1322) (@fukusuket)
- `windash` でワイルドカードが利用できない問題を修正した。 (#1327) (@hitenkoku)

## 2.14.0 [2024/03/30] "BSides Tokyo Release"

**新機能:**

- 指定した`status`のルールのみを利用する`--include-status`オプションを追加した。 (#1193) (@hitenkoku)
- メモリ使用量を最大95%削減する`-s, --low-memory-mode`(低メモリモード)オプションを追加した。ただし、そのためには結果をソートしたり、`-R, --remove-duplicate-data`または`-X, --remove-duplicate-detections`を併用したりすることはできない。(#1254) (@hach1yon @hitenkoku)

**改善:**

- 未使用のクレートを削除した。(@YamatoSecurity)
- SplunkからエクスポートしたJSONファイルの入力に対応した。 (#1083) (@hitenkoku)
- パフォーマンスの改善 (#1277, #1278) (@fukusuket)
- `csv-timeline`コマンドの結果と同様になるようにするために、`search`コマンドの結果の表示順番を変更した。 (#1297) (@hitenkoku)
- イースターエッグに最強のキャラクターを追加した。 (#1304) (@hitenkoku)
- `computer-metrics`コマンドのhelpオプションの表示をほかのコマンドの形式に合わせた。 (#1314) (@hitenkoku)

**バグ修正:**

- `search` コマンドのJSON出力で`AllFieldInfo`フィールドの情報が出力されなくなっていたのを修正した。 (#1251) (@hitenkoku)
- ウィザードのオプション選択の時間が処理時間の中に含まれていたため除外した。 (#1291) (@hitenkoku)
- `-h, --help`オプションが重複して複数回表示されていた問題を修正した。 (#1309) (@hitenkoku)

## 2.13.0 [2024/02/11] "Year Of The Dragon Release"

**改善:**

- `search` コマンドのフィルタオプションを完全一致にするようにした。加えてフィルタオプションはワイルドカード対応をするようにした。 (#1240) (@hitenkoku)
- `update-rules`コマンドを実行したときに、検知ルールが変更された場合にルール名を出力するようにした。以前は`modified`フィールドを更新したルールだけが表示されていた。(#1243) (@hitenkoku)
- `json-timeline`コマンドの標準出力でJSONフォーマットを出力するように修正した。 (#1197) (@hitenkoku)
- JSON入力でデータが配列内にある場合に解析できるようにした。 (#1248) (@hitenkoku)
- 古いターミナルでも正しく表示されるように、また読みやすくするために、`‖`区切り文字を`·`区切り文字に変更した。(#1258) (@YamatoSecurity)
- General Optionsに`-h, --help`オプションを追加した。 (#1255) (@hitenkoku)
- `json-timeline`コマンドの`Details`の出力で、要素がアルファベット順に並んでいたのをルールに記載されているオリジナルの順番に変更した。 (#1264) (@hitenkoku)
- ルールをロードする必要のないコマンドを実行した場合、検出ルールのロードをスキップするようにした。 (#1263) (@hitenkoku)
- `csv-timeline`コマンドの標準出力のカラー出力ルールを変更した。 (#1271) (@hitenkoku)
- リファクタリングとパフォーマンスの改善。(#1268, #1260) (@hach1yon)

**バグ修正:**

- `search`コマンドの出力に入っている不要な改行文字を削除した。 (#1253) (@hitenkoku)
- `no-color`オプション使用時のプログレスバーとウィザードのカラー出力を修正した。 (#1256) (@hitenkoku)
- ローカルのタイムゾーンを特定できない場合にパニックが発生する問題を修正した。`chrono`クレートのバージョン0.4.32で修正された。(#1273)

## 2.12.0 [2023/12/24] "SECCON Christmas Release"

**改善:**

- JSON出力において、MitreTactics、MitreTags, OtherTagsの出力を要素ごとに文字列で出力させるように修正した。 (#1230) (@hitenkoku)
- 検知した端末に対してMITRE ATT&CKの戦術をHTMLレポートに出力できるようにした。この機能を利用するためには利用したプロファイルに`%MitreTactics%`が存在する必要がある。 (#1226) (@hitenkoku)
- `csv-timeline`または`json-timeline`コマンドが利用されたときにissueやpull-requestの連絡先についてのメッセージを追加した。 (#1236) (@hitenkoku)

**バグ修正:**

- JSON出力において、同じ名前の複数のフィールド名が配列として出力されないため、`jq`でパースすると1つの結果しか返されなかった。同じフィールド名を持つ複数のフィールドデータを配列内に出力することで修正した。 (#1202) (@hitenkoku)
- `csv-timeline`、`json-timeline`、`eid-metrics`、`logon-summary`、`pivot-keywords-list`、`search`コマンドで調査対象ファイルの指定オプション(`-l`、 `-f`、 `-d`)が存在しないときに処理が実行されないように修正した。 (#1235) (@hitenkoku)

## 2.11.0 [2023/12/03] "Nasi Lemak Release"

**新機能:**

- PowerShell classicログのフィールドを抽出するようにした。(`--no-pwsh-field-extraction`で無効化できる) (#1220) (@fukusuket)

**改善:**

- スキャンウィザードにルール数を追加した. (#1206) (@hitenkoku)

## 2.10.1 [2023/11/12] "Kamemushi Release"

**改善:**

- スキャンウィザードに質問を追加した。 (#1207) (@hitenkoku)

**バグ修正:**

- バージョン`2.10.0`の`update-rules`コマンドでは、新しいルールがダウンロードされても、`You currently have the latest rules`というメッセージを出力していた。 (#1209) (@fukusuket)
- 正規表現が正しく処理されない場合があった。 (#1212) (@fukusuket)
- JSON入力等に`Data`フィールドが存在しない場合、パニックが発生していた。(#1215) (@fukusuket)

## 2.10.0 [2023/10/31] "Halloween Release"

**改善:**

- 初心者のユーザのために有効にしたいルールを選択するようにスキャンウィザードを追加した。`-w, --no-wizard`オプションを追加すると、従来の形式でHayabusaを実行できる。(すべてのイベントとアラートをスキャンし、オプションを手動でカスタマイズする） (#1188) (@hitenkoku)
- `pivot-keywords-list`コマンドに`--include-tag`オプションを追加し、指定した`tags`フィールドを持つルールのみをロードするようにした。(#1195) (@hitenkoku)
- `pivot-keywords-list`コマンドに`--exclude-tag`オプションを追加し、指定した`tags`フィールドを持つルールをロードしないようにした。(#1195) (@hitenkoku)

**バグ修正:**

- まれにJSONフィールドが正しくパースされない状態を修正した。(#1145) (@hitenkoku)
- JSON出力で、`AllFieldInfo`は改行文字とタブ文字を除去していたが、出力するように修正した。 (#1189) (@hitenkoku)
- 標準出力のいくつかのフィールドでスペースが削除されて見づらくなっていたのを修正した。 (#1192) (@hitenkoku)

## 2.9.0 [2023/09/22] "Autumn Rain Release"

**改善:**

- ディレクトリパスの指定にバックスラッシュを使用すべきではないことを示すエラーメッセージを追加した。 (#1166) (@hitenkoku, 提案者: @joswr1ght)
- 一度に読み込むレコード数の最適化。(#1175) (@yamatosecurity)
- プログレスバー内にあるバックスラッシュの表示をスラッシュに変更した。 (#1172) (@hitenkoku)
- JSON形式で出力する際に、`count`ルールの`Details`フィールドを文字列にし、パースしやすくした。(#1179) (@hitenkoku)
- デフォルトのスレッド数をCPU数から、プログラムが使用すべきデフォルトの並列度の推定値(`std::thread::available_parallelism`)に変更した。(#1182) (@hitenkoku)

**バグ修正:**

- まれにJSONフィールドが正しくパースされない状態を修正した。(#1145) (@hitenkoku)

**その他:**

- CIを通すために`time`クレートを利用している更新されていない`hhmmss`クレートを除外した。 (#1181) (@hitenkoku)

## 2.8.0 [2023/09/01] "Double X Release"

**新機能:**

- フィールドマッピング設定に16進数値を10進数に変換する`HexToDecimal`機能に対応した。 (元の16進数のプロセスIDを変換するのに便利。) (#1133) (@fukusuket)
- `csv-timeline`と`json-timeline`に`-x, --recover-records`オプションを追加し、evtxのスラックスペースのファイルカービングによってevtxレコードを復元できるようにした。(#952) (@hitenkoku) (Evtxカービング機能は@forensicmattに実装された。)
- `csv-timeline`と`json-timeline`に`-X, --remove-duplicate-detections`オプションを追加した。(`-x`を使用する場合、重複データのあるバックアップログを含める場合などに便利。) (#1157) (@fukusuket)
- `csv-timeline`、`json-timeline`、`logon-summary`、`eid-metrics`、`pivot-keywords-list`、`search`コマンドに、直近のイベントだけをスキャンするための`--timeline-offset`オプションを追加した。 (#1159) (@hitenkoku)
- `search`コマンドに`-a, --and-logic`オプションを追加し、複数のキーワードをAND条件で検索できるようにした。 (#1162) (@hitenkoku)

**その他:**

- 出力プロファイルに、回復されたかどうかを示す `%RecoveredRecord%` フィールドを追加した。 (#1170) (@hitenkoku)

## 2.7.0 [2023/08/03] "SANS DFIR Summit Release"

**新機能:**

- `./rules/config/data_mapping`にある`.yaml`設定ファイルに基づいて、特定のコード番号が人間が読めるメッセージにマッピングされるようになった。(例:`%%2307`は、`ACCOUNT LOCKOUT`に変換される)。この動作は`-F, --no-field-data-mapping`オプションで無効にできる。(#177) (@fukusuket)
- `csv-timeline`コマンドに`-R, --remove-duplicate-data`オプションを追加し、`%Details%`、`%AllFieldInfo%`、`%ExtraFieldInfo%`列の重複フィールドデータを`DUP`という文字列に変換し、ファイルサイズの削減を行う。(#1056) (@hitenkoku)
- `csv-timeline`と`json-timeline`コマンドに`-P, --proven-rules`オプションを追加した。有効にすると、検知が証明されたルールしかロードされない。ロードされるルールは、`./rules/config/proven_rules.txt`の設定ファイルにルールIDで定義されている。 (#1115) (@hitenkoku)
- `csv-timeline`と`json-timeline`コマンドに`--include-tag`オプションを追加し、指定した`tags`フィールドを持つルールのみをロードするようにした。(#1108) (@hitenkoku)
- `csv-timeline`と`json-timeline`コマンドに`--exclude-tag`オプションを追加し、指定した`tags`フィールドを持つルールをロードしないようにした。(#1118) (@hitenkoku)
- `csv-timeline`と`json-timeline`コマンドに`--include-category`と`--exclude-category`オプションを追加した。`include-category`は、指定された`category`フィールドのルールのみをロードする。`--exclude-category`は、指定された`category`フィールドを持つルールをロードしない。 (#1119) (@hitenkoku)
- コンピュータ名に基づくイベント数をリストアップする`computer-metrics`コマンドを追加した。(#1116) (@hitenkoku)
- `csv-timeline`、`json-timeline`、`metrics`、`logon-summary`、`pivot-keywords-list`コマンドに`--include-computer`と`--exclude-computer`オプションを追加した。`include-computer`は、指定された`computer`の検知のみを出力する。`--exclude-computer`は、指定された`computer`の検知を除外する。 (#1117) (@hitenkoku)
- `csv-timeline`、`json-timeline`、`pivot-keywords-list`コマンドに`--include-eid`と`--exclude-eid`オプションを追加した。`include-eid`は、指定された`EventID`のみを検知対象とする。`--exclude-eid`は、指定された`EventID`を検知対象から除外する。 (#1130) (@hitenkoku)
- `json-timeline`コマンドに`-R, --remove-duplicate-data`オプションを追加し、`%Details%`、`%AllFieldInfo%`、`%ExtraFieldInfo%`フィールドの重複フィールドデータを`DUP`という文字列に変換し、ファイルサイズの削減を行う。(#1134) (@hitenkoku)

**改善:**

- 新しいログ形式の`.evtx`を使用するWindows Vistaがリリースされた2007年1月31日以前のタイムスタンプを持つ破損されたイベントレコードを無視するようにした。(#1102) (@fukusuket)
- `metrics`コマンドで`--output`オプションを指定した時に標準出力に結果を表示しないように変更した。 (#1099) (@hitenkoku)
- `csv-timeline` コマンドと `json-timeline` コマンドに `--tags` オプションを追加し、指定した `tags` フィールドを持つルールのみでスキャンできるようにした。(#1108) (@hitenkoku)
- `pivot-keywords-list`コマンドに対して、出力ファイルを上書きするための`-C, --clobber`オプションを追加した。 (#1125) (@hitenkoku)
- `metrics`コマンドを`eid-metrics`に変更した。 (#1128) (@hitenkoku)
- 端末の調整に余裕を持たせるため、プログレスバーの幅を減らした。 (#1135) (@hitenkoku)
- `search`コマンドで出力時間フォーマットのオプションをサポートした。(`--European-time`, `--ISO-8601`, `--RFC-2822`, `--RFC-3339`, `--US-time`, `--US-military-time`, `-U, --UTC`) (#1040) (@hitenkoku)
- プログレスバーのETA時間が正確でなかったため、経過時間に置き換えた。 (#1143) (@YamatoSecurity)
- `logon-summary`コマンドで`--timeline-start`と`--timeline-end`オプションを追加した。 (#1152) (@hitenkoku)

**バグ修正:**

- `metrics`と`logon-summary`コマンドのレコード数の表示が`csv-timeline`のコマンドでのレコード数の表示と異なっている状態を修正した。 (#1105) (@hitenkoku)
- パスの代わりにルールIDでルール数を数えるように変更した。 (#1113) (@hitenkoku)
- JSON出力で`CommandLine`フィールド内で誤ったフィールドの分割が行われてしまう問題を修正した。 (#1145) (@hitenkoku)
- `json-timeline`コマンドで`--timeline-start`と`--timeline-end`オプションが動作しなかったのを修正した。 (#1148) (@hitenkoku)
- `pivot-keywords-list`コマンドで`--timeline-start`と`--timeline-end`オプションが動作しなかったのを修正した。 (#1150) (@hitenkoku)

**その他:**

- ルールのIDベースでユニークな検出数をカウントするように修正した。 (#1111) (@hitenkoku)
- `--live_analysis`オプションを`--live-analysis`に変更した。 (#1139) (@hitenkoku)
- `metrics`コマンドを`eid-metrics`に変更した。 (#1128) (@hitenkoku)

## 2.6.0 [2023/06/16] "Ajisai Release"

**新機能:**

- Sigmaルールの`'|all':`キーワードに対応した。 (#1038) (@kazuminn)

**改善:**

- プロファイルに`%ExtraFieldInfo%`エイリアスを追加した。デフォルトの`standard`出力プロファイルに含まれるようになった。(#900) (@hitenkoku)
- 互換性のない引数に対するエラーメッセージを追加した。 (#1054) (@YamatoSecurity)
- 標準出力とHTML出力にプロファイル名を出力する機能を追加した。 (#1055) (@hitenkoku)
- HTML出力のルールアラートにルール作者名を表示するように修正した。 (#1065) (@hitenkoku)
- 端末サイズが小さくてもテーブルが壊れないように、テーブル幅を短くした。 (#1071) (@hitenkoku)
- `csv-timeline`、`json-timeline`、`metrics`、`logon-summary`、`search`コマンドに対して、出力ファイルを上書きするための`-C, --clobber`オプションを追加した。 (#1063) (@YamatoSecurity, @hitenkoku)
- HTML内にCSSと画像を組み込んだ。 (#1078) (@hitenkoku, 提案者: @joswr1ght)
- 出力時の速度向上。 (#1088) (@hitenkoku, @fukusuket)
- `metrics`コマンドは、テーブルが正しくレンダリングされるように、ワードラップを行うようになった。 (#1067) (@garigariganzy)
- `search`コマンドでJSON/JSONLの出力できるようにした。 (#1041) (@hitenkoku)

**バグ修正:**

- `json-timeline`コマンドを利用した出力で、`MitreTactics`、`MitreTags`、`OtherTags`フィールドが出力されていない問題を修正した。 (#1062) (@hitenkoku)
- `no-summary`オプションを使用した時にイベント頻度のタイムラインが出力されない問題を修正した。 (#1072) (@hitenkoku)
- `json-timline`コマンドの出力に制御文字が含まれる問題を修正した。 (#1068) (@hitenkoku)
- `metrics`コマンドでは、チャンネル名が小文字の場合、省略されなかった。 (#1066) (@garigariganzy)
- JSON出力内でいくつかのフィールドがずれてしまっていた問題を修正した。 (#1086) (@hitenkoku)

## 2.5.1 [2023/05/14] "Mothers Day Release"

**改善:**

- 新たに変換されたルールを使用する際のメモリ使用量を半分に削減した。(#1047) (@fukusuket)

**バグ修正:**

- `AccessMask`等のフィールド内の情報が空白で区切られていなかった状態を修正した。 (#1035) (@hitenkoku)
- JSON形式に出力時に複数の空白が一つの空白に変換されていた。 (#1048) (@hitenkoku)
- `pivot-keywords-list`コマンドで`--no-color`を使用した場合でも、結果がカラーで出力された。 (#1044) (@kazuminn)

## 2.5.0 [2023/05/07] "Golden Week Release"

**改善:**

- `search`コマンドに`-M, --multiline`オプションを追加した。 (#1017) (@hitenkoku)
- `search`コマンドの出力での不要な改行やタブを削除した。 (#1003) (@hitenkoku)
- 正規表現の不要なエスケープを許容し、パースエラーを減らす`regex`クレートを1.8に更新した。(#1018) (@YamatoSecurity)
- `csv-timeline`コマンドの出力で不要な空白文字の削除を行った。 (#1019) (@hitenkoku)
- `update-rules`コマンド使用時にハヤブサのバージョン番号の詳細を確認するようにした (#1028) (@hitenkoku)
- `search`コマンドの結果を時刻順にソートした。 (#1033) (@hitenkoku)
- `pivot-keywords-list`のターミナル出力の改善。 (#1022) (@kazuminn)

**バグ修正:**

- ruleで指定された値で`\`が最後の文字のときに、検知ができない問題を修正した。 (#1025) (@fukusuket)
- results summary内のInformationalレベルアラートの結果が同じ内容が2つ表示されている状態を修正した。 (#1031) (@hitenkoku)

## 2.4.0 [2023/04/19] "SANS Secure Korea Release"

**新機能:**

- 指定されたキーワードに合致したレコードを検索する`search`コマンドを追加した。 (#617) (@itiB, @hitenkoku)
- 指定された正規表現に合致したレコードを検索する`-r, --regex`オプションを`search`コマンドに追加した。 (#992) (@itiB)
- Aho-Corasickクレートをversino1.0に更新した。 (#1013) (@hitenkoku)

**改善:**

- コマンドの表示順を辞書順に並べ替えた。 (#991) (@hitenkoku)
- `csv-timeline`, `json-timeline`, `search`コマンドの `AllFieldInfo`の出力に`Event.UserData`の属性情報を追加した。 (#1006) (@hitenkoku)

**バグ修正:**

- v2.3.3にて`-T, --visualize-timeline`データの中に存在していないタイムスタンプがイベント頻度のタイムラインに出力するバグを修正した。 (#977) (@hitenkoku)

## 2.3.3 [2023/04/07] "Sakura Release"

**改善:**

- ファイル(CSV, JSON, JSONL)出力の際にルールの`level`の余分なスペースを削除した。 (#979) (@hitenkoku)
- `-M, --multiline`オプション利用時にルール作者名の出力を複数行出力対応をした。 (#980) (@hitenkoku)
- Stringの代わりにCoWを利用することで、約5%の速度向上を実現した。 (#984) (@hitenkoku)
- Clapの新バージョンでロゴ後のメッセージとUsageテキストの出力色が緑にならないように修正した。 (#989) (@hitenkoku)

**バグ修正:**

- v2.3.0にて`level-tuning`コマンド実行時にクラッシュする問題を修正した。 (#977) (@hitenkoku)

## 2.3.2 [2023/03/22] "TMCIT Release-3"

**改善:**

- `csv-timeline`コマンドに`-M, --multiline`オプションを追加した。 (#972) (@hitenkoku)

## 2.3.1 [2023/03/18] "TMCIT Release-2"

**改善:**

- `csv-timeline`の出力のフィールドでダブルクォートを追加した。 (#965) (@hitenkoku)
- `logon-summary`の見出しを更新した。 (#964) (@yamatosecurity)
- `--enable-deprecated-rules`の`-D`ショートオプションと`--enable-unsupported-rules`の`-u`ショートオプションを追加した。(@yamatosecurity)
- Filteringセクションのオプションの表示順とヘルプの表示内容を修正した。 (#969) (@hitenkoku)

**バグ修正:**

- v2.3.0にて`update-rules`コマンド実行時にクラッシュする問題を修正した。 (#965) (@hitenkoku)
- コマンドプロンプトとPowerShellプロンプトではヘルプメニューのタイトルに長いアンダーバーが表示されていた問題が修正された。 (#911) (@yamatosecurity)

## 2.3.0 [2023/03/16] "TMCIT Release"

**新機能:**

- 新たなパイプキーワードの`|cidr`に対応した。 (#961) (@fukusuket)
- 新たなキーワードの`1 of selection*`と`all of selection*`に対応した。 (#957) (@fukusuket)
- 新たなパイプキーワードの`|contains|all`に対応した。 (#945) (@hitenkoku)
- ステータスが`unsupported`となっているルールの件数を表示した。ステータス`unsupported`のルールも検知対象とするオプションとして`--enable-supported-rules`オプションを追加した。 (#949) (@hitenkoku)

**改善:**

- 文字列が含まれているかの確認処理を改善することで約2-3%の速度改善をした。(#947) (@hitenkoku)

**バグ修正:**

- 一部のイベントタイトルが定義されていても、`metrics`コマンドで`Unknown`と表示されることがあった。 (#943) (@hitenkoku)

## 2.2.2 [2023/2/22] "Ninja Day Release"

**新機能:**

- 新たなパイプキーワード(`|base64offset|contains`)に対応した。 (#705) (@hitenkoku)

**改善:**

- オプションのグループ分けを再修正した。(#918)(@hitenkoku)
- JSONL形式のログを読み込む際のメモリ使用量を約75%削減した。 (#921) (@fukusuket)
- `rules/config/generic_abbreviations.txt`によってチャンネル名の一般的な単語名を省略する機能をmetrics、json-timeline、csv-timelineに追加した。 (#923) (@hitenkoku)
- evtxクレートを更新することにより、パースエラーを減少させた。 (@YamatoSecurity)
- Provider名(`%Provider%`)のフィールドに対する出力文字の省略機能を追加した。 (#932) (@hitenkoku)
- `metrics`コマンドで`-d`オプションが指定されたときに最初と最後のイベントのタイムスタンプを表示する機能を追加した。 (#935) (@hitenkoku)
- 結果概要に最初と最後のイベントのタイムスタンプを表示した。 (#938) (@hitenkoku)
- `logon-summary`と`metrics`コマンドに時刻表示のオプションを追加した. (#938) (@hitenkoku)
- `json-output`コマンドで`--output`で出力される結果に`\r`、`\n`、`\t`を出力するようにした。 (#940) (@hitenkoku)

**バグ修正:**

- `logon-summary`と`metrics`コマンドで、最初と最後のタイムスタンプが出力されない不具合を修正した。 (#920) (@hitenkoku)
- `metrics`コマンドで全てのイベントのタイトルが表示されない問題を修正した。 (#933) (@hitenkoku)

## 2.2.0 [2022/2/12] "SECCON Release"

**新機能:**

- JSON形式のイベントログファイルの入力(`-J, --JSON-input`)に対応した。 (#386) (@hitenkoku)
- MaxMindのGeoIPデータベースに基づき、送信元および送信先IPアドレスのASN組織、都市、国を出力することによるログエンリッチメント(`-G, --GeoIP`)を実現した。 (#879) (@hitenkoku)
- `-e, --exact-level`オプションで指定したレベルに対する結果のみを取得する機能を追加した。 (#899) (@hitenkoku)

**改善:**

- HTMLレポートの出力に実行したコマンドラインを追加した。 (#877) (@hitenkoku)
- イベントIDの完全比較を行うことで、約3%の速度向上とメモリ使用量の削減を実現した。 (#882) (@fukusuket)
- 正規表現使用前のフィルタリングにより、約14%の速度向上とメモリ使用量の削減を実現した。 (#883) (@fukusuket)
- 正規表現ではなく大文字小文字を区別しない比較により、約8%の速度向上とメモリ使用量の削減を実現した。 (#884) (@fukusuket)
- ワイルドカード表現における正規表現の使用量を削減することで、約5%の速度向上とメモリ使用量の削減を実現した。 (#890) (@fukusuket)
- 正規表現の使用を避けることで、さらなる高速化とメモリ使用量の削減を実現した。 (#894) (@fukusuket)
- 正規表現の使用量を減らすことで、約3%の速度向上と約10%のメモリ使用量削減を実現した。 (#898) (@fukuseket)
- ライブラリの更新によって`-T, --visualize-timeline`の出力を複数行にするように変更した。 (#902) (@hitenkoku)
- JSON/L形式のログを読み込む際のメモリ使用量を約50%削減した。 (#906) (@fukusuket)
- Longオプションを基にしたオプションの並べ替えを行った。 (#904) (@hitenkoku)
- `-J, --JSON-input`オプションを`logon-summary`, `metrics`, `pivot-keywords-list`コマンドに対応させた。 (#908) (@hitenkoku)

**バグ修正:**

- ルールの条件にバックスラッシュが4つある場合、ルールがマッチしない不具合を修正した。 (#897) (@fukuseket)
- JSON出力では、PowerShell EID 4103をパースする際に`Payload`フィールドが複数のフィールドに分離されるバグを修正した。(#895) (@hitenkoku)
- ファイルサイズ取得の際にpanicが発生するのを修正した。 (#914) (@hitenkoku)

**脆弱性修正:**

- ルールや設定ファイルを更新する際に起こりうるSSH MITM攻撃(CVE-2023-22742)を防ぐため、git2およびgitlib2クレートを更新した。 (#888) (@YamatoSecurity)

## 2.1.0 [2023/01/10] "Happy Year of the Rabbit Release"

**改善:**

- 速度の改善。 (#847) (@hitenkoku)
- 出力の改善を行うことによる速度の改善。 (#858) (@fukusuket)
- 実行ごとに同じ時間の検知の出力の順番のソートを行っていないのを修正した。 (#827) (@hitenkoku)

**バグ修正:**

- ログオン情報の出力機能で`--output`を指定したときにログオン成功のcsv出力ができない問題を修正した。 (#849) (@hitenkoku)
- `-J, --jsonl`を指定したときに不要な改行が含まれていたため修正した。 (#852) (@hitenkoku)

## 2.0.0 [2022/12/24] "Merry Christmas Release"

**新機能:**

- コマンドの使用方法とヘルプメニューはサブコマンドで行うようにした。 (#656) (@hitenkoku)

## 1.9.0 [2022/12/24] "Merry Christmas Release"

**新機能:**

- 新たなパイプキーワード(`|endswithfield`)に対応した。 (#740) (@hach1yon)
- 実行時のメモリ利用率を表示する機能を追加した。`--debug`オプションで利用可能。 (#788) (@fukusuket)

**改善:**

- Clap Crateパッケージの更新。更新の関係で`--visualize-timeline` のショートオプションの`-V`を`-T`に変更した。 (#725) (@hitenkoku)
- ログオン情報の出力でログオンタイプ、送信元の端末名とIPアドレス等を出力できるようにした。また、ログオンに失敗の一覧も出力するようにした。 (#835) (@garigariganzy @hitenkoku)
- 速度とメモリ使用の最適化。 (#787) (@fukusuket)
- イースターエッグのASCIIアートをカラー出力するようにした。 (#839) (@hitenkoku)
- `--debug`オプションをオプションの一覧から非表示にした。 (#841) (@hitenkoku)

**バグ修正:**

- コマンドプロンプトで`-d`オプションを設定した際にダブルクォーテーションで囲んだときにevtxファイルの収集ができていないバグを修正した。 (#828) (@hitenkoku)
- ルールのパースエラーが発生した際に不必要な改行が出力されていたのを修正した。 (#829) (@hitenkoku)

## 1.8.1 [2022/11/21]

**改善:**

- インポートしているcrateのRustバージョンによるビルドエラーを回避するためにCargo.tomlに`rust-version`を追加した。(#802) (@hitenkoku)
- メモリ使用の削減。 (#806) (@fukusuket)
- WEC機能を利用したevtxファイルのレンダーされたメッセージを出力するための`%RenderedMessage%`フィールドを追加した。 (#760) (@hitenkoku)

**バグ修正:**

- `Data`フィールドを使ったルールが検知できていない問題を修正した。 (#775) (@hitenkoku)
- プロファイルの出力で`%MitreTags%` と`%MitreTactics%` の出力が抜け落ちてしまう問題を修正した。 (#780) (@fukusuket)

## 1.8.0 [2022/11/07]

**新機能:**

- 新たな時刻表示のオプションとして`--ISO-8601`を追加した。 (#574) (@hitenkoku)

**改善:**

- イベントIDによるフィルタリングをデフォルトでは動作しないようにした。イベントIDフィルタを利用するためのオプション`-e, --eid-filter`を追加した。 (#759) (@hitenkoku)
- 異なるユーザアカウントで新しいルールをダウンロードしようとしたときに、分かりやすいエラーメッセージを表示する。 (#758) (@fukusuket)
- 合計およびユニークな検知数の情報をHTMLレポートに追加した。 (#762) (@hitenkoku)
- JSONの出力の中にある各検知内容のオブジェクトを持つ不要な配列の構造を削除した。 (#766)(@hitenkoku)
- プロファイルで出力できる情報にルール作成者(`%RuleAuthor%`)、 ルール作成日(`%RuleCreationDate%`)、 ルール修正日(`%RuleModifiedDate%`)、ルールステータス(`%Status%`)を追加した。 (#761) (@hitenkoku)
- JSON出力のDetailsフィールドをオブジェクト形式で出力するように変更した。 (#773) (@hitenkoku)
- `build.rs`を削除し、メモリアロケータをmimallocに変更した。Intel系OSでは20-30%の速度向上が見込める。 (#657) (@fukusuket)
- プロファイルの`%RecordInformation%` エイリアスを `%AllFieldInfo%` に変更した。 AllFieldInfoフィールドをJSONオブジェクト形式で出力するように変更した。 (#750) (@hitenkoku)
- AllFieldInfoフィールドのJSONオブジェクト内で利用していたHBFI-プレフィックスを廃止した。 (#791) (@hitenkoku)
- `--no-summary`  オプションを使用したときに、表示しないルール作者および検知回数の集計を省略した。(Velociraptorエージェントを利用するときに有用です。10%はこのオプションの付与により高速化します) (#780) (@hitenkoku)
- メモリ使用量を少なくし、処理速度を改善した。 (#778 #790) (@hitenkoku)
- 検知したルール作者のリストが空の時にルール作者のリストを表示しないように修正した。(#795) (@hitenkoku)
- プロファイルで出力できる情報にルールID(`%RuleID%`)、プロバイダー名情報(`%Provider%`)を追加した。 (#794) (@hitenkoku)

**バグ修正:**

- ルール作者数の集計に誤りがあったのを修正した。 (#783) (@hitenkoku)

## 1.7.2 [2022/10/17]

**新機能:**

- 利用可能な出力プロファイルの一覧を出力する`--list-profiles` オプションを追加した。 (#746) (@hitenkoku)

**改善:**

- 見やすくするためにファイル保存の出力をする位置とupdateオプションの出力を変更した。 (#754) (@YamatoSecurity)
- 検知したルールの作者名の最大文字数を40文字にした。 (#751) (@hitenkoku)

**バグ修正:**

- フィールド内にドライブレター(ex c:)が入っていた場合JSON/JSONL出力機能のフィールドの値がずれてしまっていたバグを修正した。 (#748) (@hitenkoku)

## 1.7.1 [2022/10/10]

**改善:**

- より正確な結果を出力するために、チャンネルとEIDの情報を`rules/config/channel_eid_info.txt`に基づいてチェックするようにした。 (#463) (@garigariganzy)
- 検知ルールを利用しないオプション(`-M`と`-L`オプション)の時のメッセージの出力内容を修正した。 (#730) (@hitenkoku)
- 検出したルールの作者名を標準出力に追加した。 (#724) (@hitenkoku)
- チャンネル情報が`null`となっているレコード(ETWイベント)を検知およびmetricの対象から除外した。 (#727) (@hitenkoku)

**バグ修正:**

- mericオプションのEventIDのキー名の数え上げが原因となっていたイベント集計の誤りを修正した。 (#729) (@hitenkoku)

## 1.7.0 [2022/09/29]

**新機能:**

- HTMLレポート機能 (`-H, --html-report`)の追加。 (#689) (@hitenkoku, @nishikawaakira)

**改善:**

- EventID解析のオプションをmetricsオプションに変更した。(旧: `-s, --statistics` -> 新: `-M, --metrics`) (#706) (@hitenkoku)
- ルール更新オプション(`-u`)を利用したときにHayabusaの新バージョンがないかを確認し、表示するようにした。 (#710) (@hitenkoku)
- HTMLレポート内にロゴを追加した。 (#714) (@hitenkoku)
- メトリクスオプション(`-M --metrics`)もしくはログオン情報(`-L --logon-summary`)と`-d`オプションを利用した場合に1つのテーブルで表示されるように修正した。 (#707) (@hitenkoku)
- メトリクスオプションの結果出力にチャンネル列を追加した。 (#707) (@hitenkoku)
- メトリクスオプション(`-M --metrics`)もしくはログオン情報(`-L --logon-summary`)と`-d`オプションを利用した場合に「First Timestamp」と「Last Timestamp」の出力を行わないように修正した。 (#707) (@hitenkoku)
- メトリクスオプションとログオン情報オプションに対してcsv出力機能(`-o --output`)を追加した。 (#707) (@hitenkoku)
- メトリクスオプションの出力を検出回数と全体の割合が1つのセルで表示されていた箇所を2つの列に分けた。 (#707) (@hitenkoku)
- メトリクスオプションとログオン情報の画面出力に利用していたprettytable-rsクレートをcomfy_tableクレートに修正した. (#707) (@hitenkoku)
- HTMLレポート内にfavicon.pngを追加した。 (#722) (@hitenkoku)

## v1.6.0 [2022/09/16]

**新機能:**

- 解析結果をJSONに出力する機能(`-j, --json-timeline`)を追加した。 (#654) (@hitenkoku)
- 解析結果をJSONL形式で出力する機能 (`-J, --jsonl` )を追加した。 (#694) (@hitenkoku)

**改善:**

- 結果概要に各レベルで検知した上位5つのルールを表示するようにした。 (#667) (@hitenkoku)
- 結果概要を出力しないようにするために `--no-summary` オプションを追加した。 (#672) (@hitenkoku)
- 結果概要の表示を短縮させた。 (#675 #678) (@hitenkoku)
- channel_abbreviations.txtによるChannelフィールドのチェックを大文字小文字の区別をなくした。 (#685) (@hitenkoku)
- 出力結果の区切り文字を`|`から`‖`に変更した。 (#687) (@hitenkoku)
- 結果概要の検知数と総イベント数の数に色付けを行い見やすくした。 (#690) (@hitenkoku)
- evtxクレートを0.8.0にアップデート。(ヘッダーや日付の値が無効な場合の処理が改善された。)
- 出力プロファイルの更新。（@YamatoSecurity)

**バグ修正:**

- ログオン情報の要約オプションを追加した場合に、Hayabusaがクラッシュしていたのを修正した。 (#674) (@hitenkoku)
- configオプションで指定したルールコンフィグの読み込みができていない問題を修正した。 (#681) (@hitenkoku)
- 結果概要のtotal eventsで読み込んだレコード数が出力されていたのを、検査対象にしているevtxファイルの実際のレコード数に修正した。 (#683) (@hitenkoku)

## v1.5.1 [2022/08/20]

**改善:**

- TimesketchにインポートできるCSV形式を出力するプロファイルを追加して、v1.5.1を再リリースした。 (#668) (@YamatoSecurity)

## v1.5.1 [2022/08/19]

**バグ修正:**

- Critical, medium、lowレベルのアラートはカラーで出力されていなかった。 (#663) (@fukusuket)
- `-f`で存在しないevtxファイルが指定された場合は、Hayabusaがクラッシュしていた。 (#664) (@fukusuket)

## v1.5.0 [2022/08/18]

**新機能:**

- `config/profiles.yaml`と`config/default_profile.yaml`の設定ファイルで、出力内容をカスタマイズできる。 (#165) (@hitenkoku)
- 対象のフィールドがレコード内に存在しないことを確認する `null` キーワードに対応した。 (#643) (@hitenkoku)

**改善:**

- ルールのアップデート機能のルールパスの出力から./を削除した。 (#642) (@hitenkoku)
- MITRE ATT&CK関連のタグとその他タグを出力するための出力用のエイリアスを追加した。 (#637) (@hitenkoku)
- 結果概要の数値をカンマをつけて見やすくした。 (#649) (@hitenkoku)
- `-h`オプションでメニューを使いやすいようにグループ化した。 (#651) (@YamatoSecurity and @hitenkoku)
- 結果概要内の検知数にパーセント表示を追加した。 (#658) (@hitenkoku)

**バグ修正:**

- aggregation conditionのルール検知が原因で検知しなかったイベント数の集計に誤りがあったので修正した。 (#640) (@hitenkoku)
- 一部のイベント（0.01%程度）が検出されないレースコンディションの不具合を修正した。 (#639 #660) (@fukusuket)

## v1.4.3 [2022/08/03]

**バグ修正:**

- VC再頒布パッケージがインストールされていない環境でエラーが発生している状態を修正した。 (#635) (@fukusuket)

## v1.4.2 [2022/07/24]

**改善:**

- `--update-rules` オプションを利用する時に、更新対象のレポジトリを`--rules`オプションで指定できるようにした。 (#615) (@hitenkoku)
- 並列処理の改善による高速化。 (#479) (@kazuminn)
- `--output`オプションを利用したときのRulePathをRuleFileに変更した。RuleFileは出力するファイルの容量を低減させるためにファイル名のみを出力するようにした。 (#623) (@hitenkoku)

**バグ修正:**

- `cargo run`コマンドでhayabusaを実行するとconfigフォルダの読み込みエラーが発生する問題を修正した。 (#618) (@hitenkoku)

## v1.4.1 [2022/06/30]

**改善:**

- ルールや`./rules/config/default_details.txt` に対応する`details`の記載がない場合、すべてのフィールド情報を結果の``Details`列に出力するようにした (#606) (@hitenkoku)
- `--deep-scan`オプションの追加。 このオプションがない場合、`config/target_event_ids.txt`で指定されたイベントIDのみをスキャン対象とします。 このオプションをつけることですべてのイベントIDをスキャン対象とします。(#608) (@hitenkoku)
- `-U, --update-rules`オプションで`channel_abbreviations.txt`、`statistics_event_info.txt`、`target_event_IDs.txt`を更新できるように、`config`ディレクトリから`rules/config`ディレクトリに移動した。

## v1.4.0 [2022/06/26]

**新機能:**

- `--target-file-ext` オプションの追加。evtx以外の拡張子を指定する事ができます。ただし、ファイルの中身の形式はevtxファイル形式である必要があります。 (#586) (@hitenkoku)
- `--exclude-status` オプションの追加。ルール内の`status`フィールドをもとに、読み込み対象から除外するフィルタを利用することができます。 (#596) (@hitenkoku)

**改善:**

- ルール内に`details`フィールドがないときに、`rules/config/default_details.txt`に設定されたデフォルトの出力を行えるようにした。 (#359) (@hitenkoku)
- Clap Crateパッケージの更新 (#413) (@hitenkoku)
- オプションの指定がないときに、`--help`と同じ画面出力を行うように変更した。(#387) (@hitenkoku)
- hayabusa.exeをカレントワーキングディレクトリ以外から動作できるようにした。 (#592) (@hitenkoku)
- `output` オプションで指定されファイルのサイズを出力するようにした。 (#595) (@hitenkoku)

**バグ修正:**

- カラー出力で長い出力があった場合にエラーが出て終了する問題を修正した。 (#603) (@hitenkoku)
- `Excluded rules`の合計で`rules/tools/sigmac/testfiles`配下のテストルールも入っていたので、無視するようにした。 (#602) (@hitenkoku)

## v1.3.2 [2022/06/13]

- evtxクレートを0.7.2から0.7.3に更新し、パッケージを全部更新した。 (@YamatoSecurity)

## v1.3.1 [2022/06/13]

**新機能:**

- ルール内の`details`で複数の`Data`レコードから特定のデータを指定して出力できるようにした。 (#487) (@hitenkoku)
- 読み込んだルールのステータス情報の要約を追加した。 (#583) (@hitenkoku)

**改善:**

- LinuxとmacOSのバイナリサイズをより小さくするために、デバッグシンボルをストリップします。(#568) (@YamatoSecurity)
- Crateパッケージの更新 (@YamatoSecurity)
- 新たな時刻表示のオプションとして`--US-time`、`--US-military-time`、`--European-time`の3つを追加した (#574) (@hitenkoku)
- `--rfc-3339` オプションの時刻表示形式を変更した。 (#574) (@hitenkoku)
- `-R/ --display-record-id`オプションを`-R/ --hide-record-id`に変更。レコードIDはデフォルトで出力するようにして`-R`オプションを付けた際に表示しないように変更した。(#579) (@hitenkoku)
- ルール読み込み時のメッセージを追加した。 (#583) (@hitenkoku)
- `rules/tools/sigmac/testfiles`内のテスト用のymlファイルを読み込まないようにした. (#602) (@hitenkoku)

**バグ修正:**

- 対応するオプションを付与していないときにもRecordIDとRecordInformationの列が出力されていたのを修正した。 (#577) (@hitenkoku)

## v1.3.0 [2022/06/06]

**新機能:**

- `--visualize-timeline`オプションで検知されたイベントが5つ以上の時、イベント頻度のタイムラインを作成するようにした。 (#533, #566) (@hitenkoku)
- `--all-tags`オプションでルールにある全てのtagsを、outputで指定したcsvのMitreAttackの列に出力するようにした。 (#525) (@hitenkoku)
- `-R` / `--display-record-id` オプションの追加。evtx file内のレコードを特定するレコードID`<Event><System><EventRecordID>`が出力できるようになった。 (#548) (@hitenkoku)
- レベルごとの検知数が最も多い日を表示するようにした。 (#550) (@hitenkoku)
- レベルごとの検知数上位3つのコンピュータ名を表示するようにした。 (#557)(@hitenkoku)

**改善:**

- ルールの`details`でeventkey_alias.txtやEvent.EventData内に存在しない情報を`n/a` (not available)と表記するようにした。(#528) (@hitenkoku)
- 読み込んだイベント数と検知しなかったイベント数を表示するようにした。 (#538) (@hitenkoku)
- 新しいロゴに変更した。(#536) (@YamatoSecurity)
- evtxファイルのファイルサイズの合計を出力するようにした。(#540) (@hitenkoku)
- ロゴの色を変更した (#537) (@hitenkoku)
- Channelの列にchannel_abbrevations.txtに記載されていないチャンネルも表示するようにした。(#553) (@hitenkoku)
- `Ignored rules`として集計されていた`Exclude rules`、`Noisy rules`、`Deprecated rules`に分けて表示するようにした。 (#556) (@hitenkoku)
- `output`オプションが指定されているときに、ファイル出力中のメッセージを表示するようにした。 (#561) (@hitenkoku)

**バグ修正:**

- `--start-timeline`、`--end-timeline`オプションが動かなかったのを修正した。 (#546) (@hitenkoku)
- ルール内の`level`が正しくない場合に検知数が最も多い日の集計の際にcrashが起きるのを修正した。 (#560) (@hitenkoku)

## v1.2.2 [2022/05/20]

**新機能:**

- ログオン情報の要約の機能の追加。 (`-L` / `--logon-summary`) (@garigariganzy)

**改善:**

- カラー出力はデフォルトで有効になって、コマンドプロンプトとPowerShellプロンプトに対応している。 (@hitenkoku)

**バグ修正:**

- `rules`フォルダが存在するが、レポジトリがダウンロードされていない場合は、ルール更新が失敗していたが、修正した。(#516) (@hitenkoku)
- .gitフォルダ内にあるymlファイルが一部のWindows環境で読み込まれた際にエラーが発生していたが、修正した。(#524)(@hitenkoku)
- 1.2.1バイナリで表示する誤ったバージョン番号の修正。

## v1.2.1 [2022/04/20] Black Hat Asia Arsenal 2022 RC2

**新機能:**

- `./config/channel_abbreviations`の設定ファイルにより、`Channel`列も出力されるようになった。 (@hitenkoku)
- ルールとルールの設定ファイルは強制的に上書きされる。 (@hitenkoku)

**バグ修正:**

- ルールがnoisyもしくはexcludedと設定された場合は、`--level-tuning`オプションで`level`が更新されなかったが、修正した。 (@hitenkoku)

## v1.2.0 [2022/04/15] Black Hat Asia Arsenal 2022 RC1

**新機能:**

- `-C / --config` オプションの追加。検知ルールのコンフィグを指定することが可能。(Windowsでのライブ調査に便利) (@hitenkoku)
- `|equalsfield` と記載することでルール内で二つのフィールドの値が一致するかを記載に対応。 (@hach1yon)
- `-p / --pivot-keywords-list` オプションの追加。攻撃されたマシン名や疑わしいユーザ名などの情報をピボットキーワードリストとして出力する。 (@kazuminn)
- `-F / --full-data`オプションの追加。ルールの`details`で指定されたフィールドだけではなく、全フィールド情報を出力する。(@hach1yon)
- `--level-tuning` オプションの追加。ルールの検知ファイルを設定したコンフィグファイルに従って検知レベルをチューニングすることが可能(@itib、@hitenkoku)

**改善:**

- 検知ルールとドキュメントの更新。 (@YamatoSecurity)
- MacとLinuxのバイナリに必要なOpenSSLライブラリを静的コンパイルした。 (@YamatoSecurity)
- タブ等の文字が含まれたフィールドに対しての検知性能の改善。 (@hach1yon、@hitenkoku)
- eventkey_alias.txt内に定義されていないフィールドをEvent.EventData内を自動で検索することが可能。 (@kazuminn、@hitenkoku)
- 検知ルールの更新時、更新されたルールのファイル名が表示される。 (@hitenkoku)
- ソースコードにあるClippyの警告を修正。 (@hitenkoku、@hach1yon)
- イベントIDとタイトルが記載されたコンフィグファイルの名前を `timeline_event_info.txt` から `statistics_event_info.txt`に変更。 (@YamatoSecurity、 @garigariganzy)
- 64bit Windowsで32bit版のバイナリを実行しないように修正(@hitenkoku)
- MITRE ATT&CKのデータの出力を`output_tag.txt`で修正できるように修正(@hitenkoku)
- 出力にChannel名のカラムを追加(@hitenkoku)

**バグ修正:**

- `.git` フォルダ内にある `.yml` ファイルがパースエラーを引き起こしていた問題の修正。 (@hitenkoku)
- テスト用のルールファイルの読み込みエラーで不必要な改行が発生していた問題の修正。 (@hitenkoku)
- Windows Terminalのバグで標準出力が途中で止まる場合がありましたが、Hayabusa側で解決しました。 (@hitenkoku)

## v1.1.0 [2022/03/03]

**新機能:**

- `-r / --rules`オプションで一つのルール指定が可能。(ルールをテストする際に便利！) (@kazuminn)
- ルール更新オプション (`-u / --update-rules`): [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)レポジトリにある最新のルールに更新できる。 (@hitenkoku)
- ライブ調査オプション (`-l / --live-analysis`): Windowsイベントログディレクトリを指定しないで、楽にWindows端末でライブ調査ができる。(@hitenkoku)

**改善:**

- ドキュメンテーションの更新。 (@kazuminn、@itiB、@hitenkoku、@YamatoSecurity)
- ルールの更新。(Hayabusaルール: 20個以上、Sigmaルール: 200個以上) (@YamatoSecurity)
- Windowsバイナリは静的でコンパイルしているので、Visual C++ 再頒布可能パッケージをインストールする必要はない。(@hitenkoku)
- カラー出力 (`-c / --color`) True Colorに対応しているターミナル(Windows Terminal、iTerm2等々)ではカラーで出力できる。(@hitenkoku)
- MITRE ATT&CK戦略が出力される。(@hitenkoku)
- パフォーマンスの改善。(@hitenkoku)
- exclude_rules.txtとnoisy_rules.txtの設定ファイルのコメント対応。(@kazuminn)
- より速いメモリアロケータの利用。 (Windowsの場合はrpmalloc、macOS/Linuxの場合は、jemalloc) (@kazuminn)
- Cargo crateの更新。 (@YamatoSecurity)

**バグ修正:**

- `cargo update`がより安定するために、clapのバージョンを固定した。(@hitenkoku)
- フィールドのタブや改行がある場合に、ルールが検知しなかったので、修正した。(@hitenkoku)

## v1.0.0-Release 2 [2022/01/27]

- アンチウィルスに誤検知されたExcelの結果ファイルの削除。(@YamatoSecurity)
- Rustのevtxライブラリを0.7.2に更新。 (@YamatoSecurity)

## v1.0.0 [2021/12/25]

- 最初のリリース