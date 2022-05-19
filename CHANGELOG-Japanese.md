# 変更点

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
