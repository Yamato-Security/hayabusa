# 変更点

##v1.2.0 [2022/04/??]
**新機能:**
- Specify config directory (`-C / --config`): Can easily perform live analysis on Windows machines without specifying the Windows event log directory. (@hitenkoku) 
- Added the `|equalsfield` aggregator in order to write rules that compare if two fields are equal or not. (@hach1yon)
- Pivot keyword list generator feature (`-p / --pivot-keywords-list): Will generate a list of keywords to grep for to quickly identify compromised machines, suspicious usernames, files, etc... (@kazuminn)

**改善:**
- Updated detection rules and documentation. (@YamatoSecurity)
- Mac and Linux binaries now statically compile the openssl libraries. (@YamatoSecurity)
- Performance and accuracy improvement for fields with tabs, etc... in them. (@hach1yon)
- Fields that are not defined in eventkey_alias.txt will automatically be searched in Event.EventData. (@kazuminn)
- When updating rules, the names of new rules as well as the count will be displayed. (@hitenkoku)
- Removed all clippy warnings from the source code. (@hitenkoku and @hac1yon)
- Updated the event ID and title config file (`timeline_event_info.txt`) and changed name to `statistics_event_info.txt`. (@YamatoSecurity and @garigariganzy)

**バグ修正:**
- `.yml` files in the `.git` folder would cause parse errors so they are not ignored. (@hitenkoku)

##v1.1.0 [2022/03/03]
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