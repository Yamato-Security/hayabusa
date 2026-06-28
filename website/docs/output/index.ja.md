# タイムライン出力

## 出力プロファイル

Hayabusaの`config/profiles.yaml`設定ファイルでは、５つのプロファイルが定義されています:

1. `minimal`
2. `standard` (デフォルト)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

このファイルを編集することで、簡単に独自のプロファイルをカスタマイズしたり、追加したりすることができます。
`set-default-profile --profile <profile>`コマンドでデフォルトのプロファイルを変更することもできます。
利用可能なプロファイルとそのフィールド情報を表示するには、`list-profiles`コマンドを使用してください。

### 1. `minimal`プロファイルの出力

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. `standard`プロファイルの出力

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. `verbose`プロファイルの出力

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. `all-field-info`プロファイルの出力

最小限の`details`情報を出力する代わりに、イベントにあるすべての`EventData`フィールド情報(`%AllFieldInfo%`)が出力されます。フィールド名は元々のフィールド名になります。

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. `all-field-info-verbose`プロファイルの出力

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. `super-verbose`プロファイルの出力

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. `timesketch-minimal`プロファイルの出力

[Timesketch](https://timesketch.org/)にインポートできるプロファイル。

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. `timesketch-verbose`プロファイルの出力

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### プロファイルの比較

以下のベンチマークは、2018年製のLenovo P51 (CPU: Xeon 4コア / メモリ: 64GB)上で3GBのEVTXデータに対して3891件のルールを有効にして実施されました。(2023/06/01)

| プロファイル | 処理時間 | 結果のファイルサイズ | ファイルサイズ増加 |
| :---: | :---: | :---: | :---: |
| minimal | 8分50秒 | 770 MB | -30% |
| standard (デフォルト) | 9分00秒 | 1.1 GB | 無し |
| verbose | 9分10秒 | 1.3 GB | +20% |
| all-field-info | 9分3秒 | 1.2 GB | +10% |
| all-field-info-verbose | 9分10秒 | 1.3 GB | +20% |
| super-verbose | 9分12秒 | 1.5 GB | +35% |

### プロファイルのフィールドエイリアス

ビルトインの出力プロファイルで出力できる情報は以下の通り:

| エイリアス名 | Hayabusaの出力情報 |
| :--- | :--- |
|%AllFieldInfo% | すべてのフィールド情報。 |
|%Channel% |  ログ名。イベントログの`<Event><System><EventID>`フィールド。 |
|%Computer% | イベントログの`<Event><System><Computer>`フィールド。 |
|%Details% | YML検知ルールの`details`フィールドから来ていますが、このフィールドはHayabusaルールにしかありません。このフィールドはアラートとイベントに関する追加情報を提供し、ログのフィールドから有用なデータを抽出することができます。イベントキーのマッピングが間違っている場合、もしくはフィールドが存在しない場合で抽出ができなかった箇所は`n/a` (not available)と記載されます。YML検知ルールに`details`フィールドが存在しない時のdetailsのメッセージを`./rules/config/default_details.txt`で設定できます。`default_details.txt`では`Provider Name`、`EventID`、`details`の組み合わせで設定することができます。default_details.txt`やYML検知ルールに対応するルールが記載されていない場合はすべてのフィールド情報を出力します。 |
|%ExtraFieldInfo% | %Details%で出力されなかったフィールドデータを出力する。 |
|%EventID% | イベントログの`<Event><System><EventID>`フィールド。 |
|%EvtxFile% | アラートまたはイベントを起こしたevtxファイルへのパス。 |
|%Level% | YML検知ルールの`level`フィールド。(例：`informational`、`low`、`medium`、`high`、`critical`) |
|%MitreTactics% | MITRE ATT&CKの[戦術](https://attack.mitre.org/tactics/enterprise/) (例: Initial Access、Lateral Movement等々） |
|%MitreTags% | MITRE ATT&CKの戦術以外の情報。attack.g(グループ)、attack.t(技術)、attack.s(ソフトウェア)の情報を出力する。 |
|%OtherTags% | YML検知ルールの`tags`フィールドから`MitreTactics`、`MitreTags`以外のキーワードを出力する。|
|%Provider% | `<Event><System><Provider>` フィールド内の`Name`属性。 |
|%RecordID% | `<Event><System><EventRecordID>`フィールドのイベントレコードID。 |
|%RuleAuthor% | YML検知ルールの `author` フィールド。 |
|%RuleCreationDate% | YML検知ルールの `date` フィールド。 |
|%RuleFile% | アラートまたはイベントを生成した検知ルールのファイル名。 |
|%RuleModifiedDate% | YML検知ルールの `modified` フィールド。 |
|%RuleTitle% | YML検知ルールの`title`フィールド。 |
|%Status% | YML検知ルールの `status` フィールド。 |
|%Timestamp% | デフォルトでは`YYYY-MM-DD HH:mm:ss.sss +hh:mm`形式になっている。イベントログの`<Event><System><TimeCreated SystemTime>`フィールドから来ている。デフォルトのタイムゾーンはローカルのタイムゾーンになるが、`--UTC`オプションでUTCに変更することができる。 |

#### その他のプロファイルのフィールドエイリアス

必要であれば、これらのエイリアスを出力プロファイルに追加することもできます:

| エイリアス名 | Hayabusaの出力情報 |
| :--- | :--- |
|%RenderedMessage% | WEC機能で転送されたイベントログの`<Event><RenderingInfo><Message>`フィールド。 |
|%RuleID% | YML検知ルールの`id`フィールド。 |

注意: これらはビルトインプロファイルには**含まれていない**ので、手動で`config/default_profile.yaml`ファイルを編集し、以下の行を追加する必要があります:

```
Message: "%RenderedMessage%"
```

また、[イベントキーエイリアス](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README-Japanese.md#%E3%82%A4%E3%83%99%E3%83%B3%E3%83%88%E3%82%AD%E3%83%BC%E3%82%A8%E3%82%A4%E3%83%AA%E3%82%A2%E3%82%B9)を定義し、出力することもできます。
