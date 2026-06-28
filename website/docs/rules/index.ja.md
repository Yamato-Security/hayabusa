# Hayabusaルール

Hayabusa検知ルールはSigmaのようなYML形式で記述され、`rules`ディレクトリに入っています。
[https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)のレポジトリで管理しているので、ルールのissueやpull requestはhayabusaのレポジトリではなく、ルールレポジトリへお願いします。

ルールの形式や作成方法については、本セクションの[ルールファイルの作成](creating-rules.md)、[detectionフィールド](detection-fields.md)、[Sigma相関ルール](correlations.md)をご覧ください。（出典: [hayabusa-rules レポジトリ](https://github.com/Yamato-Security/hayabusa-rules)）

[hayabusa-rulesレポジトリ](https://github.com/Yamato-Security/hayabusa-rules)にあるすべてのルールは、`rules`フォルダに配置する必要があります。
`level`がinformationのルールは`イベント`とみなされ、`low`以上は`アラート`とみなされます。

Hayabusaルールのディレクトリ構造は、2つのディレクトリに分かれています:

* `builtin`: Windowsの組み込み機能で生成できるログ。
* `sysmon`: [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)によって生成されるログ。

ルールはさらにログタイプ（例：Security、Systemなど）によってディレクトリに分けられ、次の形式で名前が付けられます。

現在のルールをご確認いただき、新規作成時のテンプレートとして、また検知ロジックの確認用としてご利用ください。

## Sigma v.s. Hayabusa(ビルトインSigmaとの互換性のある)ルール

Hayabusaは、`logsource`フィールドを内部で処理することを唯一の例外として、Sigmaルールをネイティブにサポートしています。
過検知を減らすため、コンバータで変換した方が良いです。変換のやり方は[ここ](https://github.com/Yamato-Security/hayabusa-rules/tree/main/tools/sigmac/README-Japanese.md)で説明されています。
これにより、適切な`Channel`と`EventID`が追加され、`process_creation`のような特定のカテゴリに対してフィールドマッピングが行われます。

殆どのルールはSigmaルールと互換性があるので、Sigmaルールのようにその他のSIEM形式に変換できます。
Hayabusaルールは、Windowsのイベントログ解析専用に設計されており、以下のような利点があります:

1. ログの有用なフィールドのみから抽出された追加情報を表示するための`details`フィールドを追加しています。
2. Hayabusaルールはすべてサンプルログに対してテストされ、検知することが確認されています。
3. Sigmaルール仕様にない集計式(例：`|equalsfield`、`|endswithfield`)の利用。

私たちの知る限り、HayabusaはオープンソースのWindowsイベントログ解析ツールの中でSigmaルールを最も多くサポートしています。
