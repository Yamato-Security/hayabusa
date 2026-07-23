# コマンド一覧

## 分析コマンド:
* `computer-metrics`: コンピュータ名に基づくイベントの合計を出力する。
* `eid-metrics`: イベントIDに基づくイベントの合計と割合の集計を出力する。
* `expand-list`: `expand`のプレースホルダを`rules`フォルダから取り出す。
* `extract-base64`: イベントからbase64文字列を抽出し、デコードする。
* `logon-summary`: ログオンイベントのサマリを出力する。
* `log-metrics`: ログファイルの統計情報を出力する。
* `pivot-keywords-list`: ピボットする不審なキーワードのリストを作成する。
* `search`: キーワードや正規表現で全イベントの検索。

## Configコマンド:
* `config-critical-systems`: ドメインコントローラーやファイルサーバーなどの重要なシステムを見つける。

## DFIRタイムライン作成のコマンド:
* `dfir-timeline`: CSV形式のタイムラインを出力する。
* `dfir-timeline`: JSON/JSONL形式のタイムラインを出力する。
* `level-tuning`: アラート`level`のカスタムチューニング。
* `list-profiles`: 出力プロファイルの一覧表示。
* `set-default-profile`: デフォルトプロファイルを変更する。
* `update-rules`: GitHubの[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)リポジトリにある最新のルールに同期させる。

## 汎用コマンド:
* `help`: このメッセージまたは指定されたコマンドのヘルプを表示する。
* `list-contributors`: コントリビュータ一覧の表示。
