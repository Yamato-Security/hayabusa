# Configコマンド

## `config-critical-systems`コマンド

このコマンドは、自動的にドメインコントローラーやファイルサーバーなどの重要なシステムを見つけ、`./config/critical_systems.txt`コンフィグファイルに追加します。そのためすべてのアラートが1つ上のレベルになります。
ドメインコントローラーかどうかを判断するためにSecurity 4768 (Kerberos TGT requested)イベントを検索します。
ファイルサーバーかどうかを判断するためにSecurity 5145 (Network Share File Access)イベントを検索します。
`critical_systems.txt`ファイルに追加されたホスト名は、すべてのアラートが1つ上のレベルになり、最大で`emergency`レベルになります。

```
Usage:
  hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  .evtxファイルを持つディレクトリのパス (or VHDX images with --vhdx)
  -f, --file <FILE>      1つの.evtxファイルに対して解析を行う (or a VHDX image with --vhdx)
      --vhdx             Scan VHDX images read-only; -d searches up to three subdirectory levels
      --e01              Scan E01/Ex01 images read-only without extraction; -d searches three subdirectory levels

Display Settings:
  -K, --no-color  カラーで出力しない
  -q, --quiet     Quietモード: 起動バナーを表示しない

General Options:
  -h, --help  ヘルプメニューを表示する
```

### `config-critical-systems`コマンドの使用例

* `../hayabusa-sample-evtx`ディレクトリでドメインコントローラーとファイルサーバーを検索する:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
