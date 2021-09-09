# SigmaRuleとの変換

Sigmacを用いてSigmaRuleを変換し、YEAで利用可能なルールファイルに変更する。

## Sigmac

`python3 tools/sigmac rules/windows/process_creation/win_apt_chafer_mar18.yml --config elk-windows --target yea`

- 変換対象ルールとしてrules下のファイルを指定
- `--config`
  - `sigma/tools/config` 下にあるymlファイルから選択するSigmacのconfigを指定
  - <https://github.com/SigmaHQ/sigma/tree/master/tools#configuration-file>
- `--target`
  - YEAルールを作成するためにyea独自に作成する
  - `sigma/tools/sigma/backends` 下に `base.py` をベースに作成する
  - `generate()` でルールをパースするが複数のlogsourceがルール内に存在する場合は複数回呼ばれる
  - `finalize()` で最後の処理ができる
    - 複数Yamlをまとめるならここ？
- `--backend-option`
  - ???
  - 正しいものを選んでねと言われるがあまりわかっていない
  - `--config` と `--backend-option` を適切に扱う必要があるらしい

### サンプル

- yea.py を用いて出力した結果 >> tmp.py

## うまく行かないところ

- logsoruceとしてSigmacは system/security/powershell 等が書かれている
  - YEAのルールに合わせてdetection.selection.Channel下に移動させたい
  - バックエンドの設定をどうにか書けばいい？？？
- フィールド名が違うところをどう修正する？