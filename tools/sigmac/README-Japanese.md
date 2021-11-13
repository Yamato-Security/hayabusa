# SIGMAからHayabusaルールへの自動変換
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

`hayabusa.py` はSigmaルールをHayabusaルールに変換する`sigmac`のバックエンドです。
Sigmaの持つ多くの検知ルールをHayabusaのルールセットに追加することでルールを作成する手間を省くことができます。

## Sigmaについて

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## 環境設定

hayabusa.pyはSigmaリポジトリの中にある`sigmac`を使います。
事前に任意のディレクトリにSigmaリポジトリをcloneしてください。

```sh
git clone https://github.com/SigmaHQ/sigma.git
```

## 使い方

Sigmaレポジトリのパスが書いてある`$sigma_path`という環境変数を設定して、hayabusaをSigmaのbackendとして登録します:

```sh
export sigma_path=/path/to/sigma_repository
cp hayabusa.py $sigma_path/tools/sigma/backends
```

### 単体のルールを変換

以下のシンタクスで単体のルールを変換できます：

```sh
python3 $sigma_path/tools/sigmac <変換対象ruleの指定> --config <configの指定> --target hayabusa
```

例：
```sh
python3 $sigma_path/tools/sigmac $sigma_path/rules/windows/create_remote_thread/sysmon_cactustorch.yml --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > sysmon_cactustorch.yml
```

### 複数のルールを変換

以下のように、SigmaのすべてのWindowsイベントログルールをhayabusaルールに変換して、カレントディレクトリに保存します：

```sh
find $sigma_path/rules/windows/* | grep yml | xargs -I{} sh -c 'python $sigma_path/tools/sigmac {} --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > "$(basename {})"'
```
