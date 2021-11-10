# hayabusaGenerater
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

[English](./README-en.md)

`hayabusaGenerater.py` はSIGMAルールをHayabusaに対応したルールセットに変更することができます。
SIGMAの持つ多くの検知ルールをHayabusaのルールセットに追加することでルールを作成する手間を省くことができます。

## sigma

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## 環境設定

hayabusaGeneratorはSIGMAリポジトリの中にある`sigmac`を使います。
事前に任意のディレクトリにSIGMAリポジトリをcloneしてください。

```sh
git clone https://github.com/SigmaHQ/sigma.git
```

## 使い方

hayabusaGenerater.pyをSIGMAのbackendとして登録します。

```sh
export sigma_path=/path/to/sigma_repository
cp hayabusaGenerater.py $sigma_path/tools/sigma/backends
```

### 単体のルールを変換

```sh
python3 $sigma_path/tools/sigmac <変換対象ruleの指定> --config <configの指定> --target hayabusa
```

サンプル
```sh
python3 $sigma_path/tools/sigmac $sigma/rules/windows/create_remote_thread/sysmon_cactustorch.yml --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > sysmon_cactustorch.yml
```

### 複数のルールを変換

現在のディレクトリ内に指定したディレクトリ内のルールファイルを作成するコマンドサンプルです。

```sh
find $sigma/rules/windows/* | grep yml | xargs -I{} sh -c 'python $sigma/tools/sigmac {} --config $sigma/tools/config/generic/sysmon.yml --target hayabusa > "$(basename {})"'
```
