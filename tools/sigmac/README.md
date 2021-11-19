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
事前に任意のディレクトリにSIGMAリポジトリをcloneし、SIGMAのドキュメントに沿って環境設定を行ってください。

```sh
git clone https://github.com/SigmaHQ/sigma.git
```

## 使い方

### 各種ファイルの設置
下記のコマンドを実行してください。

```sh
export sigma_path=/path/to/sigma_repository
cp hayabusaGenerater.py $sigma_path/tools/sigma/backends
cp convert.sh $sigma_path
cp splitter.py $sigma_path
```

### pythonライブラリのインストール
下記のコマンドを実行してください。

```sh
pip install pyyaml
```

### ルールの変換
convert.shを実行することでルールの変換が実行されます。変換されたルールはhayabusa_rulesフォルダに作成されます。

```sh
export sigma_path=/path/to/sigma_repository
cd $sigma_path
sh convert.sh
```

ルールの変換に利用しているsigmacには様々なオプションが用意されています。オプションを変更する場合はconvert.shを編集してください。