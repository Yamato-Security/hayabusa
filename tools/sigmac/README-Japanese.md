# SIGMAからHayabusaルールへの自動変換
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

`hayabusa.py` はSigmaルールをHayabusaルールに変換する`sigmac`のバックエンドです。
Sigmaの持つ多くの検知ルールをHayabusaのルールセットに追加することでルールを作成する手間を省くことができます。

## 事前に変換されたSigmaルールについて

Sigmaからhayabusa形式に変換されたルールが`./rules/Sigma`ディレクトリに用意されています。 
ローカル環境で新しいルールをテストしたり、Sigmaの最新のルールを変換したりしたい場合は、以下のドキュメンテーションをご参考下さい。

## Pythonの環境依存

Python 3.8以上と次のモジュールが必要です：`pyyaml`、`ruamel_yaml`、`requests` 
`pip3 install -r requirements.txt`というコマンドでインストールできます。

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

* 注意：`/path/to/sigma_repository`そのままではなくて、自分のSigmaレポジトリのパスを指定してください。

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

以下のように、SigmaのすべてのWindowsイベントログルールをhayabusaルールに変換して、カレントディレクトリに保存します。`./rules/Sigma`ディレクトリから実行して下さい。

```sh
find $sigma_path/rules/windows/ -type f -name '*.yml' -exec sh -c 'python3 $sigma_path/tools/sigmac {} --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > "$(basename {})"' \;
```

※ すべてのルールを変換するのに、約30分かかります。

## 現在サポートされていないルール

以下のルールは、まだ実装されていないaggregation operatorが含まれているため、現在は自動変換できません。

```
sigma/rules/windows/builtin/win_susp_samr_pwset.yml
sigma/rules/windows/image_load/sysmon_mimikatz_inmemory_detection.yml
sigma/rules/windows/process_creation/process_creation_apt_turla_commands_medium.yml
```

また、以下のルールも現在変換できません：
```
process_creation_apt_turla_commands_medium.yml
sysmon_mimikatz_inmemory_detection.yml
win_susp_failed_logons_explicit_credentials.yml
win_susp_failed_logons_single_process.yml
win_susp_failed_logons_single_source_kerberos.yml
win_susp_failed_logons_single_source_kerberos2.yml
win_susp_failed_logons_single_source_kerberos3.yml
win_susp_failed_logons_single_source_ntlm.yml
win_susp_failed_logons_single_source_ntlm2.yml
win_susp_failed_remote_logons_single_source.yml
win_susp_samr_pwset.yml
```

## Sigmaルールのパースエラーについて

一部のルールは変換できたものの、パースエラーが発生しています。
これらのバグは引き続き修正していきますが、当面はSigmaのルールの大部分は動作しますので、今のところエラーは無視してください。