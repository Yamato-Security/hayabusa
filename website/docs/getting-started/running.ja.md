# Hayabusaの実行

## 注意: アンチウィルス/EDRの誤検知と遅い初回実行

Hayabusa実行する際や、`.yml`ルールのダウンロードや実行時にルール内でdetectionに不審なPowerShellコマンドや`mimikatz`のようなキーワードが書かれている際に、アンチウィルスやEDRにブロックされる可能性があります。
誤検知のため、セキュリティ対策の製品がHayabusaを許可するように設定する必要があります。
マルウェア感染が心配であれば、ソースコードを確認した上で、自分でバイナリをコンパイルして下さい。

Windows PC起動後の初回実行時に時間がかかる場合があります。
これはWindows Defenderのリアルタイムスキャンが行われていることが原因です。
リアルタイムスキャンを無効にするかHayabusaのディレクトリをアンチウィルススキャンから除外することでこの現象は解消しますが、設定を変える前にセキュリティリスクを十分ご考慮ください。

## Windows

コマンドプロンプトやWindows Terminalから32ビットもしくは64ビットのWindowsバイナリをHayabusaのルートディレクトリから実行します。

### パスにスペースが含まれるファイルまたはディレクトリをスキャンしようとするとエラーが発生した場合

Windowsに組み込まれているコマンドプロンプトまたはPowerShellプロンプトを使用する場合、ファイルまたはディレクトリのパスに空白があると、.evtxファイルをロードできないというエラーが表示されることがあります。
.evtxファイルを正しくロードするために、以下のことを行ってください:

1. ファイルまたはディレクトリのパスをダブルクォートで囲む。
2. ディレクトリパスの場合は、最後の文字にバックスラッシュを入れない。

### 文字が正常に表示されない場合

デフォルトのフォントがWindowsの`Lucida Console`の場合、ロゴやテーブルに使用されているさまざまな文字が正しく表示されません。
フォントを`Consolas`に変更することで、これを修正できます。

これにより、ほとんどのテキスト表示の問題は修正されますが、終了メッセージに含まれる日本語文字の表示は修正されません。

![文字化け](../assets/screenshots/Mojibake.png)

以下の4つのオプションのいずれかで修正できます：

1. [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/)をCommand PromptまたはPowerShellの代わりに使用する。（推奨）
2. `MS Gothic`フォントを使用する。ただし、バックスラッシュが円記号（¥）に変わることに注意してください。
   ![文字化けの修正](../assets/screenshots/MojibakeFix.png)
3. [HackGen](https://github.com/yuru7/HackGen/releases)フォントをインストールし、`HackGen Console NF`を使用する。
4. 日本語を含む終了メッセージを表示しないために、`-q, --quiet`オプションを使用する。

## Linux

まず、バイナリに実行権限を与える必要があります。

```bash
chmod +x ./hayabusa
```

次に、Hayabusaのルートディレクトリから実行します：

```bash
./hayabusa
```

## macOS

まず、ターミナルやiTerm2からバイナリに実行権限を与える必要があります。

```bash
chmod +x ./hayabusa
```

次に、Hayabusaのルートディレクトリから実行してみてください：

```bash
./hayabusa
```

macOSの最新版では、以下のセキュリティ警告が出る可能性があります：

![Mac Error 1 JP](../assets/screenshots/MacOS-RunError-1-JP.png)

macOSの環境設定から「セキュリティとプライバシー」を開き、「一般」タブから「このまま許可」ボタンをクリックしてください。

![Mac Error 2 JP](../assets/screenshots/MacOS-RunError-2-JP.png)

その後、ターミナルからもう一回実行してみてください：

```bash
./hayabusa
```

以下の警告が出るので、「開く」をクリックしてください。

![Mac Error 3 JP](../assets/screenshots/MacOS-RunError-3-JP.png)

これで実行できるようになります。

## VHDX イメージの入力

すべてのイベントログ解析コマンドで、`--vhdx` と `-f <IMAGE.vhdx>` または `-d <IMAGE_DIRECTORY>` を指定できます。イメージは指定ディレクトリから最大3階層下まで探索します。イメージ内部では階層数を制限せず、読み取り可能な全NTFSボリュームのログを探索します。

```bash
./hayabusa dfir-timeline --vhdx -f host.vhdx -w -U -p verbose -o timeline.csv
./hayabusa dfir-timeline --vhdx -d images/ -w -U -p verbose -o timeline.csv
./hayabusa log-metrics --vhdx -d images/ -U -o logs.csv
```

Juntei と共有する `ys-vhdx-mount` のポータブルなイメージAPIで、内部のNTFSファイルを直接読み取ります。**Linux、macOS、Windows でネイティブ解析に対応**し、FUSE、マウントドライバー、補助プログラム、管理者権限、一時ファイルへのログ展開は不要です。各ログをシーク可能な読み取り専用ストリームとして開き、元イメージは変更しません。

対象コマンドは `dfir-timeline`、`search`、`eid-metrics`、`log-metrics`、`logon-summary`、`computer-metrics`、`extract-base64`、`pivot-keywords-list`、`config-critical-systems` です。JSON 入力対応コマンドでは `-J` も使えます。通常のイベントログ入力は変更せず、VHDX には `--vhdx` を明示的に指定します。

出力の証拠パスは `host.vhdx!/Windows/.../Security.evtx` です。複数ボリュームの場合は `Volume1`、`Volume2` なども含まれ、マウント先に依存せず、元イメージと内部パスを識別できます。入力と同じファイルを出力先に指定すると、シンボリックリンクやハードリンク経由でも拒否します。

読み取れないイメージやパーティション、対象ログがない場合は終了コードが非ゼロになります。一部のイメージやディレクトリが失敗しても解析可能なログが残っていれば、HTMLレポートとピボットファイルを含む出力を保存します。HTMLには不完全である旨を記載し、終了コードを非ゼロとします。警告を確認して欠落した入力を特定してください。対応ファイルシステムは NTFS のみです。BitLocker 暗号化ボリュームと外部の親イメージを必要とする差分イメージには対応しません。

## E01/Ex01 入力 { #e01-inputs }

`--e01` で物理 EWF1 (`.E01`) と EWF2 (`.Ex01`) イメージを直接解析できます。上記の全イベントログ解析コマンドに対応し、Linux、macOS、Windows で動作します。FUSE、マウントドライバー、補助プログラム、管理者権限、ディスク全体の書き出し、一時ファイルへのログ展開は不要です。

```bash
./hayabusa dfir-timeline --e01 -f disk.E01 -w -U -p verbose -o timeline.csv
./hayabusa log-metrics --e01 -d images/ -U -o logs.csv
./hayabusa dfir-timeline --vhdx --e01 -d images/ -w -U -o timeline.csv
```

EWF リーダーは必要なチャンクを容量制限付きのメモリキャッシュに展開します。NTFS リーダーから EVTX または JSON パーサーへ、シーク可能なファイルストリームを直接渡します。JSON 入力対応コマンドでは `-J` も利用できます。EVTX の一時コピーや OS 上のマウント先は作成しません。

ファイル名の大文字・小文字を区別せず、最初のセグメント `.E01` と `.Ex01` を探索します。分割イメージの残りのセグメントは、元のファイル名のまま同じディレクトリに置いてください。`.E02` などを個別の入力として処理することはありません。NTFS パーティションを持つディスク全体と、NTFS ボリューム単体に対応します。証拠パスは `disk.E01!/Windows/System32/winevt/Logs/Security.evtx` のように、元イメージと内部パスを保持します。複数ボリュームの場合は `Volume1`、`Volume2` なども含まれます。

破損した付随セグメントも含め、入力セグメントを出力で上書きする操作は、シンボリックリンクやハードリンク経由でも拒否します。イメージや読み取り対象データが不完全な場合も、解析できた結果を保存し、警告と不完全な HTML レポートを出力して非ゼロで終了します。取得時に読み取れずゼロとして記録されたセクターも報告します。解析は全セクターの読み出しや取得時ハッシュとの照合を行う**媒体全体の完全性検証ではありません**。

対応ファイルシステムは NTFS のみです。論理形式 `.L01`/`.Lx01`、パスワードが必要な暗号化 EWF、BitLocker ボリュームには対応しません。パーサー、ファイルシステムのメタデータ、コンテナーのキャッシュ用のメモリと、結果を保存する空き容量は必要です。元のイメージは読み取り専用で開きます。
