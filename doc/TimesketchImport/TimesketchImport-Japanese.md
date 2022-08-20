# TimesketchにHayabusa結果をインポートする方法

## Timesketchについて

"[Timesketch](https://timesketch.org/)は、フォレンジックタイムラインの共同解析のためのオープンソースツールです。スケッチを使うことで、あなたとあなたの共同作業者は、簡単にタイムラインを整理し、同時に分析することができます。リッチなアノテーション、コメント、タグ、スターで生データに意味を持たせることができます。"


## インストール

Ubuntu 22.04 LTS Serverエディションの使用を推奨します。
[こちら](https://ubuntu.com/download/server)からダウンロードできます。
セットアップ時にミニマルインストールを選択してください。
`ifconfig`はインストールされていないので、`sudo apt install net-tools`でインストールしてください。

その後、インストール手順[こちら](https://timesketch.org/guides/admin/install/)に従ってください:

``` bash
sudo apt install docker-compose
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker-compose up -d
sudo docker-compose exec timesketch-web tsctl create-user <USERNAME>
```

## 準備されたVM

[Recon InfoSec](https://www.reconinfosec.com/)主催の2022年のDEF CON 30 [OpenSOC](https://opensoc.io/) DFIR Challengeのエビデンスに対して使用できるデモ用VMを事前に構築しています。 (エビデンスは既にインポート済み。)
[こちら](https://www.dropbox.com/s/3be3s5c2r22ux2z/Prebuilt-Timesketch.ova?dl=0)からダウンロードできます。
このチャレンジの他のエビデンスは[こちら](https://docs.google.com/document/d/1XM4Gfdojt8fCn_9B8JKk9bcUTXZc0_hzWRUH4mEr7dw/mobilebasic)からダウンロードできます。
問題は[こちら](https://docs.google.com/spreadsheets/d/1vKn8BgABuJsqH5WhhS9ebIGTBG4aoP-StINRi18abo4/htmlview)からダウンロードできます。

VMのユーザ名は`user`。パスワードは`password`。

## ログイン

`ifconfig`でIPアドレスを調べ、Webブラウザで開いてください。
以下のようなログインページに移動されます:

![Timesketch Login](01-TimesketchLogin.png)

docker-composeコマンドで作成したユーザの認証情報でログインしてください。

## 新しいsketch作成

`New investiation`をクリックし、新しいスケッチに名前を付けます。

![New Investigation](02-NewInvestigation.png)

## タイムラインのアップロード

`Upload timeline`をクリックし、以下のコマンドで作成したCSVファイルをアップロードします:

`hayabusa-1.5.1-win-x64.exe -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -P timesketch -U`

Windowsのイベントを含めず、アラートだけでよい場合は、`-m low`を追加することができます。

## 結果の解析

以下のような画面が表示されるはずです:

![Timesketch timeline](03-TimesketchTimeline.png)

デフォルトでは、UTCタイムスタンプとアラートルールのタイトル名のみが表示されますので、`Customize columns`をクリックし、他のフィールドを追加してください。

> 注意: 現在のバージョンでは、新しいカラムが空白になってしまうというバグがあります。新しいカラムを表示するには、別のカラムをまず追加してください（必要なければ後で削除してください。）

以下のように検索ボックスで`Level: crit`等を入力することで、クリティカルなアラートのみを表示させるようにフィルタリングできます。

![Timeline with columns](04-TimelineWithColumns.png)

イベントをクリックすると、すべてのフィールド情報を見ることができます:

![Field Information](05-FieldInformation.png)

アラートタイトルの左側にある3つのアイコンを使って、興味のあるイベントにスターをつけたり、イベントの文脈を見るために+-5分検索したり、ラベルを追加したりすることが可能です。

![Marking Events](06-MarkingEvents.png)