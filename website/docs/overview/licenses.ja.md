# ライセンス

Hayabusa とその検知ルールは、それぞれ異なるライセンスで公開されています。

## Hayabusa（ツール本体）

Hayabusa は **[GNU Affero 一般公衆利用許諾書 v3.0（AGPLv3）](https://www.gnu.org/licenses/agpl-3.0.en.html)** の下で公開されています。
完全な法的条文は、レポジトリの [`LICENSE.txt`](https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt) ファイルをご覧ください。

## 検知ルール

[Sigma](https://github.com/SigmaHQ/sigma) ルール、および Hayabusa の検知ルール
（[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) レポジトリで管理）は、
**[Detection Rule License（DRL）1.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)** の下で公開されています。

## AGPL が意味すること

簡単に言えば、**Hayabusa は商用利用を含め、自由にご利用いただけます**。
組織内での利用、SaaS ソリューションへの組み込み、コンサルティング業務、インシデントレスポンス
対応など、用途を問いません。

ただし、AGPL には一つ重要な条件があります。**Hayabusa のコードを改変・改良し、それをサービスとして
他者に提供する場合**（例えば SaaS の一部として提供する場合）、**その改良点をオープンソースとして公開**し、
同じライセンスの下で利用できるようにすることをお願いしています。

改良を行った際は、ぜひ [プルリクエストを送信](https://github.com/Yamato-Security/hayabusa/pulls) して
アップストリームのレポジトリに **還元** していただけると大変ありがたく思います。そうすることで、
コミュニティ全体があなたの成果から恩恵を受けられます。

!!! note "その他のデータ"
    Hayabusa は [MaxMind](https://www.maxmind.com) が作成した GeoLite2 データも利用しています。
