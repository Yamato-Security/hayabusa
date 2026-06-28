# Hayabusa について

Hayabusaは、日本の[Yamato Security](https://yamatosecurity.connpass.com/)グループによって作られた**Windowsイベントログのファストフォレンジックタイムライン作成**および**脅威ハンティングツール**です。 
Hayabusaは日本語で[「ハヤブサ」](https://ja.wikipedia.org/wiki/%E3%83%8F%E3%83%A4%E3%83%96%E3%82%B5)を意味し、ハヤブサが世界で最も速く、狩猟(hunting)に優れ、とても訓練しやすい動物であることから選ばれました。
[Rust](https://www.rust-lang.org/) で開発され、マルチスレッドに対応し、可能な限り高速に動作するよう配慮されています。
Hayabusaは[upstream Sigma](https://github.com/SigmaHQ/sigma) ルールの解析に対応しています。ただし、[hayabusa-rules repository](https://github.com/Yamato-Security/hayabusa-rules)で使用およびホストしているSigmaルールは、ルールの読み込みをより柔軟にし、誤検知を減らすために一部の変換が施されています。
詳細については、[sigma-to-hayabusa-converter repository](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) リポジトリのREADMEファイルをご参照ください。
稼働中のシステムで実行してライブ調査することも、複数のシステムからログを収集してオフライン調査することも可能です。 また、 [Velociraptor](https://docs.velociraptor.app/)と[Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/)を用いることで企業向けの広範囲なスレットハンティングとインシデントレスポンスにも活用できます。
出力は一つのCSVタイムラインにまとめられ、[LibreOffice](https://www.libreoffice.org/)、[Timeline Explorer](https://ericzimmerman.github.io/#!index.md)、[Elastic Stack](../importing/elastic-stack.md)、[Timesketch](https://timesketch.org/)等で簡単に分析できるようになります。
