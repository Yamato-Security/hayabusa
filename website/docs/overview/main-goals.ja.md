# 主な目的

## スレット(脅威)ハンティングと企業向けの広範囲なDFIR

Hayabusaには現在、4000以上のSigmaルールと170以上のHayabusa検知ルールがあり、定期的にルールが追加されています。
[Velociraptor](https://docs.velociraptor.app/)の[Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/)を用いることで企業向けの広範囲なスレットハンティングだけでなくDFIR(デジタルフォレンジックとインシデントレスポンス)にも無料で利用することが可能です。
この2つのオープンソースを組み合わせることで、SIEMが設定されていない環境でも実質的に遡及してSIEMを再現することができます。
具体的な方法は[Eric Capuano](https://twitter.com/eric_capuano)の[こちら](https://www.youtube.com/watch?v=Q1IoGX--814)の動画で学ぶことができます。

## フォレンジックタイムラインの高速生成

Windowsのイベントログは、1）解析が困難なデータ形式であること、2）データの大半がノイズであり調査に有用でないことから、従来は非常に長い時間と手間がかかる解析作業となっていました。
Hayabusaは、有用なデータのみを抽出し、専門的なトレーニングを受けた分析者だけでなく、Windowsのシステム管理者であれば誰でも利用できる読みやすい形式で提示することを主な目的としています。
Hayabusaは従来のWindowsイベントログ分析解析と比較して、分析者が20%の時間で80%の作業を行えるようにすることを目指しています。

![DFIR Timeline](../assets/doc/DFIR-TimelineCreation-JP.png)
