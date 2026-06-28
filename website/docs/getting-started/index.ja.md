# ダウンロード

[Releases](https://github.com/Yamato-Security/hayabusa/releases)ページからHayabusaの安定したバージョンでコンパイルされたバイナリが含まれている最新版もしくはソースコードをダウンロードできます。

以下のアーキテクチャ用のバイナリを提供している：
- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [Linux ARM MUSLバイナリが正常に動作しません](https://github.com/Yamato-Security/hayabusa/issues/1332) そのため、現時点ではそのバイナリを提供していません。これは我々の実装の範囲外の問題なので、修正され次第、将来的に提供する予定です。

## Windowsライブレスポンスパッケージ

v2.18.0から、1つのファイルにまとめたXORエンコードされたルールと、すべての設定ファイルを1つのファイルにまとめた特別なWindowsパッケージを提供しています（[hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules)にてホストされています）。
live-responseという名前がついたzipパッケージをダウンロードするだけです。
zipファイルには、Hayabusaのバイナリ、XORエンコードされたルールファイル、設定ファイルの3つのファイルが含まれています。
これらのライブレスポンスパッケージの目的は、クライアントのエンドポイントでHayabusaを実行する際に、Windows Defenderのようなウイルス対策スキャナーが.ymlルールファイルに対して誤検知をしないようにするためです。
また、USNジャーナルなどのフォレンジックアーティファクトが上書きされないよう、システムに書き込まれるファイルの量を最小限に抑えることも目的としています。
