# Downloads

Bitte laden Sie die neueste stabile Version von Hayabusa mit kompilierten Binärdateien herunter oder kompilieren Sie den Quellcode von der Seite [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Wir stellen Binärdateien für die folgenden Architekturen bereit:

- Linux ARM 64-Bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-Bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-Bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-Bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-Bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-Bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-Bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-Bit (`hayabusa-x.x.x-win-x86.exe`)

> [Aus irgendeinem Grund läuft die Linux-ARM-MUSL-Binärdatei nicht ordnungsgemäß](https://github.com/Yamato-Security/hayabusa/issues/1332), daher stellen wir diese Binärdatei nicht bereit. Dies liegt außerhalb unserer Kontrolle, daher planen wir, sie in Zukunft bereitzustellen, sobald das Problem behoben ist.

## Windows-Live-Response-Pakete

Seit v2.18.0 stellen wir spezielle Windows-Pakete bereit, die XOR-codierte Regeln in einer einzigen Datei verwenden sowie alle Konfigurationsdateien zu einer einzigen Datei zusammengefasst (gehostet im [hayabusa-encoded-rules-Repository](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Laden Sie einfach die ZIP-Pakete mit `live-response` im Namen herunter.
Die ZIP-Dateien enthalten lediglich drei Dateien: die Hayabusa-Binärdatei, die XOR-codierte Regeldatei und die Konfigurationsdatei.
Der Zweck dieser Live-Response-Pakete besteht darin, dass wir beim Ausführen von Hayabusa auf Client-Endpunkten sicherstellen möchten, dass Antivirenscanner wie Windows Defender keine Fehlalarme bei `.yml`-Regeldateien auslösen.
Außerdem möchten wir die Menge der auf das System geschriebenen Dateien minimieren, damit forensische Artefakte wie das USN Journal nicht überschrieben werden.
