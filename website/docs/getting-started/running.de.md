# Hayabusa ausführen

## Achtung: Warnungen von Antivirus/EDR und langsame Laufzeiten

Möglicherweise erhalten Sie eine Warnung von Antivirus- oder EDR-Produkten, wenn Sie versuchen, Hayabusa auszuführen, oder sogar nur beim Herunterladen der `.yml`-Regeln, da in den Erkennungssignaturen Schlüsselwörter wie `mimikatz` und verdächtige PowerShell-Befehle enthalten sind.
Hierbei handelt es sich um Fehlalarme, daher müssen Sie in Ihren Sicherheitsprodukten Ausnahmen konfigurieren, damit Hayabusa ausgeführt werden kann.
Falls Sie sich über Malware oder Lieferkettenangriffe Sorgen machen, überprüfen Sie bitte den Hayabusa-Quellcode und kompilieren Sie die Binärdateien selbst.

Insbesondere beim ersten Start nach einem Neustart kann es aufgrund des Echtzeitschutzes von Windows Defender zu einer langsamen Laufzeit kommen.
Sie können dies vermeiden, indem Sie den Echtzeitschutz vorübergehend deaktivieren oder eine Ausnahme für das Hayabusa-Laufzeitverzeichnis hinzufügen.
(Bitte berücksichtigen Sie die Sicherheitsrisiken, bevor Sie dies tun.)

## Windows

Führen Sie in einer Eingabeaufforderung/PowerShell-Eingabeaufforderung oder im Windows Terminal einfach die passende 32-Bit- oder 64-Bit-Windows-Binärdatei aus.

### Fehler beim Versuch, eine Datei oder ein Verzeichnis mit einem Leerzeichen im Pfad zu scannen

Wenn Sie die integrierte Eingabeaufforderung oder PowerShell-Eingabeaufforderung in Windows verwenden, erhalten Sie möglicherweise einen Fehler, dass Hayabusa keine .evtx-Dateien laden konnte, falls Ihr Datei- oder Verzeichnispfad ein Leerzeichen enthält.
Um die .evtx-Dateien ordnungsgemäß zu laden, stellen Sie Folgendes sicher:
1. Schließen Sie den Datei- oder Verzeichnispfad in doppelte Anführungszeichen ein.
2. Wenn es sich um einen Verzeichnispfad handelt, achten Sie darauf, dass Sie keinen Backslash als letztes Zeichen einfügen.

### Zeichen werden nicht korrekt angezeigt

Mit der Standardschriftart `Lucida Console` unter Windows werden verschiedene Zeichen, die im Logo und in den Tabellen verwendet werden, nicht korrekt angezeigt.
Sie sollten die Schriftart auf `Consalas` ändern, um dies zu beheben.

Dadurch wird die meiste Textdarstellung korrigiert, mit Ausnahme der Anzeige japanischer Zeichen in den Abschlussmeldungen:

![Mojibake](../assets/screenshots/Mojibake.png)

Sie haben vier Möglichkeiten, dies zu beheben:
1. Verwenden Sie [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) anstelle der Eingabeaufforderung oder PowerShell-Eingabeaufforderung. (Empfohlen)
2. Verwenden Sie die Schriftart `MS Gothic`. Beachten Sie, dass Backslashes zu Yen-Symbolen werden.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. Installieren Sie die [HackGen](https://github.com/yuru7/HackGen/releases)-Schriftarten und verwenden Sie `HackGen Console NF`.
4. Verwenden Sie `-q, --quiet`, um die Abschlussmeldungen, die Japanisch enthalten, nicht anzuzeigen.

## Linux

Sie müssen die Binärdatei zunächst ausführbar machen.

```bash
chmod +x ./hayabusa
```

Führen Sie sie dann aus dem Hayabusa-Stammverzeichnis aus:

```bash
./hayabusa
```

## macOS

Im Terminal oder iTerm2 müssen Sie die Binärdatei zunächst ausführbar machen.

```bash
chmod +x ./hayabusa
```

Versuchen Sie dann, sie aus dem Hayabusa-Stammverzeichnis auszuführen:

```bash
./hayabusa
```

Auf der neuesten Version von macOS erhalten Sie möglicherweise den folgenden Sicherheitsfehler, wenn Sie versuchen, sie auszuführen:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

Klicken Sie auf "Abbrechen" und öffnen Sie dann in den Systemeinstellungen "Sicherheit & Datenschutz" und klicken Sie auf der Registerkarte "Allgemein" auf "Dennoch erlauben".

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

Versuchen Sie danach erneut, sie auszuführen.

```bash
./hayabusa
```

Die folgende Warnung wird angezeigt, klicken Sie also bitte auf "Öffnen".

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

Sie sollten nun in der Lage sein, Hayabusa auszuführen.
