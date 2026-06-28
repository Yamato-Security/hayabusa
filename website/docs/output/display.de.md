# Ausgabeanzeige & Zusammenfassung

## Fortschrittsbalken

Der Fortschrittsbalken funktioniert nur mit mehreren evtx-Dateien.
Er zeigt in Echtzeit die Anzahl und den Prozentsatz der evtx-Dateien an, deren Analyse abgeschlossen wurde.

## Farbausgabe

Die Warnungen werden farbig ausgegeben, basierend auf dem Warnungs-`level`.
Sie können die Standardfarben in der Konfigurationsdatei unter `./config/level_color.txt` im Format `level,(RGB 6-digit ColorHex)` ändern.
Wenn Sie die Farbausgabe deaktivieren möchten, können Sie die Option `-K, --no-color` verwenden.

## Ergebniszusammenfassung

Gesamtanzahl der Ereignisse, Anzahl der Ereignisse mit Treffern, Datenreduktionsmetriken, Gesamt- und eindeutige Erkennungen, Daten mit den meisten Erkennungen, Top-Computer mit Erkennungen und Top-Warnungen werden nach jedem Scan angezeigt.

### Zeitachse der Erkennungshäufigkeit

Wenn Sie die Option `-T, --visualize-timeline` hinzufügen, zeigt die Funktion „Event Frequency Timeline“ eine Sparkline-Häufigkeitszeitachse der erkannten Ereignisse an.
Hinweis: Es müssen mehr als 5 Ereignisse vorhanden sein. Außerdem werden die Zeichen in der standardmäßigen Eingabeaufforderung oder PowerShell-Eingabeaufforderung nicht korrekt dargestellt. Verwenden Sie daher ein Terminal wie Windows Terminal, iTerm2 usw.
