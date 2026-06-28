# Hayabusa-Regeln

Hayabusa-Erkennungsregeln werden in einem Sigma-ähnlichen YML-Format geschrieben und befinden sich im Ordner `rules`.
Die Regeln werden unter [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) gehostet. Bitte senden Sie daher alle Issues und Pull Requests für Regeln dorthin und nicht an das Haupt-Repository von Hayabusa.

Sehen Sie sich [Regeldateien erstellen](creating-rules.md), [Erkennungsfelder](detection-fields.md) und [Sigma-Korrelationen](correlations.md) in diesem Abschnitt an, um das Regelformat zu verstehen und zu erfahren, wie man Regeln erstellt. (Quelle: das [hayabusa-rules-Repository](https://github.com/Yamato-Security/hayabusa-rules).)

Alle Regeln aus dem hayabusa-rules-Repository sollten im Ordner `rules` abgelegt werden.
Regeln der Stufe `informational` gelten als `events`, während alles mit einem `level` von `low` und höher als `alerts` gilt.

Die Verzeichnisstruktur der Hayabusa-Regeln ist in 2 Verzeichnisse unterteilt:

* `builtin`: Protokolle, die durch die in Windows integrierte Funktionalität generiert werden können.
* `sysmon`: Protokolle, die von [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) generiert werden.

Die Regeln sind weiter nach Protokolltyp in Verzeichnisse unterteilt (Beispiel: Security, System usw.) und werden im folgenden Format benannt:

Bitte sehen Sie sich die aktuellen Regeln an, um sie als Vorlage für die Erstellung neuer Regeln oder zur Überprüfung der Erkennungslogik zu verwenden.

## Sigma vs. Hayabusa (integrierte Sigma-kompatible) Regeln

Hayabusa unterstützt Sigma-Regeln nativ, mit der einzigen Ausnahme, dass die `logsource`-Felder intern behandelt werden.
Um Fehlalarme zu reduzieren, sollten Sigma-Regeln durch unseren Konverter ausgeführt werden, der [hier](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md) erläutert wird.
Dadurch werden der richtige `Channel` und die richtige `EventID` hinzugefügt und ein Feld-Mapping für bestimmte Kategorien wie `process_creation` durchgeführt.

Nahezu alle Hayabusa-Regeln sind mit dem Sigma-Format kompatibel, sodass Sie sie wie Sigma-Regeln verwenden können, um sie in andere SIEM-Formate zu konvertieren.
Hayabusa-Regeln sind ausschließlich für die Analyse von Windows-Ereignisprotokollen konzipiert und bieten die folgenden Vorteile:

1. Ein zusätzliches `details`-Feld, um zusätzliche Informationen anzuzeigen, die nur aus den nützlichen Feldern im Protokoll stammen.
2. Sie werden alle anhand von Beispielprotokollen getestet und funktionieren nachweislich.
3. Zusätzliche Aggregatoren, die in Sigma nicht vorhanden sind, wie `|equalsfield` und `|endswithfield`.

Nach unserem Kenntnisstand bietet Hayabusa die umfangreichste native Unterstützung für Sigma-Regeln unter allen Open-Source-Tools zur Analyse von Windows-Ereignisprotokollen.
