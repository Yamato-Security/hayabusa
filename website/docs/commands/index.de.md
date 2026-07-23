# Befehlsliste

## Analysebefehle:
* `computer-metrics`: Gibt die Anzahl der Ereignisse basierend auf Computernamen aus.
* `eid-metrics`: Gibt die Anzahl und den Prozentsatz der Ereignisse basierend auf der Event-ID aus.
* `expand-list`: Extrahiert `expand`-Platzhalter aus dem `rules`-Ordner.
* `extract-base64`: Extrahiert und dekodiert Base64-Zeichenketten aus Ereignissen.
* `log-metrics`: Gibt Metriken von Protokolldateien aus.
* `logon-summary`: Gibt eine Zusammenfassung der Anmeldeereignisse aus.
* `pivot-keywords-list`: Gibt eine Liste verdächtiger Schlüsselwörter aus, anhand derer pivotiert werden kann.
* `search`: Durchsucht alle Ereignisse nach Schlüsselwörtern oder regulären Ausdrücken

## Konfigurationsbefehle:
* `config-critical-systems`: Findet kritische Systeme wie Domänencontroller und Dateiserver.

## DFIR-Timeline-Befehle:
* `dfir-timeline`: Speichert die Timeline im CSV-Format.
* `dfir-timeline`: Speichert die Timeline im JSON/JSONL-Format.
* `level-tuning`: Passt das `level` der Alarme individuell an.
* `list-profiles`: Listet die verfügbaren Ausgabeprofile auf.
* `set-default-profile`: Ändert das Standardprofil.
* `update-rules`: Synchronisiert die Regeln mit den neuesten Regeln im GitHub-Repository [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

## Allgemeine Befehle:
* `help`: Gibt diese Nachricht oder die Hilfe des angegebenen Unterbefehls aus
* `list-contributors`: Gibt die Liste der Mitwirkenden aus
