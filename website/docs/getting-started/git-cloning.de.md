# Git Cloning

Sie können das Repository mit dem folgenden Befehl per `git clone` klonen und die Binärdatei aus dem Quellcode kompilieren:

**Warnung:** Der Main-Branch des Repositorys dient Entwicklungszwecken, sodass Sie möglicherweise auf neue Funktionen zugreifen können, die noch nicht offiziell veröffentlicht wurden. Es kann jedoch Fehler geben, betrachten Sie ihn daher als instabil.

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **Hinweis:** Wenn Sie vergessen, die Option --recursive zu verwenden, wird der `rules`-Ordner, der als Git-Submodul verwaltet wird, nicht geklont.

Sie können den `rules`-Ordner synchronisieren und die neuesten Hayabusa-Regeln mit `git pull --recurse-submodules` abrufen oder den folgenden Befehl verwenden:

```bash
hayabusa.exe update-rules
```

Wenn die Aktualisierung fehlschlägt, müssen Sie möglicherweise den `rules`-Ordner umbenennen und es erneut versuchen.

>> Achtung: Beim Aktualisieren werden die Regeln und Konfigurationsdateien im `rules`-Ordner durch die neuesten Regeln und Konfigurationsdateien im [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)-Repository ersetzt.
>> Alle Änderungen, die Sie an vorhandenen Dateien vornehmen, werden überschrieben. Wir empfehlen daher, vor dem Aktualisieren Sicherungskopien aller von Ihnen bearbeiteten Dateien anzulegen.
>> Wenn Sie ein Level-Tuning mit `level-tuning` durchführen, stimmen Sie Ihre Regeldateien nach jeder Aktualisierung erneut ab.
>> Wenn Sie **neue** Regeln innerhalb des `rules`-Ordners hinzufügen, werden diese beim Aktualisieren **nicht** überschrieben oder gelöscht.
