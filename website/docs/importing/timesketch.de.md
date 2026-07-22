# Analyse von Hayabusa-Ergebnissen mit Timesketch

## Über

"[Timesketch](https://timesketch.org/) ist ein Open-Source-Tool für die kollaborative forensische Zeitleistenanalyse. Mithilfe von Sketches können Sie und Ihre Mitarbeiter Ihre Zeitleisten einfach organisieren und sie alle gleichzeitig analysieren. Verleihen Sie Ihren Rohdaten mit umfangreichen Annotationen, Kommentaren, Tags und Sternen eine Bedeutung."

Für kleine Untersuchungen, bei denen Sie eine nur wenige hundert MB große CSV-Datei alleine analysieren, ist Timeline Explorer geeignet, wenn Sie jedoch mit größeren Datenmengen oder im Team arbeiten, ist ein Tool wie Timesketch deutlich besser.

Timesketch bietet die folgenden Vorteile:

1. Es ist sehr schnell und kann große Datenmengen verarbeiten
2. Es ist ein kollaboratives Tool, das mehrere Benutzer gleichzeitig verwenden können
3. Es bietet fortgeschrittene Datenanalyse, Histogramme und Visualisierungen
4. Es ist nicht auf Windows beschränkt
5. Es unterstützt fortgeschrittene Abfragen

Es gibt viele weitere Vorteile wie CTI-Unterstützung, verschiedene Analyzer, interaktive Notebooks usw...
Bitte schauen Sie sich für weitere Informationen den [Benutzerhandbuch](https://timesketch.org/guides/user/upload-data/) und den [YouTube-Kanal](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) an.

Der einzige Nachteil ist, dass Sie einen Timesketch-Server in Ihrer Laborumgebung einrichten müssen, aber glücklicherweise ist dies sehr einfach zu bewerkstelligen.

## Installation
### Docker
Folgen Sie der offiziellen Anleitung [hier](https://docs.docker.com/compose/install).

### Ubuntu
**Hinweis:** Docker muss installiert sein, bevor Sie fortfahren. Bitte folgen Sie der [Docker-Installationsanleitung oben](#docker), falls Sie Docker noch nicht installiert haben.
Wir empfehlen die Verwendung der neuesten Ubuntu LTS Server Edition mit mindestens 8 GB Arbeitsspeicher.
Sie können sie [hier](https://ubuntu.com/download/server) herunterladen.
Wählen Sie bei der Einrichtung die minimale Installation.
Installieren Sie Docker nicht während der Einrichtung des Betriebssystems.
`ifconfig` wird nicht verfügbar sein, installieren Sie es daher mit `sudo apt install net-tools`.

Führen Sie danach `ifconfig` aus, um die IP-Adresse der VM herauszufinden und optional per SSH darauf zuzugreifen.

Führen Sie die folgenden Befehle aus:
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**Hinweis:** Stellen Sie vor dem Fortfahren sicher, dass Sie [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/) installiert und auf Ihrem System gestartet haben.
Klonen Sie das Timesketch-Repository und wechseln Sie in das Verzeichnis.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
Starten Sie den Docker-Container, indem Sie den folgenden Schritten folgen.

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Anmelden

Finden Sie die IP-Adresse des Timesketch-Servers mit `ifconfig` heraus und öffnen Sie sie mit einem Webbrowser.
Sie werden zu einer Anmeldeseite weitergeleitet.
Melden Sie sich mit den Benutzeranmeldedaten an, die Sie beim Hinzufügen eines Benutzers verwendet haben.

## Einen neuen Sketch erstellen

Klicken Sie unter `Start a new investigation` auf `BLANK SKETCH`.
Benennen Sie den Sketch mit etwas, das für Ihre Untersuchung relevant ist.

## Hochladen Ihrer Zeitleiste

Nachdem Sie auf `+ ADD TIMELINE` geklickt haben, sehen Sie ein Dialogfeld, das Sie auffordert, eine Plaso-, JSONL- oder CSV-Datei hochzuladen.
Leider kann Timesketch derzeit das `JSONL`-Format von Hayabusa nicht importieren, erstellen und laden Sie daher mit dem folgenden Befehl eine CSV-Zeitleiste hoch:

```shell
hayabusa-x.x.x-win-x64.exe dfir-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --iso-8601
```

> Hinweis: Es ist notwendig, ein `timesketch*`-Profil zu wählen und den Zeitstempel als `--iso-8601` für UTC oder `--rfc-3339` für lokale Zeit anzugeben. Sie können weitere Hayabusa-Optionen hinzufügen, falls Sie möchten, fügen Sie jedoch nicht die Option `-M, --multiline` hinzu, da die Zeilenumbruchzeichen den Import beschädigen werden.

Benennen Sie im Dialogfeld "Select file to upload" Ihre Zeitleiste mit etwas wie `hayabusa`, wählen Sie das CSV-Trennzeichen `Comma (,)` und klicken Sie auf `SUBMIT`.

> Wenn Ihre CSV-Datei zu groß zum Hochladen ist, können Sie die Datei mit dem Befehl [split-dfir-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-dfir-timeline-command) von Takajo in mehrere CSV-Dateien aufteilen.

Während die Datei importiert wird, sehen Sie einen sich drehenden Kreis, warten Sie also bitte, bis er fertig ist und Sie `hayabusa` angezeigt bekommen.

## Analyse-Tipps

### Anzeigen der Zeitleiste

**Hinweis: Selbst nachdem der Import erfolgreich abgeschlossen wurde, wird `Your search did not match any events` angezeigt und es wird `0` Ereignisse in der `hayabusa`-Zeitleiste geben.**

Suchen Sie nach `*` und die Ereignisse werden wie unten gezeigt angezeigt:

![Timesketch-Ergebnisse](../assets/doc/TimesketchImport/TimesketchResults.png)

### Alarmdetails

Wenn Sie unter der Spalte `message` auf einen Alarm-Regeltitel klicken, erhalten Sie die detaillierten Informationen über den Alarm:

![Alarmdetails](../assets/doc/TimesketchImport/AlertDetails.png)

Wenn Sie die Logik der Sigma-Regel verstehen möchten, die Beschreibung und Referenzen nachschlagen möchten usw... schlagen Sie die Regel bitte im Repository [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) nach.

#### Feldfilterung

Nachdem Sie die Details eines Ereignisses durch Klicken auf seinen Regeltitel geöffnet haben, können Sie mit dem Mauszeiger über ein beliebiges Feld fahren, um den Wert einfach ein- oder auszufiltern:

![Filter In Out](../assets/doc/TimesketchImport/FilterInOut.png)

#### Aggregations-Analyse

Wenn Sie beim Überfahren auf das Symbol `Aggregation dialog` ganz links klicken, erhalten Sie wirklich großartige Ereignisdaten-Analysen zu diesem Feld:

![Event Data Analytics](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### Benutzerkommentare

Wenn Sie auf einen Alarm klicken, um detaillierte Informationen zu erhalten, wird auf der rechten Seite ein neues Kommentar-Dialogfeld-Symbol angezeigt, wie unten gezeigt:

![Comment Icon](../assets/doc/TimesketchImport/CommentIcon.png)

Hier können Benutzer einen Chat starten und Kommentare zur Untersuchung schreiben.

> Wenn Sie in einem Team arbeiten, sollten Sie wahrscheinlich für jedes Mitglied ein eigenes Benutzerkonto erstellen, damit Sie wissen, wer was geschrieben hat.

![Comment chat](../assets/doc/TimesketchImport/CommentChat.png)

> Wenn Sie mit dem Mauszeiger über einen Kommentar fahren, können Sie die Nachrichten einfach bearbeiten und löschen.

### Spalten ändern

Standardmäßig werden nur der Zeitstempel und der Alarm-Regeltitel angezeigt, klicken Sie also auf das Symbol `Modify columns`, um die Felder anzupassen:

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

Dadurch wird das folgende Dialogfeld geöffnet:

![Select columns](../assets/doc/TimesketchImport/SelectColumns.png)

Wir empfehlen, mindestens die folgenden Spalten **in dieser Reihenfolge** hinzuzufügen:

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

Die Reihenfolge der Spalten ändert sich je nach der Reihenfolge, in der Sie sie hinzufügen, fügen Sie also wichtigere Felder zuerst hinzu.

Wenn Sie noch Platz auf Ihrem Bildschirm haben, empfehlen wir, auch `Details` hinzuzufügen, wie hier gezeigt:

![Details](../assets/doc/TimesketchImport/Details.png)

Wenn Sie noch Platz auf Ihrem Bildschirm haben, empfehlen wir, auch `ExtraFieldInfo` hinzuzufügen, wie Sie hier jedoch sehen, wird das Feld `message` zu schmal, wenn Sie zu viele Spalten hinzufügen, und Sie können die Alarmtitel nicht mehr lesen:

![Too much details](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Obere Symbole

#### Auslassungspunkte-Symbol

Wenn Sie auf das Symbol `···` klicken, können Sie die Zeilen kompakter machen und den `Timeline name` entfernen, um mehr Platz für Ergebnisse zu schaffen:

![More room](../assets/doc/TimesketchImport/MoreRoom.png)

#### Ereignis-Histogramm

Sie können das Ereignis-Histogramm einschalten, um die Zeitleiste zu visualisieren:

![Event Histogram](../assets/doc/TimesketchImport/EventHistogram.png)

Wenn Sie auf einen der Balken klicken, wird ein Zeitfilter erstellt, der nur die Ergebnisse während dieses Zeitraums anzeigt.

#### Aktuelle Suche speichern

Wenn Sie auf das Symbol `Save current search` direkt über den Zeitstempeln und links vom Symbol `Toggle Event Histogram` klicken, können Sie Ihre aktuelle Suchabfrage sowie die Spaltenkonfiguration in `Saved Searches` speichern.
Später können Sie über die linke Seitenleiste einfach auf Ihre favorisierten Suchen zugreifen.

### Suchleiste

Hier sind einige praktische Abfragen für den Anfang, die nur Alarme mit bestimmten Schweregraden anzeigen:

1. `Level:crit`, um nur kritische Alarme anzuzeigen.
2. `Level:crit OR Level:high`, um hohe und kritische Alarme anzuzeigen
3. `NOT Level:info`, um informative Alarme auszublenden

Sie können einfach filtern, indem Sie den Feldnamen plus `:` plus den Wert eingeben.
Sie können Filter mit `AND`, `OR` und `NOT` kombinieren.
Wildcards und reguläre Ausdrücke werden unterstützt.

Für fortgeschrittenere Abfragen verweisen wir auf das Benutzerhandbuch [hier](https://timesketch.org/guides/user/search-query-guide/).

#### Suchverlauf

Wenn Sie auf das Uhrsymbol links von der Suchleiste klicken, können Sie zuvor eingegebene Abfragen anzeigen.
Sie können auch auf die Links- und Rechtspfeilsymbole klicken, um vorherige und nächste Abfragen auszuführen.

![Search History](../assets/doc/TimesketchImport/SearchHistory.png)

### Vertikale Auslassungspunkte

Wenn Sie auf die vertikalen Auslassungspunkte links von einem Zeitstempel klicken und auf `Context search` klicken, können Sie Alarme sehen, die vor und nach einem bestimmten Ereignis aufgetreten sind:

![Vertical elipsis](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

Dadurch wird Folgendes angezeigt:

![Context Search](../assets/doc/TimesketchImport/ContextSearch.png)

Im obigen Beispiel werden Ereignisse vor und nach 60 Sekunden (`60S`) angezeigt, aber Sie können das von +- 1 Sekunde (`1S`) bis +- 60 Minuten (`60M`) anpassen.

Wenn Sie weiter in die angezeigten Ereignisse hineingehen möchten, klicken Sie auf `Replace Search`, um die Ereignisse in der Standard-Zeitleiste anzuzeigen.

### Sterne und Tags

Sie können auf das Sternsymbol links von einem Zeitstempel klicken, um es mit einem Stern zu versehen und als wichtiges Ereignis zu kennzeichnen.

Sie können Ereignissen auch Tags hinzufügen.
Dies ist nützlich, um anderen anzuzeigen, dass Sie bestätigt haben, dass ein Ereignis verdächtig, bösartig, ein False Positive usw. ist...
Wenn Sie in einem Team arbeiten, können Sie Tags wie `under investigation by xxx` erstellen, um anzuzeigen, dass jemand gerade den Alarm untersucht.

![Stars and tags](../assets/doc/TimesketchImport/StarsAndTags.png)
