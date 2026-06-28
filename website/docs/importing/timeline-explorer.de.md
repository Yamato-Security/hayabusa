# Analyse von Hayabusa-Ergebnissen mit Timeline Explorer

## Über

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) ist ein kostenloses, aber Closed-Source-Tool, das Excel beim Analysieren von CSV-Dateien für DFIR-Zwecke ersetzen soll.
Es handelt sich um ein reines Windows-GUI-Tool, das in C# geschrieben wurde.
Dieses Tool eignet sich hervorragend für kleine Untersuchungen durch einen einzelnen Analysten sowie für Personen, die gerade erst mit der DFIR-Analyse beginnen. Die Oberfläche kann jedoch anfangs schwer zu verstehen sein, nutzen Sie daher bitte diese Anleitung, um die verschiedenen Funktionen kennenzulernen.

## Installation und Ausführung

Es ist keine Installation der Anwendung erforderlich.
Laden Sie einfach die neueste Version von [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) herunter, entpacken Sie sie und führen Sie `TimelineExplorer.exe` aus.
Falls Sie nicht über die passende .NET-Laufzeitumgebung verfügen, erscheint eine Meldung, die Ihnen mitteilt, dass Sie diese installieren müssen.
Zum Zeitpunkt der Erstellung (14.02.2025) ist die neueste Version `2.1.0`, die unter .NET-Version `9` läuft.

## Laden einer CSV-Datei

Klicken Sie einfach im Menü auf `File` -> `Open`, um eine CSV-Datei zu laden.

Sie werden etwa Folgendes sehen:

![Erster Start](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

Ganz unten sehen Sie den Dateinamen, `Total lines` und `Visible lines`.

Neben den in der CSV-Datei vorhandenen Spalten gibt es zwei von Timeline Explorer hinzugefügte Spalten auf der linken Seite: `Line` und `Tag`.
`Line` zeigt die Zeilennummer an, ist aber für Untersuchungen normalerweise nicht nützlich, sodass Sie diese Spalte möglicherweise ausblenden möchten.
Mit `Tag` können Sie ein Häkchen bei Ereignissen setzen, die Sie sich für eine spätere weitere Analyse usw. notieren möchten ...
Leider gibt es keine Möglichkeit, benutzerdefinierte Tags zu Ereignissen hinzuzufügen oder Kommentare zu Ereignissen zu notieren, da die CSV-Datei im schreibgeschützten Modus geöffnet wird, um zu verhindern, dass Daten überschrieben werden.

## Datenfilterung

Wenn Sie mit der Maus über den oberen rechten Teil einer Kopfzeile fahren, erscheint ein schwarzes Filtersymbol.

![Grundlegende Datenfilterung](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

Sie können Häkchen bei der Schweregradstufe setzen, um zunächst die `high`- und `crit`-(`critical`-)Alarme zu triagieren.
Diese Filterung ist auch sehr nützlich, um störende Alarme herauszufiltern, indem Sie alles unter `Rule Title` ankreuzen und dann die störenden Regeln abwählen.

Wie unten gezeigt, können Sie durch Klicken auf `Text Filters` erweiterte Filter erstellen:

![Erweiterte Datenfilterung](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

Anstatt hier Filter zu erstellen, ist es jedoch meist einfacher, auf das `ABC`-Symbol unter der Kopfzeile zu klicken und Filter dort anzuwenden:

![ABC-Filterung](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

Leider bieten diese beiden Stellen leicht unterschiedliche Filteroptionen, daher sollten Sie beide Stellen zum Filtern von Daten kennen.

Wenn Sie beispielsweise zu viele `Proc Exec`-Ereignisse haben, die Sie herausfiltern möchten, können Sie `Does not contain` auswählen und `Proc Exec` eingeben, um diese Ereignisse zu ignorieren:

![Regelfilterung](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

Wenn Sie nach unten schauen, sehen Sie die Filterregel in verschiedenen Farben.
Wenn Sie den Filter vorübergehend deaktivieren möchten, entfernen Sie einfach das Häkchen.
Wenn Sie alle Filter löschen möchten, klicken Sie auf die Schaltfläche `X`.

Wenn Sie eine weitere störende Regel ignorieren möchten, sollten Sie den `Filter Editor` öffnen, indem Sie unten rechts auf `Edit Filter` klicken:

![Filter-Editor](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

Kopieren Sie den Text `Not Contains([Rule Title], 'Proc Exec')`, fügen Sie `and` hinzu, fügen Sie denselben Filter ein und ändern Sie `Proc Exec` in `Possible LOLBIN`, und nun können Sie diese beiden Regeln ignorieren:

![Mehrere Filter](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

Die einfachste Möglichkeit, mehrere Filter zu kombinieren, besteht darin, zuerst die Filtersyntax über das `ABC`-Symbol zu erstellen, dann diesen Text zu kopieren, einzufügen und zu bearbeiten und die Filter mit `and`, `or` und `not` zu kombinieren.

Sie können auch auf einen der farbigen Texte klicken, um ein Dropdown-Feld mit den möglichen Optionen zur Bearbeitung Ihrer Filter zu erhalten:

![Dropdown-Bearbeitung](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Kopfzeilenoptionen

Wenn Sie mit der rechten Maustaste auf eine der Kopfzeilen klicken, erhalten Sie die folgenden Optionen:

![Kopfzeilenoptionen](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

Die meisten dieser Optionen sind selbsterklärend.

* Nachdem Sie eine Spalte ausgeblendet haben, können Sie sie wieder einblenden, indem Sie den `Column Chooser` öffnen, mit der rechten Maustaste auf den Spaltennamen klicken und auf `Show Column` klicken.
* `Group By This Column` hat denselben Effekt wie das Ziehen einer Spaltenkopfzeile nach oben, um danach zu gruppieren. (Wird später ausführlicher erklärt.)
* `Hide Group By Box` blendet lediglich den Text `Drag a column header here to group by that column` aus und verschiebt die Suchleiste hinüber.

### Bedingte Formatierung

Sie können den Text mit Farbe, fetter Schrift usw. formatieren, indem Sie auf `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...` klicken:

![Bedingte Formatierung](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

Wenn Sie beispielsweise `critical`-Alarme mit `Red Fill` anzeigen möchten, geben Sie einfach `crit` ein, wählen Sie `Red Fill` aus den Optionen, aktivieren Sie `Apply formatting to an entire row` und klicken Sie auf `OK`.

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

Nun werden `critical`-Alarme wie unten gezeigt in Rot angezeigt:

![Rote Füllung](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

Sie können dies fortsetzen, indem Sie auch Farben für die `low`-, `medium`- und `high`-Alarme hinzufügen.

## Suchen

Wenn Sie standardmäßig einen Text in die Suchleiste eingeben, wird eine Filterung durchgeführt und nur die Ergebnisse angezeigt, die den Text irgendwo in der Zeile enthalten.
Sie können sehen, wie viele Treffer Sie haben, indem Sie das Feld `Visible lines` am unteren Rand überprüfen.

Sie können dieses Verhalten ändern, indem Sie ganz unten rechts auf `Search options` klicken.
Daraufhin erscheint Folgendes:

![Suchoptionen](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

Wenn Sie das `Behavior` von `Filter` auf `Search` ändern, können Sie normal nach Text suchen.

> Hinweis: Es dauert in der Regel eine Weile, das Verhalten umzuschalten, und Timeline Explorer hängt sich kurz auf, seien Sie also nach dem Klicken geduldig.

Die standardmäßige `Match criteria` ist `Mixed`, kann aber in `Or`, `And` oder `Exact` geändert werden.
Wenn Sie sie auf etwas anderes als `Mixed` ändern, können Sie anschließend die `Condition` von `Contains` auf `Starts with`, `Like` oder `Equals` setzen.

Die `Match criteria` `Mixed` ist kompliziert, da sie manchmal `AND`-Logik und manchmal `OR`-Logik verwendet, aber sehr flexibel sein kann, sobald man sie verstanden hat.
Sie funktioniert wie folgt:
* Wenn Sie Wörter durch Leerzeichen trennen, wird dies als `OR`-Logik behandelt.
* Wenn Sie Leerzeichen in Ihre Suche einbeziehen möchten, müssen Sie Anführungszeichen hinzufügen.
* Stellen Sie einer Bedingung ein `+` voran für `AND`-Logik.
* Stellen Sie einer Bedingung ein `-` voran, um Ergebnisse auszuschließen.
* Filtern Sie nach einer bestimmten Spalte mit dem Format `ColumnName:FilterString`.
* Wenn Sie nach einer bestimmten Spalte filtern und außerdem ein separates Schlüsselwort einschließen, wird `AND`-Logik verwendet.

Beispiele:
| Suchkriterien                    | Beschreibung                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Wählt Datensätze aus, die die Zeichenkette `mimikatz` in einer beliebigen Suchspalte enthalten.                                                  |
| one two three                    | Wählt Datensätze aus, die entweder `one` ODER `two` ODER `three` in einer beliebigen Suchspalte enthalten.                                       |
| "hoge hoge"                      | Wählt Datensätze aus, die `hoge hoge` in einer beliebigen Suchspalte enthalten.                                                                  |
| mimikatz +"Bad Guy"              | Wählt Datensätze aus, die sowohl `mimikatz` ALS AUCH `Bad Guy` in einer beliebigen Suchspalte enthalten.                                         |
| EventID:4624 kali                | Wählt Datensätze aus, die `4624` in der Spalte enthalten, die mit `EventID` beginnt, UND `kali` in einer beliebigen Suchspalte enthalten.        |
| data +entry -mark                | Wählt Datensätze aus, die sowohl `data` ALS AUCH `entry` in einer beliebigen Suchspalte enthalten, unter Ausschluss von Datensätzen, die `mark` enthalten. |
| manu mask -file                  | Wählt Datensätze aus, die `menu` ODER `mask` enthalten, unter Ausschluss von Datensätzen, die `file` enthalten.                                  |
| From:Roller Subj:"currency mask" | Wählt Datensätze aus, die `Roller` in der Spalte enthalten, die mit `From` beginnt, UND `currency mask` in der Spalte enthalten, die mit `Subj` beginnt. |
| import -From:Steve               | Wählt Datensätze aus, die `import` in einer beliebigen Suchspalte enthalten, unter Ausschluss von Datensätzen, die `Steve` in der Spalte enthalten, die mit `From` beginnt. |

## Einfrieren von Spalten

Auch wenn es sich nicht um eine Suchoption handelt, können Sie die `First scrollable column` im Menü `Search options` konfigurieren.
Die meisten Analysten setzen dies auf `Timestamp`, sodass sie immer sehen können, zu welcher Zeit bestimmte Ereignisse stattfanden.

## Ziehen von Spaltenkopfzeilen zum Gruppieren

Wenn Sie eine Spaltenkopfzeile auf `Drag a column header here to group by that column` ziehen, gruppiert Timeline Explorer nach dieser Spalte.
Es ist üblich, nach `Level` zu gruppieren, damit Sie Alarme nach Schweregrad priorisieren können:

![Gruppieren nach](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

Wenn Sie mehrere Computer in Ihren Ergebnissen haben, können Sie weiter nach `Computer` gruppieren, um die Triage auf Basis unterschiedlicher Schweregrade für jeden Computer durchzuführen.

## Überprüfen von Feldern

Standardmäßig trennt Hayabusa Felddaten durch das Symbol für den unterbrochenen Strich: `¦`.
Wenn Felddaten in einer horizontalen Zeile stehen, ist es dadurch sehr einfach, mehrere Felder zu unterscheiden, da dieses Zeichen in Logs nicht häufig vorkommt:

![Feldinformationen](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

Manchmal gibt es jedoch zu viele Feldinformationen im Log, und nicht alles passt auf einen Bildschirm.
In diesem Fall können Sie auf die Zelle doppelklicken, um ein Pop-up zu erhalten, das alle Feldinformationen anzeigt:

![Zelleninhalte](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

Das Problem ist, dass Timeline Explorer Ihnen nur erlaubt, Felddaten anhand von Zeilenumbruchzeichen (`CRLF`, `CR`, `LF`), Kommas und Tabulatoren zu formatieren.

Wenn Sie die Option `-M, --multiline` verwenden, können Sie Felder durch ein Zeilenumbruchzeichen trennen, und wenn Sie zum Öffnen des Inhalts einer Zelle doppelklicken, wird dieser ordnungsgemäß formatiert:

![Mehrzeilige Formatierung](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

Das Problem ist, dass nun nur das erste Feld in der Zeitleiste angezeigt wird, sodass Sie jedes Mal doppelklicken und ein neues Fenster öffnen müssen, wenn Sie die anderen Felddaten überprüfen möchten:

![Mehrzeiliges Einzelfeld](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

Leider unterstützt Timeline Explorer keine mehreren Zeilen in der Zeitleistenansicht.

Um dies zu umgehen, können Sie ab Hayabusa `v3.1.0` Felder durch Tabulatoren trennen:

![Tabulatortrennung](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

Es ist etwas schwieriger zu unterscheiden, wo ein Feld endet und das nächste beginnt.
Außerdem werden die Felder, wenn Sie doppelklicken und den Inhalt der Zelle öffnen, nicht automatisch formatiert:

![Tabulatortrennung nicht formatiert](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

Wenn Sie jedoch unten auf `Tab` und dann auf `Format` klicken, können Sie die Felder in eine leicht lesbare Ansicht formatieren:

![Tabulatortrennung formatiert](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Skins

Sie können das Farbschema über `Tools` -> `Skins` ändern, falls Sie beispielsweise den Dunkelmodus bevorzugen ...

## Sitzungen

Wenn Sie die Spalten und das Erscheinungsbild anpassen, Filter hinzufügen usw. und diese Einstellungen für später speichern möchten, speichern Sie unbedingt Ihre Sitzung über `File` -> `Session` -> `Save`.
