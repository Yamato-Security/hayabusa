# Analyse von Hayabusa-Ergebnissen mit jq

# Autor

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# Über

Die Fähigkeit, wichtige Felder in Logs zu identifizieren, zu extrahieren und Metriken dafür zu erstellen, ist eine wesentliche Kompetenz für DFIR- und Threat-Hunting-Analysten.
Hayabusa-Ergebnisse werden normalerweise in `.csv`-Dateien gespeichert, um sie in Programme wie Excel oder Timeline Explorer zur Timeline-Analyse zu importieren.
Wenn es jedoch Hunderte oder mehr desselben Ereignisses gibt, wird es unpraktisch oder unmöglich, sie manuell zu prüfen.
In diesen Situationen sortieren und zählen Analysten normalerweise ähnliche Datentypen, um nach Ausreißern zu suchen.
Dies wird auch als Long-Tail-Analyse, Stack Ranking, Häufigkeitsanalyse usw. bezeichnet.
Dies kann mit Hayabusa erreicht werden, indem die Ergebnisse in `.json`- oder `.jsonl`-Dateien ausgegeben und dann mit `jq` analysiert werden.

Beispielsweise könnte ein Analyst die installierten Dienste auf allen Workstations in einer Organisation vergleichen.
Obwohl es möglich ist, dass eine bestimmte Schadsoftware auf jeder Workstation installiert wird, ist es höchstwahrscheinlich, dass sie nur auf einer Handvoll Systeme existiert.
In diesem Fall sind die auf allen Systemen installierten Dienste eher gutartig, während seltene Dienste tendenziell verdächtiger sind und regelmäßig überprüft werden sollten.

Ein weiterer Anwendungsfall besteht darin, zu bestimmen, wie verdächtig etwas ist.
Beispielsweise könnte ein Analyst die `4625`-Logs für fehlgeschlagene Anmeldungen analysieren, um festzustellen, wie oft eine bestimmte IP-Adresse die Anmeldung nicht geschafft hat.
Wenn es nur wenige fehlgeschlagene Anmeldungen gab, hat ein Administrator wahrscheinlich nur sein Passwort falsch eingegeben.
Wenn es jedoch Hunderte oder mehr fehlgeschlagene Anmeldungen in kurzer Zeit durch eine bestimmte IP-Adresse gab, ist diese IP-Adresse wahrscheinlich bösartig.

Zu lernen, wie man `jq` verwendet, hilft Ihnen nicht nur, die Analyse von Windows-Ereignisprotokollen zu meistern, sondern aller im JSON-Format vorliegenden Logs.
Da JSON inzwischen ein sehr beliebtes Log-Format geworden ist und die meisten Cloud-Anbieter es für ihre Logs verwenden, ist die Fähigkeit, sie mit `jq` zu parsen, zu einer wesentlichen Kompetenz für den modernen Sicherheitsanalysten geworden.

In diesem Leitfaden erkläre ich zunächst, wie man `jq` für diejenigen nutzt, die es noch nie verwendet haben, und erläutere dann komplexere Verwendungen zusammen mit Beispielen aus der Praxis.
Ich empfehle die Verwendung von Linux, macOS oder Linux unter Windows, um `jq` mit anderen nützlichen Befehlen wie `sort`, `uniq`, `grep`, `sed` usw. kombinieren zu können.

# Installation von jq

Bitte beziehen Sie sich auf [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) und installieren Sie den Befehl `jq`.

# Über das JSON-Format

JSON-Logs sind eine Liste von Objekten, die in geschweiften Klammern `{` `}` enthalten sind.
Innerhalb dieser Objekte befinden sich Schlüssel-Wert-Paare, die durch Doppelpunkte getrennt sind.
Die Schlüssel müssen Zeichenketten sein, aber die Werte können einer der folgenden sein:
  * Zeichenkette (Bsp.: `"string"`)
  * Zahl (Bsp.: `10`)
  * ein weiteres Objekt (Bsp.: `{ xxxx }`)
  * Array (Bsp.: `["string", 10]`)
  * Boolescher Wert (Bsp.: `true`, `false`)
  * `null`

Sie können beliebig viele Objekte innerhalb von Objekten verschachteln.

In diesem Beispiel ist `Details` ein verschachteltes Objekt innerhalb eines Wurzelobjekts:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Über die JSON- und JSONL-Formate mit Hayabusa

In früheren Versionen verwendete Hayabusa das traditionelle JSON-Format, bei dem alle `{ xxx }`-Log-Objekte in ein einziges riesiges Array gepackt wurden.

Beispiel:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

Damit gibt es zwei Probleme.
Das erste Problem besteht darin, dass `jq`-Abfragen umständlicher werden, da alles mit einem zusätzlichen `.[]` beginnen muss, um anzuweisen, in dieses Array zu schauen.
Das viel größere Problem ist, dass es zum Parsen solcher Logs notwendig ist, zunächst alle Daten im Array zu laden.
Dies wird zu einem Problem, wenn Sie sehr große JSON-Dateien und nicht viel Speicher haben.
Um die erforderliche CPU- und Speichernutzung zu verringern, ist das JSONL-Format (JSON Lines), das nicht alles in ein riesiges Array packt, beliebter geworden.
Hayabusa gibt im JSON- und JSONL-Format aus, jedoch wird das JSON-Format nicht mehr innerhalb eines Arrays gespeichert.
Der einzige Unterschied besteht darin, dass das JSON-Format in einem Texteditor oder auf der Konsole leichter zu lesen ist, während das JSONL-Format jedes JSON-Objekt in einer einzigen Zeile speichert.
Das JSONL-Format ist etwas schneller und kleiner und daher ideal, wenn Sie die Logs nur in ein SIEM usw. importieren, sie aber nicht ansehen wollen.
Das JSON-Format ist ideal, wenn Sie auch einige manuelle Überprüfungen vornehmen wollen.

# Erstellen von JSON-Ergebnisdateien

In der aktuellen 2.x-Version von Hayabusa können Sie die Ergebnisse in JSON mit `hayabusa dfir-timeline -t json -d <directory> -o results.json` oder `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` für das JSONL-Format speichern.

Hayabusa verwendet das standardmäßige `standard`-Profil und speichert nur die minimale Datenmenge zur Analyse im `Details`-Objekt.
Wenn Sie alle ursprünglichen Feldinformationen in den .evtx-Logs speichern möchten, können Sie das `all-field-info`-Profil mit der Option `--profile all-field-info` verwenden.
Dadurch werden alle Feldinformationen im `AllFieldInfo`-Objekt gespeichert.
Wenn Sie sicherheitshalber sowohl die `Details`- als auch die `AllFieldInfo`-Objekte speichern möchten, können Sie das `super-verbose`-Profil verwenden.

## Vorteile der Verwendung von Details gegenüber AllFieldInfo

Der erste Vorteil der Verwendung von `Details` gegenüber `AllFieldInfo` besteht darin, dass nur die wichtigen Felder gespeichert werden und die Feldnamen verkürzt wurden, um Speicherplatz zu sparen.
Der Nachteil ist, dass die Möglichkeit besteht, Daten zu verpassen, die Ihnen eigentlich wichtig waren, aber übersehen wurden.
Der zweite Vorteil besteht darin, dass Hayabusa die Felder einheitlicher speichert, indem die Feldnamen normalisiert werden.
Beispielsweise befindet sich in ursprünglichen Windows-Logs der Benutzername normalerweise in einem `SubjectUserName`- oder `TargetUserName`-Feld.
Manchmal befindet sich der Benutzername jedoch in einem `AccountName`-Feld, manchmal befindet sich der Zielbenutzer tatsächlich im `SubjectUserName`-Feld usw.
Leider gibt es viele inkonsistente Feldnamen in Windows-Ereignisprotokollen.
Hayabusa versucht, diese Felder zu normalisieren, sodass ein Analyst nur einen gemeinsamen Namen herausparsen muss, anstatt die unendliche Menge an Eigenheiten und Diskrepanzen zwischen Event-IDs in Windows verstehen zu müssen.

Hier ist ein Beispiel für das Benutzerfeld.
Hayabusa normalisiert `SubjectUserName`, `TargetUserName`, `AccountName` usw. auf folgende Weise:
  * `SrcUser` (Source User / Quellbenutzer): wenn eine Aktion **von** einem Benutzer ausgeht. (Normalerweise ein Remote-Benutzer.)
  * `TgtUser` (Target User / Zielbenutzer): wenn eine Aktion **an** einem Benutzer geschieht. (Zum Beispiel eine Anmeldung **an** einen Benutzer.)
  * `User`: wenn eine Aktion von einem aktuell angemeldeten Benutzer ausgeführt wird. (Es gibt keine bestimmte Richtung in der Aktion.)

Ein weiteres Beispiel sind Prozesse.
In den ursprünglichen Windows-Ereignisprotokollen wird das Prozessfeld mit mehreren Namenskonventionen bezeichnet: `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName` usw.
Ohne Feldnormalisierung müsste ein Analyst zunächst über alle verschiedenen Feldnamen Bescheid wissen, dann alle Logs mit diesen Feldnamen extrahieren und sie dann zusammenführen.

Ein Analyst kann viel Zeit und Mühe sparen, indem er einfach das normalisierte einzelne `Proc`-Feld verwendet, das Hayabusa im `Details`-Objekt bereitstellt.

# jq-Lektionen/Rezepte

Ich liste nun mehrere Lektionen/Rezepte mit praktischen Beispielen auf, die Ihnen bei Ihrer Arbeit helfen können.

## 1. Manuelle Überprüfung mit jq und Less in Farbe

Dies ist eines der ersten Dinge, die man tun sollte, um zu verstehen, welche Felder in den Logs enthalten sind.
Sie könnten einfach ein `less results.json` ausführen, aber ein besserer Weg ist der folgende:
`cat results.json | jq -C | less -R`

Durch die Übergabe an `jq` werden alle Felder ordentlich formatiert, falls sie nicht von vornherein ordentlich formatiert waren.
Durch die Verwendung der Option `-C` (Farbe) bei `jq` und der Option `-R` (Rohausgabe) bei `less` können Sie in Farbe nach oben und unten scrollen.

## 2. Metriken

Hayabusa verfügt bereits über die Funktionalität, die Anzahl und den Prozentsatz von Ereignissen basierend auf Event-IDs auszugeben, jedoch ist es auch gut zu wissen, wie man dies mit `jq` macht.
Damit können Sie die Daten anpassen, für die Sie Metriken erstellen möchten.

Lassen Sie uns zunächst eine Liste von Event-IDs mit dem folgenden Befehl extrahieren:

`cat results.json | jq '.EventID'`

Dadurch wird nur die Event-ID-Nummer aus jedem Log extrahiert.
Geben Sie nach `jq` in einfachen Anführungszeichen einfach ein `.` und den Feldnamen ein, den Sie extrahieren möchten.
Sie sollten eine lange Liste wie diese sehen:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Leiten Sie nun die Ergebnisse an die Befehle `sort` und `uniq -c` weiter, um zu zählen, wie oft die Event-IDs aufgetreten sind:

`cat results.json | jq '.EventID' | sort | uniq -c`

Die Option `-c` für `uniq` zählt, wie oft eine eindeutige Event-ID aufgetreten ist.

Sie sollten so etwas sehen:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 Links steht die Anzahl und rechts die Event-ID.
 Wie Sie sehen, ist es nicht sortiert, sodass es schwer zu erkennen ist, welche Event-IDs am häufigsten aufgetreten sind.

 Sie können am Ende ein `sort -n` hinzufügen, um dies zu beheben:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

Die Option `-n` weist `sort` an, nach Zahl zu sortieren.

Sie sollten so etwas sehen:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

Wir können sehen, dass `4688`-Ereignisse (Prozesserstellung) am häufigsten aufgezeichnet wurden.
Das am zweithäufigsten aufgezeichnete Ereignis war `4625` (Fehlgeschlagene Anmeldung).

Wenn Sie die am häufigsten aufgezeichneten Ereignisse oben ausgeben möchten, können Sie die Sortierung mit `sort -n -r` oder `sort -nr` umkehren.
Sie können auch nur die 10 am häufigsten aufgezeichneten Ereignisse ausgeben, indem Sie die Ergebnisse an `head -n 10` weiterleiten.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

Dies ergibt:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

Es ist wichtig zu beachten, dass EIDs (Event-IDs) nicht eindeutig sind, sodass Sie völlig unterschiedliche Ereignisse mit derselben Event-ID haben können.
Daher ist es wichtig, auch den `Channel` zu prüfen.

Wir können diese Feldinformationen wie folgt hinzufügen:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Wir fügen `jq` die Option `-j` (join) hinzu, um alle Felder zusammenzufügen, getrennt durch Kommas und endend mit einem `\n`-Zeilenumbruchzeichen.

Dies ergibt:
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 Hinweis: `Security` wird zu `Sec`, `System` zu `Sys` und `PowerShell` zu `PwSh` abgekürzt.

Wir können den Regeltitel wie folgt hinzufügen:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Dies ergibt:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

Sie können nun beliebige Daten aus den Logs extrahieren und die Vorkommen zählen.

## 3. Filtern nach bestimmten Daten

Oft werden Sie nach bestimmten Event-IDs, Benutzern, Prozessen, LIDs (Logon-IDs) usw. filtern wollen.
Das können Sie mit `select` innerhalb der `jq`-Abfrage tun.

Lassen Sie uns beispielsweise alle `4624`-Ereignisse für erfolgreiche Anmeldungen extrahieren:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

Dies gibt alle JSON-Objekte für EID `4624` zurück:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

Wenn Sie nach mehreren Bedingungen filtern möchten, können Sie Schlüsselwörter wie `and`, `or` und `not` verwenden.

Lassen Sie uns beispielsweise nach `4624`-Ereignissen suchen, bei denen der Typ `3` ist (Netzwerkanmeldung).

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

Dies gibt alle Objekte zurück, bei denen die `EventID` `4624` ist und das verschachtelte Feld `"Details": { "Type" }` `3` ist.

Es gibt jedoch ein Problem.
Möglicherweise bemerken Sie Fehler wie `jq: error (at <stdin>:10636): Cannot index string with string "Type"`.
Immer wenn Sie den Fehler `Cannot index string with string` sehen, bedeutet dies, dass Sie `jq` anweisen, ein Feld auszugeben, das nicht existiert oder den falschen Typ hat.
Sie können diese Fehler beseitigen, indem Sie am Ende des Feldes ein `?` hinzufügen.
Dies weist `jq` an, die Fehler zu ignorieren.

Beispiel: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

Nachdem wir nach bestimmten Kriterien gefiltert haben, können wir nun ein `|` innerhalb der `jq`-Abfrage verwenden, um bestimmte interessierende Felder auszuwählen.

Lassen Sie uns beispielsweise den Zielbenutzernamen `TgtUser` und die Quell-IP-Adresse `SrcIP` extrahieren:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

Wieder fügen wir `jq` die Option `-j` (join) hinzu, um mehrere Felder zur Ausgabe auszuwählen.
Sie können dann `sort`, `uniq -c` usw. wie in den vorherigen Beispielen ausführen, um herauszufinden, wie oft sich eine bestimmte IP-Adresse über eine Typ-3-Netzwerkanmeldung bei einem Benutzer angemeldet hat.

## 4. Speichern der Ausgabe im CSV-Format

Leider unterscheiden sich die Felder in Windows-Ereignisprotokollen je nach Ereignistyp völlig, sodass es nicht ohne Weiteres möglich ist, kommagetrennte Timelines nach Feldern zu erstellen, ohne Hunderte von Spalten zu haben.
Es ist jedoch möglich, feldgetrennte Timelines für einzelne Ereignistypen zu erstellen.
Zwei häufige Beispiele sind Security `4624` (Erfolgreiche Anmeldungen) und `4625` (Fehlgeschlagene Anmeldungen), um nach Lateral Movement und Passwort-Erraten/-Spraying zu suchen.

In diesem Beispiel extrahieren wir nur Security-4624-Logs und geben den Zeitstempel, den Computernamen und alle `Details`-Informationen aus.
Wir speichern es in einer CSV-Datei mit `| @csv`, jedoch müssen wir die Daten als Array übergeben.
Das können wir tun, indem wir die auszugebenden Felder wie zuvor auswählen und sie mit eckigen Klammern `[ ]` umschließen, um sie in ein Array umzuwandeln.

Beispiel: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

Hinweise:
  * Um alle Felder im `Details`-Objekt auszuwählen, fügen wir `[]` hinzu.
  * Es gibt Fälle, in denen `Details` eine Zeichenkette und kein Array ist und `Cannot iterate over string`-Fehler ausgibt, sodass Sie ein `?` hinzufügen müssen.
  * Wir fügen `jq` die Option `-r` (Rohausgabe) hinzu, um doppelte Anführungszeichen nicht mit Backslash zu maskieren.

Ergebnisse:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

Wenn wir nur prüfen, wer erfolgreiche Anmeldungen hatte, benötigen wir möglicherweise nicht das letzte `LID`-Feld (Logon-ID).
Sie können jede nicht benötigte Spalte mit der Funktion `del` löschen.

Beispiel: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

Das Array zählt ab `0`, sodass wir zum Entfernen des 7. Feldes `6` verwenden.

Sie können nun die CSV-Datei speichern, indem Sie `> 4624-logs.csv` hinzufügen, und sie dann zur weiteren Analyse in Excel oder Timeline Explorer importieren.

Beachten Sie, dass Sie eine Kopfzeile hinzufügen müssen, um Filter durchzuführen.
Obwohl es möglich ist, eine Überschrift innerhalb der `jq`-Abfrage hinzuzufügen, ist es normalerweise am einfachsten, nach dem Speichern der Datei manuell eine oberste Zeile hinzuzufügen.

## 5. Finden von Daten mit den meisten Warnmeldungen

Hayabusa teilt Ihnen standardmäßig die Daten mit, die gemäß Schweregrad die meisten Warnmeldungen hatten.
Möglicherweise möchten Sie jedoch auch das zweit-, dritthäufigste usw. Datum mit Warnmeldungen finden.
Das können wir tun, indem wir den Zeitstempel per String-Slicing nach Jahr, Monat oder Datum gruppieren, je nach Ihren Bedürfnissen.

Beispiel: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` weist `jq` an, nur die ersten 10 Bytes aus `Timestamp` zu extrahieren.

Dies ergibt die Daten mit den meisten Ereignissen:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

Wenn Sie den Monat mit den meisten Ereignissen wissen möchten, können Sie einfach `.[:10]` in `.[:7]` ändern, um die ersten 7 Bytes zu extrahieren.

Wenn Sie die Daten mit den meisten `high`-Warnmeldungen auflisten möchten, können Sie dies tun:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

Sie können der Funktion `select` je nach Computername, Event-ID usw. weiterhin Filterbedingungen hinzufügen, je nach Ihren Bedürfnissen.

## 6. Rekonstruktion von PowerShell-Logs

Eine bedauerliche Sache an PowerShell-Logs ist, dass die Logs oft in mehrere Logs aufgeteilt werden, was sie schwer lesbar macht.
Wir können die Logs viel leichter lesbar machen, indem wir nur die Befehle extrahieren, die der Angreifer ausgeführt hat.

Wenn Sie beispielsweise EID-`4104`-ScriptBlock-Logs haben, können Sie nur dieses Feld extrahieren, um eine leicht lesbare Timeline zu erstellen.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

Dies ergibt eine Timeline wie folgt:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. Finden verdächtiger Netzwerkverbindungen

Sie können zunächst mit dem folgenden Befehl eine Liste aller Ziel-IP-Adressen abrufen:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

Wenn Sie über Threat Intelligence verfügen, können Sie prüfen, ob eine der IP-Adressen als bösartig bekannt ist.

Sie können zählen, wie oft eine bestimmte Ziel-IP-Adresse verbunden wurde, mit dem folgenden Befehl:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

Indem Sie `TgtIP` in `SrcIP` ändern, können Sie dieselbe Threat-Intelligence-Prüfung auf bösartige IP-Adressen basierend auf Quell-IP-Adressen durchführen.

Nehmen wir an, Sie haben festgestellt, dass die bösartige IP-Adresse `93.184.220.29` aus Ihrer Umgebung kontaktiert wird.
Sie können mit der folgenden Abfrage Details zu diesen Ereignissen abrufen:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

Dies ergibt JSON-Ergebnisse wie dieses:
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

Wenn Sie die kontaktierten Domains auflisten möchten, können Sie den folgenden Befehl verwenden:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> Hinweis: Ich habe einen grep-Filter für `.` hinzugefügt, um NETBIOS-Hostnamen zu entfernen.

## 8. Extrahieren von Hashes ausführbarer Binärdateien

In Sysmon-EID-`1`-Prozesserstellungs-Logs kann Sysmon so konfiguriert werden, dass es Hashes der Binärdatei berechnet.
Sicherheitsanalysten können diese Hashes mit Threat Intelligence mit bekannten bösartigen Hashes vergleichen.
Sie können das `Hashes`-Feld mit dem folgenden Befehl extrahieren:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

Dies ergibt eine Liste von Hashes wie diese:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon berechnet normalerweise mehrere Hashes wie `MD5`, `SHA1` und `IMPHASH`.
Sie können diese Hashes mit regulären Ausdrücken in `jq` extrahieren oder einfach String-Slicing für bessere Leistung verwenden.

Beispielsweise können Sie die MD5-Hashes extrahieren und Duplikate mit dem folgenden Befehl entfernen:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. PowerShell-Logs extrahieren

PowerShell-Scriptblock-Logs (EID: 4104) sind normalerweise in viele Logs aufgeteilt, und bei der Ausgabe im CSV-Format löscht Hayabusa Tabulatoren und Zeilenumbruchzeichen, um die Ausgabe präziser zu machen.
Am einfachsten lassen sich PowerShell-Logs jedoch mit der ursprünglichen Tabulator- und Zeilenumbruchformatierung und durch Zusammenführen der Logs analysieren.
Hier ist ein Beispiel für das Extrahieren der PowerShell-EID-4104-Logs von `COMPUTER-A` und das Speichern in einer `.ps1`-Datei, um sie in VSCode usw. zu öffnen und zu analysieren.
Nach dem Extrahieren des ScriptBlock-Feldes verwenden wir `awk`, um `\r\n` und `\n` durch Zeilenumbruchzeichen und `\t` durch Tabulatoren zu ersetzen.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

Nachdem der Analyst die Logs auf bösartige PowerShell-Befehle analysiert hat, muss er normalerweise nachschlagen, wann diese Befehle ausgeführt wurden.
Hier ist ein Beispiel für die Ausgabe des Zeitstempels und der PowerShell-Logs in eine CSV-Datei, um die Zeit nachzuschlagen, zu der ein Befehl ausgeführt wurde:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

Hinweis: Das verwendete Zeichenketten-Trennzeichen ist `¦`, da einfache und doppelte Anführungszeichen häufig in PowerShell-Logs vorkommen und die CSV-Ausgabe beschädigen.
Wenn Sie die CSV-Datei importieren, müssen Sie der Anwendung das Zeichenketten-Trennzeichen `¦` angeben.
