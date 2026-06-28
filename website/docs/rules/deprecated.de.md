# Veraltete Funktionen

Die veralteten Spezialschlüsselwörter und die `count`-Aggregation werden in Hayabusa weiterhin unterstützt, in Zukunft aber nicht mehr innerhalb von Regeln verwendet.

## Veraltete Spezialschlüsselwörter

Derzeit können die folgenden Spezialschlüsselwörter angegeben werden:

- `value`: gleicht über eine Zeichenkette ab (Platzhalter und Pipes können ebenfalls angegeben werden).
- `min_length`: gleicht ab, wenn die Anzahl der Zeichen größer oder gleich der angegebenen Zahl ist.
- `regexes`: gleicht ab, wenn einer der regulären Ausdrücke in der Datei übereinstimmt, die Sie in diesem Feld angeben.
- `allowlist`: die Regel wird übersprungen, wenn in der Liste der regulären Ausdrücke in der Datei, die Sie in diesem Feld angeben, eine Übereinstimmung gefunden wird.

Im folgenden Beispiel gleicht die Regel ab, wenn das Folgende zutrifft:

- `ServiceName` heißt `malicious-service` oder enthält einen regulären Ausdruck in `./rules/config/regex/detectlist_suspicous_services.txt`.
- `ImagePath` hat mindestens 1000 Zeichen.
- `ImagePath` hat keine Übereinstimmungen in der `allowlist`.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### Beispieldateien für die Schlüsselwörter regexes und allowlist

Hayabusa hatte zwei integrierte Dateien mit regulären Ausdrücken, die für die Datei `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml` verwendet wurden:

- `./rules/config/regex/detectlist_suspicous_services.txt`: zum Erkennen verdächtiger Dienstnamen
- `./rules/config/regex/allowlist_legitimate_services.txt`: zum Zulassen legitimer Dienste

Die in `regexes` und `allowlist` definierten Dateien können bearbeitet werden, um das Verhalten aller Regeln zu ändern, die sie referenzieren, ohne dass eine Regeldatei selbst geändert werden muss.

Sie können auch andere von Ihnen erstellte detectlist- und allowlist-Textdateien verwenden.

## Veraltete Aggregationsbedingungen (`count`-Regeln)

Dies wird in Hayabusa weiterhin unterstützt, wird aber in Zukunft durch Sigma-Korrelationsregeln ersetzt.

### Grundlagen

Das oben beschriebene Schlüsselwort `condition` implementiert nicht nur `AND`- und `OR`-Logik, sondern kann Ereignisse auch zählen oder "aggregieren".
Diese Funktion wird als "Aggregationsbedingung" bezeichnet und wird durch das Verbinden einer Bedingung mit einer Pipe angegeben.
Im folgenden Beispiel zur Erkennung von Password-Spray wird ein bedingter Ausdruck verwendet, um festzustellen, ob es innerhalb eines Zeitraums von 5 Minuten 5 oder mehr `TargetUserName`-Werte von einer Quell-`IpAddress` gibt.

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

Aggregationsbedingungen können im folgenden Format definiert werden:

- `count() {operator} {number}`: Für Logereignisse, die der ersten Bedingung vor der Pipe entsprechen, gleicht die Bedingung ab, wenn die Anzahl der übereinstimmenden Logs den durch `{operator}` und `{number}` angegebenen Bedingungsausdruck erfüllt.

`{operator}` kann einer der folgenden sein:

- `==`: Wenn der Wert gleich dem angegebenen Wert ist, wird er als die Bedingung erfüllend behandelt.
- `>=`: Wenn der Wert größer oder gleich dem angegebenen Wert ist, gilt die Bedingung als erfüllt.
- `>`: Wenn der Wert größer als der angegebene Wert ist, gilt die Bedingung als erfüllt.
- `<=`: Wenn der Wert kleiner oder gleich dem angegebenen Wert ist, gilt die Bedingung als erfüllt.
- `<`: Wenn der Wert kleiner als der angegebene Wert ist, wird er so behandelt, als ob die Bedingung erfüllt ist.

`{number}` muss eine Zahl sein.

`timeframe` kann folgendermaßen definiert werden:

- `15s`: 15 Sekunden
- `30m`: 30 Minuten
- `12h`: 12 Stunden
- `7d`: 7 Tage
- `3M`: 3 Monate

### Vier Muster für Aggregationsbedingungen

1. Kein count-Argument oder `by`-Schlüsselwort. Beispiel: `selection | count() > 10`
   > Wenn `selection` innerhalb des Zeitraums mehr als 10 Mal übereinstimmt, gleicht die Bedingung ab.
   > Diese werden durch Event-Count-Korrelationsregeln ersetzt, die das Feld `group-by` nicht verwenden.
2. Kein count-Argument, aber ein `by`-Schlüsselwort. Beispiel: `selection | count() by IpAddress > 10`
   > `selection` muss für **dieselbe** `IpAddress` mehr als 10 Mal wahr sein.
   > Diese Regeln #2 sind häufiger als die Regeln #1.
   > Sie können auch mehrere Felder zum Gruppieren angeben. Zum Beispiel: `by IpAddress, Computer`
   > Diese werden durch Event-Count-Korrelationsregeln ersetzt, die das Feld `group-by` verwenden.
3. Es gibt ein count-Argument, aber kein `by`-Schlüsselwort. Beispiel: `selection | count(TargetUserName) > 10`
   > Wenn `selection` übereinstimmt und `TargetUserName` innerhalb des Zeitraums mehr als 10 Mal **unterschiedlich** ist, gleicht die Bedingung ab.
   > Diese werden durch Value-Count-Korrelationsregeln ersetzt, die das Feld `group-by` nicht verwenden.
4. Es gibt sowohl ein count-Argument als auch ein `by`-Schlüsselwort. Beispiel: `selection | count(Users) by IpAddress > 10`
   > Für **dieselbe** `IpAddress` muss es mehr als 10 **unterschiedliche** `TargetUserName` geben, damit die Bedingung übereinstimmt.
   > Diese Regeln #4 sind häufiger als die Regeln #3.
   > Diese werden durch Value-Count-Korrelationsregeln ersetzt, die das Feld `group-by` verwenden.

### Beispiel für Muster 1

Dies ist das grundlegendste Muster: `count() {operator} {number}`. Die folgende Regel gleicht ab, wenn `selection` 3 oder mehr Mal auftritt.

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### Beispiel für Muster 2

`count() by {eventkey} {operator} {number}`: Logereignisse, die der `condition` vor der Pipe entsprechen, werden nach **demselben** `{eventkey}` gruppiert. Wenn die Anzahl der übereinstimmenden Ereignisse für jede Gruppierung die durch `{operator}` und `{number}` angegebene Bedingung erfüllt, gleicht die Bedingung ab.

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### Beispiel für Muster 3

`count({eventkey}) {operator} {number}`: Zählt, wie viele **unterschiedliche** Werte von `{eventkey}` im Logereignis existieren, das der Bedingung vor der Bedingungs-Pipe entspricht. Wenn die Anzahl den in `{operator}` und `{number}` angegebenen bedingten Ausdruck erfüllt, gilt die Bedingung als erfüllt.

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### Beispiel für Muster 4

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: Die Logs, die der Bedingung vor der Bedingungs-Pipe entsprechen, werden nach **demselben** `{eventkey_2}` gruppiert, und die Anzahl der **unterschiedlichen** Werte von `{eventkey_1}` in jeder Gruppe wird gezählt. Wenn die für jede Gruppierung gezählten Werte den durch `{operator}` und `{number}` angegebenen bedingten Ausdruck erfüllen, gleicht die Bedingung ab.

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Ausgabe von count-Regeln

Die Detailausgabe für count-Regeln ist fest und gibt die ursprüngliche count-Bedingung in `[condition]` aus, gefolgt von den aufgezeichneten eventkeys in `[result]`.

Im folgenden Beispiel eine Liste der `TargetUserName`-Benutzernamen, die per Bruteforce angegriffen wurden, gefolgt von der Quell-`IpAddress`:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

Der Zeitstempel der Warnung ist die Zeit des ersten erkannten Ereignisses.
