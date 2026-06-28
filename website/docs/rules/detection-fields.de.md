# Erkennungsfeld

## Grundlagen der Selektion

Zunächst werden die Grundlagen erklärt, wie man eine Selektionsregel erstellt.

### Wie man UND- und ODER-Logik schreibt

Um UND-Logik zu schreiben, verwenden wir verschachtelte Dictionaries.
Die untenstehende Erkennungsregel definiert, dass **beide Bedingungen** wahr sein müssen, damit die Regel zutrifft.
- EventID muss exakt `7040` sein.
- **AND**
- Channel muss exakt `System` sein.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

Um ODER-Logik zu schreiben, verwenden wir Listen (Dictionaries, die mit `-` beginnen).
In der untenstehenden Erkennungsregel löst **eine der beiden** Bedingungen das Zutreffen der Regel aus.
- EventID muss exakt `7040` sein.
- **OR**
- Channel muss exakt `System` sein.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

Wir können auch `AND`- und `OR`-Logik kombinieren, wie unten gezeigt.
In diesem Fall trifft die Regel zu, wenn die folgenden beiden Bedingungen beide wahr sind.
- EventID ist entweder exakt `7040` **OR** `7041`.
- **AND**
- Channel ist exakt `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

Das Folgende ist ein Auszug aus einem Windows-Ereignisprotokoll, formatiert im ursprünglichen XML.
Das Feld `Event.System.Channel` im obigen Beispiel der Regeldatei bezieht sich auf das ursprüngliche XML-Tag: `<Event><System><Channel>System<Channel><System></Event>`
Verschachtelte XML-Tags werden durch Tag-Namen ersetzt, die durch Punkte (`.`) getrennt sind.
In Hayabusa-Regeln werden diese mit Punkten verbundenen Feldzeichenketten als `eventkeys` bezeichnet.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Eventkey-Aliase

Lange Eventkeys mit vielen `.`-Trennungen sind häufig, daher verwendet Hayabusa Aliase, um die Arbeit damit zu erleichtern. Aliase werden in der Datei `rules/config/eventkey_alias.txt` definiert. Diese Datei ist eine CSV-Datei, die aus Zuordnungen von `alias` und `event_key` besteht. Sie können die obige Regel wie unten gezeigt mit Aliasen umschreiben, wodurch die Regel leichter lesbar wird.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Achtung: Undefinierte Eventkey-Aliase

Nicht alle Eventkey-Aliase sind in `rules/config/eventkey_alias.txt` definiert. Wenn Sie nicht die korrekten Daten in der `details`-Nachricht (`Alert details`) erhalten und stattdessen `n/a` (nicht verfügbar) erhalten, oder wenn die Selektion in Ihrer Erkennungslogik nicht ordnungsgemäß funktioniert, müssen Sie möglicherweise `rules/config/eventkey_alias.txt` mit einem neuen Alias aktualisieren.

### Wie man XML-Attribute in Bedingungen verwendet

XML-Elemente können Attribute haben, die durch Hinzufügen eines Leerzeichens zum Element gesetzt werden. Zum Beispiel ist `Name` in `Provider Name` unten ein XML-Attribut des `Provider`-Elements.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

Um XML-Attribute in einem Eventkey anzugeben, verwenden Sie das Format `{eventkey}_attributes.{attribute_name}`. Um zum Beispiel das `Name`-Attribut des `Provider`-Elements in einer Regeldatei anzugeben, würde es so aussehen:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep-Suche

Hayabusa kann grep-Suchen in Windows-Ereignisprotokolldateien durchführen, indem keine Eventkeys angegeben werden.

Um eine grep-Suche durchzuführen, geben Sie die Erkennung wie unten gezeigt an. In diesem Fall trifft es zu, wenn die Zeichenketten `mimikatz` oder `metasploit` im Windows-Ereignisprotokoll enthalten sind. Es ist auch möglich, Platzhalter anzugeben.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Hinweis: Hayabusa konvertiert Windows-Ereignisprotokolldaten intern in das JSON-Format, bevor die Daten verarbeitet werden, sodass ein Abgleich mit XML-Tags nicht möglich ist.

### EventData

Windows-Ereignisprotokolle sind in zwei Teile gegliedert: den `System`-Teil, in dem die grundlegenden Daten (Event ID, Zeitstempel, Record ID, Protokollname (Channel)) geschrieben werden, und den `EventData`- oder `UserData`-Teil, in dem je nach Event ID beliebige Daten geschrieben werden.
Ein häufig auftretendes Problem ist, dass die Namen der in `EventData` verschachtelten Felder alle `Data` heißen, sodass die bisher beschriebenen Eventkeys nicht zwischen `SubjectUserSid` und `SubjectUserName` unterscheiden können.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

Um dieses Problem zu lösen, können Sie den in `Data Name` zugewiesenen Wert angeben. Wenn Sie zum Beispiel `SubjectUserName` und `SubjectDomainName` in den EventData als Bedingung einer Regel verwenden möchten, können Sie es wie folgt beschreiben:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Anomale Muster in EventData

Einige der in `EventData` verschachtelten Tags haben kein `Name`-Attribut.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

Um ein Ereignisprotokoll wie das obige zu erkennen, können Sie einen Eventkey namens `Data` angeben.
In diesem Fall trifft die Bedingung zu, solange eines der verschachtelten `Data`-Tags gleich `None` ist.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Ausgabe von Felddaten aus mehreren Feldnamen mit demselben Namen

Einige Ereignisse speichern ihre Daten in Feldnamen, die alle `Data` heißen, wie im vorherigen Beispiel.
Wenn Sie `%Data%` in `details:` angeben, werden alle Daten in einem Array ausgegeben.

Zum Beispiel:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Wenn Sie nur die Daten des ersten `Data`-Feldes ausgeben möchten, können Sie `%Data[1]%` in Ihrer `details:`-Alarmzeichenkette angeben, und es wird nur `rundll32.exe` ausgegeben.

## Feld-Modifikatoren

Ein Pipe-Zeichen kann mit Eventkeys wie unten gezeigt für den Abgleich von Zeichenketten verwendet werden.
Alle bisher beschriebenen Bedingungen verwenden exakte Übereinstimmungen, aber durch die Verwendung von Feld-Modifikatoren können Sie flexiblere Erkennungsregeln beschreiben.
Im folgenden Beispiel trifft die Bedingung zu, wenn ein Wert von `Data` die Zeichenkette `EngineVersion=2` enthält.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

Zeichenketten-Übereinstimmungen sind nicht case-sensitiv. Sie werden jedoch case-sensitiv, sobald `|re` oder `|equalsfield` verwendet werden.

### Unterstützte Sigma-Feld-Modifikatoren

Hayabusa ist derzeit das einzige Open-Source-Tool, das die gesamte Sigma-Spezifikation vollständig unterstützt.

Sie können den aktuellen Status aller unterstützten Feld-Modifikatoren sowie die Häufigkeit, mit der diese Modifikatoren in Sigma- und Hayabusa-Regeln verwendet werden, unter https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md überprüfen.
Dieses Dokument wird dynamisch jedes Mal aktualisiert, wenn es ein Update für Sigma- oder Hayabusa-Regeln gibt.

- `'|all':`: Dieser Feld-Modifikator unterscheidet sich von den obigen, da er nicht auf ein bestimmtes Feld, sondern auf alle Felder angewendet wird.

    In diesem Beispiel müssen beide Zeichenketten `Keyword-1` und `Keyword-2` existieren, können aber überall in jedem Feld vorkommen:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Daten werden je nach ihrer Position in der kodierten Zeichenkette auf drei verschiedene Arten in base64 kodiert. Dieser Modifikator kodiert eine Zeichenkette in alle drei Varianten und prüft, ob die Zeichenkette irgendwo in der base64-Zeichenkette kodiert ist.
- `|cased`: Macht die Suche case-sensitiv.
- `|cidr`: Prüft, ob ein Feldwert einer IPv4- oder IPv6-CIDR-Notation entspricht. (Bsp.: `192.0.2.0/24`)
- `|contains`: Prüft, ob ein Feldwert eine bestimmte Zeichenkette enthält.
- `|contains|all`: Prüft, ob mehrere Wörter in den Daten enthalten sind.
- `|contains|all|windash`: Wie `|contains|windash`, aber alle Schlüsselwörter müssen vorhanden sein.
- `|contains|cased`: Prüft, ob ein Feldwert eine bestimmte case-sensitive Zeichenkette enthält.
- `|contains|expand`: Prüft, ob ein Feldwert eine Zeichenkette in der `expand`-Konfigurationsdatei innerhalb von `/config/expand/` enthält.
- `|contains|windash`: Prüft die Zeichenkette unverändert und konvertiert das erste `-`-Zeichen in die Permutationen der Zeichen `/`, `–` (en dash), `—` (em dash) und `―` (horizontal bar).
- `|endswith`: Prüft, ob ein Feldwert mit einer bestimmten Zeichenkette endet.
- `|endswith|cased`: Prüft, ob ein Feldwert mit einer bestimmten case-sensitiven Zeichenkette endet.
- `|endswith|windash`: Prüft das Ende der Zeichenkette und führt Variationen für Bindestriche durch.
- `|exists`: Prüft, ob ein Feld existiert.
- `|expand`: Prüft, ob ein Feldwert einer Zeichenkette in der `expand`-Konfigurationsdatei innerhalb von `/config/expand/` entspricht.
- `|fieldref`: Prüft, ob die Werte in zwei Feldern gleich sind. Sie können `not` in der `condition` verwenden, wenn Sie prüfen möchten, ob zwei Felder unterschiedlich sind.
- `|fieldref|contains`: Prüft, ob der Wert eines Feldes in einem anderen Feld enthalten ist.
- `|fieldref|endswith`: Prüft, ob das linke Feld mit der Zeichenkette des rechten Feldes endet. Sie können `not` in der `condition` verwenden, um zu prüfen, ob sie unterschiedlich sind.
- `|fieldref|startswith`: Prüft, ob das linke Feld mit der Zeichenkette des rechten Feldes beginnt. Sie können `not` in der `condition` verwenden, um zu prüfen, ob sie unterschiedlich sind.
- `|gt`: Prüft, ob ein Feldwert größer als eine bestimmte Zahl ist.
- `|gte`: Prüft, ob ein Feldwert größer oder gleich einer bestimmten Zahl ist.
- `|lt`: Prüft, ob ein Feldwert kleiner als eine bestimmte Zahl ist.
- `|lte`: Prüft, ob ein Feldwert kleiner oder gleich einer bestimmten Zahl ist.
- `|re`: Verwendet case-sensitive reguläre Ausdrücke. (Wir verwenden die regex-Crate, daher lesen Sie bitte die Dokumentation unter <https://docs.rs/regex/latest/regex/#syntax>, um zu erfahren, wie man unterstützte reguläre Ausdrücke schreibt.)
    > Achtung: [Die Syntax für reguläre Ausdrücke in Sigma-Regeln](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) verwendet PCRE, wobei bestimmte Metazeichen für Zeichenklassen, Lookbehind, atomares Gruppieren usw. nicht unterstützt werden. Die Rust-regex-Crate sollte in der Lage sein, alle regulären Ausdrücke in Sigma-Regeln zu verwenden, aber es besteht die Möglichkeit von Inkompatibilität. 
- `|re|i`: (Insensitive) Verwendet case-insensitive reguläre Ausdrücke.
- `|re|m`: (Multi-line) Abgleich über mehrere Zeilen. `^` / `$` stimmen mit dem Anfang/Ende der Zeile überein.
- `|re|s`: (Single-line) Punkt (`.`) stimmt mit allen Zeichen überein, einschließlich des Zeilenumbruchzeichens.
- `|startswith`: Prüft, ob ein Feldwert mit einer bestimmten Zeichenkette beginnt.
- `|startswith|cased`: Prüft, ob ein Feldwert mit einer bestimmten case-sensitiven Zeichenkette beginnt.
- `|utf16|base64offset|contains`: Prüft, ob eine bestimmte UTF-16-Zeichenkette innerhalb einer base64-Zeichenkette kodiert ist.
- `|utf16be|base64offset|contains`: Prüft, ob eine bestimmte UTF-16-Big-Endian-Zeichenkette innerhalb einer base64-Zeichenkette kodiert ist.
- `|utf16le|base64offset|contains`: Prüft, ob eine bestimmte UTF-16-Little-Endian-Zeichenkette innerhalb einer base64-Zeichenkette kodiert ist.
- `|wide|base64offset|contains`: Alias für `utf16le|base64offset|contains`, prüft auf UTF-16-Little-Endian-Zeichenketten.

### Veraltete Feld-Modifikatoren

Die folgenden Modifikatoren sind nun veraltet und wurden durch Modifikatoren ersetzt, die sich stärker an die Sigma-Spezifikationen halten.

- `|equalsfield`: Wird nun durch `|fieldref` ersetzt.
- `|endswithfield`: Wird nun durch `|fieldref|endswith` ersetzt.

### Expand-Feld-Modifikatoren

Die `expand`-Feld-Modifikatoren sind einzigartig, da sie die einzigen Feld-Modifikatoren sind, die vor der Verwendung eine Konfiguration erfordern.
Sie verwenden zum Beispiel Platzhalter wie `%DC-MACHINE-NAME%` und erfordern eine Konfigurationsdatei namens `/config/expand/DC-MACHINE-NAME.txt`, die alle möglichen DC-Maschinennamen enthält.

Wie man dies konfiguriert, wird [hier](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command) ausführlicher erklärt.

## Platzhalter

Platzhalter können in Eventkeys verwendet werden. Im untenstehenden Beispiel trifft die Regel zu, wenn `ProcessCommandLine` mit der Zeichenkette "malware" beginnt.
Die Spezifikation ist grundsätzlich dieselbe wie bei Sigma-Regel-Platzhaltern und ist daher case-insensitiv.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Die folgenden beiden Platzhalter können verwendet werden.
- `*`: Stimmt mit einer beliebigen Zeichenkette von null oder mehr Zeichen überein. (Intern wird er in den regulären Ausdruck `.*` konvertiert)
- `?`: Stimmt mit einem einzelnen beliebigen Zeichen überein. (Intern in den regulären Ausdruck `.` konvertiert)

Über das Escapen von Platzhaltern:
- Platzhalter (`*` und `?`) können durch Verwendung eines Backslashes escaped werden: `\*`, `\?`.
- Wenn Sie einen Backslash direkt vor einem Platzhalter verwenden möchten, schreiben Sie `\\*` oder `\\?`.
- Escapen ist nicht erforderlich, wenn Sie Backslashes alleine verwenden.

## null-Schlüsselwort

Das Schlüsselwort `null` kann verwendet werden, um zu prüfen, ob ein Feld nicht existiert.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Hinweis: Dies unterscheidet sich von `ProcessCommandLine: ''`, das prüft, ob der Wert eines Feldes leer ist.

## condition

Mit der oben erläuterten Notation können Sie `AND`- und `OR`-Logik ausdrücken, aber es wird verwirrend, wenn Sie versuchen, komplexe Logik zu definieren.
Wenn Sie komplexere Regeln erstellen möchten, sollten Sie das Schlüsselwort `condition` wie unten gezeigt verwenden.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

Die folgenden Ausdrücke können für `condition` verwendet werden.
- `{expression1} and {expression2}`: Erfordert sowohl {expression1} UND {expression2}
- `{expression1} or {expression2}`: Erfordert entweder {expression1} ODER {expression2}
- `not {expression}`: Kehrt die Logik von {expression} um
- `( {expression} )`: Legt die Vorrangstellung von {expression} fest. Es folgt derselben Vorrang-Logik wie in der Mathematik.

Im obigen Beispiel werden Selektionsnamen wie `SELECTION_1`, `SELECTION_2` usw. verwendet, aber sie können beliebig benannt werden, solange sie nur die folgenden Zeichen enthalten: `a-z A-Z 0-9 _`
> Verwenden Sie jedoch nach Möglichkeit die Standardkonvention `selection_1`, `selection_2`, `filter_1`, `filter_2` usw., um die Lesbarkeit zu erleichtern.

## not-Logik

Viele Regeln führen zu False Positives, daher ist es sehr üblich, eine Selektion für die zu suchenden Signaturen zu haben, aber auch eine Filterselektion, um nicht bei False Positives zu alarmieren.
Zum Beispiel:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma-Korrelationen

Wir haben alle Sigma-Version-2.0.0-Korrelationen implementiert, wie [hier](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md) definiert.

Unterstützte Korrelationen:
- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

Die neuen "metrics"-Korrelationsregeln (`value_sum`, `value_avg`, `value_percentile`), die am 12. September 2025 in Sigma-Version 2.1.0 veröffentlicht wurden, werden derzeit nicht unterstützt.
