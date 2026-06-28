## Event-Count-Regeln

Dies sind Regeln, die bestimmte Ereignisse zählen und warnen, wenn zu viele oder zu wenige dieser Ereignisse innerhalb eines Zeitraums auftreten.
Häufige Beispiele für die Erkennung vieler Ereignisse innerhalb eines bestimmten Zeitraums sind die Erkennung von Passwort-Rateangriffen, Password-Spray-Angriffen und Denial-of-Service-Angriffen.
Sie könnten diese Regeln auch verwenden, um Zuverlässigkeitsprobleme der Protokollquelle zu erkennen, etwa wenn bestimmte Ereignisse unter einen bestimmten Schwellenwert fallen.

### Beispiel für eine Event-Count-Regel:

Das folgende Beispiel verwendet zwei Regeln, um Passwort-Rateangriffe zu erkennen.
Es wird eine Warnung ausgelöst, wenn die referenzierte Regel innerhalb von 5 Minuten 5-mal oder häufiger zutrifft und das Feld `IpAddress` für diese Ereignisse identisch ist.

> Beachten Sie, dass wir nur die notwendigen Felder aufgenommen haben, um das Konzept zu verstehen.
> Die vollständige Regel, auf der dieses Beispiel basiert, finden Sie zu Ihrer Information [hier](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml).

### Event-Count-Korrelationsregel:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Regel "Failed Logon - Incorrect Password":

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### Beispiel für die veraltete `count`-Regel:

Die obige Korrelation und die referenzierten Regeln liefern dieselben Ergebnisse wie die folgende Regel, die den älteren `count`-Modifikator verwendet:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Ausgabe der Event-Count-Regel:

Die obigen Regeln erzeugen die folgende Ausgabe:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Value-Count-Regeln

Diese Regeln zählen dieselben Ereignisse innerhalb eines Zeitraums mit **unterschiedlichen** Werten eines bestimmten Feldes.

Beispiele:
- Netzwerk-Scans, bei denen eine einzelne Quell-IP-Adresse versucht, sich mit vielen verschiedenen Ziel-IP-Adressen und/oder -Ports zu verbinden.
- Password-Spraying-Angriffe, bei denen eine einzelne Quelle sich bei vielen verschiedenen Benutzern nicht authentifizieren kann.
- Erkennung von Tools wie BloodHound, die innerhalb eines kurzen Zeitraums viele hoch privilegierte AD-Gruppen aufzählen.

### Beispiel für eine Value-Count-Regel:

Die folgende Regel erkennt, wenn ein Angreifer versucht, Benutzernamen zu erraten.
Das heißt, wenn dieselbe Quell-IP-Adresse (`IpAddress`) innerhalb von 5 Minuten bei mehr als 3 **verschiedenen** Benutzernamen (`TargetUserName`) bei der Anmeldung scheitert.

> Beachten Sie, dass wir nur die notwendigen Felder aufgenommen haben, um das Konzept zu verstehen.
> Die vollständige Regel, auf der dieses Beispiel basiert, finden Sie zu Ihrer Information [hier](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml).

### Value-Count-Korrelationsregel:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Value-Count-Regel "Logon Failure (Non-existant User)":

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### Regel mit veraltetem `count`-Modifikator:

Die obige Korrelation und die referenzierten Regeln liefern dieselben Ergebnisse wie die folgende Regel, die den älteren `count`-Modifikator verwendet:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Ausgabe der Value-Count-Regel:

Die obigen Regeln erzeugen die folgende Ausgabe:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Temporal-Proximity-Regeln

Alle durch die im Feld rules referenzierten Regeln definierten Ereignisse müssen innerhalb des durch timespan definierten Zeitraums auftreten.
Die Werte der in `group-by` definierten Felder müssen alle denselben Wert haben (z. B. derselbe Host, Benutzer usw.).

### Beispiel für eine Temporal-Proximity-Regel:

Beispiel: In drei Sigma-Regeln definierte Aufklärungsbefehle werden innerhalb von 5 Minuten in beliebiger Reihenfolge von demselben Benutzer auf einem System aufgerufen.

### Temporal-Proximity-Korrelationsregel:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Ordered-Temporal-Proximity-Regeln

Der Korrelationstyp `temporal_ordered` verhält sich wie `temporal` und erfordert zusätzlich, dass die Ereignisse in der im Attribut `rules` angegebenen Reihenfolge auftreten.

### Beispiel für eine Ordered-Temporal-Proximity-Regel:

Beispiel: Auf viele fehlgeschlagene Anmeldungen wie oben definiert folgt innerhalb von 1 Stunde eine erfolgreiche Anmeldung desselben Benutzerkontos:

### Ordered-Temporal-Proximity-Korrelationsregel:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## Hinweise zu Korrelationsregeln

1. Sie sollten alle Ihre Korrelations- und referenzierten Regeln in einer einzigen Datei zusammenfassen und sie mit einem YAML-Trennzeichen `---` voneinander trennen.

2. Standardmäßig werden referenzierte Korrelationsregeln nicht ausgegeben. Wenn Sie die Ausgabe der referenzierten Regeln sehen möchten, müssen Sie `generate: true` unter `correlation` hinzufügen. Dies ist sehr nützlich, um es beim Erstellen von Korrelationsregeln zu aktivieren und zu überprüfen.

    Beispiel:
    ```
    correlation:
        generate: true
    ```
3. Sie können beim Referenzieren von Regeln Aliasnamen anstelle von Regel-IDs verwenden, um die Verständlichkeit zu erhöhen.

4. Sie können mehrere Regeln referenzieren.

5. Sie können mehrere Felder in `group-by` verwenden. Wenn Sie dies tun, müssen alle Werte in diesen Feldern identisch sein, andernfalls erhalten Sie keine Warnung. In den meisten Fällen werden Sie Regeln schreiben, die mit `group-by` nach bestimmten Feldern filtern, um Falschmeldungen zu reduzieren; es ist jedoch möglich, `group-by` wegzulassen, um eine allgemeinere Regel zu erstellen.

6. Der Zeitstempel der Korrelationsregel entspricht dem allerersten Beginn des Angriffs, daher sollten Sie die danach folgenden Ereignisse überprüfen, um zu bestätigen, ob es sich um eine Falschmeldung handelt oder nicht.
