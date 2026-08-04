# Timeline-Ausgabe

## Ausgabeprofile

Hayabusa verfügt über 5 vordefinierte Ausgabeprofile zur Verwendung in `config/profiles.yaml`:

1. `minimal`
2. `standard` (Standard)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Sie können ganz einfach eigene Profile anpassen oder hinzufügen, indem Sie diese Datei bearbeiten.
Außerdem können Sie das Standardprofil mit `set-default-profile --profile <profile>` problemlos ändern.
Verwenden Sie den Befehl `list-profiles`, um die verfügbaren Profile und deren Feldinformationen anzuzeigen.

### 1. Ausgabe des Profils `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. Ausgabe des Profils `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. Ausgabe des Profils `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. Ausgabe des Profils `all-field-info`

Anstatt die minimalen `details`-Informationen auszugeben, werden alle Feldinformationen in den Abschnitten `EventData` und `UserData` zusammen mit ihren ursprünglichen Feldnamen ausgegeben.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. Ausgabe des Profils `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. Ausgabe des Profils `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. Ausgabe des Profils `timesketch-minimal`

Ausgabe in einem Format, das mit dem Import in [Timesketch](https://timesketch.org/) kompatibel ist.

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. Ausgabe des Profils `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Profilvergleich

Die folgenden Benchmarks wurden auf einem Lenovo P51 aus dem Jahr 2018 (Xeon 4-Core-CPU / 64 GB RAM) mit 3 GB an evtx-Daten und 3891 aktivierten Regeln durchgeführt. (01.06.2023)

| Profil | Verarbeitungszeit | Ausgabedateigröße | Zunahme der Dateigröße |
| :---: | :---: | :---: | :---: |
| minimal | 8 Minuten 50 Sekunden | 770 MB | -30% |
| standard (Standard) | 9 Minuten 00 Sekunden | 1,1 GB | Keine |
| verbose | 9 Minuten 10 Sekunden | 1,3 GB | +20% |
| all-field-info | 9 Minuten 3 Sekunden | 1,2 GB | +10% |
| all-field-info-verbose | 9 Minuten 10 Sekunden | 1,3 GB | +20% |
| super-verbose | 9 Minuten 12 Sekunden | 1,5 GB | +35% |

### Profil-Feld-Aliase

Die folgenden Informationen können mit den integrierten Ausgabeprofilen ausgegeben werden:

| Aliasname | Hayabusa-Ausgabeinformationen |
| :--- | :--- |
|%AllFieldInfo% | Alle Feldinformationen. |
|%Channel% | Der Name des Logs. Feld `<Event><System><Channel>`. |
|%Computer% | Das Feld `<Event><System><Computer>`. |
|%Details% | Das Feld `details` in der YML-Erkennungsregel, jedoch besitzen nur Hayabusa-Regeln dieses Feld. Dieses Feld liefert zusätzliche Informationen über den Alarm oder das Ereignis und kann nützliche Daten aus den Feldern der Ereignisprotokolle extrahieren. Zum Beispiel Benutzernamen, Befehlszeileninformationen, Prozessinformationen usw. Wenn ein Platzhalter auf ein Feld verweist, das nicht existiert, oder wenn eine falsche Alias-Zuordnung vorliegt, wird es als `n/a` (nicht verfügbar) ausgegeben. Wenn das Feld `details` nicht angegeben ist (d. h. bei Sigma-Regeln), werden die standardmäßigen `details`-Meldungen zur Extraktion der in `./rules/config/default_details.txt` definierten Felder ausgegeben. Sie können weitere standardmäßige `details`-Meldungen hinzufügen, indem Sie den `Provider Name`, die `EventID` und die gewünschte `details`-Meldung in `default_details.txt` eintragen. Wenn weder in einer Regel noch in `default_details.txt` ein `details`-Feld definiert ist, werden alle Felder in der Spalte `details` ausgegeben. |
|%ExtraFieldInfo% | Gibt die Feldinformationen aus, die nicht in %Details% ausgegeben wurden. |
|%EventID% | Das Feld `<Event><System><EventID>`. |
|%EvtxFile% | Der evtx-Dateiname, der den Alarm oder das Ereignis verursacht hat. |
|%Level% | Das Feld `level` in der YML-Erkennungsregel. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [Taktiken](https://attack.mitre.org/tactics/enterprise/) (z. B. Initial Access, Lateral Movement usw.). |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID und Software ID. |
|%OtherTags% | Jedes Schlüsselwort im Feld `tags` einer YML-Erkennungsregel, das nicht in `MitreTactics` oder `MitreTags` enthalten ist. |
|%Provider% | Das Attribut `Name` im Feld `<Event><System><Provider>`. |
|%RecordID% | Die Event Record ID aus dem Feld `<Event><System><EventRecordID>`. |
|%RuleAuthor% | Das Feld `author` in der YML-Erkennungsregel. |
|%RuleCreationDate% | Das Feld `date` in der YML-Erkennungsregel. |
|%RuleFile% | Der Dateiname der Erkennungsregel, die den Alarm oder das Ereignis erzeugt hat. |
|%RuleID% | Das Feld `id` in der YML-Erkennungsregel. |
|%RuleModifiedDate% | Das Feld `modified` in der YML-Erkennungsregel. |
|%RuleTitle% | Das Feld `title` in der YML-Erkennungsregel. |
|%Status% | Das Feld `status` in der YML-Erkennungsregel. |
|%Timestamp% | Standard ist das Format `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. Feld `<Event><System><TimeCreated SystemTime>` im Ereignisprotokoll. Die Standardzeitzone ist die lokale Zeitzone, aber Sie können die Zeitzone mit der Option `--utc` auf UTC ändern. |

#### Zusätzlicher Profil-Feld-Alias

Sie können diesen zusätzlichen Alias bei Bedarf ebenfalls zu Ihrem Ausgabeprofil hinzufügen:

| Aliasname | Hayabusa-Ausgabeinformationen |
| :--- | :--- |
|%RenderedMessage% | Das Feld `<Event><RenderingInfo><Message>` in WEC-weitergeleiteten Logs. |

Hinweis: Dies ist in keinem der integrierten Profile enthalten, daher müssen Sie die Datei `config/default_profile.yaml` manuell bearbeiten und die folgende Zeile hinzufügen:

```
Message: "%RenderedMessage%"
```

Sie können auch [Event-Key-Aliase](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) definieren, um andere Felder auszugeben.
