# DFIR-Timeline-Befehle

## Scan-Assistent

Die Befehle `csv-timeline` und `json-timeline` verfügen jetzt standardmäßig über einen aktivierten Scan-Assistenten.
Dieser soll Benutzern helfen, je nach ihren Bedürfnissen und Vorlieben einfach auszuwählen, welche Erkennungsregeln sie aktivieren möchten.
Die zu ladenden Sätze von Erkennungsregeln basieren auf den offiziellen Listen im Sigma-Projekt.
Details werden in [diesem Blogbeitrag](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81) erläutert.
Sie können den Assistenten einfach ausschalten und Hayabusa auf herkömmliche Weise verwenden, indem Sie die Option `-w, --no-wizard` hinzufügen.

### Core-Regeln

Der Regelsatz `core` aktiviert Regeln mit dem Status `test` oder `stable` und einem Level von `high` oder `critical`.
Dies sind qualitativ hochwertige Regeln mit hoher Zuverlässigkeit und Relevanz, die nicht viele Fehlalarme erzeugen sollten.
Der Regelstatus ist `test` oder `stable`, was bedeutet, dass über 6 Monate lang keine Fehlalarme gemeldet wurden.
Regeln passen auf Angreifertechniken, allgemein verdächtige Aktivitäten oder bösartiges Verhalten.
Es entspricht der Verwendung der Optionen `--exclude-status deprecated,unsupported,experimental --min-level high`.

### Core+-Regeln

Der Regelsatz `core+` aktiviert Regeln mit dem Status `test` oder `stable` und einem Level von `medium` oder höher.
`medium`-Regeln benötigen meist eine zusätzliche Feinabstimmung, da bestimmte Anwendungen, legitimes Benutzerverhalten oder Skripte einer Organisation übereinstimmen könnten.
Es entspricht der Verwendung der Optionen `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### Core++-Regeln

Der Regelsatz `core++` aktiviert Regeln mit dem Status `experimental`, `test` oder `stable` und einem Level von `medium` oder höher.
Diese Regeln sind topaktuell.
Sie werden gegen die im SigmaHQ-Projekt verfügbaren Basis-Evtx-Dateien validiert und von mehreren Detection Engineers überprüft.
Abgesehen davon sind sie zunächst weitgehend ungetestet.
Verwenden Sie diese, wenn Sie Bedrohungen so früh wie möglich erkennen möchten, allerdings um den Preis, eine höhere Schwelle an Fehlalarmen zu verwalten.
Es entspricht der Verwendung der Optionen `--exclude-status deprecated,unsupported --min-level medium`.

### Emerging Threats (ET) Add-On-Regeln

Der Regelsatz `Emerging Threats (ET)` aktiviert Regeln mit dem Tag `detection.emerging_threats`.
Diese Regeln zielen auf bestimmte Bedrohungen ab und sind besonders nützlich bei aktuellen Bedrohungen, zu denen noch nicht viele Informationen verfügbar sind.
Diese Regeln sollten nicht viele Fehlalarme erzeugen, werden aber mit der Zeit an Relevanz verlieren.
Wenn diese Regeln nicht aktiviert sind, entspricht dies der Verwendung der Option `--exclude-tag detection.emerging_threats`.
Wenn Sie Hayabusa herkömmlich ohne den Assistenten ausführen, werden diese Regeln standardmäßig einbezogen.

### Threat Hunting (TH) Add-On-Regeln

Der Regelsatz `Threat Hunting (TH)` aktiviert Regeln mit dem Tag `detection.threat_hunting`.
Diese Regeln können unbekannte bösartige Aktivitäten erkennen, weisen jedoch typischerweise mehr Fehlalarme auf.
Wenn diese Regeln nicht aktiviert sind, entspricht dies der Verwendung der Option `--exclude-tag detection.threat_hunting`.
Wenn Sie Hayabusa herkömmlich ohne den Assistenten ausführen, werden diese Regeln standardmäßig einbezogen.

## Channel-basierte Filterung von Ereignisprotokollen und Regeln

Seit Hayabusa v2.16.0 aktivieren wir einen Channel-basierten Filter beim Laden von `.evtx`-Dateien und `.yml`-Regeln.
Der Zweck besteht darin, das Scannen so effizient wie möglich zu gestalten, indem nur das geladen wird, was notwendig ist.
Es ist zwar möglich, dass es mehrere Provider in einem einzigen Ereignisprotokoll gibt, aber es ist nicht üblich, mehrere Channels innerhalb einer einzigen evtx-Datei zu haben.
(Das einzige Mal, dass wir dies gesehen haben, war, als jemand zwei verschiedene evtx-Dateien für das [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)-Projekt künstlich zusammengeführt hat.)
Wir können uns dies zunutze machen, indem wir zuerst das `Channel`-Feld im ersten Datensatz jeder zum Scannen angegebenen `.evtx`-Datei überprüfen.
Wir prüfen außerdem, welche `.yml`-Regeln welche im `Channel`-Feld der Regel angegebenen Channels verwenden.
Mit diesen beiden Listen laden wir nur Regeln, die Channels verwenden, die tatsächlich in den `.evtx`-Dateien vorhanden sind.

Wenn ein Benutzer beispielsweise `Security.evtx` scannen möchte, werden nur Regeln verwendet, die `Channel: Security` angeben.
Es hat keinen Sinn, andere Erkennungsregeln zu laden, zum Beispiel Regeln, die nur nach Ereignissen im `Application`-Protokoll suchen usw.
Beachten Sie, dass Channel-Felder (z. B. `Channel: Security`) nicht **explizit** in den originalen Sigma-Regeln definiert sind.
Bei Sigma-Regeln werden die Channel- und Event-ID-Felder **implizit** mit den Feldern `service` und `category` unter `logsource` definiert. (z. B. `service: security`)
Bei der Kuratierung von Sigma-Regeln im [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)-Repository entabstrahieren wir das `logsource`-Feld und definieren die Channel- und Event-ID-Felder explizit.
Wie und warum wir das tun, erklären wir ausführlich [hier](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Derzeit gibt es nur zwei Erkennungsregeln, bei denen kein `Channel` definiert ist und die alle `.evtx`-Dateien scannen sollen, nämlich die folgenden:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Wenn Sie diese beiden Regeln verwenden und alle Regeln gegen geladene `.evtx`-Dateien scannen möchten, müssen Sie die Option `-A, --enable-all-rules` in den Befehlen `csv-timeline` und `json-timeline` hinzufügen.
In unseren Benchmarks bringt die Regelfilterung je nach gescannten Dateien in der Regel eine Geschwindigkeitsverbesserung von 20 % bis zum 10-Fachen und verbraucht natürlich weniger Speicher.

Die Channel-Filterung wird auch beim Laden von `.evtx`-Dateien verwendet.
Wenn Sie beispielsweise eine Regel angeben, die nach Ereignissen mit einem Channel von `Security` sucht, dann hat es keinen Sinn, `.evtx`-Dateien zu laden, die nicht aus dem `Security`-Protokoll stammen.
In unseren Benchmarks bringt dies bei normalen Scans einen Geschwindigkeitsvorteil von etwa 10 % und bei Scans mit einer einzigen Regel eine Leistungssteigerung von bis zu über 60 %.
Wenn Sie sicher sind, dass innerhalb einer einzigen `.evtx`-Datei mehrere Channels verwendet werden, zum Beispiel weil jemand ein Tool verwendet hat, um mehrere `.evtx`-Dateien zusammenzuführen, dann deaktivieren Sie diese Filterung mit der Option `-a, --scan-all-evtx-files` in den Befehlen `csv-timeline` und `json-timeline`.

> Hinweis: Die Channel-Filterung funktioniert nur mit `.evtx`-Dateien und Sie erhalten einen Fehler, wenn Sie versuchen, Ereignisprotokolle aus einer JSON-Datei mit `-J, --json-input` zu laden und gleichzeitig `-A` oder `-a` angeben.

## `csv-timeline`-Befehl

Der Befehl `csv-timeline` erstellt eine forensische Zeitleiste von Ereignissen im CSV-Format.

```
Usage: csv-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -M, --multiline                    Output event field information in multiple rows
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in CSV format (ex: results.csv)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)
  -S, --tab-separator                Separate event field information by tabs

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `csv-timeline`-Befehlsbeispiele

* Hayabusa gegen eine einzelne Windows-Ereignisprotokolldatei mit dem standardmäßigen `standard`-Profil ausführen:

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* Hayabusa gegen das sample-evtx-Verzeichnis mit mehreren Windows-Ereignisprotokolldateien mit dem verbose-Profil ausführen:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* In eine einzige CSV-Datei zur weiteren Analyse mit LibreOffice, Timeline Explorer, Elastic Stack usw. exportieren und alle Feldinformationen einbeziehen (Warnung: Ihre Ausgabedateigröße wird mit dem `super-verbose`-Profil deutlich größer!):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Den EID-Filter (Event ID) aktivieren:

> Hinweis: Das Aktivieren des EID-Filters beschleunigt die Analyse in unseren Tests um etwa 10-15 %, aber es besteht die Möglichkeit, dass Alarme übersehen werden.

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Nur Hayabusa-Regeln ausführen (standardmäßig werden alle Regeln in `-r .\rules` ausgeführt):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Nur Hayabusa-Regeln für Protokolle ausführen, die unter Windows standardmäßig aktiviert sind:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Nur Hayabusa-Regeln für Sysmon-Protokolle ausführen:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Nur Sigma-Regeln ausführen:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Veraltete Regeln (solche mit `status` als `deprecated` markiert) und laute Regeln (solche, deren Regel-ID in `.\rules\config\noisy_rules.txt` aufgeführt ist) aktivieren:

> Hinweis: Seit kurzem befinden sich veraltete Regeln in einem separaten Verzeichnis im Sigma-Repository und sind daher nicht mehr standardmäßig in Hayabusa enthalten.
> Daher haben Sie wahrscheinlich keinen Grund, veraltete Regeln zu aktivieren.

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Nur Regeln zur Analyse von Anmeldungen ausführen und in der UTC-Zeitzone ausgeben:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Auf einem Live-Windows-Computer ausführen (erfordert Administratorrechte) und nur Alarme (potenziell bösartiges Verhalten) erkennen:

```
hayabusa.exe csv-timeline -l -m low
```

* Ausführliche Informationen ausgeben (nützlich, um zu ermitteln, welche Dateien lange zur Verarbeitung benötigen, Parsing-Fehler usw.):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* Beispiel für ausführliche Ausgabe:

Laden von Regeln:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Fehler während des Scans:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* In ein CSV-Format ausgeben, das zum Import in [Timesketch](https://timesketch.org/) kompatibel ist:

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Stiller Fehlermodus:
Standardmäßig speichert Hayabusa Fehlermeldungen in Fehlerprotokolldateien.
Wenn Sie keine Fehlermeldungen speichern möchten, fügen Sie bitte `-Q` hinzu.

### Erweitert - GeoIP-Protokollanreicherung

Sie können GeoIP-Informationen (ASN-Organisation, Stadt und Land) zu SrcIP-Feldern (Quell-IP) und TgtIP-Feldern (Ziel-IP) mit den kostenlosen GeoLite2-Geolokalisierungsdaten hinzufügen.

Schritte:

1. Melden Sie sich zuerst [hier](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) für ein MaxMind-Konto an.
2. Laden Sie die drei `.mmdb`-Dateien von der [Download-Seite](https://www.maxmind.com/en/accounts/current/geoip/downloads) herunter und speichern Sie sie in einem Verzeichnis. Die Dateinamen sollten `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` und `GeoLite2-Country.mmdb` heißen.
3. Fügen Sie beim Ausführen der Befehle `csv-timeline` oder `json-timeline` die Option `-G` gefolgt vom Verzeichnis mit den MaxMind-Datenbanken hinzu.

* Wenn `csv-timeline` verwendet wird, werden die folgenden 6 Spalten zusätzlich ausgegeben: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* Wenn `json-timeline` verwendet wird, werden dieselben Felder `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` zum `Details`-Objekt hinzugefügt, aber nur, wenn sie Informationen enthalten.

* Wenn `SrcIP` oder `TgtIP` localhost ist (`127.0.0.1`, `::1` usw.), wird `SrcASN` oder `TgtASN` als `Local` ausgegeben.
* Wenn `SrcIP` oder `TgtIP` eine private IP-Adresse ist (`10.0.0.0/8`, `fe80::/10` usw.), wird `SrcASN` oder `TgtASN` als `Private` ausgegeben.

#### GeoIP-Konfigurationsdatei

Die Feldnamen, die Quell- und Ziel-IP-Adressen enthalten, die in den GeoIP-Datenbanken nachgeschlagen werden, sind in `rules/config/geoip_field_mapping.yaml` definiert.
Sie können diese Liste bei Bedarf erweitern.
Es gibt in dieser Datei auch einen Filterabschnitt, der bestimmt, aus welchen Ereignissen IP-Adressinformationen extrahiert werden.

#### Automatische Aktualisierungen der GeoIP-Datenbanken

MaxMind-GeoIP-Datenbanken werden alle 2 Wochen aktualisiert.
Sie können das MaxMind-Tool `geoipupdate` [hier](https://github.com/maxmind/geoipupdate) installieren, um diese Datenbanken automatisch zu aktualisieren.

Schritte unter macOS:

1. `brew install geoipupdate`
2. Bearbeiten Sie `/usr/local/etc/GeoIP.conf` oder `/opt/homebrew/etc/GeoIP.conf`: Tragen Sie Ihre `AccountID` und Ihren `LicenseKey` ein, die Sie nach dem Anmelden auf der MaxMind-Website erstellen. Stellen Sie sicher, dass die `EditionIDs`-Zeile `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` lautet.
3. Führen Sie `geoipupdate` aus.
4. Fügen Sie `-G /usr/local/var/GeoIP` oder `-G /opt/homebrew/var/GeoIP` hinzu, wenn Sie GeoIP-Informationen hinzufügen möchten.

Schritte unter Windows:

1. Laden Sie die neueste Windows-Binärdatei (z. B. `geoipupdate_4.10.0_windows_amd64.zip`) von der [Releases](https://github.com/maxmind/geoipupdate/releases)-Seite herunter.
2. Bearbeiten Sie `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: Tragen Sie Ihre `AccountID` und Ihren `LicenseKey` ein, die Sie nach dem Anmelden auf der MaxMind-Website erstellen. Stellen Sie sicher, dass die `EditionIDs`-Zeile `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country` lautet.
3. Führen Sie die ausführbare Datei `geoipupdate` aus.

Schritte unter Linux:

1. Installieren Sie mit `sudo apt install geoip-update`.
2. Bearbeiten Sie die Konfigurationsdatei mit `sudo nano /etc/GeoIP.conf`.
3. Aktualisieren Sie die Datenbankdateien mit `sudo geoipupdate`.
4. Fügen Sie `-G /var/lib/GeoIP/` hinzu, wenn Sie GeoIP-Informationen hinzufügen möchten.

### `csv-timeline`-Befehlskonfigurationsdateien

`./rules/config/channel_abbreviations.txt`: Zuordnungen von Channel-Namen und ihren Abkürzungen.

`./rules/config/default_details.txt`: Die Konfigurationsdatei dafür, welche Standard-Feldinformationen (`%Details%`-Feld) ausgegeben werden sollen, wenn keine `details:`-Zeile in einer Regel angegeben ist.
Dies basiert auf dem Provider-Namen und den Event-IDs.

`./rules/config/eventkey_alias.txt`: Diese Datei enthält die Zuordnungen von Kurznamen-Aliassen für Felder und ihren ursprünglichen längeren Feldnamen.

Beispiel:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Wenn ein Feld hier nicht definiert ist, prüft Hayabusa automatisch unter `Event.EventData` nach dem Feld.

`./rules/config/exclude_rules.txt`: Diese Datei enthält eine Liste von Regel-IDs, die von der Verwendung ausgeschlossen werden.
Normalerweise liegt dies daran, dass eine Regel eine andere ersetzt hat oder die Regel von vornherein nicht verwendet werden kann.
Wie Firewalls und IDSe erfordert jedes signaturbasierte Tool eine gewisse Feinabstimmung, um zu Ihrer Umgebung zu passen, sodass Sie bestimmte Regeln möglicherweise dauerhaft oder vorübergehend ausschließen müssen.
Sie können eine Regel-ID (Beispiel: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) zu `./rules/config/exclude_rules.txt` hinzufügen, um jede Regel zu ignorieren, die Sie nicht benötigen oder die nicht verwendet werden kann.

`./rules/config/noisy_rules.txt`: Diese Datei enthält eine Liste von Regel-IDs, die standardmäßig deaktiviert sind, aber durch das Aktivieren lauter Regeln mit der Option `-n, --enable-noisy-rules` aktiviert werden können.
Diese Regeln sind in der Regel von Natur aus oder aufgrund von Fehlalarmen laut.

`./rules/config/target_event_IDs.txt`: Nur die in dieser Datei angegebenen Event-IDs werden gescannt, wenn der EID-Filter aktiviert ist.
Standardmäßig scannt Hayabusa alle Ereignisse, aber wenn Sie die Leistung verbessern möchten, verwenden Sie bitte die Option `-E, --EID-filter`.
Dies führt in der Regel zu einer Geschwindigkeitsverbesserung von 10~25 %.

## `json-timeline`-Befehl

Der Befehl `json-timeline` erstellt eine forensische Zeitleiste von Ereignissen im JSON- oder JSONL-Format.
Die Ausgabe in JSONL ist schneller und die Dateigröße ist kleiner als bei JSON, daher ist sie gut, wenn Sie die Ergebnisse einfach in ein anderes Tool wie Elastic Stack importieren möchten.
JSON ist besser, wenn Sie die Ergebnisse manuell mit einem Texteditor analysieren möchten.
CSV-Ausgabe eignet sich gut zum Importieren kleinerer Zeitleisten (in der Regel weniger als 2 GB) in Tools wie LibreOffice oder Timeline Explorer.
JSON eignet sich am besten für eine detailliertere Analyse von Daten (einschließlich großer Ergebnisdateien) mit Tools wie `jq`, da die `Details`-Felder zur einfacheren Analyse getrennt sind.
(In der CSV-Ausgabe befinden sich alle Ereignisprotokollfelder in einer großen `Details`-Spalte, was das Sortieren von Daten usw. erschwert.)

```
Usage: json-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -L, --JSONL-output                 Save the timeline in JSONL format (ex: -L -o results.jsonl)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in JSON format (ex: results.json)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### `json-timeline`-Befehlsbeispiele und Konfigurationsdateien

Die Optionen und Konfigurationsdateien für `json-timeline` sind dieselben wie bei `csv-timeline`, jedoch mit einer zusätzlichen Option `-L, --JSONL-output` für die Ausgabe im JSONL-Format.

## `level-tuning`-Befehl

Mit dem Befehl `level-tuning` können Sie die Alarmlevel für Regeln feinabstimmen und das Risikolevel nach Belieben anheben oder senken.
Dieser Befehl verwendet eine Konfigurationsdatei, um die Risikolevel (das `level`-Feld) der Regeln im Ordner `rules` zu überschreiben.

> Warnung: Jedes Mal, wenn Sie den Befehl `update-rules` ausführen, wird das Risikolevel auf den ursprünglichen Wert zurückgesetzt, sodass Sie den Befehl `level-tuning` danach erneut ausführen müssen.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning`-Befehlsbeispiele

* Normale Verwendung: `hayabusa.exe level-tuning`
* Regel-Alarmlevel basierend auf Ihrer benutzerdefinierten Konfigurationsdatei feinabstimmen: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning`-Konfigurationsdatei

Hayabusa- und Sigma-Regelautoren schätzen beim Schreiben ihrer Regeln das angemessene Risikolevel des Alarms ein.
Allerdings sind die Risikolevel manchmal nicht konsistent und das tatsächliche Risikolevel kann sich je nach Ihrer Umgebung unterscheiden.
Yamato Security stellt eine Konfigurationsdatei unter `./rules/config/level_tuning.txt` bereit und pflegt sie, die Sie ebenfalls zur Feinabstimmung Ihrer Regeln verwenden können.

`./rules/config/level_tuning.txt`-Beispiel:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

In diesem Fall wird das Risikolevel der Regel mit einer `id` von `570ae5ec-33dc-427c-b815-db86228ad43e` im Regelverzeichnis sein `level` auf `informational` umgeschrieben bekommen.
Die möglichen einzustellenden Level sind `critical`, `high`, `medium`, `low` und `informational`.

> Warnung: Die Konfigurationsdatei `./rules/config/level_tuning.txt` wird ebenfalls jedes Mal, wenn Sie `update-rules` ausführen, auf die neueste Version im hayabusa-rules-Repository aktualisiert.
> Wenn Sie also Änderungen an dieser Datei vornehmen, gehen diese Änderungen verloren!
> Wenn Sie eine Konfigurationsdatei für sich behalten möchten, dann erstellen Sie eine Konfigurationsdatei in `./config/level_tuning.txt` und führen Sie `hayabusa.exe level-tuning -f ./config/level_tuning.txt` aus.
> Sie können auch zuerst die Feinabstimmung mit der von Yamato Security bereitgestellten Konfigurationsdatei durchführen und dann mit Ihrer eigenen Konfigurationsdatei weiter feinabstimmen.

## `list-profiles`-Befehl

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile`-Befehl

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile`-Befehlsbeispiele

* Das Standardprofil auf `minimal` setzen: `hayabusa.exe set-default-profile minimal`
* Das Standardprofil auf `super-verbose` setzen: `hayabusa.exe set-default-profile super-verbose`

## `update-rules`-Befehl

Der Befehl `update-rules` synchronisiert den Ordner `rules` mit dem [Hayabusa-rules-GitHub-Repository](https://github.com/Yamato-Security/hayabusa-rules) und aktualisiert die Regeln und Konfigurationsdateien.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules`-Befehlsbeispiel

Normalerweise führen Sie einfach dies aus: `hayabusa.exe update-rules`
