# Funktionen

* Plattformübergreifende Unterstützung: Windows, Linux, macOS.
* In Rust entwickelt, um speichersicher und schnell zu sein.
* Multithread-Unterstützung, die eine bis zu 5-fache Geschwindigkeitssteigerung ermöglicht.
* Erstellt einzelne, leicht zu analysierende Timelines für forensische Untersuchungen und Incident Response.
* Threat Hunting auf Basis von IoC-Signaturen, die in leicht zu lesenden/erstellenden/bearbeitenden YML-basierten Hayabusa-Regeln geschrieben sind.
* Sigma-Regel-Unterstützung zum Konvertieren von Sigma-Regeln in Hayabusa-Regeln.
* Derzeit unterstützt es im Vergleich zu anderen ähnlichen Tools die meisten Sigma-Regeln und unterstützt sogar Count-Regeln und neue Aggregatoren wie `|equalsfield` und `|endswithfield`.
* Computer-Metriken. (Nützlich zum Filtern bestimmter Computer mit einer großen Anzahl von Ereignissen, ein- oder ausschließend.)
* Event-ID-Metriken. (Nützlich, um sich ein Bild davon zu machen, welche Arten von Ereignissen es gibt, und um Ihre Log-Einstellungen zu optimieren.)
* Regel-Tuning-Konfiguration durch Ausschließen unnötiger oder störender Regeln.
* MITRE ATT&CK-Zuordnung von Taktiken.
* Regel-Level-Tuning.
* Erstellen einer Liste eindeutiger Pivot-Schlüsselwörter, um abnormale Benutzer, Hostnamen, Prozesse usw. schnell zu identifizieren sowie Ereignisse zu korrelieren.
* Ausgabe aller Felder für gründlichere Untersuchungen.
* Zusammenfassung erfolgreicher und fehlgeschlagener Anmeldungen.
* Unternehmensweites Threat Hunting und DFIR auf allen Endpunkten mit [Velociraptor](https://docs.velociraptor.app/).
* Ausgabe als CSV, JSON/JSONL und HTML-Zusammenfassungsberichte.
* Tägliche Sigma-Regel-Updates.
* Unterstützung für Log-Eingaben im JSON-Format.
* Normalisierung von Log-Feldern. (Konvertieren mehrerer Felder mit unterschiedlichen Namenskonventionen in denselben Feldnamen.)
* Log-Anreicherung durch Hinzufügen von GeoIP-Informationen (ASN, Stadt, Land) zu IP-Adressen.
* Durchsuchen aller Ereignisse nach Schlüsselwörtern oder regulären Ausdrücken.
* Felddatenzuordnung. (Bsp.: `0xc0000234` -> `ACCOUNT LOCKED`)
* Evtx-Datensatz-Carving aus dem Evtx-Slack-Space.
* Ereignis-Deduplizierung bei der Ausgabe. (Nützlich, wenn die Wiederherstellung von Datensätzen aktiviert ist oder wenn Sie gesicherte evtx-Dateien, evtx-Dateien aus VSS usw. einbeziehen.)
* Scan-Einstellungsassistent, der die Auswahl der zu aktivierenden Regeln erleichtert. (Um Fehlalarme usw. zu reduzieren.)
* Parsing und Extraktion von PowerShell-Classic-Log-Feldern.
* Geringer Speicherverbrauch. (Hinweis: Dies ist möglich, indem die Ergebnisse nicht sortiert werden. Am besten für die Ausführung auf Agenten oder bei Big Data.)
* Filtern nach Channels und Regeln für die effizienteste Leistung.
* Erkennen, Extrahieren und Decodieren von Base64-Strings, die in Logs gefunden werden.
* Anpassung der Warnstufe basierend auf kritischen Systemen.
