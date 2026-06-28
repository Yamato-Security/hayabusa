# Projekte & Ökosystem

## Begleitprojekte

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Dokumentation und Skripte zum korrekten Aktivieren von Windows-Ereignisprotokollen.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Das Gleiche wie das Hayabusa-Rules-Repository, aber die Regeln und Konfigurationsdateien werden in einer Datei gespeichert und mit XOR verschlüsselt, um Fehlalarme von Antivirenprogrammen zu verhindern.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa- und kuratierte Sigma-Erkennungsregeln, die von Hayabusa verwendet werden.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - Ein besser gepflegter Fork der `evtx`-Crate.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Beispiel-evtx-Dateien zum Testen von Hayabusa-/Sigma-Erkennungsregeln.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Präsentationen von Vorträgen, die wir über unsere Tools und Ressourcen gehalten haben.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Kuratiert auf Windows-Ereignisprotokollen basierende Upstream-Sigma-Regeln in eine einfacher zu verwendende Form.
* [Takajo](https://github.com/Yamato-Security/takajo) - Ein Analysetool für Hayabusa-Ergebnisse.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - Ein in PowerShell geschriebenes Analysetool für Windows-Ereignisprotokolle. (Veraltet und durch Takajo ersetzt.)

## Drittanbieterprojekte, die Hayabusa verwenden

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Ein NodeRED-Workflow, der Plaso- und Hayabusa-Ergebnisse in Timesketch importiert.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - Bietet cloudbasierte Sicherheitstools und Infrastruktur, die auf Ihre Bedürfnisse zugeschnitten sind. 
* [OpenRelik](https://openrelik.org/) - Eine quelloffene (Apache-2.0) Plattform zur Optimierung kollaborativer digitaler forensischer Untersuchungen.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Starten Sie schnell eine Splunk-Instanz mit Docker, um während Ihrer Untersuchungen Protokolle und Tool-Ausgaben zu durchsuchen.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Ein Tool zum Sammeln hostbasierter Statusinformationen mithilfe von Abfragen der Velociraptor Query Language (VQL).

## Weitere Analysetools für Windows-Ereignisprotokolle und verwandte Ressourcen

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - In Python geschriebenes Angriffserkennungstool.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Sammlung von Event-ID-Ressourcen, die für digitale Forensik und Incident Response nützlich sind
* [Chainsaw](https://github.com/countercept/chainsaw) - Ein weiteres Sigma-basiertes Angriffserkennungstool, geschrieben in Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - In Powershell geschriebenes Angriffserkennungstool von [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - Graph-Visualisierung für Windows-Ereignisprotokolle.
* [EventList](https://github.com/miriamxyra/EventList/) - Zuordnung von Event-IDs der Security-Baseline zu MITRE ATT&CK von [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - von [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - Evtx-Parser von [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Wiederherstellung von EVTX-Protokolldateien aus nicht zugewiesenem Speicherplatz und Speicherabbildern.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Python-Tool zum Senden von Evtx-Daten an den Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - EVTX-Beispiel-Ereignisprotokolldateien von Angriffen von [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - EVTX-Beispiel-Ereignisprotokolldateien von Angriffen, zugeordnet zu ATT&CK von [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - die von uns verwendete Rust-evtx-Bibliothek, geschrieben von [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Visualisierungstool für Sysmon- und PowerShell-Protokolle.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Eine grafische Oberfläche zur Visualisierung von Anmeldungen, um laterale Bewegungen zu erkennen, von [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - Der NSA-Leitfaden dazu, was überwacht werden sollte.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Rust-Portierung von DeepBlueCLI von Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - Community-basierte generische SIEM-Regeln.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - Eine vorkonfigurierte VM mit Elastic Stack zum Importieren von Daten für die DFIR-Analyse von [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Importieren von evtx-Dateien in Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Konfigurations- und Offline-Protokollvisualisierungstool für Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - Der beste CSV-Timeline-Analyzer von [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - von Steve Anson von Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - Sigma-basiertes Angriffserkennungstool, geschrieben in Python.
