# Config-Befehle

## Befehl `config-critical-systems`

Dieser Befehl versucht automatisch, kritische Systeme wie Domänencontroller und Dateiserver zu finden, und fügt sie der Konfigurationsdatei `./config/critical_systems.txt` hinzu, sodass alle Alarme um eine Stufe erhöht werden.
Er sucht nach Security-4768-Ereignissen (Kerberos TGT requested), um festzustellen, ob es sich um einen Domänencontroller handelt.
Er sucht nach Security-5145-Ereignissen (Network Share File Access), um festzustellen, ob es sich um einen Dateiserver handelt.
Bei allen Hostnamen, die der Datei `critical_systems.txt` hinzugefügt werden, werden alle Alarme oberhalb von low um eine Stufe erhöht, maximal bis zur Stufe `emergency`.

```
Usage:
  hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Verzeichnis mit mehreren .evtx-Dateien (or VHDX images with --vhdx)
  -f, --file <FILE>      Dateipfad zu einer .evtx-Datei (or a VHDX image with --vhdx)
      --vhdx             Scan VHDX images read-only; -d searches up to three subdirectory levels
      --e01              Scan E01/Ex01 images read-only without extraction; -d searches three subdirectory levels

Display Settings:
  -K, --no-color  Farbausgabe deaktivieren
  -q, --quiet     Stiller Modus: das Startbanner nicht anzeigen

General Options:
  -h, --help  Das Hilfemenü anzeigen
```

### Beispiele für den Befehl `config-critical-systems`

* Durchsuchen Sie das Verzeichnis `../hayabusa-sample-evtx` nach Domänencontrollern und Dateiservern:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
