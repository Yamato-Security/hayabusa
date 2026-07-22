# Commandes de chronologie DFIR

## Assistant de scan

La commande `dfir-timeline` dispose désormais d'un assistant de scan activé par défaut.
Ceci est destiné à aider les utilisateurs à choisir facilement les règles de détection qu'ils souhaitent activer selon leurs besoins et préférences.
Les ensembles de règles de détection à charger sont basés sur les listes officielles du projet Sigma.
Les détails sont expliqués dans [cet article de blog](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
Vous pouvez facilement désactiver l'assistant et utiliser Hayabusa de manière traditionnelle en ajoutant l'option `-w, --no-wizard`.

### Règles Core

L'ensemble de règles `core` active les règles ayant un statut `test` ou `stable` et un niveau `high` ou `critical`.
Ce sont des règles de haute qualité, de grande confiance et pertinence, qui ne devraient pas produire beaucoup de faux positifs.
Le statut de la règle est `test` ou `stable`, ce qui signifie qu'aucun faux positif n'a été signalé depuis plus de 6 mois.
Les règles correspondront aux techniques d'attaquants, à une activité suspecte générique ou à un comportement malveillant.
C'est identique à l'utilisation des options `--exclude-status deprecated,unsupported,experimental --min-level high`.

### Règles Core+

L'ensemble de règles `core+` active les règles ayant un statut `test` ou `stable` et un niveau `medium` ou supérieur.
Les règles `medium` nécessitent le plus souvent un réglage supplémentaire, car certaines applications, comportements légitimes d'utilisateurs ou scripts d'une organisation pourraient correspondre.
C'est identique à l'utilisation des options `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### Règles Core++

L'ensemble de règles `core++` active les règles ayant un statut `experimental`, `test` ou `stable` et un niveau `medium` ou supérieur.
Ces règles sont à la pointe de l'innovation.
Elles sont validées par rapport aux fichiers evtx de référence disponibles dans le projet SigmaHQ et examinées par plusieurs ingénieurs en détection.
À part cela, elles ne sont au départ pratiquement pas testées.
Utilisez-les si vous voulez pouvoir détecter les menaces le plus tôt possible, au prix de la gestion d'un seuil plus élevé de faux positifs.
C'est identique à l'utilisation des options `--exclude-status deprecated,unsupported --min-level medium`.

### Règles complémentaires Menaces émergentes (ET)

L'ensemble de règles `Emerging Threats (ET)` active les règles ayant une étiquette `detection.emerging_threats`.
Ces règles ciblent des menaces spécifiques et sont particulièrement utiles pour les menaces actuelles pour lesquelles peu d'informations sont encore disponibles.
Ces règles ne devraient pas avoir beaucoup de faux positifs, mais perdront en pertinence au fil du temps.
Lorsque ces règles ne sont pas activées, c'est identique à l'utilisation de l'option `--exclude-tag detection.emerging_threats`.
Lors de l'exécution de Hayabusa de manière traditionnelle sans l'assistant, ces règles seront incluses par défaut.

### Règles complémentaires Chasse aux menaces (TH)

L'ensemble de règles `Threat Hunting (TH)` active les règles ayant une étiquette `detection.threat_hunting`.
Ces règles peuvent détecter une activité malveillante inconnue, mais auront généralement plus de faux positifs.
Lorsque ces règles ne sont pas activées, c'est identique à l'utilisation de l'option `--exclude-tag detection.threat_hunting`.
Lors de l'exécution de Hayabusa de manière traditionnelle sans l'assistant, ces règles seront incluses par défaut.

## Filtrage des journaux d'événements et des règles basé sur le canal

Depuis Hayabusa v2.16.0, nous activons un filtre basé sur le canal lors du chargement des fichiers `.evtx` et des règles `.yml`.
L'objectif est de rendre le scan aussi efficace que possible en ne chargeant que ce qui est nécessaire.
Bien qu'il soit possible d'avoir plusieurs fournisseurs dans un seul journal d'événements, il n'est pas courant d'avoir plusieurs canaux à l'intérieur d'un même fichier evtx.
(La seule fois où nous avons observé cela, c'est lorsque quelqu'un a artificiellement fusionné deux fichiers evtx différents pour le projet [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).)
Nous pouvons en tirer parti en vérifiant d'abord le champ `Channel` dans le premier enregistrement de chaque fichier `.evtx` spécifié à scanner.
Nous vérifions également quelles règles `.yml` utilisent quels canaux spécifiés dans le champ `Channel` de la règle.
Avec ces deux listes, nous ne chargeons que les règles qui utilisent des canaux réellement présents dans les fichiers `.evtx`.

Ainsi par exemple, si un utilisateur veut scanner `Security.evtx`, seules les règles qui spécifient `Channel: Security` seront utilisées.
Il est inutile de charger d'autres règles de détection, par exemple des règles qui ne recherchent que des événements dans le journal `Application`, etc...
Notez que les champs de canal (Ex : `Channel: Security`) ne sont pas définis **explicitement** dans les règles Sigma originales.
Pour les règles Sigma, les champs de canal et d'ID d'événement sont définis **implicitement** avec les champs `service` et `category` sous `logsource`. (Ex : `service: security`)
Lors de la curation des règles Sigma dans le dépôt [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), nous désabstrayons le champ `logsource` et définissons explicitement les champs de canal et d'ID d'événement.
Nous expliquons comment et pourquoi nous faisons cela en détail [ici](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Actuellement, il n'y a que deux règles de détection qui n'ont pas de `Channel` défini et qui sont destinées à scanner tous les fichiers `.evtx`, à savoir les suivantes :

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Si vous voulez utiliser ces deux règles et scanner toutes les règles contre les fichiers `.evtx` chargés, vous devrez alors ajouter l'option `-A, --enable-all-rules` dans la commande `dfir-timeline`.
Dans nos tests de performance, le filtrage des règles donne généralement une amélioration de vitesse de 20 % à 10x selon les fichiers scannés et utilise bien sûr moins de mémoire.

Le filtrage par canal est également utilisé lors du chargement des fichiers `.evtx`.
Par exemple, si vous spécifiez une règle qui recherche des événements avec un canal `Security`, alors il est inutile de charger des fichiers `.evtx` qui ne proviennent pas du journal `Security`.
Dans nos tests de performance, cela donne un gain de vitesse d'environ 10 % avec les scans normaux et jusqu'à plus de 60 % d'augmentation des performances lors d'un scan avec une seule règle.
Si vous êtes sûr que plusieurs canaux sont utilisés à l'intérieur d'un même fichier `.evtx`, par exemple si quelqu'un a utilisé un outil pour fusionner plusieurs fichiers `.evtx` ensemble, vous pouvez alors désactiver ce filtrage avec l'option `-a, --scan-all-evtx-files` dans la commande `dfir-timeline`.

> Note : Le filtrage par canal ne fonctionne qu'avec les fichiers `.evtx` et vous recevrez une erreur si vous essayez de charger des journaux d'événements depuis un fichier JSON avec `-J, --json-input` et que vous spécifiez également `-A` ou `-a`.

## Commande `dfir-timeline`

La commande `dfir-timeline` crée une chronologie forensique des événements. Choisissez le format de sortie avec `-t, --output-type` : `csv` (par défaut), `json` ou `jsonl`. La valeur est insensible à la casse (par exemple `-t JSONL`).

- **CSV** est bien pour importer de plus petites chronologies (généralement moins de 2 Go) dans des outils comme LibreOffice ou Timeline Explorer (tous les champs d'événement sont placés dans une seule grande colonne `Details`).
- **JSON** est le mieux pour une analyse plus détaillée de grands résultats avec des outils comme `jq`, car les champs `Details` sont séparés.
- **JSONL** est plus rapide et produit un fichier plus petit que JSON, ce qui est idéal pour l'importation dans des outils comme Elastic Stack.

Les options de **sortie CSV** `-M, --multiline`, `-S, --tab-separator` et `-R, --remove-duplicate-data` ne s'appliquent qu'à la sortie CSV et produiront une erreur si elles sont combinées avec un `-t` non-CSV.

```
  hayabusa.exe dfir-timeline <INPUT> [OPTIONS]

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
  -s, --sort                           Sort results before saving the file (warning: this uses much more memory!)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)
      --threads <NUMBER>               Number of threads (default: optimal number for performance)
  -V, --validate-checksums             Enable checksum validation

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
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline to a file (ex: results.csv)
  -t, --output-type <OUTPUT_FORMAT>  Output format: csv (default), json, or jsonl (case-insensitive, e.g. -t JSONL) [default: csv] [possible values: csv, json, jsonl]
  -p, --profile <PROFILE>            Specify output profile
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

CSV Output:
  -M, --multiline              Separate event field information by newline characters (CSV output only)
  -R, --remove-duplicate-data  Duplicate field data will be replaced with "DUP" (CSV output only)
  -S, --tab-separator          Separate event field information by tabs (CSV output only)
```

### Exemples de la commande `dfir-timeline`

* Exécuter hayabusa contre un fichier de journal d'événements Windows avec le profil `standard` par défaut :

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* Exécuter hayabusa contre le répertoire sample-evtx avec plusieurs fichiers de journaux d'événements Windows avec le profil verbose :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* Exporter vers un seul fichier CSV pour une analyse plus poussée avec LibreOffice, Timeline Explorer, Elastic Stack, etc... et inclure toutes les informations de champ (Attention : la taille de votre fichier de sortie deviendra beaucoup plus grande avec le profil `super-verbose` !) :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Produire une sortie JSON au lieu de CSV (pour une analyse avec `jq`, etc.) :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* Produire une sortie JSONL (pour l'importation dans Elastic Stack, etc. ; `-t` est insensible à la casse) :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* Activer le filtre EID (Event ID) :

> Note : L'activation du filtre EID accélérera l'analyse d'environ 10 à 15 % dans nos tests, mais il existe une possibilité de manquer des alertes.

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* N'exécuter que les règles hayabusa (par défaut, toutes les règles dans `-r .\rules` sont exécutées) :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* N'exécuter que les règles hayabusa pour les journaux activés par défaut sous Windows :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* N'exécuter que les règles hayabusa pour les journaux sysmon :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* N'exécuter que les règles sigma :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Activer les règles obsolètes (celles dont le `status` est marqué `deprecated`) et les règles bruyantes (celles dont l'ID de règle est répertorié dans `.\rules\config\noisy_rules.txt`) :

> Note : Récemment, les règles obsolètes sont désormais situées dans un répertoire séparé dans le dépôt sigma et ne sont donc plus incluses par défaut dans Hayabusa.
> Par conséquent, vous n'avez probablement pas besoin d'activer les règles obsolètes.

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* N'exécuter que les règles pour analyser les connexions et produire la sortie dans le fuseau horaire UTC :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Exécuter sur une machine Windows en direct (nécessite les privilèges Administrateur) et ne détecter que les alertes (comportement potentiellement malveillant) :

```
hayabusa.exe dfir-timeline -l -m low
```

* Afficher les informations détaillées (utile pour déterminer quels fichiers prennent du temps à traiter, les erreurs d'analyse, etc...) :

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Exemple de sortie détaillée :

Chargement des règles :

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Erreurs pendant le scan :
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

* Produire une sortie au format CSV compatible avec l'importation dans [Timesketch](https://timesketch.org/) :

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Mode d'erreurs silencieux :
Par défaut, hayabusa enregistrera les messages d'erreur dans des fichiers de journaux d'erreurs.
Si vous ne voulez pas enregistrer les messages d'erreur, veuillez ajouter `-Q`.

### Avancé - Enrichissement des journaux GeoIP

Vous pouvez ajouter des informations GeoIP (organisation ASN, ville et pays) aux champs SrcIP (IP source) et TgtIP (IP cible) avec les données de géolocalisation gratuites GeoLite2.

Étapes :

1. Inscrivez-vous d'abord pour un compte MaxMind [ici](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Téléchargez les trois fichiers `.mmdb` depuis la [page de téléchargement](https://www.maxmind.com/en/accounts/current/geoip/downloads) et enregistrez-les dans un répertoire. Les noms de fichiers doivent être `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` et `GeoLite2-Country.mmdb`.
3. Lors de l'exécution de la commande `dfir-timeline`, ajoutez l'option `-G` suivie du répertoire contenant les bases de données MaxMind.

* Avec la sortie CSV, les 6 colonnes suivantes seront produites en plus : `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* Avec la sortie JSON/JSONL, les mêmes champs `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` seront ajoutés à l'objet `Details`, mais uniquement s'ils contiennent des informations.

* Lorsque `SrcIP` ou `TgtIP` est localhost (`127.0.0.1`, `::1`, etc...), `SrcASN` ou `TgtASN` sera produit comme `Local`.
* Lorsque `SrcIP` ou `TgtIP` est une adresse IP privée (`10.0.0.0/8`, `fe80::/10`, etc...), `SrcASN` ou `TgtASN` sera produit comme `Private`.

#### Fichier de configuration GeoIP

Les noms de champs contenant les adresses IP source et cible qui sont recherchées dans les bases de données GeoIP sont définis dans `rules/config/geoip_field_mapping.yaml`.
Vous pouvez ajouter à cette liste si nécessaire.
Il y a également une section de filtre dans ce fichier qui détermine de quels événements extraire les informations d'adresse IP.

#### Mises à jour automatiques des bases de données GeoIP

Les bases de données MaxMind GeoIP sont mises à jour toutes les 2 semaines.
Vous pouvez installer l'outil MaxMind `geoipupdate` [ici](https://github.com/maxmind/geoipupdate) afin de mettre à jour automatiquement ces bases de données.

Étapes sur macOS :

1. `brew install geoipupdate`
2. Modifiez `/usr/local/etc/GeoIP.conf` ou `/opt/homebrew/etc/GeoIP.conf` : Saisissez votre `AccountID` et votre `LicenseKey` que vous créez après vous être connecté au site MaxMind. Assurez-vous que la ligne `EditionIDs` indique `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Exécutez `geoipupdate`.
4. Ajoutez `-G /usr/local/var/GeoIP` ou `-G /opt/homebrew/var/GeoIP` lorsque vous voulez ajouter des informations GeoIP.

Étapes sur Windows :

1. Téléchargez le dernier binaire Windows (Ex : `geoipupdate_4.10.0_windows_amd64.zip`) depuis la page [Releases](https://github.com/maxmind/geoipupdate/releases).
2. Modifiez `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf` : Saisissez votre `AccountID` et votre `LicenseKey` que vous créez après vous être connecté au site MaxMind. Assurez-vous que la ligne `EditionIDs` indique `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Exécutez l'exécutable `geoipupdate`.

Étapes sur Linux :

1. Installez avec `sudo apt install geoip-update`.
2. Modifiez le fichier de configuration avec `sudo nano /etc/GeoIP.conf`.
3. Mettez à jour les fichiers de base de données avec `sudo geoipupdate`.
4. Ajoutez `-G /var/lib/GeoIP/` lorsque vous voulez ajouter des informations GeoIP.

### Fichiers de configuration de la commande `dfir-timeline`

`./rules/config/channel_abbreviations.txt` : Correspondances des noms de canaux et de leurs abréviations.

`./rules/config/default_details.txt` : Le fichier de configuration pour les informations de champ par défaut (champ `%Details%`) qui doivent être produites si aucune ligne `details:` n'est spécifiée dans une règle.
Ceci est basé sur le nom du fournisseur et les ID d'événements.

`./rules/config/eventkey_alias.txt` : Ce fichier contient les correspondances des alias de noms courts pour les champs et leurs noms de champs d'origine plus longs.

Exemple :
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Si un champ n'est pas défini ici, Hayabusa vérifiera automatiquement sous `Event.EventData` pour le champ.

`./rules/config/exclude_rules.txt` : Ce fichier contient une liste d'ID de règles qui seront exclues de l'utilisation.
Habituellement, c'est parce qu'une règle en a remplacé une autre ou que la règle ne peut pas être utilisée en premier lieu.
Comme les pare-feu et les IDS, tout outil basé sur des signatures nécessitera un certain réglage pour s'adapter à votre environnement, vous devrez donc peut-être exclure définitivement ou temporairement certaines règles.
Vous pouvez ajouter un ID de règle (Exemple : `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) à `./rules/config/exclude_rules.txt` afin d'ignorer toute règle dont vous n'avez pas besoin ou qui ne peut pas être utilisée.

`./rules/config/noisy_rules.txt` : Ce fichier contient une liste d'ID de règles qui sont désactivées par défaut mais qui peuvent être activées en activant les règles bruyantes avec l'option `-n, --enable-noisy-rules`.
Ces règles sont généralement bruyantes par nature ou en raison de faux positifs.

`./rules/config/target_event_IDs.txt` : Seuls les ID d'événements spécifiés dans ce fichier seront scannés si le filtre EID est activé.
Par défaut, Hayabusa scannera tous les événements, mais si vous voulez améliorer les performances, veuillez utiliser l'option `-E, --EID-filter`.
Cela se traduit généralement par une amélioration de vitesse de 10 à 25 %.

## Commande `level-tuning`

La commande `level-tuning` vous permettra de régler les niveaux d'alerte des règles, en augmentant ou en diminuant le niveau de risque comme vous le souhaitez.
Cette commande utilise un fichier de configuration pour écraser les niveaux de risque (le champ `level`) des règles dans le dossier `rules`.

> Attention : chaque fois que vous exécutez la commande `update-rules`, le niveau de risque sera ramené à sa valeur d'origine, vous devrez donc réexécuter la commande `level-tuning` par la suite.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### Exemples de la commande `level-tuning`

* Usage normal : `hayabusa.exe level-tuning`
* Régler les niveaux d'alerte des règles en fonction de votre fichier de configuration personnalisé : `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### Fichier de configuration `level-tuning`

Les auteurs de règles Hayabusa et Sigma estimeront le niveau de risque approprié de l'alerte lors de la rédaction de leurs règles.
Cependant, les niveaux de risque ne sont parfois pas cohérents et le niveau de risque réel peut également différer selon votre environnement.
Yamato Security fournit et maintient un fichier de configuration à `./rules/config/level_tuning.txt` que vous pouvez également utiliser pour régler vos règles.

Exemple de `./rules/config/level_tuning.txt` :

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

Dans ce cas, le niveau de risque de la règle ayant un `id` de `570ae5ec-33dc-427c-b815-db86228ad43e` dans le répertoire des règles aura son `level` réécrit en `informational`.
Les niveaux possibles à définir sont `critical`, `high`, `medium`, `low` et `informational`.

> Attention : Le fichier de configuration `./rules/config/level_tuning.txt` sera également mis à jour vers la dernière version du dépôt hayabusa-rules chaque fois que vous exécutez `update-rules`.
> Par conséquent, si vous apportez des modifications à ce fichier, vous perdrez ces modifications !
> Si vous voulez conserver un fichier de configuration pour vous-même, créez alors un fichier de configuration dans `./config/level_tuning.txt` et exécutez `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> Vous pouvez également d'abord effectuer le réglage des niveaux avec le fichier de configuration fourni par Yamato Security, puis affiner davantage avec votre propre fichier de configuration.

## Commande `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## Commande `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### Exemples de la commande `set-default-profile`

* Définir le profil par défaut sur `minimal` : `hayabusa.exe set-default-profile minimal`
* Définir le profil par défaut sur `super-verbose` : `hayabusa.exe set-default-profile super-verbose`

## Commande `update-rules`

La commande `update-rules` synchronisera le dossier `rules` avec le [dépôt github des règles Hayabusa](https://github.com/Yamato-Security/hayabusa-rules), mettant à jour les règles et les fichiers de configuration.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### Exemple de la commande `update-rules`

Vous exécuterez normalement simplement ceci : `hayabusa.exe update-rules`
