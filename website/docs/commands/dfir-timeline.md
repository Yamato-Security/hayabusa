# DFIR Timeline Commands

## Scan Wizard

The `dfir-timeline` command now have a scan wizard enabled by default.
This is intended to help users easily choose which detection rules they want to enable according to their needs and preferences.
The sets of detections rules to load are based off of the official lists in the Sigma project.
Details are explained in [this blog post](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
You can easily turn off the wizard and use Hayabusa in its traditional way by adding the `-w, --no-wizard` option.

### Core Rules

The `core` rule set enables rules that have a status of `test` or `stable` and a level of `high` or `critical`.
These are high quality rules of high confidence and relevance and should not produce many false positives.
The rule status is `test` or `stable` which means no false positives were reported for over 6 months.
Rules will match on attacker techniques, generic suspicious activity, or malicious behavior.
It is the same as using the `--exclude-status deprecated,unsupported,experimental --min-level high` options.

### Core+ Rules

The `core+` rule set enables rules that have a status of `test` or `stable` and a level of `medium` or higher.
`medium` rules most often need additional tuning as certain applications, legitimate user behavior or scripts of an organization might be matched.
It is the same as using the `--exclude-status deprecated,unsupported,experimental --min-level medium` options.

### Core++ Rules

The `core++` rule set enables rules that have a status of `experimental`, `test` or `stable` and a level of `medium` or higher.
These rules are bleeding edge.
They are validated against the baseline evtx files available at the SigmaHQ project and reviewed by multiple detection engineers.
Other than that they are pretty much untested at first.
Use these if you want to be able to detect threats as early as possible at the cost of managing a higher threshold of false positives.
It is the same as using the `--exclude-status deprecated,unsupported --min-level medium` options.

### Emerging Threats (ET) Add-On Rules

The `Emerging Threats (ET)` rule set enables rules that have a tag of `detection.emerging_threats`.
These rules target specific threats and are especially useful for current threats where not much information is available yet.
These rules should not have many false positives but will decrease in relevance over time.
When these rules are not enabled, it is the same as using the `--exclude-tag detection.emerging_threats` option.
When running Hayabusa traditionally without the wizard, these rules will be included by default.

### Threat Hunting (TH) Add-On Rules

The `Threat Hunting (TH)` rule set enables rules that have a tag of `detection.threat_hunting`.
These rules may detect unknown malicious activity, however, will typicially have more false positives.
When these rules are not enabled, it is the same as using the `--exclude-tag detection.threat_hunting` option.
When running Hayabusa traditionally without the wizard, these rules will be included by default.

## Channel-based event log and rules filtering

As of Hayabusa v2.16.0, we enable a Channel-based filter when loading `.evtx` files and `.yml` rules.
The purpose is to make scanning as efficient as possible by only loading what is necessary.
While it possible for there to be multiple providers in a single event log, it is not common to have multiple channels inside a single evtx file.
(The only time we have seen this is when someone has artifically merged two different evtx files together for the [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) project.)
We can use this to our advantage by first checking the `Channel` field in the first record of every `.evtx` file specified to be scanned.
We also check which `.yml` rules use what channels specified in the `Channel` field of the rule.
With these two lists, we only load rules that use channels that are actually present inside the `.evtx` files.

So for example, if a user wants to scan `Security.evtx`, only rules that specify `Channel: Security` will be used.
There is no point in loading other detection rules, for example rules that only look for events in the `Application` log, etc...
Note that channel fields (Ex: `Channel: Security`) are not **explicitly** defined inside original Sigma rules.
For Sigma rules, channel and event IDs fields are **implicitly** defined with `service` and `category` fields under `logsource`. (Ex: `service: security`)
When curating Sigma rules in the [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository, we de-abstract the `logsource` field and explicitly define the channel and event ID fields.
We explain how and why we do this in-depth [here](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Currently, there are only two detection rules that do not have `Channel` defined and are intended to scan all `.evtx` files are the following:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

If you want to use these two rules and scan all rules against loaded `.evtx` files then you will need to add the `-A, --enable-all-rules` option in the `dfir-timeline` command.
In our benchmarks, the rules filtering usually gives a 20% to 10x speed improvement depending on what files are being scanned and of course uses less memory.

Channel filtering is also used when loading `.evtx` files.
For example, if you specify a rule that looks for events with a channel of `Security`, then there is no point in loading `.evtx` files that are not from the `Security` log.
In our benchmarks, this gives a speed benefit of around 10% with normal scans and up to 60%+ performance increase when scanning with a single rule.
If you are sure that multiple channels are being used inside a single `.evtx` file, for example someone used a tool to merge multiple `.evtx` files together, then you disable this filtering with the `-a, --scan-all-evtx-files` option in `dfir-timeline` command.

> Note: Channel filtering only works with `.evtx` files and you will receive an error if you try to load event logs from a JSON file with `-J, --json-input` and also specify `-A` or `-a`.

## `dfir-timeline` command

The `dfir-timeline` command creates a forensics timeline of events. Choose the output format with `-t, --output-type`: `csv` (the default), `json`, or `jsonl`. The value is case-insensitive (e.g. `-t JSONL`).

- **CSV** is good for importing smaller timelines (usually less than 2GB) into tools like LibreOffice or Timeline Explorer (all event fields are placed in one big `Details` column).
- **JSON** is best for more detailed analysis of large results with tools like `jq`, as the `Details` fields are separated.
- **JSONL** is faster and produces a smaller file than JSON, which is ideal for importing into tools like the Elastic Stack.

The **CSV Output** options `-M, --multiline`, `-S, --tab-separator`, and `-R, --remove-duplicate-data` only apply to CSV output and will produce an error if combined with a non-CSV `-t`.

```
  hayabusa.exe dfir-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --json-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
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
  -E, --eid-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
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

CSV Output:
  -M, --multiline              Separate event field information by newline characters (CSV output only)
  -R, --remove-duplicate-data  Duplicate field data will be replaced with "DUP" (CSV output only, sort required)
  -S, --tab-separator          Separate event field information by tabs (CSV output only)

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --geo-ip <MAXMIND-DB-DIR>      Add GeoIP (ASN, city, country) info to IP addresses
  -H, --html-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline to a file (ex: results.csv)
  -t, --output-type <OUTPUT_FORMAT>  Output format: csv (default), json, or jsonl
  -p, --profile <PROFILE>            Specify output profile
  -X, --remove-duplicate-detections  Remove duplicate detections (sort required)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode, sort required)

Time Format:
      --european-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --iso-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --rfc-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --rfc-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
  -U, --utc               Output time in UTC format (default: local time)
      --us-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --us-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
```

### `dfir-timeline` command examples

* Run hayabusa against one Windows event log file with default `standard` profile:

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* Run hayabusa against the sample-evtx directory with multiple Windows event log files with the verbose profile:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* Export to a single CSV file for further analysis with LibreOffice, Timeline Explorer, Elastic Stack, etc... and include all field information (Warning: your file output size will become much larger with the `super-verbose` profile!):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Output JSON instead of CSV (for analysis with `jq`, etc.):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* Output JSONL (for importing into the Elastic Stack, etc.; `-t` is case-insensitive):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* Enable the EID (Event ID) filter:

> Note: Enabling the EID filter will speed up the analysis by about 10-15% in our tests but there is a possibility of missing alerts.

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Only run hayabusa rules (the default is to run all the rules in `-r .\rules`):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Only run hayabusa rules for logs that are enabled by default on Windows:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Only run hayabusa rules for sysmon logs:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Only run sigma rules:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Enable deprecated rules (those with `status` marked as `deprecated`) and noisy rules (those whose rule ID is listed in `.\rules\config\noisy_rules.txt`):

> Note: Recently, deprecated rules are now located in a separate directory in the sigma repository so are not included by default anymore in Hayabusa.
> Therefore, you probably have no need to enable deprecated rules.

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Only run rules to analyze logons and output in the UTC timezone:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Run on a live Windows machine (requires Administrator privileges) and only detect alerts (potentially malicious behavior):

```
hayabusa.exe dfir-timeline -l -m low
```

* Print verbose information (useful for determining which files take long to process, parsing errors, etc...):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Verbose output example:

Loading rules:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Errors during the scan:
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

* Output to a CSV format compatible to import into [Timesketch](https://timesketch.org/):

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --rfc-3339 -o timesketch-import.csv -p timesketch -U
```

* Quiet error mode:
By default, hayabusa will save error messages to error log files.
If you do not want to save error messages, please add `-Q`.

### Advanced - GeoIP Log Enrichment

You can add GeoIP (ASN organization, city and country) information to SrcIP (source IP) fields and TgtIP (target IP) fields with the free GeoLite2 geolocation data.

Steps:

1. First sign up for a MaxMind account [here](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Download the three `.mmdb` files from the [download page](https://www.maxmind.com/en/accounts/current/geoip/downloads) and save them to a directory. The filenames should be called `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb`.
3. When running the `dfir-timeline` command, add the `-G` option followed by the directory with the MaxMind databases.

* With CSV output, the following 6 columns will be additionally outputted: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* With JSON/JSONL output, the same `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` fields will be added to the `Details` object, but only if they contain information.

* When `SrcIP` or `TgtIP` is localhost (`127.0.0.1`, `::1`, etc...), `SrcASN` or `TgtASN` will be outputted as `Local`.
* When `SrcIP` or `TgtIP` is a private IP address (`10.0.0.0/8`, `fe80::/10`, etc...), `SrcASN` or `TgtASN` will be outputted as `Private`.

#### GeoIP config file

The field names that contain source and target IP addresses that get looked up in the GeoIP databases are defined in `rules/config/geoip_field_mapping.yaml`.
You can add to this list if necessary.
There is also a filter section in this file that determines what events to extract IP address information from.

#### Automatic updates of GeoIP databases

MaxMind GeoIP databases are updated every 2 weeks.
You can install the MaxMind `geoipupdate` tool [here](https://github.com/maxmind/geoipupdate) in order to automatically update these databases.

Steps on macOS:

1. `brew install geoipupdate`
2. Edit `/usr/local/etc/GeoIP.conf` or `/opt/homebrew/etc/GeoIP.conf`: Put in your `AccountID` and `LicenseKey` you create after logging into the MaxMind website. Make sure the `EditionIDs` line says `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Run `geoipupdate`.
4. Add `-G /usr/local/var/GeoIP` or `-G /opt/homebrew/var/GeoIP` when you want to add GeoIP information.

Steps on Windows:

1. Download the latest Windows binary (Ex: `geoipupdate_4.10.0_windows_amd64.zip`) from the [Releases](https://github.com/maxmind/geoipupdate/releases) page.
2. Edit `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: Put in your `AccountID` and `LicenseKey` you create after logging into the MaxMind website. Make sure the `EditionIDs` line says `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Run the `geoipupdate` executable.

Steps on Linux:

1. Install with `sudo apt install geoip-update`
2. Edit config file with `sudo nano /etc/GeoIP.conf`
3. Update the database files with `sudo geoipupdate`
4. Add `-G /var/lib/GeoIP/` when you want to add GeoIP information.

### `dfir-timeline` command config files

`./rules/config/channel_abbreviations.txt`: Mappings of channel names and their abbreviations.

`./rules/config/default_details.txt`: The configuration file for what default field information (`%Details%` field) should be outputted if no `details:` line is specified in a rule.
This is based on provider name and event IDs.

`./rules/config/eventkey_alias.txt`: This file has the mappings of short name aliases for fields and their original longer field names.

Example:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

If a field is not defined here, Hayabusa will automatically check under `Event.EventData` for the field.

`./rules/config/exclude_rules.txt`: This file has a list of rule IDs that will be excluded from use.
Usually this is because one rule has replaced another or the rule cannot be used in the first place.
Like firewalls and IDSes, any signature-based tool will require some tuning to fit your environment so you may need to permanently or temporarily exclude certain rules.
You can add a rule ID (Example: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) to `./rules/config/exclude_rules.txt` in order to ignore any rule that you do not need or cannot be used.

`./rules/config/noisy_rules.txt`: This file a list of rule IDs that are disabled by default but can be enabled by enabling noisy rules with the `-n, --enable-noisy-rules` option.
These rules are usually noisy by nature or due to false positives.

`./rules/config/target_event_IDs.txt`: Only the event IDs specified in this file will be scanned if the EID filter is enabled.
By default, Hayabusa will scan all events, but if you want to improve performance, please use the `-E, --eid-filter` option.
This usually results in a 10~25% speed improvement.

## `level-tuning` command

The `level-tuning` command will let you tune the alert levels for rules, either raising or decreasing the risk level as you would like them.
This command uses a config file to overwrite the risk levels (the `level` field) of rules in the `rules` folder.

> Warning: everytime you run the `update-rules` command, the risk level will be returned back to the original value so you will need to run the `level-tuning` command again aferwards.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### `level-tuning` command examples

* Normal usage: `hayabusa.exe level-tuning`
* Tune rule alert levels based on your custom config file: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### `level-tuning` config file

Hayabusa and Sigma rule authors will estimate the appropriate risk level of the alert when writing their rules.
However, sometimes risk levels are not consistant and also the actual risk level may differ according to your environment.
Yamato Security provides and maintains a config file at `./rules/config/level_tuning.txt` that you can use to tune your rules as well.

`./rules/config/level_tuning.txt` sample:

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

In this case, the risk level of the rule with an `id` of `570ae5ec-33dc-427c-b815-db86228ad43e` in the rules directory will have its `level` rewritten to `informational`.
The possible levels to set are `critical`, `high`, `medium`, `low` and `informational`.

> Warning: The `./rules/config/level_tuning.txt` config file will also be updated to the latest version on the hayabusa-rules repository everytime you run `update-rules`.
> Therefore, if you make changes to this file, you will loose those changes!
> If you want to keep a config file for yourself, then create a config file in `./config/level_tuning.txt` and run `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> You can also first do level tuning with the config file provided by Yamato Security and then further tune with your own config file.

## `list-profiles` command

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## `set-default-profile` command

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### `set-default-profile` command examples

* Set the default profile to `minimal`: `hayabusa.exe set-default-profile minimal`
* Set the default profile to `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## `update-rules` command

The `update-rules` command will sync the `rules` folder with the [Hayabusa rules github repository](https://github.com/Yamato-Security/hayabusa-rules), updating the rules and config files.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### `update-rules` command example

You will normally just execute this: `hayabusa.exe update-rules`
