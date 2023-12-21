# Changes

## 2.12.0 [2023/12/23] "SECCON Christmas Release"

**Enhancements:**

- `%MitreTactics%`, `%MitreTags%`, `%OtherTags%` fields are now outputted as an array of strings in JSON output. (#1230) (@hitenkoku)
- Added a summary of MITRE ATT&CK tactics that were detected for each computer in the HTML report. In order to use this feature, you need to use a profile that includes the `%MitreTactics%` field. (#1226) (@hitenkoku)
- Output messages about reporting issues and false positives when using `csv-timeline` or `json-timeline` commands. (#1236) (@hitenkoku)

**Bug Fixes:**

- In JSON output, multiple field names with the same names were not outputted as an array so only one result would be returned when parsing with `jq`. We fixed this by outputting multiple field data with the same field name inside an array. (#1202) (@hitenkoku)
- Fixed a bug in the `csv-timeline`, `json-timeline`, `eid-metrics`, `logon-summary`, `pivot-keywords-list` and `search` commands so that Hayabusa will quit whenever no input option (`-l`, `-f` or `-d`) is specified. (#1235) (@hitenkoku)

## 2.11.0 [2023/12/03] "Nasi Lemak Release"

**New Features:**

- Extraction of fields from PowerShell classic logs. (Can disable with `--no-pwsh-field-extraction`) (#1220) (@fukusuket)

**Enhancements:**

- Added rule count in the scan wizard. (#1206) (@hitenkoku)

## 2.10.1 [2023/11/13] "Kamemushi Release"

**Enhancements:**

- Added questions to the scan wizard. (#1207) (@hitenkoku)

**Bug Fixes:**

- `update-rules` command would output `You currently have the latest rules` even if new rules were downloaded in version `2.10.0`. (#1209) (@fukusuket)
- Regular expressions would sometimes be incorrectly handled. (#1212) (@fukusuket)
- In the rare case that there is no `Data` field such as for JSON input, a panic would occur. (#1215) (@fukusuket)

## 2.10.0 [2023/10/31] "Halloween Release"

**Enhancements:**

- Added a scan wizard to help new users choose which rules they want to enable. Add the `-w, --no-wizard` option to run Hayabusa in the traditional way. (Scan for all events and alerts, and customize options manually.) (#1188) (@hitenkoku)
- Added the `--include-tag` option to the `pivot-keywords-list` command to only load rules with the specified `tags` field. (#1195) (@hitenkoku)
- Added the `--exclude-tag` option to the `pivot-keywords-list` command to exclude rules with specific `tags` from being loaded. (#1195) (@hitenkoku)

**Bug Fixes:**

- Fixed that field information defined in `Details` was also output to `ExtraFieldInfo` in some cases. (#1145) (@hitenkoku)
- Fixed output of newline and tab characters in `AllFieldInfo` in JSON output. (#1189) (@hitenkoku)
- Fixed output of space characters in some fields in standard output. (#1192) (@hitenkoku)

## 2.9.0 [2023/09/22] "Autumn Rain Release"

**Enhancements:**

- Added an error message to indicate that when you can't load evtx files in Windows due to specifying a directory path with spaces in it, you need to remove the trailing backslash. (#1166) (@hitenkoku, thanks for the suggestion from @joswr1ght)
- Optimized the number of records to load at a time for performance. (#1175) (@yamatosecurity)
- Replaced double backslashes in paths under the progress bar on Windows systems with single forward slashes. (#1172) (@hitenkoku)
- Made the `Details` field for `count` rules a string in the JSON output for easier parsing. (#1179) (@hitenkoku)
- Changed the default number of threads from number of CPUs to the estimate of the default amount of parallelism a program should use (`std::thread::available_parallelism`). (#1182) (@hitenkoku)

**Bug Fixes:**

- Fixed JSON fields would not be correctly parsed in rare cases. (#1145) (@hitenkoku)

**Other:**

- Removed the unmaintained `hhmmss` crate that uses an old `time` crate in order to pass the code coverage CI checks. (#1181) (@hitenkoku)

## 2.8.0 [2023/09/01] "Double X Release"

**New Features:**

- Added support for `HexToDecimal` in the field mapping configuration files to convert hex values to decimal. (Useful for converting the original process IDs from hex to decimal.) (#1133) (@fukusuket)
- Added `-x, --recover-records` option to `csv-timeline` and `json-timeline` to recover evtx records through file carving in evtx slack space. (#952) (@hitenkoku) (Evtx carving feature is thanks to @forensicmatt)
- Added `-X, --remove-duplicate-detections` option to `csv-timeline` and `json-timeline` to not output any duplicate detection entries. (Useful when you use `-x`, include backup logs or logs extracted from VSS with duplicate data, etc...)
- Added a `--timeline-offset` option to `csv-timeline`, `json-timeline`, `logon-summary`, `eid-metrics`, `pivot-keywords-list` and `search` commands to scan just recent events based on a offset of years, months, days, hours, etc... (#1159) (@hitenkoku)
- Added a `-a, --and-logic` option in the `search` command to search keywords with AND logic. (#1162) (@hitenkoku)

**Other:**

- When using `-x, --recover-records`, an additional `%RecoveredRecord%` field will be added to the output profile and will output `Y` to indicate if a record was recovered. (#1160) (@hitenkoku)

## 2.7.0 [2023/08/03] "SANS DFIR Summit Release"

**New Features:**

- Certain code numbers are now mapped to human-readable messages based on the `.yaml` config files in `./rules/config/data_mapping`. (Example: `%%2307` will be converted to `ACCOUNT LOCKOUT`). You can turn off this behavior with the `-F, --no-field-data-mapping` option. (#177) (@fukusuket)
- Added the `-R, --remove-duplicate-data` option in the `csv-timeline` command to replace duplicate field data with the string `DUP` in the `%Details%`, `%AllFieldInfo%`, `%ExtraFieldInfo%` columns to reduce file size. (#1056) (@hitenkoku)
- Added the `-P, --proven-rules` option in `csv-timeline` and `json-timeline` commands. When used, Hayabusa will only load rules that have been proven to work. These are defined by rule ID in the `./rules/config/proven_rules.txt` config file. (#1115) (@hitenkoku)
- Added the `--include-tag` option to `csv-timeline` and `json-timeline` commands to only load rules with the specified `tags` field. (#1108) (@hitenkoku)
- Added the `--exclude-tag` option to `csv-timeline` and `json-timeline` commands to exclude rules with specific `tags` from being loaded. (#1118) (@hitenkoku)
- Added `--include-category` and `--exclude-category` options to `csv-timeline` and `json-timeline` commands. When using `--include-category`, only rules with the specified `category` field will be loaded. `--exclude-category` will exclude rules from being loaded based on `category`. (#1119) (@hitenkoku)
- Added the `computer-metrics` command to list up how many events there are based on computer name. (#1116) (@hitenkoku)
- Added `--include-computer` and `--exclude-computer` options to `csv-timeline`, `json-timeline`, `metrics`, `logon-summary` and `pivot-keywords-list` commands. The `--include-computer` option only scans the specified computer(s). `--exclude-computer` excludes them. (#1117) (@hitenkoku)
- Added `--include-eid` and `--exclude-eid` options to `csv-timeline`, `json-timeline`, and `pivot-keywords-list` commands. The `--include-eid` option only scans the specified EventID(s). `--exclude-eid` excludes them. (#1130) (@hitenkoku)
- Added the `-R, --remove-duplicate-data` option to the `json-timeline` command to replace duplicate field data with the string `DUP` in the `%Details%`, `%AllFieldInfo%`, `%ExtraFieldInfo%` fields to reduce file size. (#1134) (@hitenkoku)

**Enhancements:**

- Ignore corrupted event records with timestamps before 2007/1/31 when Windows Vista was released with the new `.evtx` log format. (#1102) (@fukusuket)
- When `--output` is set in the `metrics` command, the results will not be displayed to screen. (#1099) (@hitenkoku)
- Added the `-C, --clobber` option to overwrite existing output files in the `pivot-keywords-list` command. (#1125) (@hitenkoku)
- Renamed the `metrics` command to `eid-metrics`. (#1128) (@hitenkoku)
- Reduced progress bar width to leave room for adjustment of the terminal. (#1135) (@hitenkoku)
- Added support for outputing timestamps in the following formats in the `search` command: `--European-time`, `--ISO-8601`, `--RFC-2822`, `--RFC-3339`, `--US-time`, `--US-military-time`, `-U, --UTC`. (#1040) (@hitenkoku)
- Replaced the ETA time in the progress bar with elapsed time as the ETA time was not accurate. (#1143) (@YamatoSecurity)
- Added `--timeline-start` and `--timeline-end` to the `logon-summary` command. (#1152) (@hitenkoku)

**Bug Fixes:**

- The total number of records being displayed in the `metrics` and `logon-summary` commands differed from the `csv-timeline` command. (#1105) (@hitenkoku)
- Changed rule count by rule ID instead of path. (#1113) (@hitenkoku)
- Fixed a problem with incorrect field splitting in the `CommandLine` field in JSON output. (#1145) (@hitenkoku)
- `--timeline-start` and `--timeline-end` were not working correctly with the `json-timeline` command. (#1148) (@hitenkoku)
- `--timeline-start` and `--timeline-end` were not working correctly with the `pivot-keywords-list` command. (#1150) (@hitenkoku)

**Other:**

- The total count of unique detections are now based on rule IDs instead of rule file paths. (#1111) (@hitenkoku)
- Renamed the `--live_analysis` option to `--live-analysis`. (#1139) (@hitenkoku)
- Renamed the `metrics` command to `eid-metrics`. (#1128) (@hitenkoku)

## 2.6.0 [2023/06/16] "Ajisai Release"

**New Features:**

- Added support for `'|all':`  keyword in sigma rules. (#1038) (@kazuminn)

**Enhancements:**

- Added `%ExtraFieldInfo%` alias to output profiles which will output all of the other fields that do not get outputted in `Details`. This is now included in the default `standard` output profile. (#900) (@hitenkoku)
- Added error messages for incompatible arguments. (#1054) (@YamatoSecurity)
- The output profile name is now outputted to standard output and in the HTML report. (#1055) (@hitenkoku)
- Added rule author names next to rule alerts in the HTML report. (#1065) (@hitenkoku)
- Made the table width shorter to prevent tables breaking in smaller terminal sizes. (#1071) (@hitenkoku)
- Added the `-C, --clobber` option to overwrite existing output files in `csv-timeline`, `json-timeline`, `metrics`, `logon-summary`, and `search` commands. (#1063) (@YamatoSecurity, @hitenkoku)
- Made the HTML report portable by embedding the images and inlining CSS. (#1078) (@hitenkoku, thanks for the suggestion from @joswr1ght)
- Speed improvements in the output. (#1088) (@hitenkoku, @fukusuket)
- The `metrics` command now performs word wrapping to make sure the table gets rendered correctly. (#1067) (@garigariganzy)
- `search` command results can now be outputted to JSON/JSONL. (#1041) (@hitenkoku)

**Bug Fixes:**

- `MitreTactics`, `MitreTags`, `OtherTags` fields were not being outputted in the `json-timeline` command. (#1062) (@hitenkoku)
- The detection frequency timeline (`-T`) would not output when the `no-summary` option was also enabled. (#1072) (@hitenkoku)
- Control characters would not be escaped in the `json-timeline` command causing a JSON parsing error. (#1068) (@hitenkoku)
- In the `metrics` command, channels would not be abbreviated if they were lowercase. (#1066) (@garigariganzy)
- Fixed an issue where some fields were misaligned in the JSON output. (#1086) (@hitenkoku)

## 2.5.1 [2023/05/14] "Mothers Day Release"

**Enhancements:**

- Reduced memory usage by half when using newly converted rules. (#1047) (@fukusuket)

**Bug Fixes:**

- Data in certain fields such as `AccessMask` would not be separated by spaces when outputted from the `details` field. (#1035) (@hitenkoku)
- Multiple spaces would be condensed to a single space when outputting to JSON. (#1048) (@hitenkoku)
- Output would be in color even if `--no-color` was used in the `pivot-keywords-list` command. (#1044) (@kazuminn)

## 2.5.0 [2023/05/07] "Golden Week Release"

**Enhancements:**

- Added `-M, --multiline` option to search command. (#1017) (@hitenkoku)
- Deleted return characters in the output of the `search` command. (#1003) (@hitenkoku)
- `regex` crate updated to 1.8 which allows unnecessary escapes in regular expressions reducing parsing errors. (#1018) (@YamatoSecurity)
- Deleted return characters in output of the `csv-timeline` command. (#1019) (@hitenkoku)
- Don't show new version information with the `update-rules` command when building a newer dev build. (#1028) (@hitenkoku)
- Sorted `search` timeline order. (#1033) (@hitenkoku)
- Enhanced `pivot-keywords-list` terminal output. (#1022) (@kazuminn)

**Bug Fixes:**

- Unconverted sigma rules that search for a string that end in a backslash would not be detected. Also `|contains` conditions would not match if the string was located in the beginning. (#1025) (@fukusuket)
- In versions 2.3.3-2.4.0, informational level alerts in the Results Summary would show the top 5 events twice instead of the top 10 events. (#1031) (@hitenkoku)

## 2.4.0 [2023/04/19] "SANS Secure Korea Release"

**New Features:**

- Added `search` command to search for specified keywords in records. (#617) (@itiB, @hitenkoku)
- Added `-r, --regex` option in the `search` command to search for regular expressions. (#992) (@itiB)

**Enhancements:**

- Alphabetically sorted commands. (#991) (@hitenkoku)
- Added attribute information of `Event.UserData` to the output of `AllFieldInfo` in `csv-timeline`, `json-timeline` and `search` commands. (#1006) (@hitenkoku)
- Updated Aho-Corasick crate to 1.0. (#1013) (@hitenkoku)

**Bug Fixes:**

- Fixed timestamps that did not exist from being displayed in the event frequency timeline (`-T, --visualize-timeline`) in version 2.3.3. (#977) (@hitenkoku)

## 2.3.3 [2023/04/07] "Sakura Release"

**Enhancements:**

- Removed an extra space when outputting the rule `level` to files (CSV, JSON, JSONL). (#979) (@hitenkoku)
- Rule authors are now outputted in multiple lines with the `-M, --multiline` option. (#980) (@hitenkoku)
- Approximately 3-5% speed increase by replacing String with CoW. (#984) (@hitenkoku)
- Made sure text after the logo does not turn green with recent clap versions. (#989) (@hitenkoku)

**Bug Fixes:**

- Fixed a crash when the `level-tuning` command was executed on version 2.3.0. (#977) (@hitenkoku)

## 2.3.2 [2023/03/22] "TMCIT Release-3"

**Enhancements:**

- Added `-M, --multiline` option in the `csv-timeline` command. (#972) (@hitenkoku)

## 2.3.1 [2023/03/18] "TMCIT Release-2"

**Enhancements:**

- Added double quotes in CSV fields of `csv-timeline` output to support multiple lines in fields. (#965) (@hitenkoku)
- Updated `logon-summary` headers. (#964) (@yamatosecurity)
- Added short-hand option `-D` for `--enable-deprecated-rules` and `-u` for `--enable-unsupported-rules`. (@yamatosecurity)
- Reordered option in Filtering and changed option help contents. (#969) (@hitenkoku)

**Bug Fixes:**

- Fixed a crash when the `update-rules` command was executed on version 2.3.0. (#965) (@hitenkoku)
- Fixed long underlines displayed in the help menu in Command Prompt and PowerShell prompt. (#911) (@yamatosecurity)

## 2.3.0 [2023/03/16] "TMCIT Release"

**New Features:**

- Added support for `|cidr`. (#961) (@fukusuket)
- Added support for `1 of selection*` and `all of selection*`. (#957) (@fukusuket)
- Added support for the `|contains|all` pipe keyword. (#945) (@hitenkoku)
- Added the `--enable-unsupported-rules` option to enable rules marked as `unsupported`. (#949) (@hitenkoku)

**Enhancements:**

- Approximately 2-3% speed increase and memory usage reduction by improving string contains check. (#947) (@hitenkoku)

**Bug Fixes:**

- Some event titles would be displayed as `Unknown` in the `metrics` command even if they were defined. (#943) (@hitenkoku)

## 2.2.2 [2023/2/22] "Ninja Day Release"

**New Features:**

- Added support for the `|base64offset|contains` pipe keyword. (#705) (@hitenkoku)

**Enhancements:**

- Reorganized the grouping of command line options. (#918) (@hitenkoku)
- Reduced memory usage by approximately 75% when reading JSONL formatted logs. (#921) (@fukusuket)
- Channel names are now further abbreviated in the metrics, json-timeline, csv-timeline commands according to `rules/config/generic_abbreviations.txt`. (#923) (@hitenkoku)
- Reduced parsing errors by updating the evtx crate. (@YamatoSecurity)
- Provider names (`%Provider%` field) are now abbreviated like channel names according to `rules/config/provider_abbreviations.txt` and `rules/config/generic_abbreviations.txt`. (#932) (@hitenkoku)
- Print the first and last timestamps in the metrics command when the `-d` directory option is used. (#935) (@hitenkoku)
- Added first and last timestamp to Results Summary. (#938) (@hitenkoku)
- Added Time Format options for `logon-summary`, `metrics` commands. (#938) (@hitenkoku)
- `\r`, `\n`, and `\t` characters are preserved (not converted to spaces) when saving results with the `json-output` command. (#940) (@hitenkoku)

**Bug Fixes:**

- The first and last timestamps in the `logon-summary` and `metrics` commands were blank. (#920) (@hitenkoku)
- Event titles stopped being shown in the `metrics` command during development of 2.2.2. (#933) (@hitenkoku)

## 2.2.0 [2023/2/12] "SECCON Release"

**New Features:**

- Added support for input of JSON-formatted event logs (`-J, --JSON-input`). (#386) (@hitenkoku)
- Log enrichment by outputting the ASN organization, city and country of source and destination IP addresses based on MaxMind GeoIP databases (`-G, --GeoIP`). (#879) (@hitenkoku)
- Added the `-e, --exact-level` option to scan for only specific rule levels. (#899) (@hitenkoku)

**Enhancements:**

- Added the executed command line to the HTML report. (#877) (@hitenkoku)
- Approximately 3% speed increase and memory usage reduction by performing exact string matching on Event IDs. (#882) (@fukusuket)
- Approximately 14% speed increase and memory usage reduction by filtering before regex usage. (#883) (@fukusuket)
- Approximately 8% speed increase and memory usage reduction by case-insensitive comparisons instead of regex usage. (#884) (@fukusuket)
- Approximately 5% speed increase and memory usage reduction by reducing regex usage in wildcard expressions. (#890) (@fukusuket)
- Further speed increase and memory usage reduction by removing unnecessary regex usage. (#894) (@fukusuket)
- Approximately 3% speed increase and 10% memory usage reduction by reducing regex usage. (#898) (@fukuseket)
- Improved `-T, --visualize-timeline` by increasing the height of the markers to make it easier to read. (#902) (@hitenkoku)
- Reduced memory usage by approximately 50% when reading JSON/L formatted logs. (#906) (@fukusuket)
- Alphabetically sorted options based on their long names. (#904) (@hitenkoku)
- Added JSON input support (`-J, --JSON-input` option) for `logon-summary`, `metrics` and `pivot-keywords-list` commands. (#908) (@hitenkoku)

**Bug Fixes:**

- Fixed a bug when rules with 4 consecutive backslashes in their conditions would not be detected. (#897) (@fukusuket)
- When parsing PowerShell EID 4103, the `Payload` field would be separated into multiple fields when outputting to JSON. (#895) (@hitenkoku)
- Fixed a crash when looking up event log file size. (#914) (@hitenkoku)

**Vulnerability Fixes:**

- Updated the git2 and gitlib2 crates to prevent a possible SSH MITM attack (CVE-2023-22742) when updating rules and config files. (#888) (@YamatoSecurity)

## 2.1.0 [2023/01/10] "Happy Year of the Rabbit Release"

**Enhancements:**

- Speed improvements. (#847) (@hitenkoku)
- Improved speed by up to 20% by improving I/O processesing. (#858) (@fukusuket)
- The timeline order of detections are now sorted to a fixed order even when the timestamp is identical. (#827) (@hitenkoku)

**Bug Fixes:**

- Successful login CSV results were not correctly being outputted when using the logon timeline function. (#849) (@hitenkoku)
- Removed unnecessary line breaks that would occur when using the `-J, --jsonl` option. (#852) (@hitenkoku)

## 2.0.0 [2022/12/24] "Merry Christmas Release"

**New Features:**

- Command usage and help menu are now done by subcommands. (#656) (@hitenkoku)

## 1.9.0 [2022/12/24] "Merry Christmas Release"

**New Features:**

- Added a new pipe keyword. (`|endswithfield`) (#740) (@hach1yon)
- Added `--debug` option to display memory utilization at runtime. (#788) (@fukusuket)

**Enhancements:**

- Updated clap crate package to version 4 and changed the `--visualize-timeline` short option `-V` to `-T`. (#725) (@hitenkoku)
- Added output of logon types, source computer and source IP address in Logon Summary as well as failed logons. (#835) (@garigariganzy @hitenkoku)
- Optimized speed and memory usage. (#787) (@fukusuket)
- Changed output color in eggs ascii art.(#839) (@hitenkoku)
- Made the `--debug` option hidden by default. (#841) (@hitenkoku)
- Added color to the ascii art eggs. (#839) (@hitenkoku)

**Bug Fixes:**

- Fixed a bug where evtx files would not be loaded if run from a command prompt and the directory path was enclosed in double quotes. (#828) (@hitenkoku)
- Fixed unneeded spaces outputted when there were rule parsing errors. (#829) (@hitenkoku)

## 1.8.1 [2022/11/21]

**Enhancements:**

- Specified the minimum Rust version `rust-version` field in `Cargo.toml` to avoid build dependency errors. (#802) (@hitenkoku)
- Reduced memory usage. (#806) (@fukusuket)
- Added the support for the `%RenderedMessage%` field in output profiles which is the rendered message in logs forwarded by WEC. (#760) (@hitenkoku)

**Bug Fixes:**

- Fixed a problem where rules using the `Data` field were not being detected. (#775) (@hitenkoku)
- Fixed a problem where the `%MitreTags%` and `%MitreTactics%` fields would randomly miss values. (#807) (@fukusuket)

## 1.8.0 [2022/11/07]

**New Features:**

- Added the `--ISO-8601` output time format option. This good to use when importing to Elastic Stack. It is exactly the same as what is in the original log.  (#767) (@hitenkoku)

**Enhancements:**

- Event ID filtering is now turned off by default. Use the `-e, --eid-filter` option to filter by Event ID. (Will usually be 10%+ faster but with a small chance of false negatives.) (#759) (@hitenkoku)
- Print an easy to understand error message when a user tries to download new rules with a different user account. (#758) (@fukusuket)
- Added total and unique detecion count information in the HTML Report. (#762) (@hitenkoku)
- Removed unnecessary array structure in the JSON output. (#766)(@hitenkoku)
- Added rule authors (`%RuleAuthor%`), rule creation date (`%RuleCreationDate%`), rule modified date (`%RuleModifiedDate%`), and rule status (`%Status%`) fields to output profiles. (#761) (@hitenkoku)
- Changed Details field in JSON output to an object. (#773) (@hitenkoku)
- Removed `build.rs` and changed the memory allocator to mimalloc for a speed increase of 20-30% on Intel-based OSes. (#657) (@fukusuket)
- Replaced `%RecordInformation%` alias in output profiles to `%AllFieldInfo%`, and changed the `AllFieldInfo` field in JSON output to an object. (#750) (@hitenkoku)
- Removed `HBFI-` prefix in `AllFieldInfo` field of json output. (#791) (@hitenkoku)
- Don't display result summary, etc... when `--no-summary` option is used. (This is good to use when using as a Velociraptor agent, etc... It will usually be 10% faster.) (#780) (@hitenkoku)
- Reduced memory usage and improved speed performance. (#778 #790) (@hitenkoku)
- Don't display Rule Authors list when authors list is empty. (#795) (@hitenkoku)
- Added rule ID (`%RuleID%`) and Provider Name (`%Provider%`) fields to output profiles. (#794) (@hitenkoku)

**Bug Fixes:**

- Fixed rule author unique rule count. (It was displaying one extra.) (#783) (@hitenkoku)

## 1.7.2 [2022/10/17]

**New Features:**

- Added `--list-profiles` option to print a list of output profiles. (#746) (@hitenkoku)

**Enhancements:**

- Moved the saved file line and shortened the update option output. (#754) (@YamatoSecurity)
- Limited rule author names of detected alerts to 40 characters. (#751) (@hitenkoku)

**Bug Fixes:**

- Fixed a bug where field information would get moved over in JSON/JSONL output when a drive letter (ex: `c:`) was in the field. (#748) (@hitenkoku)

## 1.7.1 [2022/10/10]

**Enhancements:**

- Hayabusa now checks Channel and EID information based on `rules/config/channel_eid_info.txt` to provide more accurate results. (#463) (@garigariganzy)
- Do not display a message about loading detection rules when using the `-M` or `-L` options. (#730) (@hitenkoku)
- Added a table of rule authors to standard output. (#724) (@hitenkoku)
- Ignore event records when the channel name is `null` (ETW events) when scanning and showing EID metrics. (#727) (@hitenkoku)

**Bug Fixes:**

- Fixed a bug where the same Channel and EID would be counted separately with the `-M` option. (#729) (@hitenkoku)

## 1.7.0 [2022/09/29]

**New Features:**

- Added a HTML summary report output option (`-H, --html-report`). (#689) (@hitenkoku, @nishikawaakira)

**Enhancements:**

- Changed Event ID Statistics option to Event ID Metrics option. (`-s, --statistics`  -> `-M, --metrics`) (#706) (@hitenkoku)
  (Note: `statistics_event_info.txt` was changed to `event_id_info.txt`.)
- Display new version of Hayabusa link when updating rules if there is a newer version. (#710) (@hitenkoku)
- Added logo in HTML summary output. (#714) (@hitenkoku)
- Unified output to one table when using `-M` or `-L` with the `-d` option. (#707) (@hitenkoku)
- Added Channel column to metrics output. (#707) (@hitenkoku)
- Removed First Timestamp and Last Timestamp of `-M` and `-L` option with the `-d` option. (#707) (@hitenkoku)
- Added csv output option(`-o --output`) when `-M` or `-L` option is used. (#707) (@hitenkoku)
- Separated Count and Percent columns in metric output. (#707) (@hitenkoku)
- Changed output table format of the metric option and logon information crate from prettytable-rs to comfy_table. (#707) (@hitenkoku)
- Added favicon.png in HTML summary output. (#722) (@hitenkoku)

## v1.6.0 [2022/09/16]

**New Features:**

- You can now save the timeline to JSON files with the `-j, --json` option.  (#654) (@hitenkoku)
- You can now save the timeline to JSONL files with the `-J, --jsonl` option.  (#694) (@hitenkoku)

**Enhancements:**

- Added top alerts to results summary. (#667) (@hitenkoku)
- Added `--no-summary` option to not display the results summary. (#672) (@hitenkoku)
- Made the results summary more compact. (#675 #678) (@hitenkoku)
- Made Channel field in channel_abbreviations.txt case-insensitive. (#685) (@hitenkoku)
- Changed pipe separator character in output from `|` to `‖`. (#687) (@hitenkoku)
- Added color to Saved alerts and events / Total events analyzed. (#690) (@hitenkoku)
- Updated evtx crate to 0.8.0. (better handling when headers or date values are invalid.)
- Updated output profiles. (@YamatoSecurity)

**Bug Fixes:**

- Hayabusa would crash with `-L` option (logon summary option). (#674) (@hitenkoku)
- Hayabusa would continue to scan without the correct config files but now will print and error and gracefully terminate. (#681) (@hitenkoku)
- Fixed total events from the number of scanned events to actual events in evtx. (#683) (@hitenkoku)

## v1.5.1 [2022/08/20]

**Enhancements:**

- Re-released v1.5.1 with an updated output profile that is compatible with Timesketch. (#668) (@YamatoSecurity)

## v1.5.1 [2022/08/19]

**Bug Fixes:**

- Critical, medium and low level alerts were not being displayed in color. (#663) (@fukusuket)
- Hayabusa would crash when an evtx file specified with `-f` did not exist. (#664) (@fukusuket)

## v1.5.0 [2022/08/18]

**New Features:**

- Customizable output of fields defined at `config/profiles.yaml` and `config/default_profile.yaml`. (#165) (@hitenkoku)
- Implemented the `null` keyword for rule detection. It is used to check if a target field exists or not. (#643) (@hitenkoku)
- Added output to JSON option (`-j` and `--json-timeline` )  (#654) (@hitenkoku)

**Enhancements:**

- Trimmed `./` from the rule path when updating. (#642) (@hitenkoku)
- Added new output aliases for MITRE ATT&CK tags and other tags. (#637) (@hitenkoku)
- Organized the menu output when `-h` is used. (#651) (@YamatoSecurity and @hitenkoku)
- Added commas to summary numbers to make them easier to read. (#649) (@hitenkoku)
- Added output percentage of detections in Result Summary. (#658) (@hitenkoku)

**Bug Fixes:**

- Fixed miscalculation of Data Reduction due to aggregation condition rule detection. (#640) (@hitenkoku)
- Fixed a race condition bug where a few events (around 0.01%) would not be detected. (#639 #660) (@fukusuket)

## v1.4.3 [2022/08/03]

**Bug Fixes:**

- Hayabusa would not run on Windows 11 when the VC redistribute package was not installed but now everything is compiled statically. (#635) (@fukusuket)

## v1.4.2 [2022/07/24]

**Enhancements:**

- You can now update rules to a custom directory by combining the `--update-rules` and `--rules` options. (#615) (@hitenkoku)
- Improved speed with parallel processing by up to 20% with large files. (#479) (@kazuminn)
- When saving files with `-o`, the `.yml` detection rule path column changed from `RulePath` to `RuleFile` and only the rule file name will be saved in order to decrease file size. (#623) (@hitenkoku)

**Bug Fixes:**

- Fixed a runtime error when hayabusa is run from a different path than the current directory. (#618) (@hitenkoku)

## v1.4.1 [2022/06/30]

**Enhancements:**

- When no `details` field is defined in a rule nor in `./rules/config/default_details.txt`, all fields will be outputted to the `details` column. (#606) (@hitenkoku)
- Added the `-D, --deep-scan` option. Now by default, events are filtered by Event IDs that there are detection rules for defined in `./rules/config/target_event_IDs.txt`. This should improve performance by 25~55% while still detecting almost everything. If you want to do a thorough scan on all events, you can disable the event ID filter with `-D, --deep-scan`. (#608) (@hitenkoku)
- `channel_abbreviations.txt`, `statistics_event_info.txt` and `target_event_IDs.txt` have been moved from the `config` directory to the `rules/config` directory in order to provide updates with `-U, --update-rules`.

## v1.4.0 [2022/06/26]

**New Features:**

- Added `--target-file-ext` option. You can specify additional file extensions to scan in addtition to the default `.evtx` files. For example, `--target-file-ext evtx_data` or multiple extensions with `--target-file-ext evtx1 evtx2`. (#586) (@hitenkoku)
- Added `--exclude-status` option: You can ignore rules based on their `status`. (#596) (@hitenkoku)

**Enhancements:**

- Added default details output based on `rules/config/default_details.txt` when no `details` field in a rule is specified. (i.e. Sigma rules) (#359) (@hitenkoku)
- Updated clap crate package to version 3. (#413) (@hitnekoku)
- Updated the default usage and help menu. (#387) (@hitenkoku)
- Hayabusa can be run from any directory, not just from the current directory. (#592) (@hitenkoku)
- Added saved file size output when `output` is specified. (#595) (@hitenkoku)

**Bug Fixes:**

- Fixed output error and program termination when long output is displayed with color. (#603) (@hitenkoku)
- Ignore loading yml files in `rules/tools/sigmac/testfiles` to fix `Excluded rules` count. (#602) (@hitenkoku)

## v1.3.2 [2022/06/13]

**Enhancements:**

- Changed the evtx Rust crate from 0.7.2 to 0.7.3 with updated packages. (@YamatoSecurity)

## v1.3.1 [2022/06/13]

**New Features:**

- You can now specify specific fields when there are multiple fields with the same name (Ex: `Data`). In the `details` line in a rule, specify a placeholder like `%Data[1]%` to display the first `Data` field. (#487) (@hitenkoku)
- Added loaded rules status summary. (#583) (@hitenkoku)

**Enhancements:**

- Debug symbols are stripped by default for smaller Linux and macOS binaries. (#568) (@YamatoSecurity)
- Updated crate packages (@YamatoSecurity)
- Added new output time format options. (`--US-time`, `--US-military-time`, `--European-time`) (#574) (@hitenkoku)
- Changed the output time format when `--rfc-3339` option is enabled. (#574) (@hitenkoku)
- Changed the `-R / --display-record-id` option to `-R / --hide-record-id` and now by default the event record ID is displayed. You can hide the record ID with `-R / --hide-record-id`. (#579) (@hitenkoku)
- Added rule loading message. (#583) (@hitenkoku)

**Bug Fixes:**

- The RecordID and RecordInformation column headers would be shown even if those options were not enabled. (#577) (@hitenkoku)

## v1.3.0 [2022/06/06]

**New Features:**

- Added `-V / --visualize-timeline` option: Event Frequency Timeline feature to visualize the number of events. (Note: There needs to be more than 5 events and you need to use a terminal like Windows Terminal, iTerm2, etc... for it to properly render.) (#533, #566) (@hitenkoku)
- Display all the `tags` defined in a rule to the `MitreAttack` column when saving to CSV file with the `--all-tags` option. (#525) (@hitenkoku)
- Added the `-R / --display-record-id` option: Display the event record ID (`<Event><System><EventRecordID>`). (#548) (@hitenkoku)
- Display dates with most detections. (#550) (@hitenkoku)
- Display the top 5 computers with the most unique detections. (#557) (@hitenkoku)

**Enhancements:**

- In the `details` line in a rule, when a placeholder points to a field that does not exist or there is an incorrect alias mapping, it will be outputted as `n/a` (not available). (#528) (@hitenkoku)
- Display total event and data reduction count. (How many and what percent of events were ignored.) (#538) (@hitenkoku)
- New logo. (#536) (@YamatoSecurity)
- Display total evtx file size. (#540) (@hitenkoku)
- Changed logo color. (#537) (@hitenkoku)
- Display the original `Channel` name when not specified in `channel_abbrevations.txt`. (#553) (@hitenkoku)
- Display separately `Ignored rules` to `Exclude rules`, `Noisy rules`, and `Deprecated rules`. (#556) (@hitenkoku)
- Display results messge when `output` option is set. (#561) (@hitenkoku)

**Bug Fixes:**

- Fixed the `--start-timeline` and `--end-timeline` options as they were not working. (#546) (@hitenkoku)
- Fixed crash bug when level in rule is not valid. (#560) (@hitenkoku)

## v1.2.2 [2022/05/20]

**New Features:**

- Added a logon summary feature. (`-L` / `--logon-summary`) (@garigariganzy)

**Enhancements:**

- Colored output is now on by default and supports Command and Powershell prompts. (@hitenkoku)

**Bug Fixes:**

- Fixed a bug in the update feature when the rules repository does not exist but the rules folder exists. (#516) (@hitenkoku)
- Fixed a rule parsing error bug when there were .yml files in a .git folder. (#524) (@hitenkoku)
- Fixed wrong version number in the 1.2.1 binary.

## v1.2.1 [2022/04/20] Black Hat Asia Arsenal 2022 RC2

**New Features:**

- Added a `Channel` column to the output based on the `./config/channel_abbreviations.txt` config file. (@hitenkoku)
- Rule and rule config files are now forcefully updated. (@hitenkoku)

**Bug Fixes:**

- Rules marked as noisy or excluded would not have their `level` changed with `--level-tuning` but now all rules will be checked. (@hitenkoku)

## v1.2.0 [2022/04/15] Black Hat Asia Arsenal 2022 RC1

**New Features:**

- Specify config directory (`-C / --config`): When specifying a different rules directory, the rules config directory will still be the default `rules/config`, so this option is useful when you want to test rules and their config files in a different directory. (@hitenkoku)
- `|equalsfield` aggregator: In order to write rules that compare if two fields are equal or not. (@hach1yon)
- Pivot keyword list generator feature (`-p / --pivot-keywords-list`): Will generate a list of keywords to grep for to quickly identify compromised machines, suspicious usernames, files, etc... (@kazuminn)
- `-F / --full-data` option: Will output all field information in addition to the fields defined in the rule’s `details`. (@hach1yon)
- `--level-tuning` option: You can tune the risk `level` in hayabusa and sigma rules to your environment. (@itib and @hitenkoku)

**Enhancements:**

- Updated detection rules and documentation. (@YamatoSecurity)
- Mac and Linux binaries now statically compile the OpenSSL libraries. (@YamatoSecurity)
- Performance and accuracy improvement for fields with tabs, etc... in them. (@hach1yon and @hitenkoku)
- Fields that are not defined in eventkey_alias.txt will automatically be searched in Event.EventData. (@kazuminn and @hitenkoku)
- When updating rules, the names of new rules as well as the count will be displayed. (@hitenkoku)
- Removed all Clippy warnings from the source code. (@hitenkoku and @hach1yon)
- Updated the event ID and title config file (`timeline_event_info.txt`) and changed the name to `statistics_event_info.txt`. (@YamatoSecurity and @garigariganzy)
- 32-bit Hayabusa Windows binaries are now prevented from running on 64-bit Windows as it would cause unexpected results. (@hitenkoku)
- MITRE ATT&CK tag output can be customized in `output_tag.txt`. (@hitenkoku)
- Added Channel column output. (@hitenkoku)

**Bug Fixes:**

- `.yml` files in the `.git` folder would cause parse errors so they are now ignored. (@hitenkoku)
- Removed unnecessary newline due to loading test file rules. (@hitenkoku)
- Fixed output stopping in Windows Terminal due a bug in Terminal itself. (@hitenkoku)

## v1.1.0 [2022/03/03]

**New Features:**

- Can specify a single rule with the `-r / --rules` option. (Great for testing rules!) (@kazuminn)
- Rule update option (`-u / --update-rules`): Update to the latest rules in the [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository. (@hitenkoku)
- Live analysis option (`-l / --live-analysis`): Can easily perform live analysis on Windows machines without specifying the Windows event log directory. (@hitenkoku)

**Enhancements:**

- Updated documentation. (@kazuminn , @hitenkoku , @YamatoSecurity)
- Updated rules. (20+ Hayabusa rules, 200+ Sigma rules) (@YamatoSecurity)
- Windows binaries are now statically compiled so installing Visual C++ Redistributable is not required. (@hitenkoku)
- Color output (`-c / --color`) for terminals that support True Color (Windows Terminal, iTerm2, etc...). (@hitenkoku)
- MITRE ATT&CK tactics are included in the saved CSV output. (@hitenkoku)
- Performance improvement. (@hitenkoku)
- Comments added to exclusion and noisy config files. (@kazuminn)
- Using faster memory allocators (rpmalloc for Windows, jemalloc for macOS and Linux.) (@kazuminn)
- Updated cargo crates. (@YamatoSecurity)

**Bug Fixes:**

- Made the clap library version static to make `cargo update` more stable. (@hitenkoku)
- Some rules were not alerting if there were tabs or carriage returns in the fields. (@hitenkoku)

## v1.0.0-Release 2 [2022/01/27]

- Removed Excel result sample files as they were being flagged by anti-virus. (@YamatoSecurity)
- Updated the Rust evtx library to 0.7.2 (@YamatoSecurity)

## v1.0.0 [2021/12/25]

- Initial release.
