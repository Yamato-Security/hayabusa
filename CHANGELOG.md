# Changes

## 2.1.0 [2022/01/10]

**Enhancements:**

- Speed improvements. (#847) (@hitenkoku)
- Improved speed by up to 20% by improving I/O processesing. (#858) (@fukusuket)
- The timeline order of detections are now sorted to a fixed order even when the timestamp is identical. (#827) (@hitenkoku)

**Bug Fixes:**

- Successful login CSV results were not correctly being outputted when using the logon timeline function. (#849) (@hitenkoku)
- Removed unnecessary line breaks that would occur when using the `-J, --jsonl` option. (#852) (@hitenkoku)

## 2.0.0 [2022/12/24]

**New Features:**

- Command usage and help menu are now done by subcommands. (#656) (@hitenkoku)

## 1.9.0 [2022/12/24]

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
