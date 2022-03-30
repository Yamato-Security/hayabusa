# Changes

##v1.2.0 [2022/04/??]
**New Features:**
- Specify config directory (`-C / --config`): Can easily perform live analysis on Windows machines without specifying the Windows event log directory. (@hitenkoku) 
- Added the `|equalsfield` aggregator in order to write rules that compare if two fields are equal or not. (@hach1yon)
- Pivot keyword list generator feature (`-p / --pivot-keywords-list): Will generate a list of keywords to grep for to quickly identify compromised machines, suspicious usernames, files, etc... (@kazuminn)

**Enhancements:**
- Updated detection rules and documentation. (@YamatoSecurity)
- Mac and Linux binaries now statically compile the openssl libraries. (@YamatoSecurity)
- Performance and accuracy improvement for fields with tabs, etc... in them. (@hach1yon)
- Fields that are not defined in eventkey_alias.txt will automatically be searched in Event.EventData. (@kazuminn and @hitenkoku)
- When updating rules, the names of new rules as well as the count will be displayed. (@hitenkoku)
- Removed all clippy warnings from the source code. (@hitenkoku and @hac1yon)
- Updated the event ID and title config file (`timeline_event_info.txt`) and changed name to `statistics_event_info.txt`. (@YamatoSecurity and @garigariganzy)

**Bug Fixes:**
- `.yml` files in the `.git` folder would cause parse errors so they are not ignored. (@hitenkoku)

##v1.1.0 [2022/03/03]
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
