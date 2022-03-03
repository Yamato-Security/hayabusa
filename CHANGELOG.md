# Changes

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