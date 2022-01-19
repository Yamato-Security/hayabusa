<div align="center">
 <p>

  ![Hayabusa Logo](hayabusa-logo.png)
 
 </p>
</div>

# About Hayabusa
Hayabusa is a **Windows event log fast forensics timeline generator** and **threat hunting tool** created by the [Yamato Security](https://yamatosecurity.connpass.com/) group in Japan. Hayabusa means ["peregrine falcon"](https://en.wikipedia.org/wiki/Peregrine_falcon") in Japanese and was chosen as peregrine falcons are the fastest animal in the world, great at hunting and highly trainable. It is written in [Rust](https://www.rust-lang.org/) and supports multi-threading in order to be as fast as possible. We have provided a [tool](https://github.com/Yamato-Security/hayabusa/tree/main/tools/sigmac) to convert [sigma](https://github.com/SigmaHQ/sigma) rules into hayabusa rule format. The hayabusa detection rules, like sigma, are also written in YML in order to be as easily customizable and extensible as possible. It can be run either on running systems for live analysis or by gathering logs from multiple systems for offline analysis. (At the moment, it does not support real-time alerting or periodic scans.) The output will be consolidated into a single CSV timeline for easy analysis in Excel or [Timeline Explorer](https://ericzimmerman.github.io/#!index.md).

## Main goals

### Threat hunting
Hayabusa currently has over 1000 sigma rules and around 50 hayabusa rules with more rules being added regularly. The ultimate goal is to be able to push out hayabusa agents to all Windows endpoints after an incident or for periodic threat hunting and have them alert back to a central server.

### Fast forensics timeline generation
Windows event log analysis has traditionally been a very long and tedious process because Windows event logs are 1) in a data format that is hard to analyze and 2) the majority of data is noise and not useful for investigations. Hayabusa's main goal is to extract out only useful data and present it in an easy-to-read format that is usable not only by professionally trained analysts but any Windows system administrator.
Hayabusa is not intended to be a replacement for tools like [Evtx Explorer](https://ericzimmerman.github.io/#!index.md) or [Event Log Explorer](https://eventlogxp.com/) for more deep-dive analysis but is intended for letting analysts get 80% of their work done in 20% of the time. 

# About the development
 First inspired by the [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) Windows event log analyzer, we started in 2020 porting it over to Rust for the [RustyBlue](https://github.com/Yamato-Security/RustyBlue) project, then created sigma-like flexible detection signatures written in YML, and then added a backend to sigma to support converting sigma rules into our hayabusa rule format. 

# Screenshots
## Startup:

![Hayabusa Startup](/screenshots/Hayabusa-Startup.png)


## Terminal output:

![Hayabusa terminal output](/screenshots/Hayabusa-Results.png)


## Results summary:

![Hayabusa results summary](/screenshots/HayabusaResultsSummary.png)

## Analysis in Excel:

![Hayabusa analysis in Excel](/screenshots/ExcelScreenshot.png)

## Analysis in Timeline Explorer:

![Hayabusa analysis in Timeline Explorer](screenshots/TimelineExplorer-ColoredTimeline.png)

## Critical alert filtering and computer grouping in Timeline Explorer:

![Critical alert filtering and computer grouping in Timeline Explorer](screenshots/TimelineExplorer-CriticalAlerts-ComputerGrouping.png)

# Sample timeline results
You can check out sample CSV and manually edited XLSX timeline results [here](https://github.com/Yamato-Security/hayabusa/tree/main/sample-results).

You can learn how to analyze CSV timelines in Excel and Timeline Explorer [here](doc/CSV-AnalysisWithExcelAndTimelineExplorer-English.pdf).

# Features
* Cross-platform support: Windows, Linux, macOS
* Developed in Rust to be memory safe and faster than a hayabusa falcon!
* Multi-thread support delivering up to a 5x speed improvement!
* Creates a single easy-to-analyze CSV timeline for forensic investigations and incident response
* Threat hunting based on IoC signatures written in easy to read/create/edit YML based hayabusa rules
* Sigma rule support to convert sigma rules to hayabusa rules
* Currently it supports the most sigma rules compared to other similar tools and even supports count rules
* Event log statistics (Useful for getting a picture of what types of events there are and for tuning your log settings)
* Rule tuning configuration by excluding bad rules or noisy rules

# Planned Features
* Enterprise-wide hunting on all endpoints
* Japanese language support
* MITRE ATT&CK mapping
* MITRE ATT&CK heatmap generation
* User logon and failed logon summary
* Input from JSON logs
* JSON support for sending alerts to Elastic Stack/Splunk, etc...

# Downloads
You can download the latest Hayabusa version from the [Releases](https://github.com/Yamato-Security/hayabusa/releases) page.

You can also `git clone` the repository with the following command and compile binary from source code.:

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

If you forget to use `--recursive` option, `rules/` files which managed in submodule did not cloned.
Use following command to import submodules.

```bash
git submodule update --init
```

There are two different versions of the evtx library being used when compiled: `0.6.7` and `0.7.2`.
The `0.7.2` version should work but we have only tested it with `0.6.7` so please use that version if you experience any problems with `0.7.2`.

# Compiling from source (Optional)
If you have rust installed, you can compile from source with the following command:

```bash
cargo clean
cargo build --release
```

## Advanced: Updating Rust packages
You can update to the latest rust crates before compiling to get the latest libraries:

```bash
cargo update
```

Please let us know if anything breaks after you update.

## Testing hayabusa out on sample evtx files
We have provided some sample evtx files for you to test hayabusa and/or create new rules at [https://github.com/Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)

You can download the sample evtx files to a new `hayabusa-sample-evtx` sub-directory with the following command:
```bash
git clone https://github.com/Yamato-Security/hayabusa-sample-evtx.git
```

> Note: You need to run the binary from the Hayabusa root directory. 

# Usage
> Note: You need to run the Hayabusa binary from the Hayabusa root directory. Example: `.\hayabusa.exe`

## Command line options
```bash
USAGE:
    -d --directory=[DIRECTORY] 'Directory of multiple .evtx files'
    -f --filepath=[FILEPATH] 'File path to one .evtx file'
    -r --rules=[RULEDIRECTORY] 'Rule file directory (default: ./rules)'
    -o --output=[CSV_TIMELINE] 'Save the timeline in CSV format. Example: results.csv'
    -v --verbose 'Output verbose information'
    -D --enable-deprecated-rules 'Enable sigma rules marked as deprecated'
    -n --enable-noisy-rules 'Enable rules marked as noisy'
    -m --min-level=[LEVEL] 'Minimum level for rules (default: informational)'
    --start-timeline=[STARTTIMELINE] 'Start time of the event to load from event file. Example: '2018/11/28 12:00:00 +09:00''
    --end-timeline=[ENDTIMELINE] 'End time of the event to load from event file. Example: '2018/11/28 12:00:00 +09:00''
    --rfc-2822 'Output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600'
    --rfc-3339 'Output date and time in RFC 3339 format. Example: 2006-08-07T12:34:56.485214 -06:00'
    -u --utc 'Output time in UTC format (default: local time)'
    -t --thread-number=[NUMBER] 'Thread number (default: optimal number for performance)'
    -s --statistics 'Prints statistics of event IDs'
    -q --quiet 'Quiet mode. Do not display the launch banner'
    -Q --quiet-errors 'Quiet errors mode. Do not save error logs.'
    --contributors 'Prints the list of contributors'
```

## Usage examples
* Run hayabusa against one Windows event log file:
```bash
.\hayabusa.exe -f eventlog.evtx
```

* Run hayabusa against the sample-evtx directory with multiple Windows event log files:
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx
```

* Export to a single CSV file for further analysis with excel or timeline explorer:
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -o results.csv
```

* Only run hayabusa rules (the default is to run all the rules in `-r .\rules`):
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv
```

* Only run hayabusa rules for logs that are enabled by default on Windows:
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa\default -o results.csv
```

* Only run hayabusa rules for sysmon logs:
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv
```

* Only run sigma rules:
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv
```

* Enable deprecated rules (those with `status` marked as `deprecated`) and noisy rules (those whose rule ID is listed in `.\config\noisy-rules.txt`):
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv
```

* Only run rules to analyze logons and output in the UTC timezone:
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -r .\rules\hayabusa\default\events\Security\Logons -u -o results.csv
```

* Run on a live Windows machine (requires Administrator privileges) and only detect alerts (potentially malicious behavior):
```bash
.\hayabusa.exe -d C:\Windows\System32\winevt\Logs -m low
```

* Get event ID statistics:
```bash
.\hayabusa.exe -f Security.evtx -s
```

* Print verbose information (useful for determining which files take long to process, parsing errors, etc...):
```bash
.\hayabusa.exe -d .\hayabusa-sample-evtx -v
```

* Verbose output example:
```bash
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1027.004_Obfuscated Files or Information\u{a0}Compile After Delivery/sysmon.evtx"
1 / 509 [>-------------------------------------------------------------------------------------------------------------------------------------------] 0.20 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1558.004_Steal or Forge Kerberos Tickets AS-REP Roasting/Security.evtx"
2 / 509 [>-------------------------------------------------------------------------------------------------------------------------------------------] 0.39 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1558.003_Steal or Forge Kerberos Tickets\u{a0}Kerberoasting/Security.evtx"
3 / 509 [>-------------------------------------------------------------------------------------------------------------------------------------------] 0.59 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1197_BITS Jobs/Windows-BitsClient.evtx"
4 / 509 [=>------------------------------------------------------------------------------------------------------------------------------------------] 0.79 % 1s 
Checking target evtx FilePath: "./hayabusa-sample-evtx/YamatoSecurity/T1218.004_Signed Binary Proxy Execution\u{a0}InstallUtil/sysmon.evtx"
5 / 509 [=>------------------------------------------------------------------------------------------------------------------------------------------] 0.98 % 1s
```

* Quiet error mode:
By default, hayabusa will save error messages to error log files.
If you do not want to save error messages, please add `-Q`.

# Hayabusa output
When Hayabusa output is being displayed to the screen (the default), it will display the following information:

* `Timestamp`: Default is `YYYY-MM-DD HH:mm:ss.sss +hh:mm` format. This comes from the `<Event><System><TimeCreated SystemTime>` field in the event log. The default timezone will be the local timezone but you can change the timezone to UTC with the `--utc` option.
* `Computer`: This comes from the `<Event><System><Computer>` field in the event log.
* `Event ID`: This comes from the `<Event><System><EventID>` field in the event log.
* `Level`: This comes from the `level` field in the YML detection rule. (`informational`, `low`, `medium`, `high`, `critical`) By default, all level alerts will be displayed but you can set the minimum level with `-m`. For example, you can set `-m high`) in order to only scan for and display high and critical alerts.
* `Title`: This comes from the `title` field in the YML detection rule.
* `Details`: This comes from the `details` field in the YML detection rule, however, only Hayabusa rules have this field. This field gives extra information about the alert or event and can extract useful data from the `<Event><System><EventData>` portion of the log. For example, usernames, command line information, process information, etc...

When saving to a CSV file an additional two fields will be added:
* `Rule Path`: The path to the detection rule that generated the alert or event.
* `File Path`: The path to the evtx file that caused the alert or event.

## Progress bar
The progress bar will only work with multiple evtx files.
It will display in real time the number and percent of evtx files that it has analyzed.

# Hayabusa rules
Hayabusa detection rules are written in a sigma-like YML format and are located in the `rules` folder. In the future, we plan to host the rules at [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) so please send any issues and pull requests for rules there instead of the main hayabusa repository.

Please read [AboutRuleCreation-English.md](./doc/AboutRuleCreation-English.md) to understand about the rule format how to create rules.

All of the rules from the hayabusa-rules repository should be placed in the `rules` folder.
`informational` level rules are considered `events`, while anything with a `level` of `low` and higher are considered `alerts`.

The hayabusa rule directory structure is separated into 3 directories:
 * `default`: logs that are turned on in Windows by default.
 * `non-default`: logs that need to be turned on through group policy, security baselines, etc...
 * `sysmon`: logs that are generated by [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
 * `testing`: a temporary directory to put rules that you are currently testing

Rules are further seperated into directories by log type (Example: Security, System, etc...) and are named in the following format: 
 * Alert format: `<EventID>_<MITRE ATT&CK Name>_<Description>.yml`
 * Alert example: `1102_IndicatorRemovalOnHost-ClearWindowsEventLogs_SecurityLogCleared.yml`
 * Event format: `<EventID>_<Description>.yml`
 * Event example: `4776_NTLM-LogonToLocalAccount.yml`

Please check out the current rules to use as a template in creating new ones or for checking the detection logic.

## Hayabusa v.s. converted Sigma rules
Sigma rules need to first be converted to hayabusa rule format explained [here](https://github.com/Yamato-Security/hayabusa/blob/main/tools/sigmac/README-English.md). Hayabusa rules are designed solely for Windows event log analysis and have the following benefits:
1. An extra `details` field to display additional information taken from only the useful fields in the log.
2. They are all tested against sample logs and are known to work. 
   > Some sigma rules may not work as intended due to bugs in the conversion process, unsupported features, or differences in implementation (such as in regular expressions).
   
**Limitations**: To our knowledge, hayabusa provides the greatest support for sigma rules out of any open source Windows event log analysis tool, however, there are still rules that are not supported:
1. Rules that use regular expressions that do not work with the [Rust regex crate](https://docs.rs/regex/1.5.4/regex/)
2. Aggregation expressions besides `count` in the [sigma rule specification](https://github.com/SigmaHQ/sigma/wiki/Specification).

> Note: the limitation is in the sigma rule converter and not in hayabusa itself.

## Detection rule tuning
Like firewalls and IDSes, any signature-based tool will require some tuning to fit your environment so you may need to permanently or temporarily exclude certain rules.

You can add a rule ID (Example: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) to `config/exclude-rules.txt` in order to ignore any rule that you do not need or cannot be used.

You can also add a rule ID to `config/noisy-rules.txt` in order to ignore the rule by default but still be able to use the rule with the `-n` or `--enable-noisy-rules` option.

## Event ID filtering
You can filter on event IDs by placing event ID numbers in `config/target_eventids.txt`.
This will increase performance so it is recommended if you only need to search for certain IDs.

We have provided a sample ID filter list at [`config/target_eventids_sample.txt`](https://github.com/Yamato-Security/hayabusa/blob/main/config/target_eventids_sample.txt) created from the `EventID` fields in all of the rules as well as IDs seen in actual results.

Please use this list if you want the best performance but be aware that there is a slight possibility for false positives. 

# Other Windows event log analyzers and related projects
There is no "one tool to rule them all" and we have found that each has its own merits so we recommend checking out these other great tools and projects and seeing which ones you like.

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Attack detection tool written in Python.
- [Chainsaw](https://github.com/countercept/chainsaw) - A similar sigma-based attack detection tool written in Rust.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Attack detection tool written in Powershell  by [Eric Conrad](https://twitter.com/eric_conrad).
- [EVTXtract](https://github.com/williballenthin/EVTXtract) - Recover EVTX log files from unallocated space and memory images.
- [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Python tool to send Evtx data to Elastic Stack.
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - EVTX attack sample event log files by [SBousseaden](https://twitter.com/SBousseaden).
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Another great repository of EVTX attack sample logs mapped to ATT&CK.
- [EVTX parser](https://github.com/omerbenamram/evtx) - the Rust library we used written by [@OBenamram](https://twitter.com/obenamram).
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - A graphical interface to visualize logons to detect lateral movement by [JPCERTCC](https://twitter.com/jpcert_en).
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Rust port of DeepBlueCLI by Yamato Security.
- [Sigma](https://github.com/SigmaHQ/sigma) - Community based generic SIEM rules.
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Import evtx files into Security Onion.
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - The best CSV timeline analyzer by [Eric Zimmerman](https://twitter.com/ericrzimmerman).
- [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - by Forward Defense's Steve Anson.
- [Zircolite](https://github.com/wagga40/Zircolite) - Sigma-based attack detection tool written in Python.

## Comparison to other similar tools that support sigma
Please understand that it is not possible to do a perfect comparison as results will differ based on the target sample data, command-line options, rule tuning, etc...
In our tests, we have found hayabusa to support the largest number of sigma rules out of all the tools while still maintaining very fast speeds and does not require a great amount of memory. 

The following benchmarks were taken on a Lenovo P51 based on approximately 500 evtx files (130MB) from our [sample-evtx repository](https://github.com/Yamato-Security/hayabusa-sample-evtx) at 2021/12/23 with Hayabusa version 1.0.0.

| | Elapsed Time | Memory Usage | Unique Sigma Rules With Detections |
| :---: | :---: | :---: | :---: |
| Chainsaw | 7.5 seconds | 75 MB | 170 |
| Hayabusa | 7.8 seconds | 340 MB | 267 |
| Zircolite | 34 seconds | 380 MB (normally requires 3 times the size of the log files) | 237 |

* With hayabusa rules enabled, it will detect around 300 unique alerts and events. 
* When tested on many event logs files totaling 7.5 GB, it finished in under 7 minutes and used around 1 GB of memory. The amount of memory consumed is based on the size of the results, not on the size of the target evtx files.
* It is the only tool that provides a consolidated single CSV timeline to analysis in tools like [Timeline Explorer](https://ericzimmerman.github.io/#!index.md).


# License

Hayabusa is released under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) and all rules are released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md).

# Contribution

We would love any form of contribution. Pull requests, rule creation and sample evtx logs are the best but feature requests, notifying us of bugs, etc... are also very welcome.

At the least, if you like our tool then please give us a star on Github and show your support!
