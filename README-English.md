<div align="center">
 <p>

  ![Hayabusa Logo](hayabusa-logo.png)
 
 </p>
</div>

# About Hayabusa
Hayabusa ("falcon" in Japanese) is a **Windows event log fast forensics timeline generator** and **threat hunting tool** created by the [Yamato Security](https://yamatosecurity.connpass.com/) group in Japan. It is written in [Rust](https://www.rust-lang.org/) and supports multi-threading in order to be as fast as possible. It supports converted [sigma](https://github.com/SigmaHQ/sigma) and hayabusa detection rules written in YAML in order to be as easily customizable and extensible as possible. It can be run either on a live system or by gathering logs from multiple systems. The output will be consolidated into a single CSV timeline for easy analysis in Excel or [timeline explorer](https://ericzimmerman.github.io/#!index.md).

## Fast forensics timeline generation
Windows event log analysis has traditionally been a very long and tedious process because Windows event logs are 1) in a data format that is hard to analyze and 2) the majority of data is noise and not useful for investigations. Hayabusa's main goal is to extract out only useful data and present it in an easy-to-read format that is usable not only by professionally trained analysts but any Windows system administrator.
Hayabusa is not intended to be a replacement for tools like [Evtx Explorer](https://ericzimmerman.github.io/#!index.md) or [Event Log Explorer](https://eventlogxp.com/) for slower deep-dive analysis but is intended for letting analysts get 80% of their work done in 20% of the time. 

## Threat hunting
Hayabusa currently has over 1000 detection rules and the ultimate goal is to be able to push out hayabusa agents to all Windows endpoints after an incident or for periodic threat hunting and have them alert back to a central server.

# About the development
 First inspired by the [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) Windows event log analyzer, we started in 2020 porting it over to Rust for the [RustyBlue](https://github.com/Yamato-Security/RustyBlue) project, then created sigma-like flexible detection signatures written in YAML, and then added a backend to sigma to support converting sigma rules into our hayabusa rule format. 

# Screenshots
Startup:

![Hayabusa Startup](/screenshots/hayabusa-start.png)


Terminal output:

![Hayabusa terminal output](/screenshots/hayabusa-results.png)


Results summary:

![Hayabusa results summary](/screenshots/hayabusa-results-summary.png)


# Features
* Cross-platform support: Windows, Linux, macOS
* Developed in Rust to be memory safe and faster than a hayabusa falcon!
* Multi-thread support
* Creates a single easy-to-analyze CSV timeline for forensic investigations and incident response
* Threat hunting based on IoC signatures written in easy to read/create/edit YAML based hayabusa rules
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
* Output to JSON -> import to Elastic Stack/Splunk

# Downloads
You can download pre-compiled binaries for the Windows, Linux and macOS at [Releases.](https://github.com/Yamato-Security/hayabusa/releases)

# Compiling from source
If you have rust installed, you can compile from source with the following command.

````
cargo build --release
````

## When the rule file does not exist

If you forgot to use `--recursive` option when you clone this repository,
rule files were not take in to `haybusa/rules` directory.
Use the following command to take it in.

```bash
git submodule update -i
```

# Usage
## Command line options
````
USAGE:
    -f --filepath=[FILEPATH] 'File path to one .evtx file'
    --csv-timeline=[CSV_TIMELINE] 'Save the timeline in CSV format'
    --rfc-2822 'Output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600'
    --rfc-3339 'Output date and time in RFC 3339 format. Example: 2006-08-07T12:34:56.485214 -06:00'
    --verbose 'Output verbose information to target event file path and rule file'
    -q 'Quiet mode. Do not display the launch banner'
    -r --rules=[RULEDIRECTORY] 'Rule file directory (default: ./rules)'
    -m --min-level=[LEVEL] 'Minimum level for rules (default: informational)' (Possiblities are: informational, low, medium, high, critical)
    -u --utc 'Output time in UTC format (default: local time)'
    -d --directory=[DIRECTORY] 'Directory of multiple .evtx files'
    -s --statistics 'Prints statistics of event IDs'
    -n --show-noisyalerts 'do not exclude noisy rules'
    -t --threadnum=[NUM] 'Thread number (default: optimal number for performance)' (Usually there is no performance benefit in increasing the number of threads but you may want to lower to a smaller number to reduce CPU load.)
    --contributors 'Prints the list of contributors'
````

## Usage examples
* Run hayabusa against one Windows event log file:
````
hayabusa.exe -f eventlog.evtx
````

* Run hayabusa against the sample-evtx directory with multiple Windows event log files:
````
hayabusa.exe -d .\sample-evtx
````

* Export to a single CSV file for further analysis with excel or timeline explorer:
````
hayabusa.exe -d .\sample-evtx --csv-timeline results.csv
````

* Only run hayabusa rules:
````
hayabusa.exe -d .\sample-evtx --csv-timeline results.csv -r ./rules/hayabusa
````

* Only run sigma rules and show noisy alerts (disabled by default):
````
hayabusa.exe -d .\sample-evtx --csv-timeline results.csv -r ./rules/sigma --show-noisyalerts
````

* Only run rules to analyze logons and output in the UTC timezone:
````
hayabusa.exe -d .\sample-evtx --csv-timeline results.csv -r ./rules/hayabusa/default/events/Security/Logons -u
````

* Run on a live Windows machine (requires Administrator privileges) and only detect alerts (potentially malicious behavior):
````
hayabusa.exe -d C:\Windows\System32\winevt\Logs -m low
````

* Get event ID statistics:
````
hayabusa.exe -d C:\Windows\System32\winevt\Logs -s
````

## Testing hayabusa out on sample evtx files
We have provided some sample evtx files for you to test hayabusa and/or create new rules at [https://github.com/Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)

# Hayabusa rules
Hayabusa detection rules are written in a sigma-like YAML format and are located at [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

Please read [AboutRuleCreation-English.md](./doc/AboutRuleCreation-English.md) to understand about the rule format how to create rules.

All of the rules are in the `rules` folder.
`informational` level rules are considered `events`, while anything rated `low` and higher are considered `alerts`.

The hayabusa rule directory structure is separated into 3 directories:
 * `default`: logs that are turned on by default
 * `non-default`: logs that need to be turned on through group policy
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
1. An extra `output` field to display additional information taken from only the useful fields in the log.
2. They are all tested against sample logs and are known to work. 
   > Some sigma rules may not work as intended due to bugs in the conversion process, unsupported features, or differences in implementation (such as in regular expressions).
3. Japanese output in the `title_jp` and `output_jp` field.
   
**Limitations**: To our knowledge, hayabusa provides the greatest support for sigma rules out of any open source Windows event log analysis tool, however, there are still rules that are not supported:
1. Rules that use regular expressions that do not work with the [Rust regex crate](https://docs.rs/regex/1.5.4/regex/)
2. Rules that use `1 of them` or `all of them`
3. Rules that use the following modifiers: `base64`, `base64offset`, `utf16le`, `utf16be`, `wide`, `utf16`.

## Detection rule tuning
Like firewalls and IDSes, any signature-based tool will require some tuning to fit your environment so you may need to permanently or temporarily exclude certain rules.

You can add a rule ID (Example: 4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6) to `config/exclude-rules.txt` in order to ignore any rule you do not need.

You can also add a rule ID to `config/noisy-rules.txt` in order to ignore the rule by default but still be able to use the rule with the `-n` or `--show-noisyalerts` option.

# Other Windows event log analyzers and related projects
There is no "one tool to rule them all" and we have found that each has its own merits so we recommend checking out these other great tools and projects and seeing which ones you like.

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Attack detection tool written in Python.
- [Chainsaw](https://github.com/countercept/chainsaw) - A similar SIGMA based attack detection tool written in Rust.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Attack detection tool written in Powershell.
- [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Python tool to send Evtx data to Elastic Stack.
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - EVTX attack sample event log files by [SBousseaden](https://twitter.com/SBousseaden).
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Another great repository of EVTX attack sample logs mapped to ATT&CK.
- [EVTX parser](https://github.com/omerbenamram/evtx) - the Rust library we used written by [@OBenamram](https://twitter.com/obenamram).
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - A graphical interface to visualize logons to detect lateral movement by [JPCERTCC](https://twitter.com/jpcert_en).
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Rust port of DeepBlueCLI by [Eric Conrad](https://twitter.com/eric_conrad).
- [Sigma](https://github.com/SigmaHQ/sigma) - Community based generic SIEM rules.
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Import evtx files into Security Onion.
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - The best CSV timeline analyzer by [Eric Zimmerman](https://twitter.com/ericrzimmerman).
- [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - by Forward Defense's Steve Anson.
- [Zircolite](https://github.com/wagga40/Zircolite) - SIGMA based attack detection tool written in Python.

## Comparison to other similar tools that support sigma
It is not possible to do a perfect comparison as these tools support a different number of sigma rules.
Hayabusa supports the largest number of sigma rules as well as will run additional hayabusa rules so will may take more time than other tools that do not do as much analysis.
Also, time and memory usage will differ dramatically depending on what sample event log files are used, command-line options, rule tuning, etc... so please understand that results will vary.

The following were taken based on approximately 500 logs (130MB) from our sample-evtx repository at 2021/12/09.

| | Elapsed Time | Memory Usage | Total Sigma Events Detected | Unique Sigma Events Detected |
| :---: | :---: | :---: | :---: | :---: |
| Chainsaw | 10 seconds | 75 MB | 552 | 170 |
| Hayabusa | xx | xx | 9783 | 265 |
| Zircolite | 55 seconds | 400 MB | 1954 | 237 |

# License

Hayabusa is released under GPLv3 and all rules are released under the Detection Rule License (DRL) 1.1

# Contribution

We would love any form of contribution. Pull requests, rule creation and sample evtx logs are the best but feature requests, notifying us of bugs, etc... are also very welcome.

At the least, if you like our tool then please give us a star on Github and show your support!
