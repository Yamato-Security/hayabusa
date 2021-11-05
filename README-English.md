<div align="center">
 <p>

  ![Hayabusa Logo](hayabusa-logo.png)
 
 </p>
</div>

# Hayabusa
Hayabusa is a very fast Windows event analyzer used for creating forensic timelines and performing threat hunting based on IoCs written in either hayabusa or SIGMA rules. It can be run live, offline, pushed out as agents to be run on endpoints in an enterprise after an incident or even periodically reporting back alerts on slack.

# About Hayabusa
Hayabusa ("falcon" in Japanese) was written by the Yamato Security group in Japan. First inspired by the DeepblueCLI Windows event log analyzer, we started in 2020 porting it over to Rust for the RustyBlue project, then created SIGMA-like flexible signatures based in YAML, and then added a backend to SIGMA to support converting SIGMA rules into hayabusa rules. Supporting multi-threading, (to our knowledge) it is currently the fastest forensics timeline generator and threat hunting tool as well supports the most features in SIGMA. It can analyze multiple Windows event logs and consolidate the results into one timeline for easy analysis. It will output in CSV to be imported into tools like Timeline Explorer and Excel for analysis.

# Screenshots
Add screenshots here.

# Features
* Cross-platform support: Windows, Linux, macOS (Intel + ARM)
* Faster than a hayabusa falcon!
* English and Japanese support
* Multi-thread support
* Enterprise-wide threat hunting via alerts to Slack
* Creating event timelines for forensic investigations and incident response
* Threat hunting based on IoC signatures written in easy to read/create/edit YAML based hayabusa rules
* SIGMA support to convert SIGMA rules to hayabusa rules
* Event log statistics (Useful for getting a picture of what types of events there are and for tuning your log settings)

# Downloads
You can download pre-compiled binaries for the Windows, Linux and macOS at [Releases.](https://github.com/Yamato-Security/hayabusa/releases)

# Usage
## Command line options
````
USAGE:
    hayabusa.exe [FLAGS] [OPTIONS]

FLAGS:
        --credits       Prints a list of contributors
    -h, --help          Prints help information
        --rfc-2822      Output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600
        --slack         Sends alerts to Slack
    -s, --statistics    Prints statistics for event logs
    -u, --utc           Output time in UTC format (default: local time)
    -V, --version       Prints version information

OPTIONS:
        --csv-timeline <CSV_TIMELINE>                          Save timeline to CSV file
    -d, --directory <DIRECTORY>                                Event log files directory
    -f, --filepath <FILEPATH>                                  Event file path
        --human-readable-timeline <HUMAN_READABLE_TIMELINE>    Human readable timeline
    -l, --lang <LANG>                                          Output language
    -t, --threadnum <NUM>                                      Number of threads (Default is the number of CPU cores)
````

## Usage examples
* Run hayabusa against one Windows event log file:
````
hayabusa.exe --filepath=eventlog.evtx
````

* Run hayabusa against a directory with multiple Windows event log files:
````
hayabusa.exe --directory=.\evtx
````

* Export to a CSV file:
````
hayabusa.exe --directory=.\evtx --csv-timeline results.csv
````

# Hayabusa rules
Hayabusa attack detection rules are written in a SIGMA-like YAML format.

Please read [AboutRuleCreation-English.md](./doc/AboutRuleCreation-English.md) to understand about how to create rules.

All of the rules are in the `rules` folder.
You can check out the current rules to use as a template in creating new ones.

# Compiling from source
If you have rust installed, you can compile from source with the following command.

````
cargo build --release
````

# How to send alerts to a Slack channel

Slackチャンネルへの通知にはSlackでのWEBHOOKURLの設定と実行マシンの環境変数(WEBHOOKURL、CHANNEL)への追加が必要です。

1. Add an "Incoming Webhook" to the slack workspace you want to send alerts to.
2. 「チャンネルへの投稿」で投稿するチャンネルを選択し 「Incoming Webhookインテグレーションの追加」をクリックします。
3. 遷移後のぺージの「Webhook URL」の内容(https:hooks.slack.com/services/xxx...)を環境変数の`WEBHOOK_URL` に代入してください。
4. 投入するchannelを#付きで環境変数の`CHANNEL`に代入してください。
5. 以下のコマンドで実行をするとCHANNELで指定したチャンネルに検知情報の通知が送付されます。

````
hayabusa.exe --slack 
````

# Other Windows event log analyzers and related projects
There is no "one tool to rule them all" and we have found that each have their own merits so we recommend checking out these other great tools and projects and see which ones you like.

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Attack detection tool written in Python.
- [Chainsaw](https://github.com/countercept/chainsaw) - A similar SIGMA based attack detection tool written in Rust.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Attack detection tool written in Powershell.
- [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Python tool to send Evtx data to Elastic Stack.
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - EVTX attack sample event log files by [SBousseaden](https://twitter.com/SBousseaden).
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Another great repository of EVTX attack sample logs mapped to ATT&CK.
- [EVTX parser](https://github.com/omerbenamram/evtx) - the Rust library we used written by [@OBenamram](https://twitter.com/obenamram).
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - A graphical interface to visualize logons to detect lateral movement by [JPCERTCC](https://twitter.com/jpcert_en).
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Rust port of DeepBlueCLI by [Eric Conrad](https://twitter.com/eric_conrad).
- [SIGMA](https://github.com/SigmaHQ/sigma) - Generic SIEM rules.
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Import evtx files into Security Onion.
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - The best CSV timeline analyzer by [Eric Zimmerman](https://twitter.com/ericrzimmerman).
- [Zircolite](https://github.com/wagga40/Zircolite) - SIGMA based attack detection tool written in Python.

## License

Hayabusa is released under GPLv3 and all rules are release under the Detection Rule License (DRL) 1.1

## Contributing

We would love any form of contributing. Pull requests and rule creation are the best but feature requests, notifying us of bugs, etc... are also very welcome.

At the least, if you like our tool then please give us a star on Github and show your support!
