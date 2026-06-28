# Features

* Cross-platform support: Windows, Linux, macOS.
* Developed in Rust to be memory safe and fast.
* Multi-thread support delivering up to a 5x speed improvement.
* Creates single easy-to-analyze timelines for forensic investigations and incident response.
* Threat hunting based on IoC signatures written in easy to read/create/edit YML based hayabusa rules.
* Sigma rule support to convert sigma rules to hayabusa rules.
* Currently it supports the most sigma rules compared to other similar tools and even supports count rules and new aggregators such as `|equalsfield` and `|endswithfield`.
* Computer metrics. (Useful for filtering on/out certain computers with a large amount of events.)
* Event ID metrics. (Useful for getting a picture of what types of events there are and for tuning your log settings.)
* Rule tuning configuration by excluding unneeded or noisy rules.
* MITRE ATT&CK mapping of tactics.
* Rule level tuning.
* Create a list of unique pivot keywords to quickly identify abnormal users, hostnames, processes, etc... as well as correlate events.
* Output all fields for more thorough investigations.
* Successful and failed logon summary.
* Enterprise-wide threat hunting and DFIR on all endpoints with [Velociraptor](https://docs.velociraptor.app/).
* Output to CSV, JSON/JSONL and HTML Summary Reports.
* Daily Sigma rule updates.
* Support for JSON-formatted log input.
* Log field normalization. (Converting multiple fields with different naming conventions into the same field name.)
* Log enrichment by adding GeoIP (ASN, city, country) information to IP addresses.
* Search all events for keywords or regular expressions.
* Field data mapping. (Ex: `0xc0000234` -> `ACCOUNT LOCKED`)
* Evtx record carving from evtx slack space.
* Event de-duplication when outputting. (Useful when recovery records is enabled or when you include backed up evtx files, evtx files from VSS, etc...)
* Scan setting wizard to help choose which rules to enable easier. (In order to reduce false positives, etc...)
* PowerShell classic log field parsing and extraction.
* Low memory usage. (Note: this is possible by not sorting results. Best for running on agents or big data.)
* Filtering on Channels and Rules for the most efficient performance.
* Detect, extract and decode Base64 strings found in logs.
* Alert level adjustment based on critical systems.
