# Command List

## Analysis Commands:
* `computer-metrics`: Print the number of events based on computer names.
* `eid-metrics`: Print the number and percentage of events based on Event ID.
* `expand-list`: Extract `expand` placeholders from the `rules` folder.
* `extract-base64`: Extract and decode base64 strings from events.
* `log-metrics`: Print log file metrics.
* `logon-summary`: Print a summary of logon events.
* `pivot-keywords-list`: Print a list of suspicious keywords to pivot on.
* `search`: Search all events by keyword(s) or regular expressions

## Config Commands:
* `config-critical-systems`: Find critical systems like domain controllers and file servers.

## DFIR Timeline Commands:
* `csv-timeline`: Save the timeline in CSV format.
* `json-timeline`: Save the timeline in JSON/JSONL format.
* `level-tuning`: Custom tune the alerts' `level`.
* `list-profiles`: List the available output profiles.
* `set-default-profile`: Change the default profile.
* `update-rules`: Sync the rules to the latest rules in the [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) GitHub repository.

## General Commands:
* `help`: Print this message or the help of the given subcommand(s)
* `list-contributors`: Print the list of contributors
