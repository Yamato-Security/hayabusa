# Config Commands

## `config-critical-systems` command

This command will automatically try to find critical systems like domain controllers and file servers and add them to the `./config/critical_systems.txt` config file so that all of the alerts will be increased by one level.
It will search for Security 4768 (Kerberos TGT requested) events to determine if it is a domain controller.
It will search for Security 5145 (Network Share File Access) events to determine if it is a file server.
Any hostnames added to the `critical_systems.txt` file will have all alerts above low increased by one level with a maximum of `emergency` level.

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### `config-critical-systems` command examples

* Search the `../hayabusa-sample-evtx` directory for domain controllers and file servers:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
