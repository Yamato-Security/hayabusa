# Automatic conversion of Sigma to Hayabusa rules
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

You can use `hayabusa.py`, a `sigmac` backend, to automatically convert Sigma rules to Hayabusa rules.

## Pre-converted Sigma rules

Sigma rules have already been pre-converted to hayabusa format and placed in the `./rules/Sigma` directory. 
Please refer to this documentation to convert rules on your own for local testing, using the latest rules, etc...

## Python requirements

You need Python 3.8+ and the following modules: `pyyaml`, `ruamel_yaml`, `requests`. 
You can install the modules with `pip3 install -r requirements.txt`.

## About Sigma

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## Settings

hayabusa.py needs `sigmac` from the Sigma repository.
Before using hayabusa.py, please clone the Sigma repository.

```sh
git clone https://github.com/SigmaHQ/sigma.git
```

## Usage

Create an environmental variable `$sigma_path` that points to the Sigma repository and register haybausa as a backend for Sigma:

```sh
export sigma_path=/path/to/sigma_repository
cp hayabusa.py $sigma_path/tools/sigma/backends
```

* Caution：Be sure to specify the path to your Sigma repository in place of `/path/to/sigma_repository`.

### Converting a single rule

You can convert a single rule with the following syntax:

```sh
python3 $sigma_path/tools/sigmac <Target Rule> --config <Config File Name> --target hayabusa
```

Example:
```sh
python3 $sigma_path/tools/sigmac $sigma_path/rules/windows/create_remote_thread/sysmon_cactustorch.yml --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > sysmon_cactustorch.yml
```

### Converting multiple rules

This example will convert all Sigma rules for Windows event logs to hayabusa rules and save them to the current directory.
Please run this command from the `./rules/Sigma` directory.

```sh
find $sigma_path/rules/windows/ -type f -name '*.yml' -exec sh -c 'python3 $sigma_path/tools/sigmac {} --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > "$(basename {})"' \;
```

※  It takes around 30 minutes to convert all rules.

## Currently unsupported rules

The following rules currently cannot be automatically converted because it contains an aggregation operator that has not been implemented yet.

```
sigma/rules/windows/builtin/win_susp_samr_pwset.yml
sigma/rules/windows/image_load/sysmon_mimikatz_inmemory_detection.yml
sigma/rules/windows/process_creation/process_creation_apt_turla_commands_medium.yml
```

Also, the following rules cannot be automatically converted：
```
process_creation_apt_turla_commands_medium.yml
sysmon_mimikatz_inmemory_detection.yml
win_susp_failed_logons_explicit_credentials.yml
win_susp_failed_logons_single_process.yml
win_susp_failed_logons_single_source_kerberos.yml
win_susp_failed_logons_single_source_kerberos2.yml
win_susp_failed_logons_single_source_kerberos3.yml
win_susp_failed_logons_single_source_ntlm.yml
win_susp_failed_logons_single_source_ntlm2.yml
win_susp_failed_remote_logons_single_source.yml
win_susp_samr_pwset.yml
```

## Sigma rule parsing errors

Some rules will have been able to be converted but will cause parsing errors. We will continue to fix these bugs but for the meantime the majority of Sigma rules do work so please ignore the errors for now.