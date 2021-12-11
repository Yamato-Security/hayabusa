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

You need Python 3.8+ and the following modules: `pyyaml`, `ruamel.yaml`, `requests`. 

```sh
pip3 install -r requirements.txt
```

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
cp convert.sh $sigma_path
cp splitter.py $sigma_path
```

* Caution：Be sure to specify the path to your Sigma repository in place of `/path/to/sigma_repository`.

### Convert Rule

`convert.sh` will convert sigma rules to hayabusa rules and save them in a new `hayabusa_rules` folder.

```sh
export sigma_path=/path/to/sigma_repository
cd $sigma_path
sh convert.sh
```

`sigmac` which we use for convert rule files has many options.
If you want to use some option, edit `convert.sh`

## Currently unsupported rules

The following rules currently cannot be automatically converted because it contains an aggregation operator that has not been implemented yet.

```
sigma/rules/windows/builtin/win_susp_samr_pwset.yml
sigma/rules/windows/image_load/sysmon_mimikatz_inmemory_detection.yml
sigma/rules/windows/process_creation/process_creation_apt_turla_commands_medium.yml
```

## Sigma rule parsing errors

Some rules will have been able to be converted but will cause parsing errors or will not be usable due to various bugs. We will continue to fix these bugs but for the meantime the majority of Sigma rules do work so please ignore the errors for now.
