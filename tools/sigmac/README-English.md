# Automatic conversion of Sigma to Hayabusa rules
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

You can use `hayabusa.py`, a `sigmac` backend, to automatically convert Sigma rules to Hayabusa rules.

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

```sh
find $sigma_path/rules/windows/* | grep yml | xargs -I{} sh -c 'python $sigma_path/tools/sigmac {} --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > "$(basename {})"'
```
