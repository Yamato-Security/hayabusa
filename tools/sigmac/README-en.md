# hayabusaGenerator
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

[Japanese](./README.md)

`hayabusaGenerater.py` allows to convert SIGMA rules to Hayabusa ruleset.

## sigma

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## Settings

hayabusaGenerator needs `sigmac` from the SIGMA repository.
Before using hayabusaGenerator, clone the repository.

```sh
git clone https://github.com/SigmaHQ/sigma.git
```

## Quickstart

Regist haybausa for SIGMA's backend.

```sh
export sigma_path=/path/to/sigma_repository
cp hayabusaGenerater.py $sigma_path/tools/sigma/backends
```

### Convert Single Rule

```sh
python3 $sigma_path/tools/sigmac <Target Rule> --config <config Name> --target hayabusa
```

Sample
```sh
python3 $sigma_path/tools/sigmac $sigma/rules/windows/create_remote_thread/sysmon_cactustorch.yml --config $sigma_path/tools/config/generic/sysmon.yml --target hayabusa > sysmon_cactustorch.yml
```

### Convert Multiple Rules

This is a command sample that creates a rule file from the specified directory in the current directory.

```sh
find $sigma/rules/windows/* | grep yml | xargs -I{} sh -c 'python $sigma/tools/sigmac {} --config $sigma/tools/config/generic/sysmon.yml --target hayabusa > "$(basename {})"'
```
