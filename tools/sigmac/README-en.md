# hayabusaGenerater
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

Regist hayabusaGenerater.py for SIGMA's backend.

### set hayabusaGenerater files

```sh
export sigma_path=/path/to/sigma_repository
cp hayabusaGenerater.py $sigma_path/tools/sigma/backends
cp convert.sh $sigma_path
cp splitter.py $sigma_path
```

### install python librariy

```
pip install ruamel.yaml
```

### Convert Rule

Conversion rules can be created by executing `convert.sh`.
The rules will be created to hayabusa_rules folder.

```sh
export sigma_path=/path/to/sigma_repository
cd $sigma_path
sh convert.sh
```

`sigmac` which we use for convert rule files has many options.
If you want to use some option, edit `convert.sh`