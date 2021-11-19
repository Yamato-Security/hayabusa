python ./tools/sigmac -t hayabusa --config ./tools/config/generic/sysmon.yml --defer-abort -r rules/windows/ > sigma_to_hayabusa.yml
python splitter.py