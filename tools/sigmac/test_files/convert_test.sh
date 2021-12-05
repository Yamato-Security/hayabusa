rm -rf hayabusa_rules
python ./tools/sigmac -t hayabusa --config ./tools/config/generic/sysmon.yml --defer-abort -r test_rules/ > sigma_to_hayabusa.yml
python splitter.py hayabusa_rules_test