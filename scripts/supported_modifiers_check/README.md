# About

This script will create a markdown table of the field modifiers being used by Sigma and tell if Hayabusa supports the modifiers or not.

# How to use
## Run locally
1. `git clone https://github.com/SigmaHQ/sigma`
2. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
3. `git clone https://github.com/Yamato-Security/hayabusa.git`
4. `cd hayabusa/scripts/supported_modifiers_check`
5. `poetry install --no-root`
6. `poetry python supported-modifier.py ../sigma ../hayabusa-rules ../../doc/SupportedSigmaFieldModifiers.md`

## Run Actions
- Manual: https://github.com/fukusuket/hayabusa/actions/runs/10643011211/job/29506086051
- Schedule: `cron: '0 20 * * *'`