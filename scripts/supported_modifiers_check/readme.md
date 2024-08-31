# About

This script will create a markdown table of the field modifiers being used by Sigma and tell if Hayabusa supports the modifiers or not.

# How to use
## Run locally
1. `git clone https://github.com/SigmaHQ/sigma`
2. `git clone https://github.com/Yamato-Security/hayabusa.git`
3. `cd hayabusa/doc/script`
4. `poetry install --no-root`
5. `poetry python supported-modifier.py ../sigma ../SupportedSigmaFieldModifiers.md`

## Run Actions
- Manual: https://github.com/fukusuket/hayabusa/actions/runs/10643011211/job/29506086051
- Schedule: `cron: '0 20 * * *'`