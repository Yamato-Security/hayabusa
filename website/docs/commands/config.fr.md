# Commandes de configuration

## Commande `config-critical-systems`

Cette commande tentera de trouver automatiquement les systèmes critiques tels que les contrôleurs de domaine et les serveurs de fichiers, et les ajoutera au fichier de configuration `./config/critical_systems.txt` afin que toutes les alertes soient augmentées d'un niveau.
Elle recherchera les événements Security 4768 (Kerberos TGT requested) pour déterminer s'il s'agit d'un contrôleur de domaine.
Elle recherchera les événements Security 5145 (Network Share File Access) pour déterminer s'il s'agit d'un serveur de fichiers.
Tout nom d'hôte ajouté au fichier `critical_systems.txt` verra toutes ses alertes supérieures à low augmentées d'un niveau, avec un maximum de niveau `emergency`.

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

### Exemples de la commande `config-critical-systems`

* Rechercher les contrôleurs de domaine et les serveurs de fichiers dans le répertoire `../hayabusa-sample-evtx` :

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
