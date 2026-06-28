# Liste des commandes

## Commandes d'analyse :
* `computer-metrics` : Affiche le nombre d'événements en fonction des noms d'ordinateurs.
* `eid-metrics` : Affiche le nombre et le pourcentage d'événements en fonction de l'Event ID.
* `expand-list` : Extrait les espaces réservés `expand` du dossier `rules`.
* `extract-base64` : Extrait et décode les chaînes base64 des événements.
* `log-metrics` : Affiche les métriques des fichiers journaux.
* `logon-summary` : Affiche un résumé des événements de connexion.
* `pivot-keywords-list` : Affiche une liste de mots-clés suspects pour pivoter.
* `search` : Recherche tous les événements par mot(s)-clé(s) ou expressions régulières

## Commandes de configuration :
* `config-critical-systems` : Trouve les systèmes critiques tels que les contrôleurs de domaine et les serveurs de fichiers.

## Commandes de chronologie DFIR :
* `csv-timeline` : Enregistre la chronologie au format CSV.
* `json-timeline` : Enregistre la chronologie au format JSON/JSONL.
* `level-tuning` : Ajuste de manière personnalisée le `level` des alertes.
* `list-profiles` : Liste les profils de sortie disponibles.
* `set-default-profile` : Modifie le profil par défaut.
* `update-rules` : Synchronise les règles avec les dernières règles du dépôt GitHub [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

## Commandes générales :
* `help` : Affiche ce message ou l'aide de la ou des sous-commandes données
* `list-contributors` : Affiche la liste des contributeurs
