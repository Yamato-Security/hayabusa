# Règles Hayabusa

Les règles de détection Hayabusa sont écrites dans un format YML proche de sigma et se trouvent dans le dossier `rules`.
Les règles sont hébergées sur [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), veuillez donc envoyer tout problème ou pull request concernant les règles à cet emplacement plutôt que dans le dépôt principal de Hayabusa.

Consultez [Création de fichiers de règles](creating-rules.md), [Champs de détection](detection-fields.md) et [Corrélations Sigma](correlations.md) dans cette section pour comprendre le format des règles et comment les créer. (Source : le [dépôt hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).)

Toutes les règles du dépôt hayabusa-rules doivent être placées dans le dossier `rules`.
Les règles de niveau `informational` sont considérées comme des `events`, tandis que tout ce qui a un `level` de `low` et supérieur est considéré comme des `alerts`.

La structure du répertoire des règles Hayabusa est séparée en 2 répertoires :

* `builtin` : journaux qui peuvent être générés par les fonctionnalités intégrées de Windows.
* `sysmon` : journaux qui sont générés par [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

Les règles sont ensuite séparées en répertoires par type de journal (Exemple : Security, System, etc...) et sont nommées selon le format suivant :

Veuillez consulter les règles actuelles pour les utiliser comme modèle lors de la création de nouvelles règles ou pour vérifier la logique de détection.

## Règles Sigma c. Hayabusa (compatibles Sigma intégrées)

Hayabusa prend en charge les règles Sigma nativement, à une seule exception près : le traitement des champs `logsource` en interne.
Afin de réduire les faux positifs, les règles Sigma doivent être passées par notre convertisseur expliqué [ici](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md).
Cela ajoutera les bons `Channel` et `EventID`, et effectuera le mappage des champs pour certaines catégories comme `process_creation`.

Presque toutes les règles Hayabusa sont compatibles avec le format Sigma, vous pouvez donc les utiliser comme des règles Sigma pour les convertir vers d'autres formats SIEM.
Les règles Hayabusa sont conçues uniquement pour l'analyse des journaux d'événements Windows et présentent les avantages suivants :

1. Un champ `details` supplémentaire pour afficher des informations additionnelles tirées uniquement des champs utiles du journal.
2. Elles sont toutes testées avec des exemples de journaux et sont connues pour fonctionner.
3. Des agrégateurs supplémentaires que l'on ne trouve pas dans sigma, tels que `|equalsfield` et `|endswithfield`.

À notre connaissance, hayabusa offre le meilleur support natif des règles sigma parmi tous les outils open source d'analyse des journaux d'événements Windows.
