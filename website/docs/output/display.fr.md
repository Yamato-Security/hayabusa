# Affichage et résumé des résultats

## Barre de progression

La barre de progression ne fonctionne qu'avec plusieurs fichiers evtx.
Elle affiche en temps réel le nombre et le pourcentage de fichiers evtx dont l'analyse est terminée.

## Sortie en couleur

Les alertes seront affichées en couleur en fonction du `level` de l'alerte.
Vous pouvez modifier les couleurs par défaut dans le fichier de configuration situé à `./config/level_color.txt`, au format `level,(RGB 6-digit ColorHex)`.
Si vous souhaitez désactiver la sortie en couleur, vous pouvez utiliser l'option `-K, --no-color`.

## Résumé des résultats

Le nombre total d'événements, le nombre d'événements avec correspondances, les indicateurs de réduction des données, le nombre total et unique de détections, les dates comptant le plus de détections, les principaux ordinateurs avec détections et les principales alertes sont affichés après chaque analyse.

### Chronologie de la fréquence des détections

Si vous ajoutez l'option `-T, --visualize-timeline`, la fonction de chronologie de la fréquence des événements affiche une chronologie de fréquence sous forme de sparkline des événements détectés.
Remarque : il doit y avoir plus de 5 événements. De plus, les caractères ne s'afficheront pas correctement dans l'invite de commande ou l'invite PowerShell par défaut, veuillez donc utiliser un terminal comme Windows Terminal, iTerm2, etc...
