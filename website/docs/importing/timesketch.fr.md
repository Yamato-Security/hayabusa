# Analyse des résultats Hayabusa avec Timesketch

## À propos

"[Timesketch](https://timesketch.org/) est un outil open-source d'analyse collaborative de chronologies forensiques. À l'aide de sketches, vous et vos collaborateurs pouvez facilement organiser vos chronologies et les analyser tous en même temps. Donnez du sens à vos données brutes grâce à de riches annotations, commentaires, tags et favoris."

Pour les petites investigations où vous analysez seul un fichier CSV de seulement quelques centaines de Mo, Timeline Explorer convient, cependant, lorsque vous travaillez avec des données plus volumineuses ou en équipe, un outil comme Timesketch est bien meilleur.

Timesketch offre les avantages suivants :
1. Il est très rapide et peut gérer de grandes quantités de données
2. C'est un outil collaboratif permettant à plusieurs utilisateurs de l'utiliser simultanément
3. Il fournit une analyse avancée des données, des histogrammes et des visualisations
4. Il ne se limite pas à Windows
5. Il prend en charge les requêtes avancées

Il existe de nombreux autres avantages tels que la prise en charge de la CTI, divers analyseurs, des notebooks interactifs, etc...
Veuillez consulter le [guide de l'utilisateur](https://timesketch.org/guides/user/upload-data/) et la [chaîne YouTube](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) pour plus d'informations.

Le seul inconvénient est que vous devrez configurer un serveur Timesketch dans votre environnement de laboratoire, mais heureusement cela est très simple à faire.

## Installation
### Docker
Suivez les instructions officielles [ici](https://docs.docker.com/compose/install).

### Ubuntu
**Remarque :** Docker doit être installé avant de continuer. Veuillez suivre les [instructions d'installation de Docker ci-dessus](#docker) si vous n'avez pas encore installé Docker.
Nous recommandons d'utiliser la dernière édition Ubuntu LTS Server avec au moins 8 Go de mémoire.
Vous pouvez la télécharger [ici](https://ubuntu.com/download/server).
Choisissez l'installation minimale lors de la configuration.
N'installez pas docker lors de la configuration du système d'exploitation.
Vous n'aurez pas `ifconfig` disponible, alors installez-le avec `sudo apt install net-tools`.

Ensuite, exécutez `ifconfig` pour trouver l'adresse IP de la VM et éventuellement vous y connecter en ssh.

Exécutez les commandes suivantes :
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**Remarque :** Avant de continuer, assurez-vous d'avoir [Docker Desktop pour Mac](https://docs.docker.com/desktop/install/mac/) installé et en cours d'exécution sur votre système.
Clonez le dépôt Timesketch et accédez au répertoire.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
Démarrez le conteneur Docker en suivant les étapes ci-dessous.
- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Connexion

Trouvez l'adresse IP du serveur Timesketch avec `ifconfig` et ouvrez-la avec un navigateur web.
Vous serez redirigé vers une page de connexion.
Connectez-vous avec les identifiants utilisateur que vous avez utilisés lors de l'ajout d'un utilisateur.

## Création d'un nouveau sketch

Sous `Start a new investigation`, cliquez sur `BLANK SKETCH`.
Donnez au sketch un nom pertinent pour votre investigation.

## Téléversement de votre chronologie

Après avoir cliqué sur `+ ADD TIMELINE`, vous verrez une boîte de dialogue vous demandant de téléverser un fichier Plaso, JSONL ou CSV.
Malheureusement, Timesketch ne peut actuellement pas importer le format `JSONL` de Hayabusa, alors créez et téléversez une chronologie CSV avec la commande suivante :

```shell
hayabusa-x.x.x-win-x64.exe csv-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --ISO-8601
```

> Remarque : Il est nécessaire de choisir un profil `timesketch*` et de spécifier l'horodatage comme `--ISO-8601` pour l'UTC ou `--RFC-3339` pour l'heure locale. Vous pouvez ajouter d'autres options Hayabusa si vous le souhaitez, cependant, n'ajoutez pas l'option `-M, --multiline` car les caractères de saut de ligne corrompront l'importation.

Dans la boîte de dialogue "Select file to upload", nommez votre chronologie quelque chose comme `hayabusa`, choisissez le délimiteur CSV `Comma (,)` et cliquez sur `SUBMIT`.

> Si votre fichier CSV est trop volumineux pour être téléversé, vous pouvez le diviser en plusieurs fichiers CSV avec la commande [split-csv-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-csv-timeline-command) de Takajo.

Pendant l'importation du fichier, vous verrez un cercle tournant, alors veuillez attendre la fin du processus et l'apparition de `hayabusa`.

## Conseils d'analyse

### Affichage de la chronologie

**Remarque : Même après la fin réussie de l'importation, il affichera `Your search did not match any events` et il y aura `0` événement dans la chronologie `hayabusa`.**

Recherchez `*` et les événements apparaîtront comme indiqué ci-dessous :

![Résultats Timesketch](../assets/doc/TimesketchImport/TimesketchResults.png)

### Détails des alertes

Si vous cliquez sur un titre de règle d'alerte sous la colonne `message`, vous obtiendrez les informations détaillées sur l'alerte :

![Détails de l'alerte](../assets/doc/TimesketchImport/AlertDetails.png)

Si vous souhaitez comprendre la logique de la règle sigma, recherchez la description et les références, etc... veuillez consulter la règle dans le dépôt [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

#### Filtrage des champs

Après avoir ouvert les détails d'un événement en cliquant sur son titre de règle, vous pouvez survoler n'importe quel champ pour filtrer facilement la valeur, en l'incluant ou en l'excluant :

![Filtrer Inclure Exclure](../assets/doc/TimesketchImport/FilterInOut.png)

#### Analyse d'agrégation

Lors du survol, si vous cliquez sur l'icône `Aggregation dialog` la plus à gauche, vous obtenez d'excellentes analyses de données d'événements concernant ce champ :

![Analyse des données d'événements](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### Commentaires des utilisateurs

Lorsque vous cliquez sur une alerte pour obtenir des informations détaillées, une nouvelle icône de boîte de dialogue de commentaire s'affiche sur le côté droit, comme indiqué ci-dessous :

![Icône de commentaire](../assets/doc/TimesketchImport/CommentIcon.png)

Ici, les utilisateurs peuvent démarrer une discussion et écrire des commentaires sur l'investigation.

> Si vous travaillez en équipe, vous devriez probablement créer un compte utilisateur différent pour chaque membre afin de savoir qui a écrit quoi.

![Discussion de commentaires](../assets/doc/TimesketchImport/CommentChat.png)

> Si vous survolez un commentaire, vous pouvez facilement modifier et supprimer les messages.

### Modification des colonnes

Par défaut, seuls l'horodatage et le titre de la règle d'alerte sont affichés, alors cliquez sur les icônes `Modify columns` pour personnaliser les champs :

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

Cela ouvrira la boîte de dialogue suivante :

![Sélectionner les colonnes](../assets/doc/TimesketchImport/SelectColumns.png)

Nous recommandons d'ajouter au moins les colonnes suivantes **dans l'ordre** :

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

L'ordre des colonnes changera en fonction de l'ordre dans lequel vous les ajoutez, alors ajoutez d'abord les champs les plus importants.

S'il vous reste de la place sur votre écran, nous recommandons également d'ajouter `Details`, comme indiqué ici :

![Details](../assets/doc/TimesketchImport/Details.png)

S'il vous reste de la place sur votre écran, nous recommandons également d'ajouter `ExtraFieldInfo`, cependant, comme vous le voyez ici, si vous ajoutez trop de colonnes, le champ `message` deviendra trop étroit et vous ne pourrez plus lire les titres des alertes :

![Trop de détails](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Icônes du haut

#### Icône points de suspension

Si vous cliquez sur l'icône `···`, vous pouvez rendre les lignes plus compactes et supprimer le `Timeline name` pour créer plus d'espace pour les résultats :

![Plus d'espace](../assets/doc/TimesketchImport/MoreRoom.png)

#### Histogramme des événements

Vous pouvez activer l'histogramme des événements pour visualiser la chronologie :

![Histogramme des événements](../assets/doc/TimesketchImport/EventHistogram.png)

Si vous cliquez sur l'une des barres, cela créera un filtre temporel pour n'afficher que les résultats pendant cette période.

#### Enregistrer la recherche actuelle

Si vous cliquez sur l'icône `Save current search` juste au-dessus des horodatages et à gauche de l'icône `Toggle Event Histogram`, vous pouvez enregistrer votre requête de recherche actuelle ainsi que la configuration des colonnes dans `Saved Searches`.
Plus tard, depuis la barre latérale gauche, vous pouvez facilement accéder à vos recherches favorites.

### Barre de recherche

Voici quelques requêtes pratiques pour commencer en n'affichant que les alertes avec certains niveaux de gravité :
1. `Level:crit` pour n'afficher que les alertes critiques.
2. `Level:crit OR Level:high` pour afficher les alertes hautes et critiques
3. `NOT Level:info` pour masquer les alertes informationnelles

Vous pouvez facilement filtrer en tapant le nom du champ plus `:` plus la valeur.
Vous pouvez combiner les filtres avec `AND`, `OR` et `NOT`.
Les caractères génériques et les expressions régulières sont pris en charge.

Consultez le guide de l'utilisateur [ici](https://timesketch.org/guides/user/search-query-guide/) pour des requêtes plus avancées.

#### Historique de recherche

Si vous cliquez sur l'icône d'horloge à gauche de la barre de recherche, vous pouvez afficher les requêtes précédemment saisies.
Vous pouvez également cliquer sur les icônes de flèche gauche et droite pour exécuter les requêtes précédentes et suivantes.

![Historique de recherche](../assets/doc/TimesketchImport/SearchHistory.png)

### Points de suspension verticaux

Si vous cliquez sur les points de suspension verticaux à gauche d'un horodatage et cliquez sur `Context search`, vous pouvez voir les alertes survenues avant et après un certain événement :

![Points de suspension verticaux](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

Cela fera apparaître ceci :

![Recherche contextuelle](../assets/doc/TimesketchImport/ContextSearch.png)

Dans l'exemple ci-dessus, les événements avant et après 60 secondes (`60S`) sont affichés, mais vous pouvez ajuster cela de +- 1 seconde (`1S`) à +- 60 minutes (`60M`).

Si vous souhaitez approfondir davantage les événements affichés, cliquez sur `Replace Search` pour afficher les événements dans la chronologie standard.

### Favoris et tags

Vous pouvez cliquer sur l'icône d'étoile à gauche d'un horodatage pour le marquer comme favori et le noter comme un événement important.

Vous pouvez également ajouter des tags aux événements.
Ceci est utile pour indiquer aux autres que vous avez confirmé qu'un événement est suspect, malveillant, un faux positif, etc...
Si vous travaillez en équipe, vous pouvez créer des tags comme `under investigation by xxx` pour indiquer que quelqu'un est en train d'enquêter sur l'alerte.

![Favoris et tags](../assets/doc/TimesketchImport/StarsAndTags.png)
