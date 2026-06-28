# Analyse des résultats de Hayabusa avec Timeline Explorer

## À propos

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) est un outil gratuit mais à code source fermé conçu pour remplacer Excel lors de l'analyse de fichiers CSV à des fins DFIR.
C'est un outil graphique disponible uniquement sous Windows et écrit en C#.
Cet outil est idéal pour les petites investigations menées par un seul analyste et pour les personnes qui débutent dans l'analyse DFIR, cependant, l'interface peut être difficile à comprendre au premier abord, alors veuillez utiliser ce guide pour comprendre les différentes fonctionnalités.

## Installation et exécution

Il n'est pas nécessaire d'installer l'application.
Téléchargez simplement la dernière version depuis [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md), décompressez-la et exécutez `TimelineExplorer.exe`.
Si vous ne disposez pas du runtime .NET approprié, un message apparaîtra vous indiquant que vous devez l'installer.
Au moment de la rédaction (2025/2/14), la dernière version est `2.1.0`, qui fonctionne avec la version `9` de .NET.

## Chargement d'un fichier CSV

Cliquez simplement sur `File` -> `Open` depuis le menu pour charger un fichier CSV.

Vous verrez quelque chose comme ceci :

![First Start](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

Tout en bas, vous pouvez voir le nom du fichier, `Total lines` et `Visible lines`.

En plus des colonnes présentes dans le fichier CSV, deux colonnes sont ajoutées à gauche par Timeline Explorer : `Line` et `Tag`.
`Line` affiche le numéro de ligne mais n'est généralement pas utile pour les investigations, vous voudrez donc peut-être masquer cette colonne.
`Tag` vous permet de cocher les événements que vous souhaitez noter pour une analyse ultérieure, etc.
Malheureusement, il n'y a aucun moyen d'ajouter des balises personnalisées aux événements ni d'écrire des commentaires à leur sujet, car le fichier CSV est ouvert en lecture seule afin d'éviter que les données ne soient écrasées.

## Filtrage des données

Si vous passez la souris sur la partie supérieure droite d'un en-tête, vous verrez apparaître une icône de filtre noire.

![Basic Data Filtering](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

Vous pouvez cocher le niveau de gravité pour d'abord trier les alertes `high` et `crit` (`critical`).
Ce filtrage est également très utile pour éliminer les alertes bruyantes en cochant tout sous `Rule Title` puis en décochant les règles bruyantes.

Comme indiqué ci-dessous, si vous cliquez sur `Text Filters`, vous pouvez créer des filtres plus avancés :

![Advanced Data Filtering](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

Au lieu de créer des filtres ici, il est généralement plus facile de cliquer sur l'icône `ABC` sous l'en-tête et d'appliquer les filtres ici :

![ABC Filtering](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

Malheureusement, ces deux emplacements offrent des options de filtrage légèrement différentes, vous devez donc connaître les deux endroits pour filtrer les données.

Par exemple, si vous avez trop d'événements `Proc Exec` que vous souhaitez éliminer, vous pouvez choisir `Does not contain` et taper `Proc Exec` pour ignorer ces événements :

![Rule Filtering](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

Si vous regardez vers le bas, vous pouvez voir la règle du filtre dans différentes couleurs.
Si vous souhaitez désactiver temporairement le filtre, décochez-le simplement.
Si vous souhaitez effacer tous les filtres, cliquez sur le bouton `X`.

Si vous souhaitez ignorer une autre règle bruyante, vous devez ouvrir le `Filter Editor` en cliquant sur `Edit Filter` dans le coin inférieur droit :

![Filter Editor](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

Copiez le texte `Not Contains([Rule Title], 'Proc Exec')`, ajoutez `and`, collez le même filtre et changez `Proc Exec` en `Possible LOLBIN` et vous pouvez maintenant ignorer ces deux règles :

![Multiple Filters](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

La façon la plus simple de combiner plusieurs filtres consiste à d'abord créer la syntaxe du filtre à partir de l'icône `ABC`, puis à copier, coller et modifier ce texte et à combiner les filtres avec `and`, `or` et `not`.

Vous pouvez également cliquer sur n'importe quel texte coloré pour obtenir une liste déroulante des options possibles afin de modifier vos filtres :

![Dropdown editing](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Options d'en-tête

Si vous faites un clic droit sur l'un des en-têtes, vous obtiendrez les options suivantes :

![Header Options](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

La plupart de ces options sont explicites.

* Après avoir masqué une colonne, vous pouvez l'afficher à nouveau en ouvrant le `Column Chooser`, en faisant un clic droit sur le nom de la colonne et en cliquant sur `Show Column`.
* `Group By This Column` a le même effet que de faire glisser un en-tête de colonne au-dessus pour grouper. (Expliqué plus en détail plus loin.)
* `Hide Group By Box` masquera simplement le texte `Drag a column header here to group by that column` et déplacera la barre de recherche.

### Mise en forme conditionnelle

Vous pouvez mettre en forme le texte avec de la couleur, du gras, etc. en cliquant sur `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...` :

![Conditional Formatting](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

Par exemple, si vous vouliez afficher les alertes `critical` avec `Red Fill`, tapez simplement `crit` et choisissez `Red Fill` parmi les options, cochez `Apply formatting to an entire row` et cliquez sur `OK`.

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

Maintenant, les alertes `critical` apparaîtront en rouge comme indiqué ci-dessous :

![Red fill](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

Vous pouvez continuer ainsi en ajoutant des couleurs pour les alertes `low`, `medium` et `high` également.

## Recherche

Par défaut, lorsque vous tapez du texte dans la barre de recherche, cela effectuera un filtrage et n'affichera que les résultats qui contiennent le texte quelque part dans la ligne.
Vous pouvez voir combien de correspondances vous avez en vérifiant le champ `Visible lines` en bas.

Vous pouvez modifier ce comportement en cliquant sur `Search options` tout en bas à droite.
Cela affichera ce qui suit :

![Search Options](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

Si vous changez le `Behavior` de `Filter` à `Search`, vous pouvez rechercher du texte normalement.

> Remarque : Le changement de comportement prend généralement du temps et Timeline Explorer se bloquera un moment, soyez donc patient après avoir cliqué.

Le `Match criteria` par défaut est `Mixed` mais peut être changé en `Or`, `And` ou `Exact`.
Si vous le changez en autre chose que `Mixed`, vous pouvez alors définir la `Condition` de `Contains` à `Starts with`, `Like` ou `Equals`.

Le `Match criteria` `Mixed` est compliqué car il utilise parfois la logique `AND` et parfois `OR` mais peut être très flexible une fois maîtrisé.
Il fonctionne comme suit :

* Si vous séparez les mots par des espaces, ce sera traité comme une logique `OR`.
* Si vous souhaitez inclure des espaces dans votre recherche, vous devez ajouter des guillemets.
* Faites précéder une condition de `+` pour la logique `AND`.
* Faites précéder une condition de `-` pour exclure des résultats.
* Filtrez sur une colonne spécifique avec le format `ColumnName:FilterString`.
* Si vous filtrez sur une colonne spécifique et incluez également un mot-clé distinct, ce sera une logique `AND`.

Exemples :

| Critère de recherche             | Description                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Sélectionne les enregistrements qui contiennent la chaîne `mimikatz` dans n'importe quelle colonne de recherche.                                |
| one two three                    | Sélectionne les enregistrements qui contiennent `one` OU `two` OU `three` dans n'importe quelle colonne de recherche.                           |
| "hoge hoge"                      | Sélectionne les enregistrements qui contiennent `hoge hoge` dans n'importe quelle colonne de recherche.                                         |
| mimikatz +"Bad Guy"              | Sélectionne les enregistrements qui contiennent à la fois `mimikatz` ET `Bad Guy` dans n'importe quelle colonne de recherche.                   |
| EventID:4624 kali                | Sélectionne les enregistrements qui contiennent `4624` dans la colonne commençant par `EventID` ET contiennent `kali` dans n'importe quelle colonne de recherche.                          |
| data +entry -mark                | Sélectionne les enregistrements qui contiennent à la fois `data` ET `entry` dans n'importe quelle colonne de recherche, en excluant les enregistrements qui contiennent `mark`.                               |
| manu mask -file                  | Sélectionne les enregistrements qui contiennent `menu` OU `mask`, en excluant les enregistrements qui contiennent `file`.                       |
| From:Roller Subj:"currency mask" | Sélectionne les enregistrements qui contiennent `Roller` dans la colonne commençant par `From` ET contiennent `currency mask` dans la colonne commençant par `Subj`. |
| import -From:Steve               | Sélectionne les enregistrements qui contiennent `import` dans n'importe quelle colonne de recherche, en excluant les enregistrements qui contiennent `Steve` dans la colonne commençant par `From`.       |

## Figer des colonnes

Bien qu'il ne s'agisse pas d'une option de recherche, vous pouvez configurer la `First scrollable column` dans le menu `Search options`.
La plupart des analystes la définiront sur `Timestamp` afin de toujours voir à quel moment certains événements se sont produits.

## Faire glisser les en-têtes de colonnes pour grouper

Si vous faites glisser un en-tête de colonne vers `Drag a column header here to group by that column`, Timeline Explorer groupera par cette colonne.
Il est courant de grouper par `Level` afin de pouvoir prioriser les alertes par gravité :

![Group by](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

Si vous avez plusieurs ordinateurs dans vos résultats, vous pouvez en outre grouper par `Computer` pour trier en fonction des différents niveaux de gravité pour chaque ordinateur.

## Vérification des champs

Par défaut, Hayabusa séparera les données de champ par la barre verticale brisée : `¦`.
Lorsque les données de champ sont sur une ligne horizontale, cela rend très facile la distinction de plusieurs champs car ce caractère ne se trouve pas souvent dans les journaux :

![Field Information](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

Parfois, cependant, il y aura trop d'informations de champ dans le journal et tout ne pourra pas tenir sur un seul écran.
Dans ce cas, vous pouvez double-cliquer sur la cellule pour obtenir une fenêtre contextuelle qui affiche toutes les informations de champ :

![Cell Contents](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

Le problème est que Timeline Explorer ne vous permet de mettre en forme les données de champ que par caractères de saut de ligne (`CRLF`, `CR`, `LF`), virgules et tabulations.

Si vous utilisez l'option `-M, --multiline`, vous pouvez séparer les champs par un caractère de saut de ligne et lorsque vous double-cliquez pour ouvrir le contenu d'une cellule, il sera correctement mis en forme :

![Multi-line formatting](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

Le problème est que désormais, seul le premier champ sera affiché dans la chronologie, vous devrez donc double-cliquer et ouvrir une nouvelle fenêtre chaque fois que vous souhaitez vérifier les données des autres champs :

![Multiline single fiels](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

Malheureusement, Timeline Explorer ne prend pas en charge plusieurs lignes dans la vue chronologique.

Pour contourner ce problème, à partir de Hayabusa `v3.1.0`, vous pouvez séparer les champs par des tabulations :

![Tab separation](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

Il est un peu plus difficile de distinguer où un champ se termine et où le suivant commence.
De plus, lorsque vous double-cliquez et ouvrez le contenu de la cellule, les champs ne sont pas automatiquement mis en forme :

![Tab separation not formatted](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

Cependant, si vous cliquez sur `Tab` en bas puis sur `Format`, vous pouvez mettre en forme les champs dans une vue facile à lire :

![Tab separation formatted](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Thèmes (Skins)

Vous pouvez changer le thème de couleur depuis `Tools` -> `Skins` si vous préférez le mode sombre, etc.

## Sessions

Si vous personnalisez les colonnes, l'apparence, ajoutez des filtres, etc. et que vous souhaitez enregistrer ces paramètres pour plus tard, assurez-vous d'enregistrer votre session depuis `File` -> `Session` -> `Save`.
