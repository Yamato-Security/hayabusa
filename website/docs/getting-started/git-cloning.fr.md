# Clonage Git

Vous pouvez utiliser `git clone` sur le dépôt avec la commande suivante et compiler le binaire depuis le code source :

**Avertissement :** La branche principale du dépôt est destinée au développement, vous pourrez donc accéder à de nouvelles fonctionnalités pas encore officiellement publiées ; cependant, il peut y avoir des bugs, considérez-la donc comme instable.

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **Note :** Si vous oubliez d'utiliser l'option --recursive, le dossier `rules`, qui est géré comme un sous-module git, ne sera pas cloné.

Vous pouvez synchroniser le dossier `rules` et obtenir les dernières règles Hayabusa avec `git pull --recurse-submodules` ou utiliser la commande suivante :

```bash
hayabusa.exe update-rules
```

Si la mise à jour échoue, vous devrez peut-être renommer le dossier `rules` et réessayer.

>> Attention : Lors de la mise à jour, les règles et les fichiers de configuration du dossier `rules` sont remplacés par les dernières règles et fichiers de configuration du dépôt [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).
>> Toute modification que vous apportez aux fichiers existants sera écrasée, c'est pourquoi nous vous recommandons de faire des sauvegardes de tous les fichiers que vous éditez avant la mise à jour.
>> Si vous effectuez un réglage de niveau avec `level-tuning`, veuillez ré-régler vos fichiers de règles après chaque mise à jour.
>> Si vous ajoutez de **nouvelles** règles dans le dossier `rules`, elles ne seront **pas** écrasées ou supprimées lors de la mise à jour.
