# Sortie de la chronologie

## Profils de sortie

Hayabusa dispose de 5 profils de sortie prédéfinis à utiliser dans `config/profiles.yaml` :

1. `minimal`
2. `standard` (par défaut)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Vous pouvez facilement personnaliser ou ajouter vos propres profils en modifiant ce fichier.
Vous pouvez également changer facilement le profil par défaut avec `set-default-profile --profile <profile>`.
Utilisez la commande `list-profiles` pour afficher les profils disponibles et leurs informations de champ.

### 1. Sortie du profil `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. Sortie du profil `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. Sortie du profil `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. Sortie du profil `all-field-info`

Au lieu de produire les informations minimales de `details`, toutes les informations de champ dans les sections `EventData` et `UserData` seront produites avec leurs noms de champ d'origine.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. Sortie du profil `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. Sortie du profil `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. Sortie du profil `timesketch-minimal`

Sortie dans un format compatible avec l'importation dans [Timesketch](https://timesketch.org/).

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. Sortie du profil `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Comparaison des profils

Les benchmarks suivants ont été réalisés sur un Lenovo P51 de 2018 (CPU Xeon 4 cœurs / 64 Go de RAM) avec 3 Go de données evtx et 3891 règles activées. (2023/06/01)

| Profil | Temps de traitement | Taille du fichier de sortie | Augmentation de la taille |
| :---: | :---: | :---: | :---: |
| minimal | 8 minutes 50 secondes | 770 MB | -30% |
| standard (par défaut) | 9 minutes 00 secondes | 1,1 GB | Aucune |
| verbose | 9 minutes 10 secondes | 1,3 GB | +20% |
| all-field-info | 9 minutes 3 secondes | 1,2 GB | +10% |
| all-field-info-verbose | 9 minutes 10 secondes | 1,3 GB | +20% |
| super-verbose | 9 minutes 12 secondes | 1,5 GB | +35% |

### Alias de champ de profil

Les informations suivantes peuvent être produites avec les profils de sortie intégrés :

| Nom d'alias | Information produite par Hayabusa |
| :--- | :--- |
|%AllFieldInfo% | Toutes les informations de champ. |
|%Channel% | Le nom du journal. Champ `<Event><System><Channel>`. |
|%Computer% | Le champ `<Event><System><Computer>`. |
|%Details% | Le champ `details` dans la règle de détection YML, cependant, seules les règles hayabusa possèdent ce champ. Ce champ fournit des informations supplémentaires sur l'alerte ou l'événement et peut extraire des données utiles des champs des journaux d'événements. Par exemple, les noms d'utilisateur, les informations de ligne de commande, les informations de processus, etc. Lorsqu'un espace réservé pointe vers un champ qui n'existe pas ou qu'il y a un mappage d'alias incorrect, il sera produit sous la forme `n/a` (non disponible). Si le champ `details` n'est pas spécifié (c.-à-d. les règles sigma), les messages `details` par défaut pour extraire les champs définis dans `./rules/config/default_details.txt` seront produits. Vous pouvez ajouter d'autres messages `details` par défaut en ajoutant le `Provider Name`, l'`EventID` et le message `details` que vous souhaitez produire dans `default_details.txt`. Lorsqu'aucun champ `details` n'est défini dans une règle ni dans `default_details.txt`, tous les champs seront produits dans la colonne `details`. |
|%ExtraFieldInfo% | Affiche les informations de champ qui n'ont pas été produites dans %Details%. |
|%EventID% | Le champ `<Event><System><EventID>`. |
|%EvtxFile% | Le nom du fichier evtx qui a provoqué l'alerte ou l'événement. |
|%Level% | Le champ `level` dans la règle de détection YML. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | [Tactiques](https://attack.mitre.org/tactics/enterprise/) MITRE ATT&CK (ex. : Initial Access, Lateral Movement, etc.). |
|%MitreTags% | ID de groupe, ID de technique et ID de logiciel MITRE ATT&CK. |
|%OtherTags% | Tout mot-clé dans le champ `tags` d'une règle de détection YML qui n'est pas inclus dans `MitreTactics` ou `MitreTags`. |
|%Provider% | L'attribut `Name` dans le champ `<Event><System><Provider>`. |
|%RecordID% | L'ID d'enregistrement d'événement provenant du champ `<Event><System><EventRecordID>`. |
|%RuleAuthor% | Le champ `author` dans la règle de détection YML. |
|%RuleCreationDate% | Le champ `date` dans la règle de détection YML. |
|%RuleFile% | Le nom du fichier de la règle de détection qui a généré l'alerte ou l'événement. |
|%RuleID% | Le champ `id` dans la règle de détection YML. |
|%RuleModifiedDate% | Le champ `modified` dans la règle de détection YML. |
|%RuleTitle% | Le champ `title` dans la règle de détection YML. |
|%Status% | Le champ `status` dans la règle de détection YML. |
|%Timestamp% | Le format par défaut est `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. Champ `<Event><System><TimeCreated SystemTime>` dans le journal d'événements. Le fuseau horaire par défaut sera le fuseau horaire local, mais vous pouvez le changer en UTC avec l'option `--UTC`. |

#### Alias de champ de profil supplémentaire

Vous pouvez également ajouter cet alias supplémentaire à votre profil de sortie si vous en avez besoin :

| Nom d'alias | Information produite par Hayabusa |
| :--- | :--- |
|%RenderedMessage% | Le champ `<Event><RenderingInfo><Message>` dans les journaux transférés par WEC. |

Remarque : ceci n'est **pas** inclus dans les profils intégrés, vous devrez donc modifier manuellement le fichier `config/default_profile.yaml` et ajouter la ligne suivante :

```
Message: "%RenderedMessage%"
```

Vous pouvez également définir des [alias de clé d'événement](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) pour produire d'autres champs.
