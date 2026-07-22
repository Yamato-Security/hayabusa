# Analyse des résultats Hayabusa avec jq

# Auteur

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# À propos

Être capable d'identifier, d'extraire et de créer des métriques sur les champs importants des journaux est une compétence essentielle pour les analystes DFIR et de chasse aux menaces.
Les résultats de Hayabusa sont généralement enregistrés dans des fichiers `.csv` afin d'être importés dans des programmes comme Excel ou Timeline Explorer pour l'analyse chronologique.
Cependant, lorsqu'il y a des centaines d'événements identiques ou plus, il devient peu pratique voire impossible de les vérifier manuellement.
Dans ces situations, les analystes trient et comptent généralement les types de données similaires à la recherche d'anomalies.
On parle aussi d'analyse de longue traîne, de classement par pile, d'analyse de fréquence, etc...
Cela peut être réalisé avec Hayabusa en exportant les résultats vers des fichiers `.json` ou `.jsonl` puis en les analysant avec `jq`.

Par exemple, un analyste pourrait comparer les services installés sur tous les postes de travail d'une organisation.
Bien qu'il soit possible qu'un certain logiciel malveillant soit installé sur chaque poste de travail, il est plus que probable qu'il n'existe que sur une poignée de systèmes.
Dans ce cas, les services installés sur tous les systèmes sont plus susceptibles d'être bénins, tandis que les services rares ont tendance à être plus suspects et doivent être vérifiés périodiquement.

Un autre cas d'usage est d'aider à déterminer à quel point quelque chose est suspect.
Par exemple, un analyste pourrait analyser les journaux d'échec de connexion `4625` pour déterminer combien de fois une certaine adresse IP a échoué à se connecter.
S'il n'y avait que quelques échecs de connexion, alors il est probable qu'un administrateur ait simplement mal saisi son mot de passe.
Cependant, s'il y avait des centaines d'échecs de connexion ou plus en peu de temps de la part d'une certaine adresse IP, alors il est probable que cette adresse IP soit malveillante.

Apprendre à utiliser `jq` vous aidera à maîtriser non seulement l'analyse des journaux d'événements Windows, mais aussi de tous les journaux au format JSON.
Maintenant que JSON est devenu un format de journal très populaire et que la plupart des fournisseurs cloud l'utilisent pour leurs journaux, être capable de les analyser avec `jq` est devenu une compétence essentielle pour l'analyste de sécurité moderne.

Dans ce guide, j'expliquerai d'abord comment utiliser `jq` pour ceux qui ne l'ont jamais utilisé auparavant, puis j'expliquerai des usages plus complexes accompagnés d'exemples concrets.
Je recommande d'utiliser linux, macOS ou linux sur Windows afin de pouvoir combiner `jq` avec d'autres commandes utiles telles que `sort`, `uniq`, `grep`, `sed`, etc...

# Installation de jq

Veuillez vous référer à [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) et installer la commande `jq`.

# À propos du format JSON

Les journaux JSON sont une liste d'objets contenus dans des accolades `{` `}`.
À l'intérieur de ces objets se trouvent des paires clé-valeur séparées par des deux-points.
Les clés doivent être des chaînes de caractères, mais les valeurs peuvent être l'une des suivantes :
  * chaîne de caractères (Ex : `"string"`)
  * nombre (Ex : `10`)
  * un autre objet (Ex : `{ xxxx }`)
  * tableau (Ex : `["string", 10]`)
  * booléen (Ex : `true`, `false`)
  * `null`

Vous pouvez imbriquer autant d'objets que vous le souhaitez à l'intérieur d'objets.

Dans cet exemple, `Details` est un objet imbriqué à l'intérieur d'un objet racine :
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# À propos des formats JSON et JSONL avec Hayabusa

Dans les versions antérieures, Hayabusa utilisait le format JSON traditionnel consistant à placer tous les objets de journal `{ xxx }` dans un seul tableau géant.

Exemple :
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

Il y a deux problèmes avec cela.
Le premier problème est que les requêtes `jq` deviennent plus encombrantes car tout doit commencer par un `.[]` supplémentaire pour lui indiquer de regarder dans ce tableau.
Le problème bien plus important est que pour analyser de tels journaux, il faut d'abord charger toutes les données du tableau.
Cela devient un problème si vous avez de très gros fichiers JSON et peu de mémoire.
Afin de réduire l'utilisation du processeur et de la mémoire requise, le format JSONL (JSON Lines), qui ne place pas tout dans un tableau géant, est devenu plus populaire.
Hayabusa exporte aux formats JSON et JSONL, cependant le format JSON n'est plus enregistré dans un tableau.
La seule différence est que le format JSON est plus facile à lire dans un éditeur de texte ou sur la console, tandis que le format JSONL stocke chaque objet JSON sur une seule ligne.
Le format JSONL sera légèrement plus rapide et plus petit en taille, il est donc idéal si vous allez uniquement importer les journaux dans un SIEM, etc... mais pas les consulter.
Le format JSON est idéal si vous allez également effectuer des vérifications manuelles.

# Création de fichiers de résultats JSON

Dans la version 2.x actuelle de Hayabusa, vous pouvez enregistrer les résultats au format JSON avec `hayabusa dfir-timeline -t json -d <directory> -o results.json` ou `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` pour le format JSONL.

Hayabusa utilisera le profil `standard` par défaut et n'enregistrera que la quantité minimale de données pour l'analyse dans l'objet `Details`.
Si vous souhaitez enregistrer toutes les informations de champ d'origine dans les journaux .evtx, vous pouvez utiliser le profil `all-field-info` avec l'option `--profile all-field-info`.
Cela enregistrera toutes les informations de champ dans l'objet `AllFieldInfo`.
Si vous souhaitez enregistrer à la fois les objets `Details` et `AllFieldInfo` au cas où, vous pouvez utiliser le profil `super-verbose`.

## Avantages de l'utilisation de Details plutôt que AllFieldInfo

Le premier avantage de l'utilisation de `Details` plutôt que `AllFieldInfo` est que seuls les champs importants sont enregistrés, et les noms de champs ont été raccourcis pour économiser de l'espace fichier.
L'inconvénient est qu'il existe une possibilité de manquer des données qui vous intéressaient réellement mais qui ont été omises.
Le deuxième avantage est que Hayabusa enregistrera les champs de manière plus uniforme en normalisant les noms de champs.
Par exemple, dans les journaux Windows d'origine, le nom d'utilisateur se trouve généralement dans un champ `SubjectUserName` ou `TargetUserName`. 
Cependant, le nom d'utilisateur se trouve parfois dans un champ `AccountName`, parfois l'utilisateur cible se trouve en réalité dans le champ `SubjectUserName`, etc...
Malheureusement, il existe de nombreux noms de champs incohérents dans les journaux d'événements Windows.
Hayabusa tente de normaliser ces champs, de sorte qu'un analyste n'a qu'à analyser un nom commun au lieu de devoir comprendre la quantité infinie de particularités et de divergences entre les ID d'événement dans Windows.

Voici un exemple du champ utilisateur.
Hayabusa normalisera `SubjectUserName`, `TargetUserName`, `AccountName`, etc... de la manière suivante :
  * `SrcUser` (Utilisateur source) : lorsqu'une action provient **d'un** utilisateur. (Généralement un utilisateur distant.)
  * `TgtUser` (Utilisateur cible) : lorsqu'une action se produit **vers** un utilisateur. (Par exemple, une connexion **vers** un utilisateur.)
  * `User` : lorsqu'une action se produit par un utilisateur actuellement connecté. (Il n'y a pas de direction particulière dans l'action.)

Un autre exemple concerne les processus.
Dans les journaux d'événements Windows d'origine, le champ du processus est désigné par plusieurs conventions de nommage : `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName`, etc...
Sans normalisation des champs, un analyste devrait d'abord connaître tous les différents noms de champs, puis extraire tous les journaux portant ces noms de champs, puis les combiner ensemble. 

Un analyste peut gagner beaucoup de temps et éviter bien des soucis en utilisant simplement le champ unique normalisé `Proc` que Hayabusa fournit dans l'objet `Details`.

# Leçons/Recettes jq

Je vais maintenant énumérer plusieurs leçons/recettes d'exemples pratiques qui pourraient vous aider dans votre travail.

## 1. Vérification manuelle avec jq et Less en couleur

C'est l'une des premières choses à faire pour comprendre quels champs se trouvent dans les journaux.
Vous pourriez simplement faire un `less results.json` mais une meilleure manière est la suivante :
`cat results.json | jq -C | less -R`

En passant par `jq`, il formatera proprement tous les champs pour vous s'ils n'étaient pas formatés proprement au départ.
En utilisant l'option `-C` (couleur) avec `jq` et l'option `-R` (sortie brute) avec `less`, vous pouvez faire défiler vers le haut et vers le bas en couleur.

## 2. Métriques

Hayabusa dispose déjà d'une fonctionnalité pour afficher le nombre et le pourcentage d'événements selon les ID d'événement, cependant, il est également bon de savoir comment le faire avec `jq`.
Cela vous permettra de personnaliser les données pour lesquelles vous souhaitez créer des métriques.

Extrayons d'abord une liste d'ID d'événement avec la commande suivante :

`cat results.json | jq '.EventID'`

Cela extraira uniquement le numéro d'ID d'événement de chaque journal.
Après `jq`, entre guillemets simples, tapez simplement un `.` et le nom du champ que vous souhaitez extraire.
Vous devriez voir une longue liste comme celle-ci :

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Maintenant, redirigez les résultats vers les commandes `sort` et `uniq -c` pour compter combien de fois les ID d'événement se sont produits :

`cat results.json | jq '.EventID' | sort | uniq -c`

L'option `-c` de `uniq` comptera combien de fois un ID d'événement unique s'est produit.

Vous devriez voir quelque chose comme ceci :

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 La gauche est le nombre, et la droite est l'ID d'événement.
 Comme vous pouvez le voir, ce n'est pas trié, il est donc difficile de dire quels ID d'événement se sont produits le plus.

 Vous pouvez ajouter un `sort -n` à la fin pour corriger cela :

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

L'option `-n` indique à `sort` de trier par nombre.

Vous devriez voir quelque chose comme ceci :
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

Nous pouvons voir que les événements `4688` (Création de processus) ont été enregistrés le plus.
Le deuxième événement le plus enregistré était `4625` (Échec de connexion).

Si vous souhaitez afficher les événements les plus enregistrés en haut, vous pouvez inverser le tri avec `sort -n -r` ou `sort -nr`.
Vous pouvez également afficher uniquement les 10 événements les plus enregistrés en redirigeant les résultats vers `head -n 10`.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

Cela vous donnera :
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

Il est important de considérer que les EID (ID d'événement) ne sont pas uniques, vous pouvez donc avoir des événements complètement différents avec le même ID d'événement.
Par conséquent, il est important de vérifier également le `Channel`.

Nous pouvons ajouter ces informations de champ comme ceci :

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Nous ajoutons l'option `-j` (join) à `jq` pour joindre tous les champs ensemble, délimités par des virgules et se terminant par un caractère de nouvelle ligne `\n`.

Cela nous donnera :
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 Remarque : `Security` est abrégé en `Sec`, `System` en `Sys`, et `PowerShell` en `PwSh`.

Nous pouvons ajouter le titre de la règle comme suit :

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Cela nous donnera :
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

Vous pouvez désormais extraire librement toutes les données des journaux et compter les occurrences.

## 3. Filtrage sur certaines données

Bien souvent, vous voudrez filtrer sur certains ID d'événement, utilisateurs, processus, LID (ID de connexion), etc...
Vous pouvez le faire avec `select` à l'intérieur de la requête `jq`.

Par exemple, extrayons tous les événements de connexion réussie `4624` :

`cat results.json | jq 'select ( .EventID == 4624 ) '`

Cela renverra tous les objets JSON pour l'EID `4624` :
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

Si vous souhaitez filtrer sur plusieurs conditions, vous pouvez utiliser des mots-clés comme `and`, `or` et `not`.

Par exemple, recherchons les événements `4624` où le type est `3` (connexion réseau).

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

Cela renverra tous les objets où l'`EventID` est `4624` et le champ imbriqué `"Details": { "Type" }` est `3`.

Il y a cependant un problème.
Vous pourriez remarquer des erreurs indiquant `jq: error (at <stdin>:10636): Cannot index string with string "Type"`.
Chaque fois que vous voyez l'erreur `Cannot index string with string`, cela signifie que vous demandez à `jq` d'afficher un champ qui n'existe pas ou qui est du mauvais type.
Vous pouvez vous débarrasser de ces erreurs en ajoutant un `?` à la fin du champ.
Cela indique à `jq` d'ignorer les erreurs.

Exemple : `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

Maintenant, après avoir filtré selon certains critères, nous pouvons utiliser un `|` à l'intérieur de la requête `jq` pour sélectionner désormais certains champs d'intérêt.

Par exemple, extrayons le nom d'utilisateur cible `TgtUser` et l'adresse IP source `SrcIP` :

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

Encore une fois, nous ajoutons l'option `-j` (join) à `jq` pour sélectionner plusieurs champs à afficher.
Vous pouvez ensuite exécuter `sort`, `uniq -c`, etc... comme dans les exemples précédents pour découvrir combien de fois une certaine adresse IP s'est connectée à un utilisateur via une connexion réseau de type 3.

## 4. Enregistrement de la sortie au format CSV

Malheureusement, les champs des journaux d'événements Windows diffèrent complètement selon le type d'événement, il n'est donc pas facilement possible de créer des chronologies séparées par des virgules par champs sans avoir des centaines de colonnes.
Cependant, il est possible de créer des chronologies séparées par champs pour des types d'événements uniques.
Deux exemples courants sont les événements Security `4624` (Connexions réussies) et `4625` (Échecs de connexion) pour vérifier les mouvements latéraux et la devination/pulvérisation de mots de passe.

Dans cet exemple, nous extrayons uniquement les journaux Security 4624 et affichons l'horodatage, le nom de l'ordinateur et toutes les informations `Details`.
Nous l'enregistrons dans un fichier CSV en utilisant `| @csv`, cependant, nous devons passer les données sous forme de tableau.
Nous pouvons le faire en sélectionnant les champs que nous voulons afficher comme nous l'avons fait précédemment et en les entourant de crochets `[ ]` pour les transformer en tableau.

Exemple : `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

Remarques :
  * Pour sélectionner tous les champs de l'objet `Details`, nous ajoutons `[]`.
  * Il y a des cas où `Details` est une chaîne et non un tableau et donnera des erreurs `Cannot iterate over string`, vous devez donc ajouter un `?`.
  * Nous ajoutons l'option `-r` (sortie brute) à `jq` pour ne pas échapper les guillemets doubles avec une barre oblique inverse.

Résultats :
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

Si nous vérifions simplement qui a eu des connexions réussies, nous n'avons peut-être pas besoin du dernier champ `LID` (ID de connexion).
Vous pouvez supprimer toute colonne inutile avec la fonction `del`.

Exemple : `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

Le tableau compte à partir de `0`, donc pour supprimer le 7e champ, nous utilisons `6`.

Vous pouvez maintenant enregistrer le fichier CSV en ajoutant `> 4624-logs.csv` puis l'importer dans Excel ou Timeline Explorer pour une analyse plus approfondie.

Notez que vous devrez ajouter un en-tête pour effectuer le filtrage.
Bien qu'il soit possible d'ajouter un en-tête à l'intérieur de la requête `jq`, il est généralement plus simple d'ajouter manuellement une ligne supérieure après avoir enregistré le fichier.

## 5. Recherche des dates avec le plus d'alertes

Hayabusa vous indiquera, par défaut, les dates qui ont eu le plus d'alertes selon les niveaux de gravité.
Cependant, vous pourriez vouloir trouver aussi les deuxième, troisième, etc... dates avec le plus d'alertes.
Nous pouvons le faire en découpant la chaîne de l'horodatage pour regrouper par année, mois ou date selon vos besoins.

Exemple : `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` indique à `jq` d'extraire uniquement les 10 premiers octets de `Timestamp`.

Cela nous donnera les dates avec le plus d'événements :
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

Si vous voulez connaître le mois avec le plus d'événements, vous pouvez simplement changer `.[:10]` en `.[:7]` pour extraire les 7 premiers octets.

Si vous souhaitez lister les dates avec le plus d'alertes `high`, vous pouvez faire ceci :

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

Vous pouvez continuer à ajouter des conditions de filtrage à la fonction `select` selon le nom de l'ordinateur, l'ID d'événement, etc... en fonction de vos besoins.

## 6. Reconstruction des journaux PowerShell

Une chose malheureuse à propos des journaux PowerShell est que les journaux sont souvent fragmentés en plusieurs journaux, ce qui les rend difficiles à lire.
Nous pouvons rendre les journaux beaucoup plus faciles à lire en extrayant uniquement les commandes que l'attaquant a exécutées.

Par exemple, si vous avez des journaux ScriptBlock EID `4104`, vous pouvez extraire uniquement ce champ pour créer une chronologie facile à lire.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

Cela donnera une chronologie comme suit :
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. Recherche de connexions réseau suspectes

Vous pouvez d'abord obtenir une liste de toutes les adresses IP cibles avec la commande suivante :

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

Si vous disposez de renseignements sur les menaces, vous pouvez vérifier si l'une des adresses IP est connue pour être malveillante.

Vous pouvez compter le nombre de fois qu'une certaine adresse IP cible a été contactée avec ce qui suit :

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

En changeant `TgtIP` en `SrcIP`, vous pouvez effectuer la même vérification de renseignements sur les menaces pour les adresses IP malveillantes basées sur les adresses IP sources.

Disons que vous avez découvert que l'adresse IP malveillante `93.184.220.29` était contactée depuis votre environnement.
Vous pouvez obtenir des détails sur ces événements avec la requête suivante :

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

Cela vous donnera les résultats JSON tels que celui-ci :
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

Si vous souhaitez lister les domaines qui ont été contactés, vous pouvez utiliser la commande suivante :

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> Remarque : J'ai ajouté un filtre grep pour `.` afin de supprimer les noms d'hôte NETBIOS.

## 8. Extraction des hachages de binaires exécutables

Dans les journaux de création de processus Sysmon EID `1`, sysmon peut être configuré pour calculer les hachages du binaire.
Les analystes de sécurité peuvent comparer ces hachages aux hachages malveillants connus grâce aux renseignements sur les menaces.
Vous pouvez extraire le champ `Hashes` avec ce qui suit :

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

Cela vous donnera une liste de hachages comme celle-ci :

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon calculera généralement plusieurs hachages comme `MD5`, `SHA1` et `IMPHASH`.
Vous pouvez extraire ces hachages avec des expressions régulières dans `jq` ou simplement utiliser le découpage de chaîne pour de meilleures performances.

Par exemple, vous pouvez extraire les hachages MD5 et supprimer les doublons avec ce qui suit :

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. Extraction des journaux PowerShell

Les journaux PowerShell Scriptblock (EID : 4104) sont généralement fragmentés en de nombreux journaux et, lors de l'exportation au format CSV, Hayabusa supprimera les tabulations et les caractères de retour pour rendre la sortie plus concise.
Cependant, il est plus facile d'analyser les journaux powershell avec le formatage d'origine des tabulations et des caractères de retour et en combinant les journaux ensemble.
Voici un exemple d'extraction des journaux PowerShell EID 4104 de `COMPUTER-A` et de leur enregistrement dans un fichier `.ps1` afin de les ouvrir et de les analyser avec VSCode, etc...
Après avoir extrait le champ ScriptBlock, nous utilisons `awk` pour remplacer `\r\n` et `\n` par des caractères de retour et `\t` par des tabulations.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

Après que l'analyste a analysé les journaux à la recherche de commandes PowerShell malveillantes, il devra ensuite généralement rechercher quand ces commandes ont été exécutées.
Voici un exemple d'exportation de l'horodatage et des journaux PowerShell dans un fichier CSV afin de rechercher l'heure à laquelle une commande a été exécutée :

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

Remarque : Le délimiteur de chaîne utilisé est `¦` car les guillemets simples et doubles se trouvent souvent dans les journaux PowerShell et corrompront la sortie CSV.
Lorsque vous importez le fichier CSV, vous devez spécifier à l'application le délimiteur de chaîne `¦`.
