## Règles de comptage d'événements (Event Count)

Ce sont des règles qui comptent certains événements et alertent si un nombre trop élevé ou insuffisant de ces événements se produit dans un intervalle de temps.
Des exemples courants de détection de nombreux événements sur une certaine période sont la détection des attaques par devinette de mot de passe, des attaques par pulvérisation de mots de passe (password spray) et des attaques par déni de service.
Vous pourriez également utiliser ces règles pour détecter des problèmes de fiabilité des sources de journaux, par exemple lorsque certains événements tombent en dessous d'un certain seuil.

### Exemple de règle de comptage d'événements :

L'exemple suivant utilise deux règles pour détecter les attaques par devinette de mot de passe.
Il y aura une alerte lorsque la règle référencée correspond 5 fois ou plus en 5 minutes et que le champ `IpAddress` est identique pour ces événements.

> Notez que nous n'avons inclus que les champs nécessaires afin de comprendre le concept.
> La règle complète sur laquelle cet exemple est basé se trouve [ici](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) pour votre référence.

### Règle de corrélation de comptage d'événements :

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Règle Échec de connexion - Mot de passe incorrect :

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### Exemple de règle `count` obsolète :

La corrélation ci-dessus et les règles référencées fournissent les mêmes résultats que la règle suivante qui utilise l'ancien modificateur `count` :

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Sortie de la règle de comptage d'événements :

Les règles ci-dessus créeront la sortie suivante :
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Règles de comptage de valeurs (Value Count)

Ces règles comptent les mêmes événements dans un intervalle de temps avec des valeurs **différentes** d'un champ donné.

Exemples :
- Analyses réseau où une seule adresse IP source tente de se connecter à de nombreuses adresses IP de destination et/ou ports différents.
- Attaques par pulvérisation de mots de passe où une seule source échoue à s'authentifier avec de nombreux utilisateurs différents.
- Détecter des outils comme BloodHound qui énumèrent de nombreux groupes AD à privilèges élevés dans un court intervalle de temps.

### Exemple de règle de comptage de valeurs :

La règle suivante détecte lorsqu'un attaquant tente de deviner des noms d'utilisateur.
C'est-à-dire lorsque la **même** adresse IP source (`IpAddress`) échoue à se connecter avec plus de 3 noms d'utilisateur **différents** (`TargetUserName`) en 5 minutes.

> Notez que nous n'avons inclus que les champs nécessaires afin de comprendre le concept.
> La règle complète sur laquelle cet exemple est basé se trouve [ici](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) pour votre référence.

### Règle de corrélation de comptage de valeurs :

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Règle Échec de connexion par comptage de valeurs (Utilisateur inexistant) :

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### Règle avec modificateur `count` obsolète :

La corrélation ci-dessus et les règles référencées fournissent les mêmes résultats que la règle suivante qui utilise l'ancien modificateur `count` :

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Sortie de la règle de comptage de valeurs :

Les règles ci-dessus créeront la sortie suivante :
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Règles de proximité temporelle (Temporal Proximity)

Tous les événements définis par les règles référencées par le champ rule doivent se produire dans l'intervalle de temps défini par timespan.
Les valeurs des champs définis dans `group-by` doivent toutes avoir la même valeur (ex : même hôte, même utilisateur, etc...).

### Exemple de règle de proximité temporelle :

Exemple : Des commandes de reconnaissance définies dans trois règles Sigma sont invoquées dans un ordre arbitraire en 5 minutes sur un système par le même utilisateur.

### Règle de corrélation de proximité temporelle :

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Règles de proximité temporelle ordonnée (Ordered Temporal Proximity)

Le type de corrélation `temporal_ordered` se comporte comme `temporal` et exige en plus que les événements apparaissent dans l'ordre fourni dans l'attribut `rules`.

### Exemple de règle de proximité temporelle ordonnée :

Exemple : de nombreuses connexions échouées telles que définies ci-dessus sont suivies d'une connexion réussie du même compte utilisateur en 1 heure :

### Règle de corrélation de proximité temporelle ordonnée :

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## Notes sur les règles de corrélation

1. Vous devez inclure toutes vos règles de corrélation et règles référencées dans un seul fichier et les séparer avec un séparateur YAML `---`.

2. Par défaut, les règles de corrélation référencées ne seront pas affichées. Si vous voulez voir la sortie des règles référencées, vous devez ajouter `generate: true` sous `correlation`. Il est très utile d'activer cela et de vérifier lors de la création de règles de corrélation.

    Exemple :
    ```
    correlation:
        generate: true
    ```
3. Vous pouvez utiliser des noms d'alias au lieu des identifiants de règles lors du référencement des règles afin de rendre les choses plus faciles à comprendre.

4. Vous pouvez référencer plusieurs règles.

5. Vous pouvez utiliser plusieurs champs dans `group-by`. Si vous le faites, toutes les valeurs de ces champs doivent être identiques, sinon vous n'obtiendrez pas d'alerte. La plupart du temps, vous écrirez des règles qui filtrent sur certains champs avec `group-by` afin de réduire les faux positifs, cependant, il est possible d'omettre `group-by` pour créer une règle plus générique.

6. L'horodatage de la règle de corrélation correspondra au tout début de l'attaque, vous devez donc vérifier les événements survenus après cela pour confirmer s'il s'agit d'un faux positif ou non.
