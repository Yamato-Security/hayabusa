# Champ de détection

## Fondamentaux de la sélection

Tout d'abord, les fondamentaux de la création d'une règle de sélection seront expliqués.

### Comment écrire la logique AND et OR

Pour écrire une logique AND, nous utilisons des dictionnaires imbriqués.
La règle de détection ci-dessous définit que **les deux conditions** doivent être vraies pour que la règle corresponde.

- EventID doit être exactement `7040`.
- **AND**
- Channel doit être exactement `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

Pour écrire une logique OR, nous utilisons des listes (des dictionnaires qui commencent par `-`).
Dans la règle de détection ci-dessous, **l'une ou l'autre** des conditions déclenchera la règle.

- EventID doit être exactement `7040`.
- **OR**
- Channel doit être exactement `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

Nous pouvons également combiner la logique `AND` et `OR` comme indiqué ci-dessous.
Dans ce cas, la règle correspond lorsque les deux conditions suivantes sont toutes deux vraies.

- EventID est exactement soit `7040` **OR** `7041`.
- **AND**
- Channel est exactement `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

Ce qui suit est un extrait d'un journal d'événements Windows, formaté dans le XML d'origine.
Le champ `Event.System.Channel` dans l'exemple de fichier de règle ci-dessus fait référence à la balise XML d'origine : `<Event><System><Channel>System<Channel><System></Event>`
Les balises XML imbriquées sont remplacées par les noms de balises séparés par des points (`.`).
Dans les règles hayabusa, ces chaînes de champs reliées entre elles par des points sont appelées `eventkeys`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Alias d'Eventkey

Les eventkeys longs avec de nombreuses séparations par `.` sont courants, c'est pourquoi hayabusa utilisera des alias pour les rendre plus faciles à manipuler. Les alias sont définis dans le fichier `rules/config/eventkey_alias.txt`. Ce fichier est un fichier CSV composé de correspondances entre `alias` et `event_key`. Vous pouvez réécrire la règle ci-dessus comme indiqué ci-dessous avec des alias rendant la règle plus facile à lire.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Attention : Alias d'Eventkey non définis

Tous les alias d'eventkey ne sont pas définis dans `rules/config/eventkey_alias.txt`. Si vous n'obtenez pas les données correctes dans le message `details` (`Alert details`), et obtenez plutôt `n/a` (non disponible) ou si la sélection dans votre logique de détection ne fonctionne pas correctement, alors vous devrez peut-être mettre à jour `rules/config/eventkey_alias.txt` avec un nouvel alias.

### Comment utiliser les attributs XML dans les conditions

Les éléments XML peuvent avoir des attributs définis en ajoutant un espace à l'élément. Par exemple, `Name` dans `Provider Name` ci-dessous est un attribut XML de l'élément `Provider`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

Pour spécifier des attributs XML dans un eventkey, utilisez le format `{eventkey}_attributes.{attribute_name}`. Par exemple, pour spécifier l'attribut `Name` de l'élément `Provider` dans un fichier de règle, cela ressemblerait à ceci :

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### recherche grep

Hayabusa peut effectuer des recherches grep dans les fichiers de journaux d'événements Windows en ne spécifiant aucun eventkey.

Pour effectuer une recherche grep, spécifiez la détection comme indiqué ci-dessous. Dans ce cas, si les chaînes `mimikatz` ou `metasploit` sont incluses dans le journal d'événements Windows, cela correspondra. Il est également possible de spécifier des caractères génériques.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Note : Hayabusa convertit en interne les données du journal d'événements Windows au format JSON avant de traiter les données, il n'est donc pas possible de faire correspondre sur les balises XML.

### EventData

Les journaux d'événements Windows sont divisés en deux parties : la partie `System` où sont écrites les données fondamentales (Event ID, Timestamp, Record ID, nom du journal (Channel)) et la partie `EventData` ou `UserData` où des données arbitraires sont écrites en fonction de l'Event ID.
Un problème qui se pose souvent est que les noms des champs imbriqués dans `EventData` sont tous appelés `Data`, de sorte que les eventkeys décrits jusqu'à présent ne peuvent pas distinguer entre `SubjectUserSid` et `SubjectUserName`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

Pour résoudre ce problème, vous pouvez spécifier la valeur attribuée dans `Data Name`. Par exemple, si vous souhaitez utiliser `SubjectUserName` et `SubjectDomainName` dans EventData comme condition d'une règle, vous pouvez le décrire comme suit :

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Modèles anormaux dans EventData

Certaines des balises imbriquées dans `EventData` n'ont pas d'attribut `Name`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

Pour détecter un journal d'événements comme celui ci-dessus, vous pouvez spécifier un eventkey nommé `Data`.
Dans ce cas, la condition correspondra tant que l'une des balises `Data` imbriquées est égale à `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Affichage des données de champ à partir de plusieurs noms de champs portant le même nom

Certains événements enregistreront leurs données dans des noms de champs tous appelés `Data` comme dans l'exemple précédent.
Si vous spécifiez `%Data%` dans `details:`, toutes les données seront affichées dans un tableau.

Par exemple :
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Si vous souhaitez afficher uniquement les données du premier champ `Data`, vous pouvez spécifier `%Data[1]%` dans votre chaîne d'alerte `details:` et seul `rundll32.exe` sera affiché.

## Modificateurs de champ

Un caractère pipe peut être utilisé avec les eventkeys comme indiqué ci-dessous pour faire correspondre des chaînes.
Toutes les conditions que nous avons décrites jusqu'à présent utilisent des correspondances exactes, mais en utilisant des modificateurs de champ, vous pouvez décrire des règles de détection plus flexibles.
Dans l'exemple suivant, si une valeur de `Data` contient la chaîne `EngineVersion=2`, cela correspondra à la condition.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

Les correspondances de chaînes ne sont pas sensibles à la casse. Cependant, elles deviennent sensibles à la casse chaque fois que `|re` ou `|equalsfield` sont utilisés.

### Modificateurs de champ Sigma pris en charge

Hayabusa est actuellement le seul outil open-source qui prend entièrement en charge toute la spécification Sigma.

Vous pouvez vérifier l'état actuel de tous les modificateurs de champ pris en charge ainsi que le nombre de fois où ces modificateurs sont utilisés dans les règles Sigma et Hayabusa sur https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
Ce document est mis à jour dynamiquement chaque fois qu'il y a une mise à jour des règles Sigma ou Hayabusa.

- `'|all':`: Ce modificateur de champ est différent de ceux ci-dessus car il ne s'applique pas à un certain champ mais à tous les champs.

    Dans cet exemple, les deux chaînes `Keyword-1` et `Keyword-2` doivent exister mais peuvent se trouver n'importe où dans n'importe quel champ :
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Les données seront encodées en base64 de trois manières différentes selon leur position dans la chaîne encodée. Ce modificateur encodera une chaîne dans les trois variantes et vérifiera si la chaîne est encodée quelque part dans la chaîne base64.
- `|cased`: Rend la recherche sensible à la casse.
- `|cidr`: Vérifie si une valeur de champ correspond à une notation CIDR IPv4 ou IPv6. (Ex : `192.0.2.0/24`)
- `|contains`: Vérifie si une valeur de champ contient une certaine chaîne.
- `|contains|all`: Vérifie si plusieurs mots sont contenus dans les données.
- `|contains|all|windash`: Identique à `|contains|windash` mais tous les mots-clés doivent être présents.
- `|contains|cased`: Vérifie si une valeur de champ contient une certaine chaîne sensible à la casse.
- `|contains|expand`: Vérifie si une valeur de champ contient une chaîne dans le fichier de configuration `expand` à l'intérieur de `/config/expand/`.
- `|contains|windash`: Vérifiera la chaîne telle quelle, ainsi que la conversion du premier caractère `-` en permutations de caractères `/`, `–` (tiret demi-cadratin), `—` (tiret cadratin) et `―` (barre horizontale).
- `|endswith`: Vérifie si une valeur de champ se termine par une certaine chaîne.
- `|endswith|cased`: Vérifie si une valeur de champ se termine par une certaine chaîne sensible à la casse.
- `|endswith|windash`: Vérifie la fin de la chaîne et effectue des variations pour les tirets.
- `|exists`: Vérifie si un champ existe.
- `|expand`: Vérifie si une valeur de champ est égale à une chaîne dans le fichier de configuration `expand` à l'intérieur de `/config/expand/`.
- `|fieldref`: Vérifie si les valeurs de deux champs sont identiques. Vous pouvez utiliser `not` dans la `condition` si vous souhaitez vérifier si deux champs sont différents.
- `|fieldref|contains`: Vérifie si la valeur d'un champ est contenue dans un autre champ.
- `|fieldref|endswith`: Vérifie si le champ de gauche se termine par la chaîne du champ de droite. Vous pouvez utiliser `not` dans la `condition` pour vérifier s'ils sont différents.
- `|fieldref|startswith`: Vérifie si le champ de gauche commence par la chaîne du champ de droite. Vous pouvez utiliser `not` dans la `condition` pour vérifier s'ils sont différents.
- `|gt`: Vérifie si une valeur de champ est supérieure à un certain nombre.
- `|gte`: Vérifie si une valeur de champ est supérieure ou égale à un certain nombre.
- `|lt`: Vérifie si une valeur de champ est inférieure à un certain nombre.
- `|lte`: Vérifie si une valeur de champ est inférieure ou égale à un certain nombre.
- `|re`: Utilise des expressions régulières sensibles à la casse. (Nous utilisons le crate regex, veuillez donc consulter la documentation à <https://docs.rs/regex/latest/regex/#syntax> pour apprendre à écrire les expressions régulières prises en charge.)
    > Attention : [La syntaxe des expressions régulières dans les règles Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) utilise PCRE avec certains métacaractères pour les classes de caractères, le lookbehind, le groupement atomique, etc. qui ne sont pas pris en charge. Le crate regex de Rust devrait pouvoir utiliser toutes les expressions régulières des règles Sigma, mais il existe une possibilité d'incompatibilité. 
- `|re|i`: (Insensitive) Utilise des expressions régulières insensibles à la casse.
- `|re|m`: (Multi-line) Correspond sur plusieurs lignes. `^` / `$` correspondent au début/fin de ligne.
- `|re|s`: (Single-line) le point (`.`) correspond à tous les caractères, y compris le caractère de nouvelle ligne.
- `|startswith`: Vérifie si une valeur de champ commence par une certaine chaîne.
- `|startswith|cased`: Vérifie si une valeur de champ commence par une certaine chaîne sensible à la casse.
- `|utf16|base64offset|contains`: Vérifie si une certaine chaîne UTF-16 est encodée à l'intérieur d'une chaîne base64.
- `|utf16be|base64offset|contains`: Vérifie si une certaine chaîne UTF-16 big-endian est encodée à l'intérieur d'une chaîne base64.
- `|utf16le|base64offset|contains`: Vérifie si une certaine chaîne UTF-16 little-endian est encodée à l'intérieur d'une chaîne base64.
- `|wide|base64offset|contains`: Alias pour `utf16le|base64offset|contains`, vérifiant les chaînes UTF-16 little-endian.

### Modificateurs de champ obsolètes

Les modificateurs suivants sont désormais obsolètes et remplacés par des modificateurs qui adhèrent davantage aux spécifications sigma.

- `|equalsfield`: Est désormais remplacé par `|fieldref`.
- `|endswithfield`: Est désormais remplacé par `|fieldref|endswith`.

### Modificateurs de champ Expand

Les modificateurs de champ `expand` sont uniques en ce sens qu'ils sont le seul modificateur de champ qui nécessite une configuration préalable pour être utilisé.
Par exemple, ils utilisent des espaces réservés tels que `%DC-MACHINE-NAME%` et nécessitent un fichier de configuration nommé `/config/expand/DC-MACHINE-NAME.txt` qui contient tous les noms de machines DC possibles.

La configuration est expliquée plus en détail [ici](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## Caractères génériques

Les caractères génériques peuvent être utilisés dans les eventkeys. Dans l'exemple ci-dessous, si `ProcessCommandLine` commence par la chaîne "malware", la règle correspondra.
La spécification est fondamentalement la même que celle des caractères génériques des règles sigma et sera donc insensible à la casse.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Les deux caractères génériques suivants peuvent être utilisés.

- `*`: Correspond à toute chaîne de zéro ou plusieurs caractères. (En interne, il est converti en expression régulière `.*`)
- `?`: Correspond à un seul caractère quelconque. (En interne, converti en expression régulière `.`)

À propos de l'échappement des caractères génériques :

- Les caractères génériques (`*` et `?`) peuvent être échappés en utilisant une barre oblique inverse : `\*`, `\?`.
- Si vous souhaitez utiliser une barre oblique inverse juste avant un caractère générique, écrivez alors `\\*` ou `\\?`.
- L'échappement n'est pas requis si vous utilisez des barres obliques inverses seules.

## mot-clé null

Le mot-clé `null` peut être utilisé pour vérifier si un champ n'existe pas.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Note : Ceci est différent de `ProcessCommandLine: ''` qui vérifie si la valeur d'un champ est vide.

## condition

Avec la notation que nous avons expliquée ci-dessus, vous pouvez exprimer la logique `AND` et `OR` mais cela deviendra déroutant si vous essayez de définir une logique complexe.
Lorsque vous voulez créer des règles plus complexes, vous devez utiliser le mot-clé `condition` comme indiqué ci-dessous.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

Les expressions suivantes peuvent être utilisées pour `condition`.

- `{expression1} and {expression2}`: Nécessite à la fois {expression1} AND {expression2}
- `{expression1} or {expression2}`: Nécessite soit {expression1} OR {expression2}
- `not {expression}`: Inverse la logique de {expression}
- `( {expression} )`: Définit la priorité de {expression}. Il suit la même logique de priorité qu'en mathématiques.

Dans l'exemple ci-dessus, des noms de sélection tels que `SELECTION_1`, `SELECTION_2`, etc. sont utilisés mais ils peuvent être nommés n'importe comment tant qu'ils ne contiennent que les caractères suivants : `a-z A-Z 0-9 _`
> Cependant, veuillez utiliser la convention standard `selection_1`, `selection_2`, `filter_1`, `filter_2`, etc. pour faciliter la lecture chaque fois que possible.

## logique not

De nombreuses règles entraîneront des faux positifs, il est donc très courant d'avoir une sélection de signatures à rechercher mais aussi une sélection de filtre pour ne pas alerter sur les faux positifs.
Par exemple :

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Corrélations Sigma

Nous avons implémenté toutes les corrélations Sigma version 2.0.0 telles que définies [ici](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

Corrélations prises en charge :

- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

Les nouvelles règles de corrélation "metrics" (`value_sum`, `value_avg`, `value_percentile`) publiées le 12 septembre 2025 dans Sigma version 2.1.0 ne sont actuellement pas prises en charge.
