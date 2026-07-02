# Curation des règles Sigma pour les journaux d'événements Windows

Cette page décrit comment Yamato Security cure les règles [Sigma](https://github.com/SigmaHQ/sigma) en amont destinées aux journaux d'événements Windows afin d'en obtenir une forme plus utilisable, en dé-abstrayant le champ `logsource` et en filtrant les règles inutilisables ou difficiles à utiliser. Cela est réalisé avec l'outil [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter), qui sert principalement à créer l'ensemble de règles Sigma curées hébergé dans [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules). Cet ensemble de règles est utilisé par [Hayabusa](https://github.com/Yamato-Security/hayabusa) et [Velociraptor](https://github.com/Velocidex/velociraptor).

!!! info "Source"
    Cette documentation est maintenue en parallèle de l'outil de conversion sur [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter). Nous espérons que ces informations seront également utiles à d'autres projets souhaitant utiliser les règles Sigma pour détecter des attaques dans les journaux d'événements Windows. Voir aussi [Création de fichiers de règles](creating-rules.md) et [Modificateurs de champs](field-modifiers.md).

## TL;DR

* Dé-abstraire le champ `logsource` et créer de nouveaux fichiers de règles `.yml` pour les règles natives (built-in) ainsi que pour les règles originales basées sur Sysmon facilite la prise en charge complète des événements natifs par les règles Sigma, et rend les règles plus faciles à lire pour les analystes.
* Lors de l'écriture de règles Sigma pour les journaux d'événements Windows, il est important de comprendre les différences entre les journaux originaux basés sur Sysmon et les journaux natifs compatibles, et idéalement d'écrire vos règles de manière à ce qu'elles soient compatibles avec les deux.
* De nombreuses organisations ne peuvent pas ou ne veulent pas installer et maintenir des agents Sysmon sur tous leurs postes Windows, parce qu'elles ne disposent pas des ressources dédiées pour le gérer, ou parce qu'elles souhaitent éviter le risque de ralentissements ou de plantages provoqués par Sysmon. C'est pourquoi il est important d'activer autant de journaux d'événements natifs que possible et d'utiliser des outils capables de détecter les attaques dans ces journaux natifs.

## Difficultés liées aux règles Sigma en amont pour les journaux d'événements Windows

D'après notre expérience, la principale difficulté pour créer un analyseur natif de règles Sigma pour les journaux d'événements Windows a été la prise en charge du champ `logsource`. C'est actuellement l'une des rares choses que Hayabusa ne prend pas encore en charge nativement, car cela reste très complexe et constitue un travail en cours. Pour le moment, nous contournons ce problème en convertissant les règles en amont vers un format plus facile à utiliser, comme expliqué en détail ci-dessous.

### À propos du champ `logsource`

Dans les règles Sigma pour les journaux d'événements Windows, le champ `product` est défini sur `windows`, suivi soit d'un champ `service`, soit d'un champ `category`.

Exemple de champ `service` :

```yaml
logsource:
    product: windows
    service: application
```

Exemple de champ `category` :

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Champs `service`

Les champs `service` sont relativement simples à gérer et indiquent au backend qui utilise la règle Sigma de rechercher un seul canal ou plusieurs canaux en fonction du champ `Channel` dans le journal d'événements XML de Windows.

**Exemple de canal unique**

`service: application` revient à ajouter une condition de sélection `Channel: Application` à la règle Sigma.

**Exemple de plusieurs canaux**

`service: applocker` génère actuellement le plus grand nombre de canaux à parcourir, car AppLocker enregistre ses informations dans quatre journaux différents. Pour rechercher correctement uniquement les journaux AppLocker, il faut ajouter la condition suivante à la logique de la règle Sigma :

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Liste actuelle des correspondances de service**

| Service                                    | Canal                                                                                                                               |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**Sources des correspondances de service**

Nous avons créé des fichiers de correspondance YAML associant les services aux noms de canaux, que nous maintenons régulièrement et hébergeons dans le dépôt du convertisseur. Ils sont basés sur les informations de correspondance de service de [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) : bien que cela ne semble pas être un fichier de configuration générique officiel destiné à être utilisé, il semble être le plus à jour.

#### Champs `category`

La plupart des champs `category` ajoutent simplement une condition permettant de vérifier certains identifiants d'événement dans le champ `EventID`, en plus de rechercher un `Channel` spécifique. Les noms de catégorie sont principalement basés sur les événements [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), avec quelques catégories supplémentaires pour les journaux PowerShell natifs et Windows Defender.

**Exemple de champ `category`**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Liste actuelle des correspondances de catégorie**

Certaines catégories correspondent à plus d'un service/EventID (indiqués en **gras**).

| Catégorie                 | Service            | EventIDs                                                               |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**Difficultés des champs `category`**

Comme illustré ci-dessus, une même `category` peut utiliser plusieurs services et identifiants d'événement (indiqués en **gras**). Cela signifie qu'il est possible d'utiliser certaines règles Sigma conçues pour `sysmon` avec des journaux d'événements Windows natifs `security` similaires, si les champs utilisés par la règle existent également dans le journal d'événements natif. Dans ce cas, les noms de champs — et parfois aussi les valeurs — peuvent devoir être convertis pour correspondre aux noms de champs et aux valeurs du journal d'événements natif `security`. Bien que cela puisse être aussi simple que de renommer certains noms de champs pour certaines catégories, pour d'autres catégories cela peut également nécessiter diverses conversions des valeurs de champs. La façon dont nous effectuons cette conversion, ainsi que la compatibilité entre les journaux `sysmon` et les journaux `security`, sont expliquées en détail [ci-dessous](#sysmon-builtin-comparison).

**Sources des correspondances de catégorie**

Les fichiers de correspondance YAML pour les catégories sont eux aussi hébergés dans le dépôt du convertisseur et sont également basés sur les informations de [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

## Avantages et difficultés de l'abstraction de la source de journal

L'abstraction de la source de journal et la création de correspondances pour différents `Channel`, `EventID` et champs côté backend présentent à la fois des avantages et des difficultés.

### Avantages

1. Il peut être plus facile de convertir les noms de champs `Channel` et `EventID` vers les bons noms de champs du backend lors de la conversion des règles Sigma en requêtes pour d'autres backends.
2. Il est possible de regrouper deux règles en une seule. Par exemple, les événements de création de processus peuvent être journalisés dans `Sysmon 1` ainsi que dans `Security 4688`. Au lieu d'écrire deux règles qui examinent des canaux, des identifiants d'événement et des champs différents mais qui contiennent par ailleurs la même logique, il est possible de standardiser les champs sur ceux qu'utilise Sysmon, puis de laisser un convertisseur backend ajouter les champs `Channel` et `EventID` et convertir les autres informations de champs si nécessaire. Cela facilite la maintenance des règles, car il y a moins de règles à maintenir.
3. Bien que ce soit très rare, si une source de journal se met à enregistrer ses données dans un `Channel` ou un `EventID` différent, seule la logique de correspondance doit être mise à jour au lieu de toutes les règles Sigma, ce qui facilite la maintenance.

### Difficultés

1. Que se passe-t-il si la règle Sigma originale basée sur Sysmon utilise, pour filtrer les faux positifs, un champ qui n'existe pas dans les journaux natifs ? Faut-il créer la règle malgré tout, en privilégiant une détection possible, ou l'ignorer pour privilégier un moindre nombre de faux positifs ? Idéalement, il faudrait créer deux règles avec des informations de `severity`, de `status` et de faux positifs différentes afin que l'utilisateur puisse mieux les gérer.
2. Cela rend le filtrage des règles plus difficile, car vous ne pouvez pas simplement filtrer en fonction des champs `Channel` ou `EventID` du fichier `.yml` ou du chemin du fichier de la règle si le fichier n'a pas encore été créé — parce qu'il s'agit d'une règle dérivée pour un journal natif au lieu de la règle Sysmon originale. De plus, comme l'ID de la règle est identique, vous ne pouvez pas filtrer sur les ID de règle.
3. Cela rend la confirmation de l'alerte plus difficile lorsque celle-ci provient d'une règle pour les journaux natifs dérivée d'un journal Sysmon. Les noms de champs et les valeurs ne correspondront pas, si bien que l'analyste doit comprendre le processus de conversion, quelque peu complexe.
4. Cela rend la création de la logique du backend plus complexe.

Bien que nous ne puissions rien faire au sujet du premier problème, si ce n'est créer et maintenir de nouvelles règles lorsqu'un cas d'usage important justifie cet effort, pour répondre aux problèmes 2 à 4 nous avons décidé de dé-abstraire le champ `logsource` et de créer deux ensembles de règles pour toute règle susceptible d'en produire plusieurs. Les règles capables de détecter des attaques dans les journaux natifs sont générées dans le répertoire `builtin`, et les règles pour Sysmon sont générées dans le répertoire `sysmon`.

## Exemple de conversion

Voici un exemple simple pour mieux comprendre le processus de conversion.

**Avant conversion** — la règle Sigma originale :

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Après conversion** — une règle compatible Hayabusa pour les journaux Sysmon :

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

...et une règle compatible Hayabusa pour les journaux natifs de Windows :

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

Comme vous pouvez le voir, deux règles ont été créées : une pour les journaux Sysmon 1 et une pour les journaux natifs Security 4688. Une nouvelle condition `process_creation` a été ajoutée avec les informations de canal et d'identifiant d'événement, et elle a été ajoutée au champ `condition` pour rendre cette condition obligatoire. De plus, le nom du champ original `Image` a été remplacé par `NewProcessName`.

## Points communs de la conversion

Avant d'expliquer en détail comment nous convertissons des catégories spécifiques, voici la partie de la conversion qui s'applique à toutes les règles.

1. Toute règle dont l'ID figure dans `ignore-uuid-list.txt` est ignorée. Actuellement, nous n'ignorons que les règles qui provoquent des faux positifs sur Windows Defender parce qu'elles contiennent des mots-clés comme `mimikatz`.
2. Les règles « placeholder » sont ignorées car elles ne peuvent pas être utilisées telles quelles. Il s'agit des règles placées dans le dossier [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) du dépôt Sigma.
3. Les règles qui utilisent des modificateurs de champs incompatibles sont écartées. Hayabusa prend en charge la majorité des modificateurs de champs, si bien que le convertisseur ne produira aucune règle utilisant un modificateur autre que ceux-ci, afin d'éviter les erreurs d'analyse (voir [Modificateurs de champs](field-modifiers.md)) :

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Les règles comportant des erreurs de syntaxe ne sont pas converties.
5. Les tags des règles `deprecated` et `unsupported` sont mis à jour du format V1 vers le format V2, qui utilise `-` au lieu de `_`, afin de tout garder cohérent et de gérer plus facilement les abréviations dans Hayabusa. Exemple : `initial_access` devient `initial-access`.
6. Puisque nous ajoutons des informations `Channel` et `EventID` aux règles, nous créons un nouvel ID UUIDv4 à partir du hachage MD5 de l'ID original, indiquons l'ID original dans le champ `related`, et marquons le `type` comme `derived`. Pour les règles pouvant être converties en plusieurs règles (`sysmon` et `builtin`), nous devons également créer de nouveaux ID de règle pour les règles `builtin` dérivées. Pour ce faire, nous calculons un hachage MD5 de l'ID de la règle `sysmon` et l'utilisons comme ID UUIDv4. Par exemple :

    Règle Sigma originale :

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Nouvelle règle `sysmon` :

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Nouvelle règle `builtin` :

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Les règles qui détectent des éléments dans les journaux d'événements Windows natifs sont générées dans le répertoire `builtin`, tandis que les règles qui reposent sur les journaux Sysmon sont générées dans le répertoire `sysmon`, avec des sous-répertoires correspondant aux répertoires du dépôt Sigma en amont.

## Limites de la conversion

Il n'y a qu'un seul [bug connu](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2) pour le moment : les lignes de commentaire des règles Sigma ne seront pas incluses dans les règles générées, sauf si les commentaires suivent du code source.

## Comparaison des événements Sysmon et natifs et conversion des règles { #sysmon-builtin-comparison }

### Création de processus

* Catégorie : `process_creation`
* Sysmon
    * Canal : `Microsoft-Windows-Sysmon/Operational`
    * ID d'événement : `1`
* Journal natif
    * Canal : `Security`
    * ID d'événement : `4688`

**Comparaison**

![Comparaison de la création de processus](../assets/rules-doc/process_creation_comparison.png)

**Notes de conversion**

1. Les informations du champ `User` doivent être séparées dans les champs `SubjectUserName` et `SubjectDomainName`.
2. Le nom du champ `LogonId` devient `SubjectLogonId`, et toutes les lettres de la valeur hexadécimale doivent être mises en minuscules.
3. Le nom du champ `ProcessId` devient `NewProcessId`, et la valeur doit être convertie en hexadécimal.
4. Le nom du champ `Image` devient `NewProcessName`.
5. Le nom du champ `ParentProcessId` devient `ProcessId`, et la valeur doit être convertie en hexadécimal.
6. Le nom du champ `ParentImage` devient `ParentProcessName`.
7. Le nom du champ `IntegrityLevel` devient `MandatoryLabel`, et la conversion de valeur suivante est nécessaire :
    * `Low` : `S-1-16-4096`
    * `Medium` : `S-1-16-8192`
    * `High` : `S-1-16-12288`
    * `System` : `S-1-16-16384`
8. Si la règle contient les champs suivants qui n'existent que dans les événements `Security 4688`, alors nous ne créons pas de règle `Sysmon 1` :
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Si la règle contient les champs suivants qui n'existent que dans les événements `Sysmon 1`, alors nous ne créons pas de règle `Security 4688` :
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. Il existe une exception aux points 8 et 9 : même si un champ qui n'existe que dans un seul type d'événement de journal est utilisé, si ce champ figure dans une condition `OR`, vous devez tout de même créer cette règle. Par exemple, la règle suivante ne doit **pas** générer de règle `Security 4688` car le champ `OriginalFileName` est obligatoire (logique `AND` au sein de la sélection) :

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    En revanche, une règle avec la condition suivante **doit** créer une règle `Security 4688` car `OriginalFileName` est optionnel (logique `OR` au sein de la sélection) :

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    La difficulté vient du fait que votre analyseur doit comprendre non seulement la logique à l'intérieur des sélections, mais aussi celle du champ `condition`. Par exemple, la règle suivante ne **doit pas** créer de règle `Security 4688` car elle utilise une logique `AND` :

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    En revanche, la règle suivante **doit** créer une règle `Security 4688` car elle utilise une logique `OR` :

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Autres notes**

* Le champ `SubjectUserSid` dans `Security 4688` affiche le SID ; cependant, dans le `Message` rendu du journal d'événements, il est converti en `DOMAIN\User`.
* Les événements `Security 4688` peuvent ne pas inclure les informations d'options de ligne de commande dans `CommandLine`, selon les paramètres.
* `TokenElevationType` est affiché tel quel dans le `Message` et n'est pas rendu.
* `S-1-16-4096`, etc. dans `MandatoryLabel` est converti en `Mandatory Label\Low Mandatory Level`, etc. dans le `Message` rendu.

**Paramètres des journaux natifs**

!!! warning "Non activé par défaut"
    Les importants journaux d'événements natifs de création de processus `Security 4688` ne sont pas activés par défaut. Vous devez activer à la fois les événements `4688` et la journalisation des options de ligne de commande pour pouvoir utiliser la majorité des règles Sigma.

*Activation via une stratégie de groupe :*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation` : `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events` : `Enabled`

*Activation en ligne de commande :*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Connexion réseau

* Catégorie : `network_connection`
* Sysmon
    * Canal : `Microsoft-Windows-Sysmon/Operational`
    * ID d'événement : `3`
* Journal natif
    * Canal : `Security`
    * ID d'événement : `5156`

**Comparaison**

![Comparaison de la connexion réseau](../assets/rules-doc/network_connection_comparison.png)

**Notes de conversion**

1. Le nom du champ `ProcessId` devient `ProcessID`.
2. Le nom du champ `Image` devient `Application`, et `C:\` devient `\device\harddiskvolume?\`. (Remarque : comme nous ne connaissons pas le numéro de volume du disque dur, nous le remplaçons par un caractère générique unique `?`.)
3. La valeur `tcp` du champ `Protocol` devient `6` et `udp` devient `17`.
4. Le nom du champ `Initiated` devient `Direction`, et la valeur `true` devient `%%14593` et `false` devient `%%14592`.
5. Le nom du champ `SourceIp` devient `SourceAddress`.
6. Le nom du champ `DestinationIp` devient `DestAddress`.
7. Le nom du champ `DestinationPort` devient `DestPort`.

**Paramètres des journaux natifs**

!!! warning "Non activé par défaut"
    Les journaux natifs de connexion réseau `Security 5156` ne sont pas activés par défaut. Ils génèrent une grande quantité de journaux, ce qui peut écraser d'autres journaux importants dans le journal d'événements `Security` et potentiellement ralentir le système s'il présente un grand nombre de connexions réseau. Assurez-vous que la taille de fichier maximale du journal `Security` est élevée, et testez pour vous assurer qu'il n'y a pas d'effets néfastes sur le système.

*Activation via une stratégie de groupe :*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection` : `Success and Failure`

*Activation en ligne de commande :*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...ou la commande suivante si vous utilisez une locale non anglophone :

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Voir aussi"
    Pour en savoir plus sur l'activation des journaux d'événements Windows natifs nécessaires pour capturer les preuves sur lesquelles reposent ces règles, voir [Journalisation Windows et Sysmon](../resources/logging.md) et le projet [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

## Conseils pour l'écriture de règles Sigma

!!! tip
    Si vous utilisez un champ qui existe dans un journal `sysmon` mais pas dans un journal `builtin`, veillez à rendre ce champ optionnel afin qu'il reste possible d'utiliser la règle pour les journaux `builtin`.

Par exemple :

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Cette sélection recherche les cas où le processus (`Image`) porte le nom `addinutil.exe`. Le problème est qu'un attaquant pourrait simplement renommer le fichier pour contourner la règle. Le champ `OriginalFileName`, qui n'existe que dans les journaux Sysmon, est le nom de fichier intégré au binaire au moment de la compilation. Même si un attaquant renomme le fichier, le nom intégré ne change pas ; cette règle peut donc détecter les attaques où l'attaquant a renommé le fichier lors de l'utilisation de Sysmon, et peut également détecter les attaques où le nom de fichier n'a pas été modifié lors de l'utilisation des journaux natifs standards.

## Règles Sigma pré-converties

Les règles Sigma curées de la manière décrite sur cette page — en dé-abstrayant le champ `logsource` — sont hébergées dans le dépôt [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) dans le dossier `sigma`.

## Environnement de l'outil

Si vous souhaitez convertir localement des règles Sigma au format compatible Hayabusa, vous devez d'abord installer [Poetry](https://python-poetry.org/). Veuillez consulter la [documentation d'installation](https://python-poetry.org/docs/#installation) officielle de Poetry.

## Utilisation de l'outil

`sigma-to-hayabusa-converter.py` est notre principal outil pour convertir le champ `logsource` des règles Sigma au format compatible Hayabusa. Effectuez les tâches suivantes pour l'exécuter :

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Après avoir exécuté les commandes ci-dessus, les règles converties au format compatible Hayabusa seront générées dans le répertoire `./converted_sigma_rules`.
