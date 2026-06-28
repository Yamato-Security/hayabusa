# Conseils pour la création de règles

## Conseils pour la création de règles

1. **Lorsque cela est possible, spécifiez toujours le nom du `Channel` ou du `ProviderName` ainsi que le numéro de l'`EventID`.** Par défaut, seuls les identifiants d'événements répertoriés dans `./rules/config/target_event_IDs.txt` seront analysés. Vous devrez donc peut-être ajouter un nouveau numéro d'`EventID` à ce fichier si l'EID ne s'y trouve pas déjà.

2. **Veuillez ne pas utiliser plusieurs champs `selection` ou `filter` ni un regroupement excessif lorsque cela n'est pas nécessaire.** Par exemple :

#### Au lieu de

```yaml
detection:
    SELECTION_1:
        Channnel: Security
    SELECTION_2:
        EventID: 4625
    SELECTION_3:
        LogonType: 3
    FILTER_1:
        SubStatus: "0xc0000064"   #Non-existent user
    FILTER_2:
        SubStatus: "0xc000006a"   #Wrong password
    condition: SELECTION_1 and SELECTION_2 and SELECTION_3 and not (FILTER_1 or FILTER_2)
```

#### Veuillez faire ceci

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        - SubStatus: "0xc0000064"   #Non-existent user
        - SubStatus: "0xc000006a"   #Wrong password
    condition: selection and not filter
```

3. **Lorsque vous avez besoin de plusieurs sections, veuillez nommer la première section contenant les informations de canal et d'identifiant d'événement dans la section `section_basic`, et les autres sélections avec des noms significatifs après `section_` et `filter_`. Veuillez également écrire des commentaires pour expliquer tout ce qui est difficile à comprendre.** Par exemple :

#### Au lieu de

```yaml
detection:
    Takoyaki:
        Channel: Security
        EventID: 4648
    Naruto:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    Sushi:
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    Godzilla:
        SubjectUserName|endswith: "$"
    Ninja:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$"
        IpAddress: "-"
    Daisuki:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: Takoyaki and Daisuki and not (Naruto and not Godzilla) and not Ninja and not Sushi
```

#### Veuillez faire ceci

```yaml
detection:
    selection_basic:
        Channel: Security
        EventID: 4648
    selection_TargetUserIsComputerAccount:
        TargetUserName|endswith: "$"
        IpAddress: "-"
    filter_UsersAndTargetServerAreComputerAccounts:     #Filter system noise
        SubjectUserName|endswith: "$"
        TargetUserName|endswith: "$"
        TargetInfo|endswith: "$"
    filter_SubjectUserIsComputerAccount:
        SubjectUserName|endswith: "$"
    filter_SystemAccounts:
        TargetUserName|re: "(DWM|UMFD)-([0-9]|1[0-2])$" #Filter out default Desktop Windows Manager and User Mode Driver Framework accounts
        IpAddress: "-"                                  #Don't filter if the IP address is remote to catch attackers who created backdoor accounts that look like DWM-12, etc..
    selection_SuspiciousProcess:
        - ProcessName|endswith: "powershell.exe"
        - ProcessName|endswith: "WMIC.exe"
    condition: selection_basic and selection_SuspiciousProcess and not (selection_TargetUserIsComputerAccount
               and not filter_SubjectUserIsComputerAccount) and not filter_SystemAccounts and not filter_UsersAndTargetServerAreComputerAccounts
```

## Conversion des règles Sigma au format Hayabusa

Nous avons créé un backend pour convertir les règles du format Sigma au format compatible Hayabusa [ici](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).
