# Création de fichiers de règles

## À propos de Hayabusa-Rules

Il s'agit d'un dépôt contenant des règles sigma sélectionnées qui détectent les attaques dans les journaux d'événements Windows.
Il est principalement utilisé pour les règles de détection et les fichiers de configuration de [Hayabusa](https://github.com/Yamato-Security/hayabusa), ainsi que pour la détection sigma intégrée de [Velociraptor](https://github.com/Velocidex/velociraptor).
L'avantage d'utiliser ce dépôt plutôt que le [dépôt sigma en amont](https://github.com/SigmaHQ/sigma) est que nous n'incluons que les règles que la plupart des outils natifs sigma devraient être capables d'analyser.
Nous désabstrayons également le champ `logsource` en ajoutant aux règles les champs nécessaires `Channel`, `EventID`, etc., afin de faciliter la compréhension de ce que la règle filtre et, surtout, de réduire les faux positifs.
Nous créons également de nouvelles règles avec des noms et des valeurs de champs convertis pour les règles `process_creation` et les règles basées sur le `registry`, afin que les règles sigma ne détectent pas seulement dans les journaux Sysmon, mais aussi dans les journaux Windows intégrés.

## À propos de la création de fichiers de règles

Les règles de détection Hayabusa sont écrites au format [YAML](https://en.wikipedia.org/wiki/YAML) avec une extension de fichier `.yml`. (Les fichiers `.yaml` seront ignorés.)
Elles constituent un sous-ensemble des règles sigma mais contiennent aussi quelques fonctionnalités supplémentaires.
Nous essayons de les rendre aussi proches que possible des règles sigma afin qu'il soit facile de reconvertir les règles Hayabusa en sigma pour les redonner à la communauté.
Les règles Hayabusa peuvent exprimer des règles de détection complexes en combinant non seulement de simples correspondances de chaînes, mais aussi des expressions régulières, des conditions `AND`, `OR`, et d'autres.
Dans cette section, nous expliquerons comment écrire des règles de détection Hayabusa.

### Format du fichier de règle

Exemple :

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## Section auteur

- **author [requis]** : Nom du ou des auteurs.
- **date [requis]** : Date à laquelle la règle a été créée.
- **modified** [optionnel] : Date à laquelle la règle a été mise à jour.

> ## Section alerte

- **title [requis]** : Titre du fichier de règle. Ce sera également le nom de l'alerte affichée, donc plus c'est bref, mieux c'est. (Ne devrait pas dépasser 85 caractères.)
- **details** [optionnel] : Les détails de l'alerte qui s'affiche. Veuillez afficher tous les champs du journal d'événements Windows utiles pour l'analyse. Les champs sont séparés par `" ¦ "`. Les espaces réservés de champ sont entourés d'un `%` (Exemple : `%MemberName%`) et doivent être définis dans `rules/config/eventkey_alias.txt`. (Expliqué ci-dessous.)
- **description** [optionnel] : Une description de la règle. Elle ne s'affiche pas, vous pouvez donc la rendre longue et détaillée.

> ## Section règle

- **id [requis]** : Un UUID version 4 généré aléatoirement, utilisé pour identifier la règle de manière unique. Vous pouvez en générer un [ici](https://www.uuidgenerator.net/version4).
- **level [requis]** : Niveau de gravité basé sur [la définition de sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Veuillez écrire l'une des valeurs suivantes : `informational`,`low`,`medium`,`high`,`critical`
- **status[requis]** : Statut basé sur [la définition de sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Veuillez écrire l'une des valeurs suivantes : `deprecated`, `experimental`, `test`, `stable`.
- **logsource [requis]** : Bien que cela ne soit pas réellement utilisé par Hayabusa pour le moment, nous définissons logsource de la même manière que sigma afin d'être compatible avec les règles sigma.
- **detection  [requis]** : La logique de détection se place ici. (Expliqué ci-dessous.)
- **falsepositives [requis]** : Les possibilités de faux positifs. Par exemple : `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Si c'est inconnu, veuillez écrire `unknown`.
- **tags** [optionnel] : Si la technique est une technique [LOLBINS/LOLBAS](https://lolbas-project.github.io/), veuillez ajouter le tag `lolbas`. Si l'alerte peut être mappée à une technique du framework [MITRE ATT&CK](https://attack.mitre.org/), veuillez ajouter l'ID de technique (Exemple : `attack.t1098`) et toutes les tactiques applicables ci-dessous :
  - `attack.reconnaissance` -> Reconnaissance (Recon)
  - `attack.resource-development` -> Resource Development  (ResDev)
  - `attack.initial-access` -> Initial Access (InitAccess)
  - `attack.execution` -> Execution (Exec)
  - `attack.persistence` -> Persistence (Persis)
  - `attack.privilege-escalation` -> Privilege Escalation (PrivEsc)
  - `attack.stealth` -> Stealth (Stealth)
  - `attack.defense-impairment` -> Defense Impairment (DefImpair)
  - `attack.credential-access` -> Credential Access (CredAccess)
  - `attack.discovery` -> Discovery (Disc)
  - `attack.lateral-movement` -> Lateral Movement (LatMov)
  - `attack.collection` -> Collection (Collect)
  - `attack.command-and-control` -> Command and Control (C2)
  - `attack.exfiltration` -> Exfiltration (Exfil)
  - `attack.impact` -> Impact (Impact)
- **references** [optionnel] : Tout lien vers des références.
- **ruletype [requis]** : `Hayabusa` pour les règles hayabusa. Les règles automatiquement converties depuis les règles sigma Windows seront `Sigma`.

> ## Exemple d'événement XML

- **sample-message [requis]** : Désormais, nous demandons aux auteurs de règles d'inclure des exemples de messages pour leurs règles. Il s'agit du message rendu que l'Observateur d'événements de Windows affiche.
- **sample-evtx [requis]** : Désormais, nous demandons aux auteurs de règles d'inclure des exemples d'événements XML pour leurs règles.
