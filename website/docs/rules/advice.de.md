# Ratschläge zur Regelerstellung

## Ratschläge zur Regelerstellung

1. **Geben Sie nach Möglichkeit immer den Namen `Channel` oder `ProviderName` und die `EventID`-Nummer an.** Standardmäßig werden nur die in `./rules/config/target_event_IDs.txt` aufgeführten Event-IDs gescannt. Daher müssen Sie dieser Datei möglicherweise eine neue `EventID`-Nummer hinzufügen, falls die EID dort noch nicht enthalten ist.

2. **Bitte verwenden Sie nicht mehrere `selection`- oder `filter`-Felder und übermäßige Gruppierungen, wenn dies nicht erforderlich ist.** Zum Beispiel:

#### Anstelle von

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

#### Bitte tun Sie dies

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

3. **Wenn Sie mehrere Abschnitte benötigen, benennen Sie bitte den ersten Abschnitt mit Channel- und Event-ID-Informationen im Abschnitt `section_basic` und andere Selektionen mit aussagekräftigen Namen nach `section_` und `filter_`. Bitte schreiben Sie außerdem Kommentare, um alles Schwerverständliche zu erläutern.** Zum Beispiel:

#### Anstelle von

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

#### Bitte tun Sie dies

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

## Konvertieren von Sigma-Regeln in das Hayabusa-Format

Wir haben ein Backend erstellt, um Regeln von Sigma in ein Hayabusa-kompatibles Format zu konvertieren [hier](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).
