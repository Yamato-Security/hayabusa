# Kural Oluşturma Tavsiyeleri

## Kural oluşturma tavsiyeleri

1. **Mümkün olduğunda, her zaman `Channel` veya `ProviderName` adını ve `EventID` numarasını belirtin.** Varsayılan olarak yalnızca `./rules/config/target_event_IDs.txt` dosyasında listelenen olay ID'leri taranır; bu nedenle EID zaten orada yoksa bu dosyaya yeni bir `EventID` numarası eklemeniz gerekebilir.

2. **Gerekli olmadığında lütfen birden fazla `selection` veya `filter` alanı ve aşırı gruplama kullanmayın.** Örneğin:

#### Bunun yerine

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

#### Lütfen bunu yapın

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

3. **Birden fazla bölüme ihtiyaç duyduğunuzda, lütfen ilk bölümü kanal ve olay ID bilgisiyle `section_basic` bölümünde adlandırın ve diğer seçimleri `section_` ve `filter_` öneklerinden sonra anlamlı adlarla adlandırın. Ayrıca, anlaşılması zor olan her şeyi açıklamak için lütfen yorumlar yazın.** Örneğin:

#### Bunun yerine

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

#### Lütfen bunu yapın

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

## Sigma kurallarını Hayabusa formatına dönüştürme

Kuralları Sigma'dan Hayabusa uyumlu formata dönüştürmek için bir arka uç oluşturduk: [burada](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).
