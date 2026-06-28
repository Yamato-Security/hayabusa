# Saran Pembuatan Aturan

## Saran pembuatan aturan

1. **Jika memungkinkan, selalu tentukan nama `Channel` atau `ProviderName` dan nomor `EventID`.** Secara default, hanya event ID yang tercantum dalam `./rules/config/target_event_IDs.txt` yang akan dipindai, sehingga Anda mungkin perlu menambahkan nomor `EventID` baru ke file ini jika EID tersebut belum ada di dalamnya.

2. **Mohon jangan menggunakan beberapa field `selection` atau `filter` dan pengelompokan yang berlebihan saat tidak diperlukan.** Sebagai contoh:

#### Daripada

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

#### Mohon lakukan ini

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

3. **Saat Anda memerlukan beberapa bagian, mohon beri nama bagian pertama dengan informasi channel dan event ID pada bagian `section_basic` dan selection lainnya dengan nama yang bermakna setelah `section_` dan `filter_`. Selain itu, mohon tuliskan komentar untuk menjelaskan apa pun yang sulit dipahami.** Sebagai contoh:

#### Daripada

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

#### Mohon lakukan ini

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

## Mengonversi aturan Sigma ke format Hayabusa

Kami telah membuat backend untuk mengonversi aturan dari Sigma ke format yang kompatibel dengan Hayabusa [di sini](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).
