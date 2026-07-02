# Курування правил Sigma для журналів подій Windows

Ця сторінка описує, як Yamato Security курує вихідні правила [Sigma](https://github.com/SigmaHQ/sigma) для журналів подій Windows, приводячи їх до зручнішої форми шляхом деабстрагування поля `logsource` та відфільтровування правил, які неможливо або важко використовувати. Це робиться за допомогою інструмента [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter), який використовується здебільшого для створення курованого набору правил Sigma, розміщеного в [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules). Цей набір правил використовується в [Hayabusa](https://github.com/Yamato-Security/hayabusa) та [Velociraptor](https://github.com/Velocidex/velociraptor).

!!! info "Джерело"
    Ця документація підтримується разом з інструментом-конвертером у [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter). Сподіваємося, що ця інформація також буде корисною для інших проєктів, які хочуть використовувати правила Sigma для виявлення атак у журналах подій Windows. Дивіться також [Створення файлів правил](creating-rules.md) та [Модифікатори полів](field-modifiers.md).

## Коротко про головне

* Деабстрагування поля `logsource` та створення нових файлів правил `.yml` для вбудованих правил, а також для оригінальних правил на основі Sysmon, спрощує повну підтримку вбудованих подій для правил Sigma та робить правила зручнішими для читання аналітиками.
* Під час написання правил Sigma для журналів подій Windows важливо розуміти відмінності між оригінальними журналами на основі Sysmon та сумісними з ними вбудованими журналами, а в ідеалі — писати правила так, щоб вони були сумісні з обома.
* Багато організацій не можуть або не хочуть встановлювати та підтримувати агентів Sysmon на всіх своїх кінцевих точках Windows, оскільки не мають виділених ресурсів для цього або хочуть уникнути ризику будь-яких уповільнень чи збоїв, спричинених Sysmon. Через це важливо вмикати якомога більше вбудованих журналів подій та використовувати інструменти, здатні виявляти атаки в цих вбудованих журналах.

## Проблеми з вихідними правилами Sigma для журналів подій Windows

Головною проблемою при створенні власного парсера правил Sigma для журналів подій Windows, за нашим досвідом, була підтримка поля `logsource`. Наразі це одна з небагатьох речей, які Hayabusa ще не підтримує нативно, оскільки це все ще дуже складно і перебуває в стадії розробки. Наразі ми обходимо це, конвертуючи вихідні правила у зручніший для використання формат, як детально пояснено нижче.

### Про поле `logsource`

У правилах Sigma для журналів подій Windows поле `product` встановлюється в `windows`, після чого йде або поле `service`, або поле `category`.

Приклад поля `service`:

```yaml
logsource:
    product: windows
    service: application
```

Приклад поля `category`:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Поля Service

Поля `service` порівняно прості в обробці та вказують будь-якому бекенду, що використовує правило Sigma, шукати один або кілька каналів на основі поля `Channel` у XML-журналі подій Windows.

**Приклад одного каналу**

`service: application` — це те саме, що додати до правила Sigma умову вибірки `Channel: Application`.

**Приклад кількох каналів**

`service: applocker` наразі створює найбільшу кількість каналів для пошуку, оскільки AppLocker зберігає інформацію в чотирьох різних журналах. Щоб коректно шукати лише в журналах AppLocker, до логіки правила Sigma потрібно додати таку умову:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Поточний список зіставлень service**

| Service                                    | Channel                                                                                                                             |
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

**Джерела зіставлень service**

Ми створили YAML-файли зіставлень служб до імен каналів, які періодично підтримуємо та розміщуємо в репозиторії конвертера. Вони базуються на інформації про зіставлення служб з [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml): хоча це, схоже, не є офіційним загальним конфігураційним файлом для використання людьми, він, вочевидь, найбільш актуальний.

#### Поля Category

Більшість полів `category` просто додають умову перевірки певних ідентифікаторів подій у полі `EventID`, окрім пошуку за конкретним `Channel`. Назви категорій здебільшого базуються на подіях [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), з деякими додатковими категоріями для вбудованих журналів PowerShell та Windows Defender.

**Приклад поля category**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Поточний список зіставлень category**

Деякі категорії зіставляються з кількома службами/EventID (позначено **жирним**).

| Category                  | Service            | EventIDs                                                               |
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

**Проблеми поля category**

Як показано вище, та сама `category` може використовувати кілька служб та ідентифікаторів подій (позначено **жирним**). Це означає, що деякі правила Sigma, розроблені для `sysmon`, можна використовувати зі схожими вбудованими журналами подій Windows `security`, якщо поля, які використовує правило, також існують у вбудованому журналі подій. У такому випадку назви полів — а іноді й значення — можуть потребувати перетворення для відповідності назвам полів та значенням вбудованого журналу подій `security`. Хоча для деяких категорій це може бути так само просто, як перейменування кількох назв полів, для інших категорій це може вимагати різноманітних перетворень і значень полів. Те, як ми виконуємо це перетворення, та сумісність між журналами `sysmon` і журналами `security` детально пояснено [нижче](#sysmon-builtin-comparison).

**Джерела зіставлень category**

YAML-файли зіставлень для категорій також розміщені в репозиторії конвертера та також базуються на інформації з [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

## Переваги та проблеми абстрагування джерела журналу

Абстрагування джерела журналу та створення зіставлень для різних `Channel`, `EventID` та полів на бекенді має як переваги, так і проблеми.

### Переваги

1. Може бути простіше перетворювати назви полів `Channel` та `EventID` у відповідні назви полів бекенду під час конвертації правил Sigma в запити інших бекендів.
2. Можна об'єднати два правила в одне. Наприклад, події створення процесів можуть реєструватися як у `Sysmon 1`, так і в `Security 4688`. Замість написання двох правил, які переглядають різні канали, ідентифікатори подій та поля, але в іншому містять однакову логіку, можна стандартизувати поля до того, що використовує Sysmon, а потім доручити конвертеру бекенду додати поля `Channel` та `EventID` і за потреби перетворити іншу інформацію полів. Це спрощує підтримку правил, оскільки правил, які потрібно підтримувати, стає менше.
3. Хоча це трапляється дуже рідко, якщо джерело журналу починає реєструвати свої дані в іншому `Channel` або `EventID`, потрібно оновити лише логіку зіставлення замість оновлення всіх правил Sigma, що спрощує підтримку.

### Проблеми

1. Що станеться, якщо оригінальне правило Sigma на основі Sysmon використовує поле, яке не існує у вбудованих журналах, для відфільтровування хибних спрацювань? Чи слід усе одно створювати правило, надаючи пріоритет можливому виявленню, чи ігнорувати його, надаючи пріоритет меншій кількості хибних спрацювань? В ідеалі потрібно було б створити два правила з різними `severity`, `status` та інформацією про хибні спрацювання, щоб користувач міг краще з цим впоратися.
2. Це ускладнює фільтрування правил, оскільки не можна просто фільтрувати за полями `Channel` чи `EventID` у файлі `.yml` або за шляхом файлу правила, якщо файл ще не створено, — тому що це похідне правило для вбудованого журналу замість оригінального правила Sysmon. Крім того, оскільки ідентифікатор правила той самий, не можна фільтрувати за ідентифікаторами правил.
3. Це ускладнює підтвердження сповіщення, коли сповіщення надходить від правила для вбудованих журналів, похідного від журналу Sysmon. Назви полів та значення не збігатимуться, тож аналітику потрібно розуміти дещо складний процес перетворення.
4. Це ускладнює створення логіки бекенду.

Хоча ми не можемо нічого зробити з першою проблемою, окрім створення та підтримки нових правил, коли є вагомий сценарій використання, що виправдовує зусилля, для вирішення проблем 2–4 ми вирішили деабстрагувати поле `logsource` та створювати два набори правил для будь-якого правила, яке може породити кілька правил. Правила, здатні виявляти атаки у вбудованих журналах, виводяться в каталог `builtin`, а правила для Sysmon виводяться в каталог `sysmon`.

## Приклад перетворення

Ось простий приклад для кращого розуміння процесу перетворення.

**До перетворення** — оригінальне правило Sigma:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Після перетворення** — сумісне з Hayabusa правило для журналів Sysmon:

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

...та сумісне з Hayabusa правило для вбудованих журналів Windows:

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

Як бачите, було створено два правила: одне для журналів Sysmon 1 та одне для вбудованих журналів Security 4688. Було додано нову умову `process_creation` з інформацією про канал та ідентифікатор події, і її додано до поля `condition`, щоб вимагати виконання цієї умови. Також оригінальну назву поля `Image` було змінено на `NewProcessName`.

## Спільні риси перетворення

Перш ніж детально пояснювати, як ми перетворюємо конкретні категорії, ось частина перетворення, яка застосовується до всіх правил.

1. Будь-яке правило, ідентифікатор якого є в `ignore-uuid-list.txt`, ігнорується. Наразі ми ігноруємо лише правила, що спричиняють хибні спрацювання у Windows Defender, оскільки вони містять ключові слова на кшталт `mimikatz`.
2. "Заповнювачі" (placeholder) правила ігноруються, оскільки їх неможливо використовувати як є. Це правила, розміщені в теці [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) у репозиторії Sigma.
3. Правила, які використовують несумісні модифікатори полів, відкидаються. Hayabusa підтримує більшість модифікаторів полів, тож конвертер не виводитиме жодного правила, що використовує модифікатор, окрім цих, щоб уникнути помилок парсингу (див. [Модифікатори полів](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Правила із синтаксичними помилками не перетворюються.
5. Теги в правилах `deprecated` та `unsupported` оновлюються з формату V1 до формату V2, який використовує `-` замість `_`, щоб зберегти всюди узгодженість та легше обробляти скорочення в Hayabusa. Приклад: `initial_access` стає `initial-access`.
6. Оскільки ми додаємо до правил інформацію `Channel` та `EventID`, ми створюємо новий ідентифікатор UUIDv4, використовуючи MD5-хеш оригінального ідентифікатора, вказуємо оригінальний ідентифікатор у полі `related` та позначаємо `type` як `derived`. Для правил, які можуть бути перетворені на кілька правил (`sysmon` та `builtin`), нам потрібно створити нові ідентифікатори правил і для похідних правил `builtin`. Для цього ми обчислюємо MD5-хеш ідентифікатора правила `sysmon` і використовуємо його для ідентифікатора UUIDv4. Наприклад:

    Оригінальне правило Sigma:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Нове правило `sysmon`:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Нове правило `builtin`:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Правила, які виявляють щось у вбудованих журналах подій Windows, виводяться в каталог `builtin`, тоді як правила, що покладаються на журнали Sysmon, виводяться в каталог `sysmon`, з підкаталогами, що відповідають каталогам у вихідному репозиторії Sigma.

## Обмеження перетворення

Наразі є лише одна [відома вада](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2): рядки коментарів у правилах Sigma не будуть включені у вихідні правила, якщо коментарі не йдуть після якогось вихідного коду.

## Порівняння подій Sysmon та вбудованих подій і перетворення правил { #sysmon-builtin-comparison }

### Створення процесу

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Вбудований журнал
    * Channel: `Security`
    * Event ID: `4688`

**Порівняння**

![Порівняння створення процесу](../assets/rules-doc/process_creation_comparison.png)

**Примітки щодо перетворення**

1. Інформацію поля `User` потрібно розділити на поля `SubjectUserName` та `SubjectDomainName`.
2. Назва поля `LogonId` змінюється на `SubjectLogonId`, а будь-які літери в шістнадцятковому значенні потрібно зробити малими.
3. Назва поля `ProcessId` змінюється на `NewProcessId`, а значення потрібно перетворити в шістнадцяткове.
4. Назва поля `Image` змінюється на `NewProcessName`.
5. Назва поля `ParentProcessId` змінюється на `ProcessId`, а значення потрібно перетворити в шістнадцяткове.
6. Назва поля `ParentImage` змінюється на `ParentProcessName`.
7. Назва поля `IntegrityLevel` змінюється на `MandatoryLabel`, і потрібне таке перетворення значень:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. Якщо правило містить такі поля, які існують лише в подіях `Security 4688`, то ми не створюємо правило `Sysmon 1`:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Якщо правило містить такі поля, які існують лише в подіях `Sysmon 1`, то ми не створюємо правило `Security 4688`:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. Є виняток для пунктів №8 та №9: навіть якщо використовується поле, яке існує лише в одній події журналу, але це поле в умові `OR`, то правило все одно слід створити. Наприклад, наступне правило **не** повинно породжувати правило `Security 4688`, оскільки поле `OriginalFileName` є обов'язковим (логіка `AND` всередині вибірки):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    Однак правило з наступною умовою **повинно** створити правило `Security 4688`, оскільки `OriginalFileName` є необов'язковим (логіка `OR` всередині вибірки):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    Складність полягає в тому, що ваш парсер має розуміти логіку не лише всередині вибірок, але й усередині поля `condition`. Наприклад, наступне правило **не повинно** створювати правило `Security 4688`, оскільки воно використовує логіку `AND`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    Однак наступне правило **повинно** створити правило `Security 4688`, оскільки воно використовує логіку `OR`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Інші примітки**

* Поле `SubjectUserSid` у `Security 4688` показує SID; проте у відрендереному повідомленні `Message` журналу подій воно перетворюється на `DOMAIN\User`.
* Події `Security 4688` можуть не містити інформації про параметри командного рядка в `CommandLine` залежно від налаштувань.
* `TokenElevationType` відображається як є в `Message` і не рендериться.
* `S-1-16-4096` тощо всередині `MandatoryLabel` перетворюється на `Mandatory Label\Low Mandatory Level` тощо у відрендереному `Message`.

**Налаштування вбудованого журналу**

!!! warning "Не увімкнено за замовчуванням"
    Важливі вбудовані журнали подій створення процесів `Security 4688` не увімкнено за замовчуванням. Щоб використовувати більшість правил Sigma, вам потрібно увімкнути як події `4688`, так і журналювання параметрів командного рядка.

*Увімкнення через групову політику:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*Увімкнення через командний рядок:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Мережеве з'єднання

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Вбудований журнал
    * Channel: `Security`
    * Event ID: `5156`

**Порівняння**

![Порівняння мережевого з'єднання](../assets/rules-doc/network_connection_comparison.png)

**Примітки щодо перетворення**

1. Назва поля `ProcessId` змінюється на `ProcessID`.
2. Назва поля `Image` змінюється на `Application`, а `C:\` змінюється на `\device\harddiskvolume?\`. (Примітка: оскільки ми не знаємо номер тому жорсткого диска, ми замінюємо його односимвольним підстановним знаком `?`.)
3. Значення поля `Protocol` `tcp` змінюється на `6`, а `udp` — на `17`.
4. Назва поля `Initiated` змінюється на `Direction`, а значення `true` змінюється на `%%14593`, а `false` — на `%%14592`.
5. Назва поля `SourceIp` змінюється на `SourceAddress`.
6. Назва поля `DestinationIp` змінюється на `DestAddress`.
7. Назва поля `DestinationPort` змінюється на `DestPort`.

**Налаштування вбудованого журналу**

!!! warning "Не увімкнено за замовчуванням"
    Вбудовані журнали мережевих з'єднань `Security 5156` не увімкнено за замовчуванням. Вони створюють велику кількість журналів, які можуть перезаписати інші важливі журнали в журналі подій `Security` та потенційно уповільнити систему, якщо вона має велику кількість мережевих з'єднань. Переконайтеся, що максимальний розмір файлу для журналу `Security` є великим, та протестуйте, щоб переконатися, що немає негативного впливу на систему.

*Увімкнення через групову політику:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*Увімкнення через командний рядок:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...або таке, якщо ви використовуєте неанглійську локаль:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Дивіться також"
    Докладніше про ввімкнення вбудованих журналів подій Windows, необхідних для збору доказів, на які покладаються ці правила, див. [Журналювання Windows та Sysmon](../resources/logging.md) та проєкт [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

## Поради щодо написання правил Sigma

!!! tip
    Якщо ви використовуєте будь-яке поле, яке існує в журналі `sysmon`, але не в журналі `builtin`, обов'язково зробіть це поле необов'язковим, щоб правило все ще можна було використовувати для журналів `builtin`.

Наприклад:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Ця вибірка шукає, коли процес (`Image`) має назву `addinutil.exe`. Проблема в тому, що зловмисник може просто перейменувати файл, щоб обійти правило. Поле `OriginalFileName`, яке існує лише в журналах Sysmon, — це назва файлу, вбудована в бінарний файл під час компіляції. Навіть якщо зловмисник перейменує файл, вбудована назва не зміниться, тож це правило може виявляти атаки, у яких зловмисник перейменував файл, при використанні Sysmon, а також може виявляти атаки, у яких назву файлу не було змінено, при використанні стандартних вбудованих журналів.

## Попередньо перетворені правила Sigma

Правила Sigma, куровані в описаний на цій сторінці спосіб — шляхом деабстрагування поля `logsource` — розміщені в репозиторії [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) у теці `sigma`.

## Середовище інструмента

Якщо ви хочете локально перетворювати правила Sigma у сумісний з Hayabusa формат, спочатку потрібно встановити [Poetry](https://python-poetry.org/). Будь ласка, зверніться до офіційної [документації зі встановлення](https://python-poetry.org/docs/#installation) Poetry.

## Використання інструмента

`sigma-to-hayabusa-converter.py` — це наш основний інструмент для перетворення поля `logsource` правил Sigma у сумісний з Hayabusa формат. Щоб його запустити, виконайте такі завдання:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Після виконання наведених вище команд правила, перетворені у сумісний з Hayabusa формат, будуть виведені в каталог `./converted_sigma_rules`.

## Автори

Цей документ створив Zach Mathis (@yamatosecurity), а японською переклав Fukusuke Takahashi (@fukusuket).

Реалізацію та підтримку інструмента `sigma-to-hayabusa-converter.py` виконує Fukusuke Takahashi.

Оригінальний інструмент перетворення, який покладався на нині застарілий інструмент `sigmac`, реалізували ItiB ([@itiB_S144](https://x.com/itib_s144)) та James Takai / hachiyone (@hach1yon).
