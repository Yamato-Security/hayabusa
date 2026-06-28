# Поле виявлення

## Основи selection

Спершу буде пояснено основи того, як створити правило selection.

### Як писати логіку AND та OR

Щоб записати логіку AND, ми використовуємо вкладені словники.
Правило виявлення нижче визначає, що **обидві умови** мають бути істинними, щоб правило спрацювало.
- EventID має точно дорівнювати `7040`.
- **AND**
- Channel має точно дорівнювати `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

Щоб записати логіку OR, ми використовуємо списки (словники, що починаються з `-`).
У правилі виявлення нижче **будь-яка одна** з умов призведе до спрацювання правила.
- EventID має точно дорівнювати `7040`.
- **OR**
- Channel має точно дорівнювати `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

Ми також можемо комбінувати логіку `AND` та `OR`, як показано нижче.
У цьому випадку правило спрацьовує, коли обидві наступні умови є істинними.
- EventID є точно або `7040`, **OR** `7041`.
- **AND**
- Channel є точно `System`.

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

Нижче наведено уривок журналу подій Windows, відформатований у вихідному XML.
Поле `Event.System.Channel` у наведеному вище прикладі файлу правила посилається на вихідний XML-тег: `<Event><System><Channel>System<Channel><System></Event>`
Вкладені XML-теги замінюються іменами тегів, розділеними крапками (`.`).
У правилах hayabusa ці рядки полів, з'єднані разом крапками, називаються `eventkeys`.

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

#### Псевдоніми Eventkey

Довгі eventkeys з багатьма розділеннями `.` є поширеними, тому hayabusa використовуватиме псевдоніми, щоб з ними було легше працювати. Псевдоніми визначаються у файлі `rules/config/eventkey_alias.txt`. Цей файл є CSV-файлом, що складається зі зіставлень `alias` та `event_key`. Ви можете переписати наведене вище правило, як показано нижче, з псевдонімами, що робить правило легшим для читання.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Увага: невизначені псевдоніми Eventkey

Не всі псевдоніми eventkey визначені у `rules/config/eventkey_alias.txt`. Якщо ви не отримуєте правильні дані у повідомленні `details` (`Alert details`), а замість цього отримуєте `n/a` (недоступно), або якщо selection у вашій логіці виявлення не працює належним чином, то вам, можливо, потрібно оновити `rules/config/eventkey_alias.txt` новим псевдонімом.

### Як використовувати XML-атрибути в умовах

XML-елементи можуть мати атрибути, встановлені додаванням пробілу до елемента. Наприклад, `Name` у `Provider Name` нижче є XML-атрибутом елемента `Provider`.

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

Щоб вказати XML-атрибути в eventkey, використовуйте формат `{eventkey}_attributes.{attribute_name}`. Наприклад, щоб вказати атрибут `Name` елемента `Provider` у файлі правила, це виглядатиме так:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### Пошук grep

Hayabusa може виконувати пошук grep у файлах журналів подій Windows, не вказуючи жодних eventkeys.

Щоб виконати пошук grep, вкажіть detection, як показано нижче. У цьому випадку, якщо рядки `mimikatz` або `metasploit` присутні в журналі подій Windows, він спрацює. Також можливо вказувати символи підстановки.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Примітка: Hayabusa внутрішньо перетворює дані журналу подій Windows у формат JSON перед обробкою даних, тому неможливо зіставляти з XML-тегами.

### EventData

Журнали подій Windows поділяються на дві частини: частину `System`, де записуються фундаментальні дані (Event ID, Timestamp, Record ID, ім'я журналу (Channel)), та частину `EventData` або `UserData`, де записуються довільні дані залежно від Event ID.
Одна проблема, що часто виникає, полягає в тому, що імена полів, вкладених у `EventData`, усі називаються `Data`, тому описані досі eventkeys не можуть розрізнити `SubjectUserSid` та `SubjectUserName`.

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

Щоб впоратися з цією проблемою, ви можете вказати значення, призначене у `Data Name`. Наприклад, якщо ви хочете використати `SubjectUserName` та `SubjectDomainName` у EventData як умову правила, ви можете описати це наступним чином:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Аномальні шаблони в EventData

Деякі з тегів, вкладених у `EventData`, не мають атрибута `Name`.

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

Щоб виявити журнал подій, подібний до наведеного вище, ви можете вказати eventkey з ім'ям `Data`.
У цьому випадку умова спрацює, доки будь-який з вкладених тегів `Data` дорівнює `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Виведення даних поля з кількох полів з однаковим ім'ям

Деякі події зберігатимуть свої дані в полях, усі з яких називаються `Data`, як у попередньому прикладі.
Якщо ви вкажете `%Data%` у `details:`, усі дані будуть виведені у вигляді масиву.

Наприклад:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Якщо ви хочете вивести лише дані першого поля `Data`, ви можете вказати `%Data[1]%` у вашому рядку сповіщення `details:`, і буде виведено лише `rundll32.exe`.

## Модифікатори полів

Символ вертикальної риски можна використовувати з eventkeys, як показано нижче, для зіставлення рядків.
Усі умови, які ми описали досі, використовують точні збіги, але за допомогою модифікаторів полів ви можете описувати гнучкіші правила виявлення.
У наступному прикладі, якщо значення `Data` містить рядок `EngineVersion=2`, воно спрацює за умовою.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

Зіставлення рядків нечутливі до регістру. Однак вони стають чутливими до регістру щоразу, коли використовуються `|re` або `|equalsfield`.

### Підтримувані модифікатори полів Sigma

Hayabusa наразі є єдиним інструментом з відкритим кодом, який повністю підтримує всю специфікацію Sigma.

Ви можете перевірити поточний статус усіх підтримуваних модифікаторів полів, а також скільки разів ці модифікатори використовуються в правилах Sigma та Hayabusa, за адресою https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
Цей документ динамічно оновлюється щоразу, коли відбувається оновлення правил Sigma або Hayabusa.

- `'|all':`: Цей модифікатор поля відрізняється від наведених вище, оскільки він застосовується не до певного поля, а до всіх полів.

    У цьому прикладі обидва рядки `Keyword-1` та `Keyword-2` мають існувати, але можуть існувати будь-де в будь-якому полі:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Дані будуть закодовані в base64 трьома різними способами залежно від їхньої позиції в закодованому рядку. Цей модифікатор закодує рядок усіма трьома варіаціями та перевірить, чи закодований рядок десь у рядку base64.
- `|cased`: Робить пошук чутливим до регістру.
- `|cidr`: Перевіряє, чи значення поля відповідає нотації CIDR IPv4 або IPv6. (Напр.: `192.0.2.0/24`)
- `|contains`: Перевіряє, чи значення поля містить певний рядок.
- `|contains|all`: Перевіряє, чи містяться кілька слів у даних.
- `|contains|all|windash`: Те саме, що `|contains|windash`, але всі ключові слова мають бути присутні.
- `|contains|cased`: Перевіряє, чи значення поля містить певний чутливий до регістру рядок.
- `|contains|expand`: Перевіряє, чи значення поля містить рядок у конфігураційному файлі `expand` всередині `/config/expand/`.
- `|contains|windash`: Перевірятиме рядок як є, а також перетворить перший символ `-` на перестановки символів `/`, `–` (en dash), `—` (em dash) та `―` (horizontal bar).
- `|endswith`: Перевіряє, чи значення поля закінчується певним рядком.
- `|endswith|cased`: Перевіряє, чи значення поля закінчується певним чутливим до регістру рядком.
- `|endswith|windash`: Перевіряє кінець рядка та виконує варіації для тире.
- `|exists`: Перевіряє, чи поле існує.
- `|expand`: Перевіряє, чи значення поля дорівнює рядку в конфігураційному файлі `expand` всередині `/config/expand/`.
- `|fieldref`: Перевіряє, чи значення у двох полях однакові. Ви можете використовувати `not` у `condition`, якщо хочете перевірити, чи два поля різні.
- `|fieldref|contains`: Перевіряє, чи значення одного поля міститься в іншому полі.
- `|fieldref|endswith`: Перевіряє, чи поле зліва закінчується рядком поля справа. Ви можете використовувати `not` у `condition`, щоб перевірити, чи вони різні.
- `|fieldref|startswith`: Перевіряє, чи поле зліва починається з рядка поля справа. Ви можете використовувати `not` у `condition`, щоб перевірити, чи вони різні.
- `|gt`: Перевіряє, чи значення поля більше за певне число.
- `|gte`: Перевіряє, чи значення поля більше або дорівнює певному числу.
- `|lt`: Перевіряє, чи значення поля менше за певне число.
- `|lte`: Перевіряє, чи значення поля менше або дорівнює певному числу.
- `|re`: Використовуйте чутливі до регістру регулярні вирази. (Ми використовуємо regex crate, тому, будь ласка, ознайомтеся з документацією за адресою <https://docs.rs/regex/latest/regex/#syntax>, щоб дізнатися, як писати підтримувані регулярні вирази.)
    > Увага: [Синтаксис регулярних виразів у правилах Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) використовує PCRE з певними метасимволами для класів символів, lookbehind, atomic grouping тощо, які не підтримуються. Rust regex crate має бути в змозі використовувати всі регулярні вирази в правилах Sigma, але існує ймовірність несумісності. 
- `|re|i`: (Insensitive) Використовуйте нечутливі до регістру регулярні вирази.
- `|re|m`: (Multi-line) Зіставлення через кілька рядків. `^` / `$` зіставляють початок/кінець рядка.
- `|re|s`: (Single-line) крапка (`.`) зіставляє всі символи, включаючи символ нового рядка.
- `|startswith`: Перевіряє, чи значення поля починається з певного рядка.
- `|startswith|cased`: Перевіряє, чи значення поля починається з певного чутливого до регістру рядка.
- `|utf16|base64offset|contains`: Перевіряє, чи певний рядок UTF-16 закодований всередині рядка base64.
- `|utf16be|base64offset|contains`: Перевіряє, чи певний рядок UTF-16 big-endian закодований всередині рядка base64.
- `|utf16le|base64offset|contains`: Перевіряє, чи певний рядок UTF-16 little-endian закодований всередині рядка base64.
- `|wide|base64offset|contains`: Псевдонім для `utf16le|base64offset|contains`, перевіряє на рядки UTF-16 little-endian.

### Застарілі модифікатори полів

Наступні модифікатори тепер застарілі та замінені модифікаторами, які більше відповідають специфікаціям sigma.

- `|equalsfield`: Тепер замінено на `|fieldref`.
- `|endswithfield`: Тепер замінено на `|fieldref|endswith`.

### Модифікатори полів Expand

Модифікатори полів `expand` унікальні тим, що вони є єдиним модифікатором поля, який вимагає попереднього налаштування для використання.
Наприклад, вони використовують заповнювачі, такі як `%DC-MACHINE-NAME%`, і вимагають конфігураційного файлу з ім'ям `/config/expand/DC-MACHINE-NAME.txt`, який містить усі можливі імена машин DC.

Як це налаштувати, детальніше пояснюється [тут](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## Символи підстановки

Символи підстановки можна використовувати в eventkeys. У прикладі нижче, якщо `ProcessCommandLine` починається з рядка "malware", правило спрацює.
Специфікація фундаментально така сама, як і символи підстановки правил sigma, тому буде нечутливою до регістру.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Можна використовувати наступні два символи підстановки.
- `*`: Зіставляє будь-який рядок з нуля або більше символів. (Внутрішньо він перетворюється на регулярний вираз `.*`)
- `?`: Зіставляє будь-який окремий символ. (Внутрішньо перетворюється на регулярний вираз `.`)

Про екранування символів підстановки:
- Символи підстановки (`*` та `?`) можна екранувати за допомогою зворотної косої риски: `\*`, `\?`.
- Якщо ви хочете використати зворотну косу риску безпосередньо перед символом підстановки, то пишіть `\\*` або `\\?`.
- Екранування не потрібне, якщо ви використовуєте зворотні косі риски самі по собі.

## Ключове слово null

Ключове слово `null` можна використовувати для перевірки, чи поле не існує.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Примітка: Це відрізняється від `ProcessCommandLine: ''`, яке перевіряє, чи значення поля порожнє.

## condition

За допомогою нотації, яку ми пояснили вище, ви можете виразити логіку `AND` та `OR`, але це буде заплутано, якщо ви намагаєтеся визначити складну логіку.
Коли ви хочете створити складніші правила, вам слід використовувати ключове слово `condition`, як показано нижче.

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

Для `condition` можна використовувати наступні вирази.
- `{expression1} and {expression2}`: Вимагає обидва {expression1} AND {expression2}
- `{expression1} or {expression2}`: Вимагає або {expression1} OR {expression2}
- `not {expression}`: Обертає логіку {expression}
- `( {expression} )`: Встановлює пріоритет {expression}. Він дотримується тієї самої логіки пріоритету, що і в математиці.

У наведеному вище прикладі використовуються імена selection, такі як `SELECTION_1`, `SELECTION_2` тощо, але їх можна назвати як завгодно, доки вони містять лише наступні символи: `a-z A-Z 0-9 _`
> Однак, будь ласка, використовуйте стандартну угоду `selection_1`, `selection_2`, `filter_1`, `filter_2` тощо, щоб робити речі легкими для читання, коли це можливо.

## логіка not

Багато правил призведуть до хибних спрацювань, тому дуже поширеним є наявність selection для сигнатур для пошуку, а також filter selection, щоб не сповіщати про хибні спрацювання.
Наприклад:

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

# Кореляції Sigma

Ми реалізували всі кореляції Sigma версії 2.0.0, як визначено [тут](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

Підтримувані кореляції:
- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

Нові кореляційні правила "metrics" (`value_sum`, `value_avg`, `value_percentile`), випущені 12 вересня 2025 року в Sigma версії 2.1.0, наразі не підтримуються.
