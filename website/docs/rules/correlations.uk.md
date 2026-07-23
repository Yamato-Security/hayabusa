## Правила підрахунку подій (Event Count)

Це правила, які підраховують певні події та сповіщають, якщо за певний проміжок часу відбувається занадто багато або занадто мало таких подій.
Поширені приклади виявлення великої кількості подій за певний період часу — це виявлення атак на вгадування паролів, атак розпилення паролів (password spray) та атак на відмову в обслуговуванні.
Ви також можете використовувати ці правила для виявлення проблем з надійністю джерела журналів, наприклад, коли певні події опускаються нижче певного порогу.

### Приклад правила підрахунку подій:

У наступному прикладі використовуються два правила для виявлення атак на вгадування паролів.
Сповіщення з'явиться, коли згадуване правило збігається 5 або більше разів протягом 5 хвилин і поле `IpAddress` є однаковим для цих подій.

> Зверніть увагу, що ми включили лише необхідні поля для розуміння концепції.
> Повне правило, на якому базується цей приклад, розташоване [тут](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) для вашого ознайомлення.

### Кореляційне правило підрахунку подій:

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

### Правило невдалого входу — неправильний пароль:

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

### Приклад застарілого правила `count`:

Наведене вище кореляційне та згадуване правила дають ті самі результати, що й наступне правило, яке використовує старіший модифікатор `count`:

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
### Вивід правила підрахунку подій:

Наведені вище правила створять такий вивід:
```
% ./hayabusa dfir-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Правила підрахунку значень (Value Count)

Ці правила підраховують однакові події протягом проміжку часу з **різними** значеннями заданого поля.

Приклади:

- Сканування мережі, коли одна вихідна IP-адреса намагається підключитися до багатьох різних IP-адрес призначення та/або портів.
- Атаки розпилення паролів, коли одне джерело не може автентифікуватися з багатьма різними користувачами.
- Виявлення інструментів на кшталт BloodHound, які перелічують багато AD-груп з високими привілеями за короткий проміжок часу.

### Приклад правила підрахунку значень:

Наступне правило виявляє, коли зловмисник намагається вгадати імена користувачів.
Тобто, коли **та сама** вихідна IP-адреса (`IpAddress`) не може увійти більш ніж з 3 **різними** іменами користувачів (`TargetUserName`) протягом 5 хвилин.

> Зверніть увагу, що ми включили лише необхідні поля для розуміння концепції.
> Повне правило, на якому базується цей приклад, розташоване [тут](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) для вашого ознайомлення.

### Кореляційне правило підрахунку значень:

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

### Правило невдалого входу (неіснуючий користувач) для підрахунку значень:

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

### Правило із застарілим модифікатором `count`:

Наведене вище кореляційне та згадуване правила дають ті самі результати, що й наступне правило, яке використовує старіший модифікатор `count`:

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

### Вивід правила підрахунку значень:

Наведені вище правила створять такий вивід:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Правила часової близькості (Temporal Proximity)

Усі події, визначені правилами, на які посилається поле rule, мають відбутися у проміжку часу, визначеному timespan.
Значення полів, визначених у `group-by`, повинні мати однакове значення (наприклад: той самий хост, користувач тощо).

### Приклад правила часової близькості:

Приклад: команди розвідки, визначені у трьох правилах Sigma, викликаються у довільному порядку протягом 5 хвилин у системі тим самим користувачем.

### Кореляційне правило часової близькості:

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

## Правила впорядкованої часової близькості (Ordered Temporal Proximity)

Кореляційний тип `temporal_ordered` поводиться як `temporal` і додатково вимагає, щоб події з'являлися в порядку, наданому в атрибуті `rules`.

### Приклад правила впорядкованої часової близькості:

Приклад: за багатьма невдалими входами, як визначено вище, слідує успішний вхід того самого облікового запису користувача протягом 1 години:

### Кореляційне правило впорядкованої часової близькості:

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

## Примітки щодо кореляційних правил

1. Вам слід включити всі ваші кореляційні та згадувані правила в один файл і розділити їх YAML-роздільником `---`.

2. За замовчуванням згадувані кореляційні правила не виводитимуться. Якщо ви хочете побачити вивід згадуваних правил, то вам потрібно додати `generate: true` під `correlation`. Це дуже корисно вмикати та перевіряти під час створення кореляційних правил.

    Приклад:
    ```
    correlation:
        generate: true
    ```
3. Ви можете використовувати псевдоніми замість ідентифікаторів правил при посиланні на правила, щоб зробити речі легшими для розуміння.

4. Ви можете посилатися на кілька правил.

5. Ви можете використовувати кілька полів у `group-by`. Якщо ви це зробите, то всі значення в цих полях повинні бути однаковими, інакше ви не отримаєте сповіщення. Здебільшого ви писатимете правила, які фільтрують за певними полями з `group-by`, щоб зменшити кількість хибних спрацьовувань, однак можна опустити `group-by`, щоб створити більш загальне правило.

6. Часова мітка кореляційного правила буде самим початком атаки, тому вам слід перевірити події після неї, щоб підтвердити, чи є це хибним спрацьовуванням чи ні.
