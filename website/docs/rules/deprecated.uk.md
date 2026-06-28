# Застарілі можливості

Застарілі спеціальні ключові слова та агрегація `count` все ще підтримуються в Hayabusa, але в майбутньому не використовуватимуться всередині правил.

## Застарілі спеціальні ключові слова

Наразі можна вказувати такі спеціальні ключові слова:

- `value`: збіг за рядком (також можна вказувати символи підстановки та канали).
- `min_length`: збіг, коли кількість символів більша або дорівнює вказаному числу.
- `regexes`: збіг, якщо збігається один з регулярних виразів у файлі, який ви вказуєте в цьому полі.
- `allowlist`: правило буде пропущено, якщо знайдено будь-який збіг у списку регулярних виразів у файлі, який ви вказуєте в цьому полі.

У наведеному нижче прикладі правило збігатиметься, якщо виконуються такі умови:

- `ServiceName` називається `malicious-service` або містить регулярний вираз у `./rules/config/regex/detectlist_suspicous_services.txt`.
- `ImagePath` має мінімум 1000 символів.
- `ImagePath` не має жодних збігів у `allowlist`.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### Зразкові файли ключових слів regexes та allowlist

Hayabusa мала два вбудовані файли регулярних виразів, що використовувалися для файлу `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml`:

- `./rules/config/regex/detectlist_suspicous_services.txt`: для виявлення підозрілих імен служб
- `./rules/config/regex/allowlist_legitimate_services.txt`: для дозволу легітимних служб

Файли, визначені в `regexes` та `allowlist`, можна редагувати, щоб змінити поведінку всіх правил, які на них посилаються, без потреби змінювати сам файл правила.

Ви також можете використовувати інші текстові файли detectlist та allowlist, які ви створюєте.

## Застарілі умови агрегації (правила `count`)

Це все ще підтримується в Hayabusa, але в майбутньому буде замінено правилами кореляції Sigma.

### Основи

Описане вище ключове слово `condition` реалізує не лише логіку `AND` та `OR`, але також здатне підраховувати або "агрегувати" події.
Ця функція називається "умовою агрегації" і вказується шляхом з'єднання умови з каналом.
У наведеному нижче прикладі виявлення розпилення паролів умовний вираз використовується для визначення, чи є 5 або більше значень `TargetUserName` з однієї вихідної `IpAddress` протягом проміжку часу в 5 хвилин.

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

Умови агрегації можна визначити у такому форматі:

- `count() {operator} {number}`: Для подій журналу, що відповідають першій умові перед каналом, умова збігатиметься, якщо кількість збіжних журналів задовольняє умовний вираз, вказаний за допомогою `{operator}` та `{number}`.

`{operator}` може бути одним із наступних:

- `==`: Якщо значення дорівнює вказаному значенню, воно вважається таким, що відповідає умові.
- `>=`: Якщо значення більше або дорівнює вказаному значенню, умова вважається виконаною.
- `>`: Якщо значення більше за вказане значення, умова вважається виконаною.
- `<=`: Якщо значення менше або дорівнює вказаному значенню, умова вважається виконаною.
- `<`: Якщо значення менше за вказане значення, воно вважатиметься таким, що умову виконано.

`{number}` має бути числом.

`timeframe` можна визначити так:

- `15s`: 15 секунд
- `30m`: 30 хвилин
- `12h`: 12 годин
- `7d`: 7 днів
- `3M`: 3 місяці

### Чотири шаблони для умов агрегації

1. Немає аргументу count або ключового слова `by`. Приклад: `selection | count() > 10`
   > Якщо `selection` збігається більше 10 разів протягом проміжку часу, умова збігатиметься.
   > Вони замінюються правилами кореляції Event Count, які не використовують поле `group-by`.
2. Немає аргументу count, але є ключове слово `by`. Приклад: `selection | count() by IpAddress > 10`
   > `selection` має бути істинним більше 10 разів для **однієї й тієї ж** `IpAddress`.
   > Ці правила №2 більш поширені, ніж правила №1.
   > Ви також можете вказати кілька полів для групування. Наприклад: `by IpAddress, Computer`
   > Вони замінюються правилами кореляції Event Count, які використовують поле `group-by`.
3. Є аргумент count, але немає ключового слова `by`. Приклад: `selection | count(TargetUserName) > 10`
   > Якщо `selection` збігається і `TargetUserName` **відрізняється** більше 10 разів протягом проміжку часу, умова збігатиметься.
   > Вони замінюються правилами кореляції Value Count, які не використовують поле `group-by`.
4. Є як аргумент count, так і ключове слово `by`. Приклад: `selection | count(Users) by IpAddress > 10`
   > Для **однієї й тієї ж** `IpAddress` має бути більше 10 **різних** `TargetUserName`, щоб умова збіглася.
   > Ці правила №4 більш поширені, ніж правила №3.
   > Вони замінюються правилами кореляції Value Count, які використовують поле `group-by`.

### Приклад шаблону 1

Це найбазовіший шаблон: `count() {operator} {number}`. Наведене нижче правило збігатиметься, якщо `selection` трапляється 3 або більше разів.

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### Приклад шаблону 2

`count() by {eventkey} {operator} {number}`: Події журналу, що відповідають `condition` перед каналом, групуються за **однаковим** `{eventkey}`. Якщо кількість збіжних подій для кожного групування задовольняє умову, вказану за допомогою `{operator}` та `{number}`, то умова збігатиметься.

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### Приклад шаблону 3

`count({eventkey}) {operator} {number}`: Підраховує, скільки **різних** значень `{eventkey}` існує в події журналу, що відповідає умові перед каналом умови. Якщо кількість задовольняє умовний вираз, вказаний у `{operator}` та `{number}`, умова вважається виконаною.

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### Приклад шаблону 4

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: Журнали, що відповідають умові перед каналом умови, групуються за **однаковим** `{eventkey_2}`, і підраховується кількість **різних** значень `{eventkey_1}` у кожній групі. Якщо значення, підраховані для кожного групування, задовольняють умовний вираз, вказаний за допомогою `{operator}` та `{number}`, умова збігатиметься.

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Вивід правила count

Вивід деталей для правил count є фіксованим і друкуватиме оригінальну умову count у `[condition]`, за якою йдуть записані eventkeys у `[result]`.

У наведеному нижче прикладі список імен користувачів `TargetUserName`, які піддавалися перебору, за яким йде вихідна `IpAddress`:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

Часова мітка сповіщення буде часом з першої виявленої події.
