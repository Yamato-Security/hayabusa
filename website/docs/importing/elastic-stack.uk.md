- [Імпорт результатів у SOF-ELK (Elastic Stack)](#importing-results-into-sof-elk-elastic-stack)
  - [Встановлення та запуск SOF-ELK](#install-and-start-sof-elk)
    - [Проблеми з мережевим підключенням на Mac](#network-connectivity-trouble-on-macs)
  - [Оновіть SOF-ELK!](#update-sof-elk)
  - [Запуск Hayabusa](#run-hayabusa)
  - [Необов'язково: видалення старих імпортованих даних](#optional-deleting-old-imported-data)
  - [Налаштування конфігураційного файлу logstash для Hayabusa у SOF-ELK](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Імпорт результатів Hayabusa у SOF-ELK](#import-hayabusa-results-into-sof-elk)
  - [Перевірка успішності імпорту в Kibana](#check-that-the-import-worked-in-kibana)
  - [Перегляд результатів у Discover](#view-results-in-discover)
  - [Аналіз результатів](#analyzing-results)
    - [Додавання стовпців](#adding-columns)
    - [Фільтрація](#filtering)
    - [Перемикання деталей](#toggling-details)
    - [Перегляд сусідніх документів](#view-surrounding-documents)
    - [Швидкі метрики за полями](#get-quick-metrics-on-fields)
  - [Плани на майбутнє](#future-plans)

# Імпорт результатів у SOF-ELK (Elastic Stack)

## Встановлення та запуск SOF-ELK

Результати Hayabusa можна легко імпортувати в Elastic Stack.
Ми рекомендуємо використовувати [SOF-ELK](https://github.com/philhagen/sof-elk), безкоштовний дистрибутив Linux з elastic stack, орієнтований на розслідування DFIR.

Спочатку завантажте та розпакуйте 7-zip образ VMware SOF-ELK із [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README).

Існує дві версії: x86 для процесорів Intel та версія ARM для комп'ютерів Apple серії M.

Коли ви завантажите віртуальну машину, ви побачите екран, подібний до цього:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Зверніть увагу на URL-адресу Kibana та IP-адресу SSH-сервера.

Ви можете увійти за допомогою таких облікових даних:

* Ім'я користувача: `elk_user`
* Пароль: `forensics`

Відкрийте Kibana у веб-браузері за відображеною URL-адресою.
Наприклад: http://172.16.23.128:5601/

> Примітка: завантаження Kibana може зайняти деякий час.

Ви повинні побачити веб-сторінку наступного вигляду:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

Ми рекомендуємо підключатися до VM через SSH замість введення команд усередині VM за допомогою `ssh elk_user@172.16.23.128`.

> Примітка: типова розкладка клавіатури — це клавіатура США.

### Проблеми з мережевим підключенням на Mac

Якщо ви працюєте в macOS і отримуєте помилку `no route to host` у терміналі або не можете отримати доступ до Kibana у браузері, це, ймовірно, спричинено засобами контролю конфіденційності локальної мережі macOS.

У розділі `System Settings` відкрийте `Privacy & Security` -> `Local Network` і переконайтеся, що вашому браузеру та програмі терміналу дозволено зв'язуватися з пристроями у вашій локальній мережі.

## Оновіть SOF-ELK!

Перед імпортом даних обов'язково оновіть SOF-ELK за допомогою команди `sudo sof-elk_update.sh`.

## Запуск Hayabusa

Запустіть Hayabusa та збережіть результати у JSONL.

Наприклад: `./hayabusa json-timeline -L -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## Необов'язково: видалення старих імпортованих даних

Якщо це не перший раз імпортування результатів Hayabusa і ви хочете очистити все, ви можете зробити це наступним чином:

1. Перевірте, які записи наразі є в SOF-ELK: `sof-elk_clear.py -i list`
2. Видаліть поточні дані: `sof-elk_clear.py -a`
3. Видаліть файли в каталозі logstash: `rm /logstash/hayabusa/*`

## Налаштування конфігураційного файлу logstash для Hayabusa у SOF-ELK

У SOF-ELK уже включено конфігураційний файл logstash для Hayabusa, який перетворює імена полів у формат Elastic Common Schema.
Якщо вам зручніше працювати з іменами полів Hayabusa, ми рекомендуємо використовувати той, який ми надаємо.

1. Спочатку підключіться до SOF-ELK через SSH: `ssh elk_user@172.16.23.128`
2. Видаліть або перемістіть поточний конфігураційний файл logstash: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. Завантажте новий файл [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) до `/etc/logstash/conf.d/`: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. Перезавантажте logstash: `sudo systemctl restart logstash`

Цей конфігураційний файл створить консолідовані поля `DetailsText` та `ExtraFieldInfoText`, які дозволяють швидко переглянути найважливіші поля з першого погляду замість того, щоб витрачати час на відкриття кожного запису по черзі для перегляду всіх полів.

## Імпорт результатів Hayabusa у SOF-ELK

Журнали потрапляють у SOF-ELK шляхом копіювання журналів у відповідний каталог усередині каталогу `/logstash`.

Спочатку вийдіть із SSH за допомогою `exit`, а потім скопіюйте створений вами файл результатів Hayabusa:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Перевірка успішності імпорту в Kibana

Спочатку зверніть увагу на `Total detections`, `First Timestamp` та `Last Timestamp` у розділі `Results Summary` вашого сканування Hayabusa.

Якщо ви не можете отримати цю інформацію, ви можете виконати `wc -l results.jsonl` в *nix, щоб отримати загальну кількість рядків для `Total detections`.

За замовчуванням Hayabusa не сортує результати з метою підвищення продуктивності, тому ви не можете подивитися на перший і останній рядки, щоб отримати першу й останню мітку часу.
Якщо ви не знаєте точних першої та останньої міток часу, просто встановіть першу дату в Kibana як 2007 рік, а останній день — як `now`, і ви матимете всі результати.

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

Тепер ви повинні побачити `Total Records`, а також першу й останню мітки часу подій, які були імпортовані.

Іноді імпорт усіх подій займає деякий час, тому просто продовжуйте оновлювати сторінку, доки `Total Records` не досягне очікуваної вами кількості.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

Ви також можете перевірити з терміналу, виконавши `sof-elk_clear.py -i list`, щоб дізнатися, чи був імпорт успішним.
Ви повинні побачити, що ваш індекс `evtxlogs` повинен мати більше записів:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

Будь ласка, створіть issue на GitHub, якщо у вас виникають помилки парсингу під час імпорту.
Ви можете перевірити це, переглянувши кінець файлу журналу `/var/log/logstash/logstash-plain.log`.

## Перегляд результатів у Discover

Натисніть на іконку бічної панелі у верхньому лівому куті та виберіть `Discover`:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

Ви, ймовірно, побачите `No results match your search criteria`.

У верхньому лівому куті, де вказано індекс `logstash-*`, натисніть на нього та змініть його на `evtxlogs-*`.
Тепер ви повинні побачити часову шкалу Discover.

## Аналіз результатів

Типовий вигляд Discover повинен виглядати приблизно так:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

Ви можете отримати огляд того, коли відбувалися події та з якою частотою, переглянувши гістограму вгорі. 

### Додавання стовпців

На бічній панелі ліворуч ви можете додати поля, які бажаєте відобразити у стовпцях, натиснувши знак плюс після наведення курсора на поле.
Оскільки полів багато, ви можете ввести ім'я потрібного поля в полі пошуку.

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

Для початку ми рекомендуємо такі стовпці:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

Якщо ваш монітор достатньо широкий, ви можете також додати `ExtraFieldInfoText`, щоб бачити всю інформацію про поля.

Тепер ваш вигляд Discover повинен виглядати так:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### Фільтрація

Ви можете фільтрувати за допомогою KQL (Kibana Query Language), щоб шукати певні події та сповіщення. Наприклад:
  * `Level: "crit"`: показати лише критичні сповіщення.
  * `Level: "crit" OR Level: "high"`: показати сповіщення високого та критичного рівня.
  * `NOT Level: info`: не показувати інформаційні події, лише сповіщення.
  * `MitreTactics: *LatMov*`: показати події та сповіщення, пов'язані з горизонтальним переміщенням.
  * `"PW Spray"`: показати лише певні атаки, такі як "Password Spray".
  * `"LID: 0x8724ead"`: відобразити всю активність, пов'язану з Logon ID 0x8724ead.
  * `Details_TgtUser: admmig`: пошук усіх подій, де цільовий користувач — `admmig`.

### Перемикання деталей

Щоб перевірити всі поля в записі, просто натисніть іконку (Toggle dialog with details) поряд із міткою часу:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### Перегляд сусідніх документів

Якщо ви хочете переглянути події безпосередньо до та після певного сповіщення, спочатку відкрийте деталі цього сповіщення, а потім натисніть `View surrounding documents` у верхньому правому куті:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

У цьому прикладі ми бачимо події до та після сповіщення про атаку Pass the Hash:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Примітка: змініть числа вгорі `Load x newer documents` або внизу `Load x older documents`, щоб отримати більше подій.

### Швидкі метрики за полями

У лівому стовпці, якщо ви натиснете на ім'я поля, воно надасть вам швидкі метрики щодо його використання:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> Зверніть увагу, що дані вибираються для швидкості, тому вони не є на 100% точними.

## Плани на майбутнє

* Парсери Logstash для CSV
* Попередньо побудована інформаційна панель
