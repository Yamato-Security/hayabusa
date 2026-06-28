# Виведення часової шкали

## Профілі виведення

Hayabusa має 5 попередньо визначених профілів виведення для використання у `config/profiles.yaml`:

1. `minimal`
2. `standard` (за замовчуванням)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Ви можете легко налаштувати або додати власні профілі, редагуючи цей файл.
Ви також можете легко змінити профіль за замовчуванням за допомогою `set-default-profile --profile <profile>`.
Використовуйте команду `list-profiles`, щоб показати доступні профілі та інформацію про їхні поля.

### 1. Виведення профілю `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. Виведення профілю `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. Виведення профілю `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. Виведення профілю `all-field-info`

Замість виведення мінімальної інформації `details` буде виведено всю інформацію полів у розділах `EventData` та `UserData` разом з їхніми оригінальними назвами полів.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. Виведення профілю `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. Виведення профілю `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. Виведення профілю `timesketch-minimal`

Виведення у форматі, сумісному для імпорту в [Timesketch](https://timesketch.org/).

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. Виведення профілю `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Порівняння профілів

Наведені нижче бенчмарки були проведені на Lenovo P51 2018 року (Xeon 4 Core CPU / 64GB RAM) з 3GB даних evtx та 3891 увімкненими правилами. (2023/06/01)

| Профіль | Час обробки | Розмір вихідного файлу | Збільшення розміру файлу |
| :---: | :---: | :---: | :---: |
| minimal | 8 хвилин 50 секунд | 770 MB | -30% |
| standard (за замовчуванням) | 9 хвилин 00 секунд | 1.1 GB | Немає |
| verbose | 9 хвилин 10 секунд | 1.3 GB | +20% |
| all-field-info | 9 хвилин 3 секунди | 1.2 GB | +10% |
| all-field-info-verbose | 9 хвилин 10 секунд | 1.3 GB | +20% |
| super-verbose | 9 хвилин 12 секунд | 1.5 GB | +35% |

### Псевдоніми полів профілю

Наведену нижче інформацію можна вивести за допомогою вбудованих профілів виведення:

| Назва псевдоніма | Інформація виведення Hayabusa|
| :--- | :--- |
|%AllFieldInfo% | Уся інформація полів. |
|%Channel% | Назва журналу. Поле `<Event><System><Channel>`. |
|%Computer% | Поле `<Event><System><Computer>`. |
|%Details% | Поле `details` у YML-правилі виявлення, однак це поле мають лише правила hayabusa. Це поле надає додаткову інформацію про сповіщення або подію і може витягувати корисні дані з полів у журналах подій. Наприклад, імена користувачів, інформацію командного рядка, інформацію про процеси тощо. Коли заповнювач вказує на поле, яке не існує, або є некоректне зіставлення псевдонімів, воно буде виведено як `n/a` (недоступно). Якщо поле `details` не вказано (тобто правила sigma), будуть виведені стандартні повідомлення `details` для витягування полів, визначених у `./rules/config/default_details.txt`. Ви можете додати більше стандартних повідомлень `details`, додавши `Provider Name`, `EventID` та повідомлення `details`, яке ви хочете вивести, у `default_details.txt`. Коли поле `details` не визначено ні у правилі, ні в `default_details.txt`, усі поля будуть виведені у стовпець `details`. |
|%ExtraFieldInfo% | Виводить інформацію полів, яка не була виведена у %Details%. |
|%EventID% | Поле `<Event><System><EventID>`. |
|%EvtxFile% | Ім'я файлу evtx, який спричинив сповіщення або подію. |
|%Level% | Поле `level` у YML-правилі виявлення. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | MITRE ATT&CK [тактики](https://attack.mitre.org/tactics/enterprise/) (наприклад: Initial Access, Lateral Movement тощо). |
|%MitreTags% | MITRE ATT&CK Group ID, Technique ID та Software ID. |
|%OtherTags% | Будь-яке ключове слово в полі `tags` у YML-правилі виявлення, яке не включено в `MitreTactics` або `MitreTags`. |
|%Provider% | Атрибут `Name` у полі `<Event><System><Provider>`. |
|%RecordID% | Event Record ID з поля `<Event><System><EventRecordID>`. |
|%RuleAuthor% | Поле `author` у YML-правилі виявлення. |
|%RuleCreationDate% | Поле `date` у YML-правилі виявлення. |
|%RuleFile% | Ім'я файлу правила виявлення, яке згенерувало сповіщення або подію. |
|%RuleID% | Поле `id` у YML-правилі виявлення. |
|%RuleModifiedDate% | Поле `modified` у YML-правилі виявлення. |
|%RuleTitle% | Поле `title` у YML-правилі виявлення. |
|%Status% | Поле `status` у YML-правилі виявлення. |
|%Timestamp% | За замовчуванням використовується формат `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. Поле `<Event><System><TimeCreated SystemTime>` у журналі подій. Часовим поясом за замовчуванням буде місцевий часовий пояс, але ви можете змінити часовий пояс на UTC за допомогою опції `--UTC`. |

#### Додатковий псевдонім поля профілю

Ви також можете додати цей додатковий псевдонім до вашого профілю виведення, якщо він вам потрібен:

| Назва псевдоніма | Інформація виведення Hayabusa|
| :--- | :--- |
|%RenderedMessage% | Поле `<Event><RenderingInfo><Message>` у журналах, переадресованих через WEC. |

Примітка: це **не** включено в жоден вбудований профіль, тому вам потрібно буде вручну відредагувати файл `config/default_profile.yaml` і додати такий рядок:

```
Message: "%RenderedMessage%"
```

Ви також можете визначити [псевдоніми ключів подій](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) для виведення інших полів.
