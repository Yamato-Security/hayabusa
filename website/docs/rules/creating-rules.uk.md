# Створення файлів правил

## Про Hayabusa-Rules

Це репозиторій, що містить підібрані правила sigma, які виявляють атаки в журналах подій Windows.
Він в основному використовується для правил виявлення та конфігураційних файлів [Hayabusa](https://github.com/Yamato-Security/hayabusa), а також для вбудованого виявлення sigma в [Velociraptor](https://github.com/Velocidex/velociraptor).
Перевага використання цього репозиторію над [основним репозиторієм sigma](https://github.com/SigmaHQ/sigma) полягає в тому, що ми включаємо лише правила, які більшість нативних інструментів sigma повинні бути здатні розібрати.
Ми також деабстрагуємо поле `logsource`, додаючи до правил необхідні поля `Channel`, `EventID` тощо, щоб полегшити розуміння того, на що правило фільтрує, і, що важливіше, зменшити кількість хибних спрацювань.
Ми також створюємо нові правила з перетвореними іменами полів та значеннями для правил `process_creation` та правил на основі `registry`, щоб правила sigma виявляли не лише в журналах Sysmon, а й у вбудованих журналах Windows.

## Про створення файлів правил

Правила виявлення Hayabusa пишуться у форматі [YAML](https://en.wikipedia.org/wiki/YAML) з розширенням файлу `.yml`. (Файли `.yaml` ігноруватимуться.)
Вони є підмножиною правил sigma, але також містять деякі додаткові можливості.
Ми намагаємося зробити їх якомога ближчими до правил sigma, щоб правила Hayabusa було легко конвертувати назад у sigma та повертати спільноті.
Правила Hayabusa можуть виражати складні правила виявлення, поєднуючи не лише просте зіставлення рядків, а й регулярні вирази, умови `AND`, `OR` та інші.
У цьому розділі ми пояснимо, як писати правила виявлення Hayabusa.

### Формат файлу правила

Приклад:

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

> ## Author section

- **author [required]**: Імена автора(ів).
- **date [required]**: Дата створення правила.
- **modified** [optional]: Дата оновлення правила.

> ## Alert section

- **title [required]**: Заголовок файлу правила. Це також буде назвою оповіщення, яке відображається, тож чим коротше, тим краще. (Не повинно перевищувати 85 символів.)
- **details** [optional]: Деталі оповіщення, яке відображається. Будь ласка, виводьте будь-які поля з журналу подій Windows, корисні для аналізу. Поля розділяються `" ¦ "`. Заповнювачі полів обрамлені символом `%` (Приклад: `%MemberName%`) і повинні бути визначені у `rules/config/eventkey_alias.txt`. (Пояснено нижче.)
- **description** [optional]: Опис правила. Він не відображається, тож ви можете зробити його довгим і детальним.

> ## Rule section

- **id [required]**: Випадково згенерований UUID версії 4, що використовується для унікальної ідентифікації правила. Ви можете згенерувати його [тут](https://www.uuidgenerator.net/version4).
- **level [required]**: Рівень серйозності на основі [визначення sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Будь ласка, напишіть одне з наступного: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: Статус на основі [визначення sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Будь ласка, напишіть одне з наступного: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [required]**: Хоча наразі Hayabusa фактично не використовує це, ми визначаємо logsource так само, як sigma, щоб бути сумісними з правилами sigma.
- **detection  [required]**: Сюди йде логіка виявлення. (Пояснено нижче.)
- **falsepositives [required]**: Можливості хибних спрацювань. Наприклад: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Якщо це невідомо, будь ласка, напишіть `unknown`.
- **tags** [optional]: Якщо техніка є технікою [LOLBINS/LOLBAS](https://lolbas-project.github.io/), будь ласка, додайте тег `lolbas`. Якщо оповіщення можна зіставити з технікою у фреймворку [MITRE ATT&CK](https://attack.mitre.org/), будь ласка, додайте ідентифікатор тактики (Приклад: `attack.t1098`) та будь-які застосовні тактики нижче:
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
- **references** [optional]: Будь-які посилання на джерела.
- **ruletype [required]**: `Hayabusa` для правил hayabusa. Правила, автоматично конвертовані з правил sigma для Windows, матимуть `Sigma`.

> ## Sample XML Event

- **sample-message [required]**: Надалі ми просимо авторів правил включати зразкові повідомлення для своїх правил. Це відрендерене повідомлення, яке відображає Переглядач подій Windows.
- **sample-evtx [required]**: Надалі ми просимо авторів правил включати зразкові XML-події для своїх правил.
