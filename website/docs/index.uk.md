---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Hayabusa](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Hayabusa</strong> — це <strong>швидкий генератор криміналістичних таймлайнів</strong>
журналів подій Windows та <strong>інструмент для пошуку загроз</strong>, створений
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Написаний на безпечному щодо пам'яті Rust, багатопотоковий для швидкості, і єдиний інструмент з відкритим кодом
з повною підтримкою специфікації Sigma — включно з кореляційними правилами v2.
</p>

<div class="hb-cta" markdown>
[Почати роботу :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Довідник команд :material-console:](commands/index.md){ .md-button }
[Переглянути на GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
<a href="https://www.blackhat.com/asia-22/arsenal/schedule/#hayabusa-26211"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20Asia-2022-blue"></a>
<a href="https://codeblue.jp/2022/en/talks/?content=talks_24"><img src="https://img.shields.io/badge/CODE%20BLUE%20Bluebox-2022-blue"></a>
<a href="https://www.seccon.jp/2022/seccon_workshop/windows.html"><img src="https://img.shields.io/badge/SECCON-2023-blue"></a>
<a href="https://www.security-camp.or.jp/minicamp/tokyo2023.html"><img src="https://img.shields.io/badge/Security%20MiniCamp%20Tokyo-2023-blue"></a>
<a href="https://www.sans.org/cyber-security-training-events/digital-forensics-summit-2023/"><img src="https://img.shields.io/badge/SANS%20DFIR%20Summit-2023-blue"></a>
<a href="https://bsides.tokyo/2024/"><img src="https://img.shields.io/badge/BSides%20Tokyo-2024-blue"></a>
<a href="https://www.hacker.or.jp/hack-fes-2024/"><img src="https://img.shields.io/badge/Hack%20Fes.-2024-blue"></a>
<a href="https://hitcon.org/2024/CMT/"><img src="https://img.shields.io/badge/HITCON-2024-blue"></a>
<a href="https://www.blackhat.com/sector/2024/briefings/schedule/index.html#performing-dfir-and-threat-hunting-with-yamato-security-oss-tools-and-community-driven-knowledge-41347"><img src="https://img.shields.io/badge/SecTor-2024-blue"></a>
<a href="https://www.infosec-city.com/schedule/sin25-con"><img src="https://img.shields.io/badge/SINCON%20Kampung%20Workshop-2025-blue"></a>
<a href="https://www.blackhat.com/us-25/arsenal/schedule/index.html#windows-fast-forensics-with-yamato-securitys-hayabusa-45629"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2025-blue"></a>
<a href="https://codeblue.jp/en/program/time-table/day2-t3-02/"><img src="https://img.shields.io/badge/CODE%20BLUE%20-2025-blue"></a>
<a href="https://blackhat.com/us-26/arsenal/schedule/index.html#mecha-hayabusa-by-yamato-security-52897"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2026-blue"></a>
<a href="https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d"><img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg" /></a>
<a href="https://github.com/Yamato-Security/hayabusa/commits/main/"><img src="https://img.shields.io/github/commit-activity/t/Yamato-Security/hayabusa/main" /></a>
<a href="https://rust-reportcard.xuri.me/report/github.com/Yamato-Security/hayabusa"><img src="https://rust-reportcard.xuri.me/badge/github.com/Yamato-Security/hayabusa" /></a>
<a href="https://codecov.io/gh/Yamato-Security/hayabusa" ><img src="https://codecov.io/gh/Yamato-Security/hayabusa/branch/main/graph/badge.svg?token=WFN5XO9W8C"/></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## Чому Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Блискавично швидко__

    ---

    Написаний на безпечному щодо пам'яті **Rust** з повною багатопотоковістю для розбору гір
    `.evtx` файлів та створення єдиного таймлайну якомога швидше.

-   :material-shield-search:{ .lg .middle } __Повна підтримка Sigma__

    ---

    Єдиний інструмент з відкритим кодом з повною підтримкою специфікації Sigma, включно з
    **кореляційними правилами v2**, що спирається на понад 4000 ретельно відібраних правил виявлення.

-   :material-timeline-clock:{ .lg .middle } __DFIR таймлайни__

    ---

    Об'єднує події з одного хосту чи тисяч у єдиний криміналістичний таймлайн **CSV / JSON / JSONL**,
    готовий до аналізу.

-   :material-server-network:{ .lg .middle } __Пошук у масштабі підприємства__

    ---

    Запускайте наживо на одній системі, збирайте журнали для офлайн-аналізу або шукайте по всьому
    підприємству за допомогою артефакту Hayabusa для **Velociraptor**.

-   :material-chart-box:{ .lg .middle } __Багатий аналітичний вивід__

    ---

    Метрики, зведення про входи в систему, зведення за ключовими словами, HTML-звіти та таймлайн
    частоти виявлень, щоб швидко виявити те, що важливо.

-   :material-import:{ .lg .middle } __Добре працює з іншими__

    ---

    Імпортуйте результати прямо в **Elastic Stack**, **Timesketch**, **Timeline
    Explorer** або обробляйте JSON за допомогою **jq**.

</div>

## Подивіться в дії

![Створення DFIR таймлайну Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

Перегляньте галерею [Скриншоти](overview/screenshots.md), щоб побачити вивід терміналу,
HTML-зведення результатів та аналіз у LibreOffice, Timeline Explorer і Timesketch.

## Швидкі посилання

<div class="grid cards" markdown>

-   __:material-book-open-variant: Уперше тут?__

    Почніть з [Огляду](overview/index.md), потім переходьте до
    [Початку роботи](getting-started/index.md), щоб завантажити та запустити Hayabusa.

-   __:material-console-line: Працюєте з CLI?__

    Перейдіть до [Списку команд](commands/index.md) та довідника по окремих командах для
    [Аналізу](commands/analysis.md), [Конфігурації](commands/config.md) та
    команд [DFIR таймлайну](commands/dfir-timeline.md).

-   __:material-tune: Налаштовуєте вивід?__

    Дивіться [Профілі виводу](output/index.md), [Скорочення](output/abbreviations.md)
    та параметри [Відображення й зведення](output/display.md).

-   __:material-puzzle: Хочете більше?__

    Досліджуйте [Правила](rules/index.md), [екосистему проєкту](resources/index.md)
    та як [зробити внесок](resources/contributing.md).

</div>
