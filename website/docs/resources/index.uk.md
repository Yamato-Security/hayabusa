# Проєкти та екосистема

## Супутні проєкти

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Документація та скрипти для належного увімкнення журналів подій Windows.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Те саме, що й репозиторій Hayabusa Rules, але правила та конфігураційні файли зберігаються в одному файлі та обробляються XOR, щоб запобігти хибним спрацюванням антивірусу.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Правила виявлення Hayabusa та відібрані правила виявлення Sigma, що використовуються в Hayabusa.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - Краще підтримуваний форк крейту `evtx`.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Зразкові файли evtx для тестування правил виявлення hayabusa/sigma.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Презентації з доповідей, які ми робили про наші інструменти та ресурси.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Перетворює правила Sigma на основі журналів подій Windows із вищестоящого джерела на зручнішу для використання форму.
* [Takajo](https://github.com/Yamato-Security/takajo) - Аналізатор результатів hayabusa.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - Аналізатор журналів подій Windows, написаний на PowerShell. (Застарілий і замінений на Takajo.)

## Сторонні проєкти, що використовують Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Робочий процес NodeRED, який імпортує результати Plaso та Hayabusa до Timesketch.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - Надає хмарні інструменти безпеки та інфраструктуру відповідно до ваших потреб. 
* [OpenRelik](https://openrelik.org/) - Платформа з відкритим кодом (Apache-2.0), розроблена для оптимізації спільних цифрових криміналістичних розслідувань.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Швидко розгорніть екземпляр splunk за допомогою Docker для перегляду журналів і виводу інструментів під час ваших розслідувань.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Інструмент для збору інформації про стан хоста за допомогою запитів The Velociraptor Query Language (VQL).

## Інші аналізатори журналів подій Windows та пов'язані ресурси

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Інструмент виявлення атак, написаний на Python.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Колекція ресурсів про Event ID, корисних для цифрової криміналістики та реагування на інциденти
* [Chainsaw](https://github.com/countercept/chainsaw) - Ще один інструмент виявлення атак на основі sigma, написаний на Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Інструмент виявлення атак, написаний на Powershell, від [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - Графова візуалізація журналів подій Windows.
* [EventList](https://github.com/miriamxyra/EventList/) - Зіставлення ідентифікаторів подій базового рівня безпеки з MITRE ATT&CK від [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - від [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - Парсер Evtx від [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Відновлення файлів журналів EVTX з нерозподіленого простору та образів пам'яті.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Інструмент Python для надсилання даних Evtx до Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Зразкові файли журналів подій атак EVTX від [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Зразкові файли журналів подій атак EVTX, зіставлені з ATT&CK, від [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - бібліотека evtx на Rust, яку ми використовуємо, написана [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Візуалізатор журналів Sysmon та PowerShell.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Графічний інтерфейс для візуалізації входів у систему з метою виявлення латерального переміщення від [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - Посібник NSA щодо того, що слід моніторити.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Порт DeepBlueCLI на Rust від Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - Загальні правила SIEM на основі спільноти.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - Попередньо упакована ВМ з Elastic Stack для імпорту даних для аналізу DFIR від [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Імпорт файлів evtx до Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Інструмент конфігурації та офлайн-візуалізації журналів для Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - Найкращий аналізатор часових шкал CSV від [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - від Steve Anson з Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - Інструмент виявлення атак на основі Sigma, написаний на Python.
