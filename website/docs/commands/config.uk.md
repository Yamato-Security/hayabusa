# Команди конфігурації

## Команда `config-critical-systems`

Ця команда автоматично намагатиметься знайти критично важливі системи, такі як контролери домену та файлові сервери, і додати їх до файлу конфігурації `./config/critical_systems.txt`, щоб рівень усіх сповіщень було підвищено на один рівень.
Вона шукатиме події Security 4768 (запит Kerberos TGT), щоб визначити, чи є система контролером домену.
Вона шукатиме події Security 5145 (доступ до файлу мережевого спільного ресурсу), щоб визначити, чи є система файловим сервером.
Для всіх імен хостів, доданих до файлу `critical_systems.txt`, усі сповіщення вище low буде підвищено на один рівень з максимальним рівнем `emergency`.

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Каталог з кількома файлами .evtx
  -f, --file <FILE>      Шлях до одного файлу .evtx

Display Settings:
  -K, --no-color  Вимкнути кольоровий вивід
  -q, --quiet     Тихий режим: не відображати банер запуску

General Options:
  -h, --help  Показати меню довідки
```

### Приклади команди `config-critical-systems`

* Пошук контролерів домену та файлових серверів у каталозі `../hayabusa-sample-evtx`:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
