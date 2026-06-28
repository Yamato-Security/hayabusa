# Завантаження

Будь ласка, завантажте найновішу стабільну версію Hayabusa зі скомпільованими бінарними файлами або скомпілюйте вихідний код зі сторінки [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Ми надаємо бінарні файли для таких архітектур:
- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [З певних причин бінарний файл Linux ARM MUSL не працює належним чином](https://github.com/Yamato-Security/hayabusa/issues/1332), тому ми не надаємо цей бінарний файл. Це поза нашим контролем, тож ми плануємо надати його в майбутньому, коли проблему буде виправлено.

## Пакети для оперативного реагування у Windows

Починаючи з v2.18.0, ми надаємо спеціальні пакети для Windows, які використовують правила, закодовані XOR, надані в одному файлі, а також усі конфігураційні файли, об'єднані в один файл (розміщені у [репозиторії hayabusa-encoded-rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Просто завантажте zip-пакети з `live-response` у назві.
Zip-файли містять лише три файли: бінарний файл Hayabusa, файл правил, закодований XOR, та конфігураційний файл.
Призначення цих пакетів для оперативного реагування полягає в тому, що під час запуску Hayabusa на клієнтських кінцевих точках ми хочемо переконатися, що антивірусні сканери, такі як Windows Defender, не дають хибних спрацьовувань на файлах правил `.yml`.
Крім того, ми хочемо мінімізувати кількість файлів, що записуються в систему, щоб криміналістичні артефакти, такі як USN Journal, не перезаписувалися.
