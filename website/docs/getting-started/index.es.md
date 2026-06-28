# Descargas

Descargue la última versión estable de Hayabusa con binarios compilados o compile el código fuente desde la página de [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Proporcionamos binarios para las siguientes arquitecturas:

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [Por alguna razón, el binario de Linux ARM MUSL no se ejecuta correctamente](https://github.com/Yamato-Security/hayabusa/issues/1332), por lo que no proporcionamos ese binario. Está fuera de nuestro control, así que planeamos proporcionarlo en el futuro cuando se solucione.

## Paquetes de respuesta en vivo para Windows

A partir de la v2.18.0, proporcionamos paquetes especiales de Windows que utilizan reglas codificadas con XOR proporcionadas en un único archivo, así como todos los archivos de configuración combinados en un único archivo (alojados en el [repositorio hayabusa-encoded-rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Simplemente descargue los paquetes zip con `live-response` en el nombre.
Los archivos zip solo incluyen tres archivos: el binario de Hayabusa, el archivo de reglas codificadas con XOR y el archivo de configuración.
El propósito de estos paquetes de respuesta en vivo es que, al ejecutar Hayabusa en endpoints de clientes, queremos asegurarnos de que los escáneres antivirus como Windows Defender no generen falsos positivos en los archivos de reglas `.yml`.
Además, queremos minimizar la cantidad de archivos que se escriben en el sistema para que los artefactos forenses como el USN Journal no se sobrescriban.
