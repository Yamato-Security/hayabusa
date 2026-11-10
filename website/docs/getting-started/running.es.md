# Ejecutar Hayabusa

## Precaución: Advertencias de Antivirus/EDR y Tiempos de Ejecución Lentos

Es posible que reciba una alerta de productos antivirus o EDR al intentar ejecutar hayabusa o incluso simplemente al descargar las reglas `.yml`, ya que habrá palabras clave como `mimikatz` y comandos sospechosos de PowerShell en la firma de detección.
Estos son falsos positivos, por lo que necesitará configurar exclusiones en sus productos de seguridad para permitir que hayabusa se ejecute.
Si le preocupa el malware o los ataques a la cadena de suministro, revise el código fuente de hayabusa y compile los binarios usted mismo.

Es posible que experimente tiempos de ejecución lentos, especialmente en la primera ejecución después de un reinicio, debido a la protección en tiempo real de Windows Defender.
Puede evitar esto desactivando temporalmente la protección en tiempo real o agregando una exclusión al directorio de ejecución de hayabusa.
(Por favor, tenga en cuenta los riesgos de seguridad antes de hacer esto.)

## Windows

En un símbolo del sistema de Command/PowerShell o en Windows Terminal, simplemente ejecute el binario de Windows de 32 bits o 64 bits apropiado.

### Error al intentar escanear un archivo o directorio con un espacio en la ruta

Al usar el símbolo del sistema integrado de Command o PowerShell en Windows, es posible que reciba un error que indica que Hayabusa no pudo cargar ningún archivo .evtx si hay un espacio en la ruta de su archivo o directorio.
Para cargar los archivos .evtx correctamente, asegúrese de hacer lo siguiente:

1. Encierre la ruta del archivo o directorio entre comillas dobles.
2. Si es una ruta de directorio, asegúrese de no incluir una barra invertida como último carácter.

### Caracteres que no se muestran correctamente

Con la fuente predeterminada `Lucida Console` en Windows, varios caracteres usados en el logotipo y las tablas no se mostrarán correctamente.
Debe cambiar la fuente a `Consalas` para solucionar esto.

Esto corregirá la mayor parte del renderizado de texto, excepto la visualización de caracteres japoneses en los mensajes de cierre:

![Mojibake](../assets/screenshots/Mojibake.png)

Tiene cuatro opciones para solucionar esto:

1. Use [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) en lugar del símbolo del sistema de Command o PowerShell. (Recomendado)
2. Use la fuente `MS Gothic`. Tenga en cuenta que las barras invertidas se convertirán en símbolos de Yen.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. Instale las fuentes [HackGen](https://github.com/yuru7/HackGen/releases) y use `HackGen Console NF`.
4. Use `-q, --quiet` para no mostrar los mensajes de cierre que contienen japonés.

## Linux

Primero necesita hacer que el binario sea ejecutable.

```bash
chmod +x ./hayabusa
```

Luego ejecútelo desde el directorio raíz de Hayabusa:

```bash
./hayabusa
```

## macOS

Desde Terminal o iTerm2, primero necesita hacer que el binario sea ejecutable.

```bash
chmod +x ./hayabusa
```

Luego, intente ejecutarlo desde el directorio raíz de Hayabusa:

```bash
./hayabusa
```

En la última versión de macOS, es posible que reciba el siguiente error de seguridad al intentar ejecutarlo:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

Haga clic en "Cancelar" y luego, desde Preferencias del Sistema, abra "Seguridad y Privacidad" y, en la pestaña General, haga clic en "Permitir de todos modos".

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

Después de eso, intente ejecutarlo de nuevo.

```bash
./hayabusa
```

Aparecerá la siguiente advertencia, así que haga clic en "Abrir".

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

Ahora debería poder ejecutar hayabusa.

## Entradas VHDX


Todos los comandos de análisis de registros de eventos admiten `--vhdx` con `-f <IMAGE.vhdx>` o `-d <DIR>`. La búsqueda incluye el directorio indicado y tres niveles de subdirectorios. Dentro de las imágenes se examinan todos los volúmenes NTFS legibles sin ese límite de profundidad.

```bash
./hayabusa dfir-timeline --vhdx -f host.vhdx -w -U -p verbose -o timeline.csv
./hayabusa dfir-timeline --vhdx -d images/ -w -U -p verbose -o timeline.csv
```


El análisis nativo funciona en **Linux, macOS y Windows** mediante la interfaz NTFS portátil compartida con Juntei. Los archivos se leen directamente como flujos de solo lectura con acceso por posición. No requiere FUSE, controladores de montaje, privilegios de administrador ni extracción temporal. Las imágenes originales permanecen intactas. Las rutas usan `host.vhdx!/path/log.evtx`. No se admiten BitLocker ni imágenes que necesiten una imagen principal externa.

[English: VHDX input details and limitations](https://yamato-security.github.io/hayabusa/getting-started/running/#vhdx-inputs).

## E01/Ex01 { #e01-inputs }

`--e01` analiza directamente imágenes físicas EWF1 (`.E01`) y EWF2 (`.Ex01`) en Linux, macOS y Windows, sin FUSE, permisos de administrador ni extracción temporal. Indique el primer segmento y mantenga los demás con sus nombres originales en el mismo directorio. `-d` busca hasta tres niveles de subdirectorios; `--vhdx --e01` admite directorios mixtos. Se admiten discos con particiones NTFS y volúmenes NTFS individuales. Los daños se notifican, se conservan resultados legibles y se termina con un código distinto de cero. No es una verificación completa de integridad del medio. No se admiten `.L01`/`.Lx01` lógicos, EWF que requieran contraseña ni BitLocker.

```bash
./hayabusa dfir-timeline --e01 -f disk.E01 -w -U -p verbose -o timeline.csv
./hayabusa log-metrics --e01 -d images/ -U -o logs.csv
./hayabusa dfir-timeline --vhdx --e01 -d images/ -w -U -o timeline.csv
```

[English: E01/Ex01 details](https://yamato-security.github.io/hayabusa/getting-started/running/#e01-inputs).
