# Comandos de Cronología DFIR

## Asistente de escaneo

El comando `dfir-timeline` ahora tiene un asistente de escaneo habilitado de forma predeterminada.
Su objetivo es ayudar a los usuarios a elegir fácilmente qué reglas de detección desean habilitar según sus necesidades y preferencias.
Los conjuntos de reglas de detección que se cargan se basan en las listas oficiales del proyecto Sigma.
Los detalles se explican en [esta publicación de blog](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
Puede desactivar fácilmente el asistente y usar Hayabusa de su manera tradicional añadiendo la opción `-w, --no-wizard`.

### Reglas Core

El conjunto de reglas `core` habilita las reglas que tienen un estado de `test` o `stable` y un nivel de `high` o `critical`.
Estas son reglas de alta calidad con alta confianza y relevancia y no deberían producir muchos falsos positivos.
El estado de la regla es `test` o `stable`, lo que significa que no se reportaron falsos positivos durante más de 6 meses.
Las reglas coincidirán con técnicas de atacantes, actividad sospechosa genérica o comportamiento malicioso.
Es lo mismo que usar las opciones `--exclude-status deprecated,unsupported,experimental --min-level high`.

### Reglas Core+

El conjunto de reglas `core+` habilita las reglas que tienen un estado de `test` o `stable` y un nivel de `medium` o superior.
Las reglas `medium` con mayor frecuencia necesitan ajustes adicionales, ya que ciertas aplicaciones, comportamiento legítimo de usuarios o scripts de una organización podrían coincidir.
Es lo mismo que usar las opciones `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### Reglas Core++

El conjunto de reglas `core++` habilita las reglas que tienen un estado de `experimental`, `test` o `stable` y un nivel de `medium` o superior.
Estas reglas son de vanguardia.
Se validan contra los archivos evtx de referencia disponibles en el proyecto SigmaHQ y son revisadas por múltiples ingenieros de detección.
Aparte de eso, prácticamente no están probadas al principio.
Úselas si desea poder detectar amenazas lo antes posible a costa de gestionar un umbral más alto de falsos positivos.
Es lo mismo que usar las opciones `--exclude-status deprecated,unsupported --min-level medium`.

### Reglas adicionales de Amenazas Emergentes (ET)

El conjunto de reglas `Emerging Threats (ET)` habilita las reglas que tienen una etiqueta de `detection.emerging_threats`.
Estas reglas apuntan a amenazas específicas y son especialmente útiles para amenazas actuales sobre las cuales todavía no hay mucha información disponible.
Estas reglas no deberían tener muchos falsos positivos, pero disminuirán en relevancia con el tiempo.
Cuando estas reglas no están habilitadas, es lo mismo que usar la opción `--exclude-tag detection.emerging_threats`.
Cuando se ejecuta Hayabusa de forma tradicional sin el asistente, estas reglas se incluirán de forma predeterminada.

### Reglas adicionales de Caza de Amenazas (TH)

El conjunto de reglas `Threat Hunting (TH)` habilita las reglas que tienen una etiqueta de `detection.threat_hunting`.
Estas reglas pueden detectar actividad maliciosa desconocida, sin embargo, normalmente tendrán más falsos positivos.
Cuando estas reglas no están habilitadas, es lo mismo que usar la opción `--exclude-tag detection.threat_hunting`.
Cuando se ejecuta Hayabusa de forma tradicional sin el asistente, estas reglas se incluirán de forma predeterminada.

## Filtrado de registros de eventos y reglas basado en canales

A partir de Hayabusa v2.16.0, habilitamos un filtro basado en canales al cargar archivos `.evtx` y reglas `.yml`.
El propósito es hacer que el escaneo sea lo más eficiente posible cargando únicamente lo necesario.
Si bien es posible que haya múltiples proveedores en un solo registro de eventos, no es común tener múltiples canales dentro de un solo archivo evtx.
(La única vez que hemos visto esto es cuando alguien fusionó artificialmente dos archivos evtx diferentes para el proyecto [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).)
Podemos usar esto a nuestro favor comprobando primero el campo `Channel` en el primer registro de cada archivo `.evtx` especificado para escanear.
También comprobamos qué reglas `.yml` usan qué canales especificados en el campo `Channel` de la regla.
Con estas dos listas, solo cargamos las reglas que usan canales que realmente están presentes dentro de los archivos `.evtx`.

Así, por ejemplo, si un usuario desea escanear `Security.evtx`, solo se usarán las reglas que especifiquen `Channel: Security`.
No tiene sentido cargar otras reglas de detección, por ejemplo reglas que solo buscan eventos en el registro `Application`, etc...
Tenga en cuenta que los campos de canal (Ej: `Channel: Security`) no están definidos **explícitamente** dentro de las reglas Sigma originales.
Para las reglas Sigma, los campos de canal e ID de evento están definidos **implícitamente** con los campos `service` y `category` bajo `logsource`. (Ej: `service: security`)
Al curar las reglas Sigma en el repositorio [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), desabstraemos el campo `logsource` y definimos explícitamente los campos de canal e ID de evento.
Explicamos cómo y por qué hacemos esto en profundidad [aquí](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Actualmente, solo hay dos reglas de detección que no tienen `Channel` definido y están destinadas a escanear todos los archivos `.evtx` que son las siguientes:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Si desea usar estas dos reglas y escanear todas las reglas contra los archivos `.evtx` cargados, entonces necesitará añadir la opción `-A, --enable-all-rules` en el comando `dfir-timeline`.
En nuestras pruebas comparativas, el filtrado de reglas normalmente da una mejora de velocidad del 20% a 10 veces dependiendo de qué archivos se están escaneando y, por supuesto, usa menos memoria.

El filtrado de canales también se usa al cargar archivos `.evtx`.
Por ejemplo, si especifica una regla que busca eventos con un canal de `Security`, entonces no tiene sentido cargar archivos `.evtx` que no son del registro `Security`.
En nuestras pruebas comparativas, esto da un beneficio de velocidad de alrededor del 10% con escaneos normales y hasta un aumento de rendimiento del 60%+ al escanear con una sola regla.
Si está seguro de que se están usando múltiples canales dentro de un solo archivo `.evtx`, por ejemplo si alguien usó una herramienta para fusionar múltiples archivos `.evtx`, entonces puede desactivar este filtrado con la opción `-a, --scan-all-evtx-files` en el comando `dfir-timeline`.

> Nota: El filtrado de canales solo funciona con archivos `.evtx` y recibirá un error si intenta cargar registros de eventos desde un archivo JSON con `-J, --json-input` y también especifica `-A` o `-a`.

## Comando `dfir-timeline`

El comando `dfir-timeline` crea una cronología forense de eventos. Elija el formato de salida con `-t, --output-type`: `csv` (el predeterminado), `json` o `jsonl`. El valor no distingue entre mayúsculas y minúsculas (por ejemplo, `-t JSONL`).

- **CSV** es bueno para importar cronologías más pequeñas (normalmente menos de 2GB) a herramientas como LibreOffice o Timeline Explorer (todos los campos de eventos se colocan en una gran columna `Details`).
- **JSON** es mejor para un análisis más detallado de resultados grandes con herramientas como `jq`, ya que los campos `Details` están separados.
- **JSONL** es más rápido y produce un archivo más pequeño que JSON, lo que lo hace ideal para importar a herramientas como Elastic Stack.

Las opciones de **Salida CSV** `-M, --multiline`, `-S, --tab-separator` y `-R, --remove-duplicate-data` solo se aplican a la salida CSV y producirán un error si se combinan con un `-t` que no sea CSV.

```
  hayabusa.exe dfir-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort results before saving the file (warning: this uses much more memory!)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)
      --threads <NUMBER>               Number of threads (default: optimal number for performance)
  -V, --validate-checksums             Enable checksum validation

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline to a file (ex: results.csv)
  -t, --output-type <OUTPUT_FORMAT>  Output format: csv (default), json, or jsonl (case-insensitive, e.g. -t JSONL) [default: csv] [possible values: csv, json, jsonl]
  -p, --profile <PROFILE>            Specify output profile
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)

CSV Output:
  -M, --multiline              Separate event field information by newline characters (CSV output only)
  -R, --remove-duplicate-data  Duplicate field data will be replaced with "DUP" (CSV output only)
  -S, --tab-separator          Separate event field information by tabs (CSV output only)
```

### Ejemplos del comando `dfir-timeline`

* Ejecutar hayabusa contra un archivo de registro de eventos de Windows con el perfil `standard` predeterminado:

```
hayabusa.exe dfir-timeline -f eventlog.evtx
```

* Ejecutar hayabusa contra el directorio sample-evtx con múltiples archivos de registro de eventos de Windows con el perfil verbose:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -p verbose
```

* Exportar a un único archivo CSV para análisis posterior con LibreOffice, Timeline Explorer, Elastic Stack, etc... e incluir toda la información de campos (Advertencia: ¡el tamaño de salida de su archivo será mucho mayor con el perfil `super-verbose`!):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Generar salida en JSON en lugar de CSV (para análisis con `jq`, etc.):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t json -o results.json
```

* Generar salida en JSONL (para importar a Elastic Stack, etc.; `-t` no distingue entre mayúsculas y minúsculas):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -t JSONL -o results.jsonl
```

* Habilitar el filtro EID (Event ID):

> Nota: Habilitar el filtro EID acelerará el análisis en aproximadamente un 10-15% en nuestras pruebas, pero existe la posibilidad de perder alertas.

```
hayabusa.exe dfir-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Ejecutar solo las reglas de hayabusa (lo predeterminado es ejecutar todas las reglas en `-r .\rules`):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Ejecutar solo las reglas de hayabusa para registros que están habilitados de forma predeterminada en Windows:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Ejecutar solo las reglas de hayabusa para registros de sysmon:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Ejecutar solo las reglas sigma:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Habilitar reglas obsoletas (aquellas con `status` marcado como `deprecated`) y reglas ruidosas (aquellas cuyo ID de regla está listado en `.\rules\config\noisy_rules.txt`):

> Nota: Recientemente, las reglas obsoletas ahora se encuentran en un directorio separado en el repositorio sigma, por lo que ya no se incluyen de forma predeterminada en Hayabusa.
> Por lo tanto, probablemente no tenga necesidad de habilitar reglas obsoletas.

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Ejecutar solo reglas para analizar inicios de sesión y mostrar la salida en la zona horaria UTC:

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Ejecutar en una máquina Windows en vivo (requiere privilegios de Administrador) y detectar solo alertas (comportamiento potencialmente malicioso):

```
hayabusa.exe dfir-timeline -l -m low
```

* Imprimir información detallada (útil para determinar qué archivos tardan mucho en procesarse, errores de análisis, etc...):

```
hayabusa.exe dfir-timeline -d .\hayabusa-sample-evtx -v
```

* Ejemplo de salida detallada:

Cargando reglas:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Errores durante el escaneo:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* Generar una salida en un formato CSV compatible para importar a [Timesketch](https://timesketch.org/):

```
hayabusa.exe dfir-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Modo de errores silenciosos:
De forma predeterminada, hayabusa guardará los mensajes de error en archivos de registro de errores.
Si no desea guardar los mensajes de error, añada `-Q`.

### Avanzado - Enriquecimiento de registros con GeoIP

Puede añadir información de GeoIP (organización ASN, ciudad y país) a los campos SrcIP (IP de origen) y a los campos TgtIP (IP de destino) con los datos de geolocalización gratuitos de GeoLite2.

Pasos:

1. Primero regístrese para obtener una cuenta de MaxMind [aquí](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Descargue los tres archivos `.mmdb` desde la [página de descargas](https://www.maxmind.com/en/accounts/current/geoip/downloads) y guárdelos en un directorio. Los nombres de los archivos deben llamarse `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` y `GeoLite2-Country.mmdb`.
3. Al ejecutar el comando `dfir-timeline`, añada la opción `-G` seguida del directorio con las bases de datos de MaxMind.

* Con salida CSV, se mostrarán adicionalmente las siguientes 6 columnas: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* Con salida JSON/JSONL, los mismos campos `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` se añadirán al objeto `Details`, pero solo si contienen información.

* Cuando `SrcIP` o `TgtIP` es localhost (`127.0.0.1`, `::1`, etc...), `SrcASN` o `TgtASN` se mostrará como `Local`.
* Cuando `SrcIP` o `TgtIP` es una dirección IP privada (`10.0.0.0/8`, `fe80::/10`, etc...), `SrcASN` o `TgtASN` se mostrará como `Private`.

#### Archivo de configuración de GeoIP

Los nombres de campo que contienen las direcciones IP de origen y destino que se buscan en las bases de datos de GeoIP están definidos en `rules/config/geoip_field_mapping.yaml`.
Puede añadir a esta lista si es necesario.
También hay una sección de filtro en este archivo que determina de qué eventos extraer la información de direcciones IP.

#### Actualizaciones automáticas de las bases de datos de GeoIP

Las bases de datos de GeoIP de MaxMind se actualizan cada 2 semanas.
Puede instalar la herramienta `geoipupdate` de MaxMind [aquí](https://github.com/maxmind/geoipupdate) para actualizar automáticamente estas bases de datos.

Pasos en macOS:

1. `brew install geoipupdate`
2. Edite `/usr/local/etc/GeoIP.conf` o `/opt/homebrew/etc/GeoIP.conf`: Ponga su `AccountID` y `LicenseKey` que crea después de iniciar sesión en el sitio web de MaxMind. Asegúrese de que la línea `EditionIDs` diga `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Ejecute `geoipupdate`.
4. Añada `-G /usr/local/var/GeoIP` o `-G /opt/homebrew/var/GeoIP` cuando desee añadir información de GeoIP.

Pasos en Windows:

1. Descargue el binario de Windows más reciente (Ej: `geoipupdate_4.10.0_windows_amd64.zip`) desde la página de [Releases](https://github.com/maxmind/geoipupdate/releases).
2. Edite `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: Ponga su `AccountID` y `LicenseKey` que crea después de iniciar sesión en el sitio web de MaxMind. Asegúrese de que la línea `EditionIDs` diga `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Ejecute el ejecutable `geoipupdate`.

Pasos en Linux:

1. Instale con `sudo apt install geoip-update`.
2. Edite el archivo de configuración con `sudo nano /etc/GeoIP.conf`.
3. Actualice los archivos de la base de datos con `sudo geoipupdate`.
4. Añada `-G /var/lib/GeoIP/` cuando desee añadir información de GeoIP.

### Archivos de configuración del comando `dfir-timeline`

`./rules/config/channel_abbreviations.txt`: Asignaciones de nombres de canales y sus abreviaturas.

`./rules/config/default_details.txt`: El archivo de configuración para qué información de campos predeterminada (campo `%Details%`) debe mostrarse si no se especifica una línea `details:` en una regla.
Esto se basa en el nombre del proveedor y los ID de eventos.

`./rules/config/eventkey_alias.txt`: Este archivo tiene las asignaciones de alias de nombres cortos para los campos y sus nombres de campo originales más largos.

Ejemplo:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Si un campo no está definido aquí, Hayabusa comprobará automáticamente bajo `Event.EventData` para el campo.

`./rules/config/exclude_rules.txt`: Este archivo tiene una lista de IDs de reglas que se excluirán del uso.
Normalmente esto se debe a que una regla ha reemplazado a otra o a que la regla no se puede usar en primer lugar.
Al igual que los firewalls y los IDS, cualquier herramienta basada en firmas requerirá algún ajuste para adaptarse a su entorno, por lo que es posible que deba excluir permanentemente o temporalmente ciertas reglas.
Puede añadir un ID de regla (Ejemplo: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) a `./rules/config/exclude_rules.txt` para ignorar cualquier regla que no necesite o que no pueda usarse.

`./rules/config/noisy_rules.txt`: Este archivo es una lista de IDs de reglas que están deshabilitadas de forma predeterminada pero que pueden habilitarse habilitando las reglas ruidosas con la opción `-n, --enable-noisy-rules`.
Estas reglas suelen ser ruidosas por naturaleza o debido a falsos positivos.

`./rules/config/target_event_IDs.txt`: Solo se escanearán los ID de eventos especificados en este archivo si el filtro EID está habilitado.
De forma predeterminada, Hayabusa escaneará todos los eventos, pero si desea mejorar el rendimiento, use la opción `-E, --EID-filter`.
Esto normalmente resulta en una mejora de velocidad del 10~25%.

## Comando `level-tuning`

El comando `level-tuning` le permitirá ajustar los niveles de alerta de las reglas, ya sea aumentando o disminuyendo el nivel de riesgo como desee.
Este comando usa un archivo de configuración para sobrescribir los niveles de riesgo (el campo `level`) de las reglas en la carpeta `rules`.

> Advertencia: cada vez que ejecute el comando `update-rules`, el nivel de riesgo volverá a su valor original, por lo que necesitará ejecutar el comando `level-tuning` nuevamente después.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### Ejemplos del comando `level-tuning`

* Uso normal: `hayabusa.exe level-tuning`
* Ajustar los niveles de alerta de las reglas basándose en su archivo de configuración personalizado: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### Archivo de configuración de `level-tuning`

Los autores de las reglas de Hayabusa y Sigma estimarán el nivel de riesgo apropiado de la alerta al escribir sus reglas.
Sin embargo, a veces los niveles de riesgo no son consistentes y además el nivel de riesgo real puede diferir según su entorno.
Yamato Security proporciona y mantiene un archivo de configuración en `./rules/config/level_tuning.txt` que también puede usar para ajustar sus reglas.

Ejemplo de `./rules/config/level_tuning.txt`:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

En este caso, la regla con un `id` de `570ae5ec-33dc-427c-b815-db86228ad43e` en el directorio de reglas tendrá su `level` reescrito a `informational`.
Los niveles posibles a establecer son `critical`, `high`, `medium`, `low` e `informational`.

> Advertencia: El archivo de configuración `./rules/config/level_tuning.txt` también se actualizará a la última versión en el repositorio hayabusa-rules cada vez que ejecute `update-rules`.
> Por lo tanto, si realiza cambios en este archivo, ¡perderá esos cambios!
> Si desea mantener un archivo de configuración para usted mismo, cree un archivo de configuración en `./config/level_tuning.txt` y ejecute `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> También puede primero hacer el ajuste de niveles con el archivo de configuración proporcionado por Yamato Security y luego ajustar más con su propio archivo de configuración.

## Comando `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## Comando `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### Ejemplos del comando `set-default-profile`

* Establecer el perfil predeterminado a `minimal`: `hayabusa.exe set-default-profile minimal`
* Establecer el perfil predeterminado a `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## Comando `update-rules`

El comando `update-rules` sincronizará la carpeta `rules` con el [repositorio github de reglas de Hayabusa](https://github.com/Yamato-Security/hayabusa-rules), actualizando las reglas y los archivos de configuración.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### Ejemplo del comando `update-rules`

Normalmente solo ejecutará esto: `hayabusa.exe update-rules`
