# Análisis de resultados de Hayabusa con jq

# Autor

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# Acerca de

Ser capaz de identificar, extraer y crear métricas sobre campos importantes en los registros es una habilidad esencial para los analistas de DFIR y de caza de amenazas.
Los resultados de Hayabusa normalmente se guardan en archivos `.csv` para importarlos a programas como Excel o Timeline Explorer para el análisis de líneas de tiempo.
Sin embargo, cuando hay cientos o más de un mismo evento, se vuelve impráctico o imposible revisarlos manualmente.
En estas situaciones, los analistas suelen ordenar y contar tipos similares de datos en busca de valores atípicos.
Esto también se conoce como análisis de cola larga, clasificación por pilas, análisis de frecuencia, etc...
Esto se puede lograr con Hayabusa generando los resultados en archivos `.json` o `.jsonl` y luego analizándolos con `jq`.

Por ejemplo, un analista podría comparar los servicios instalados en todas las estaciones de trabajo de una organización.
Si bien es posible que cierta pieza de malware se instale en todas las estaciones de trabajo, es más que probable que solo exista en un puñado de sistemas.
En este caso, es más probable que los servicios instalados en todos los sistemas sean benignos, mientras que los servicios raros tienden a ser más sospechosos y deberían revisarse periódicamente.

Otro caso de uso es ayudar a determinar cuán sospechoso es algo.
Por ejemplo, un analista podría analizar los registros de inicio de sesión fallidos `4625` para determinar cuántas veces una determinada dirección IP no logró iniciar sesión.
Si solo hubo unos pocos inicios de sesión fallidos, entonces es probable que un administrador simplemente haya escrito mal su contraseña.
Sin embargo, si hubo cientos o más inicios de sesión fallidos en un corto período de tiempo por parte de una determinada dirección IP, entonces es probable que la dirección IP sea maliciosa.

Aprender a usar `jq` te ayudará a dominar no solo el análisis de los registros de eventos de Windows, sino de todos los registros con formato JSON.
Ahora que JSON se ha convertido en un formato de registro muy popular y la mayoría de los proveedores de la nube lo utilizan para sus registros, ser capaz de analizarlos con `jq` se ha convertido en una habilidad esencial para el analista de seguridad moderno.

En esta guía, primero explicaré cómo utilizar `jq` para aquellos que nunca lo han usado antes y luego explicaré usos más complejos junto con ejemplos del mundo real.
Recomiendo usar linux, macOS o linux en Windows para poder combinar `jq` con otros comandos útiles como `sort`, `uniq`, `grep`, `sed`, etc...

# Instalación de jq

Por favor consulta [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) e instala el comando `jq`.

# Acerca del formato JSON

Los registros JSON son una lista de objetos contenidos entre llaves `{` `}`.
Dentro de estos objetos hay pares clave-valor separados por dos puntos.
Las claves deben ser cadenas, pero los valores pueden ser uno de los siguientes:
  * cadena (Ej: `"string"`)
  * número (Ej: `10`)
  * otro objeto (Ej: `{ xxxx }`)
  * arreglo (Ej: `["string", 10]`)
  * booleano (Ej: `true`, `false`)
  * `null`

Puedes anidar tantos objetos como quieras dentro de objetos.

En este ejemplo, `Details` es un objeto anidado dentro de un objeto raíz:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Acerca de los formatos JSON y JSONL con Hayabusa

En versiones anteriores, Hayabusa utilizaba el formato JSON tradicional de colocar todos los objetos de registro `{ xxx }` en un único arreglo gigante.

Ejemplo:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

Hay dos problemas con esto.
El primer problema es que las consultas de `jq` se vuelven más engorrosas, ya que todo tiene que comenzar con un `.[]` adicional para indicarle que mire dentro de ese arreglo.
El problema mucho mayor es que para que cualquier cosa pueda analizar dichos registros, es necesario primero cargar todos los datos del arreglo.
Esto se convierte en un problema si tienes archivos JSON muy grandes y no tienes abundancia de memoria.
Para reducir el uso requerido de CPU y memoria, el formato JSONL (JSON Lines), que no coloca todo en un arreglo gigante, se ha vuelto más popular.
Hayabusa genera en los formatos JSON y JSONL, sin embargo, el formato JSON ya no se guarda dentro de un arreglo.
La única diferencia es que el formato JSON es más fácil de leer en un editor de texto o en la consola, mientras que el formato JSONL almacena cada objeto JSON en una sola línea.
El formato JSONL será ligeramente más rápido y de menor tamaño, por lo que es ideal si solo vas a importar los registros a un SIEM, etc... pero no a mirarlos.
El formato JSON es ideal si también vas a realizar alguna comprobación manual.

# Creación de archivos de resultados JSON

En la versión actual 2.x de Hayabusa, puedes guardar los resultados en JSON con `hayabusa dfir-timeline -t json -d <directory> -o results.json` o `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` para el formato JSONL.

Hayabusa utilizará el perfil predeterminado `standard` y solo guardará la cantidad mínima de datos para el análisis en el objeto `Details`.
Si deseas guardar toda la información original de los campos en los registros .evtx, puedes usar el perfil `all-field-info` con la opción `--profile all-field-info`.
Esto guardará toda la información de los campos en el objeto `AllFieldInfo`.
Si deseas guardar tanto el objeto `Details` como el `AllFieldInfo` por si acaso, puedes usar el perfil `super-verbose`.

## Beneficios de usar Details en lugar de AllFieldInfo

El primer beneficio de usar `Details` en lugar de `AllFieldInfo` es que solo se guardan los campos importantes, y los nombres de los campos se han acortado para ahorrar espacio en el archivo.
La desventaja es que existe la posibilidad de perder datos que realmente te importaban pero que se pasaron por alto.
El segundo beneficio es que Hayabusa guardará los campos de una manera más uniforme al normalizar los nombres de los campos.
Por ejemplo, en los registros originales de Windows, el nombre de usuario suele estar en un campo `SubjectUserName` o `TargetUserName`. 
Sin embargo, a veces el nombre de usuario estará en un campo `AccountName`, a veces el usuario objetivo estará en realidad en el campo `SubjectUserName`, etc...
Desafortunadamente, hay muchos nombres de campo inconsistentes en los registros de eventos de Windows.
Hayabusa intenta normalizar estos campos, de modo que un analista solo tenga que analizar un nombre común en lugar de tener que entender la cantidad infinita de peculiaridades y discrepancias entre los IDs de eventos en Windows.

Aquí hay un ejemplo del campo de usuario.
Hayabusa normalizará `SubjectUserName`, `TargetUserName`, `AccountName`, etc... de la siguiente manera:
  * `SrcUser` (Usuario de origen): cuando una acción ocurre **desde** un usuario. (Generalmente un usuario remoto.)
  * `TgtUser` (Usuario objetivo): cuando una acción ocurre **hacia** un usuario. (Por ejemplo, un inicio de sesión **hacia** un usuario.)
  * `User`: cuando una acción ocurre por un usuario actualmente conectado. (No hay una dirección particular en la acción.)

Otro ejemplo son los procesos.
En los registros originales de eventos de Windows, el campo de proceso se refiere con múltiples convenciones de nomenclatura: `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName`, etc...
Sin la normalización de campos, un analista tendría que primero tener conocimiento de todos los diferentes nombres de campo, luego extraer todos los registros con estos nombres de campo y luego combinarlos. 

Un analista puede ahorrar mucho tiempo y problemas simplemente usando el único campo normalizado `Proc` que Hayabusa proporciona en el objeto `Details`.

# Lecciones/Recetas de jq

Ahora enumeraré varias lecciones/recetas de ejemplos prácticos que pueden ayudarte en tu trabajo.

## 1. Comprobación manual con jq y Less a color

Esto es una de las primeras cosas que hay que hacer para entender qué campos hay en los registros.
Podrías simplemente hacer un `less results.json` pero una mejor manera es la siguiente:
`cat results.json | jq -C | less -R`

Al pasarlo a `jq`, formateará ordenadamente todos los campos por ti si no estaban formateados ordenadamente desde el principio.
Al usar la opción `-C` (color) con `jq` y la opción `-R` (salida sin procesar) con `less`, puedes desplazarte hacia arriba y hacia abajo a color.

## 2. Métricas

Hayabusa ya tiene funcionalidad para imprimir el número y el porcentaje de eventos basándose en los IDs de eventos, sin embargo, también es bueno saber cómo hacerlo con `jq`.
Esto te permitirá personalizar los datos para los que quieres crear métricas.

Primero extraigamos una lista de IDs de eventos con el siguiente comando:

`cat results.json | jq '.EventID'`

Esto extraerá solo el número de ID de evento de cada registro.
Después de `jq`, entre comillas simples, simplemente escribe un `.` y el nombre del campo que deseas extraer.
Deberías ver una larga lista como esta:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Ahora, canaliza los resultados a los comandos `sort` y `uniq -c` para contar cuántas veces ocurrieron los IDs de eventos:

`cat results.json | jq '.EventID' | sort | uniq -c`

La opción `-c` de `uniq` contará cuántas veces ocurrió un ID de evento único.

Deberías ver algo como esto:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 La izquierda es el conteo, y la derecha es el ID de evento.
 Como puedes ver, no está ordenado, por lo que es difícil saber qué IDs de eventos ocurrieron más.

 Puedes agregar un `sort -n` al final para corregir esto:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

La opción `-n` le indica a `sort` que ordene por número.

Deberías ver algo como esto:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

Podemos ver que los eventos `4688` (Creación de procesos) fueron los más registrados.
El segundo evento más registrado fue `4625` (Inicio de sesión fallido).

Si deseas imprimir los eventos más registrados en la parte superior, entonces puedes invertir el orden con `sort -n -r` o `sort -nr`.
También puedes imprimir solo los 10 eventos más registrados canalizando los resultados a `head -n 10`.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

Esto te dará:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

Es importante considerar que los EIDs (IDs de eventos) no son únicos, por lo que podrías tener eventos completamente diferentes con el mismo ID de evento.
Por lo tanto, es importante también comprobar el `Channel`.

Podemos agregar esta información de campo de esta manera:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Agregamos la opción `-j` (join) a `jq` para unir todos los campos delimitados por comas y terminando con un carácter de nueva línea `\n`.

Esto nos dará:
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 Nota: `Security` se abrevia como `Sec`, `System` como `Sys`, y `PowerShell` como `PwSh`.

Podemos agregar el título de la regla de la siguiente manera:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Esto nos dará:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

Ahora puedes extraer libremente cualquier dato de los registros y contar las ocurrencias.

## 3. Filtrado en ciertos datos

Muchas veces querrás filtrar por ciertos IDs de eventos, usuarios, procesos, LIDs (IDs de inicio de sesión), etc...
Puedes hacerlo con `select` dentro de la consulta de `jq`.

Por ejemplo, extraigamos todos los eventos de inicio de sesión exitoso `4624`:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

Esto devolverá todos los objetos JSON para el EID `4624`:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

Si deseas filtrar por múltiples condiciones, puedes usar palabras clave como `and`, `or` y `not`.

Por ejemplo, busquemos eventos `4624` donde el tipo es `3` (Inicio de sesión de red).

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

Esto devolverá todos los objetos donde el `EventID` es `4624` y el campo anidado `"Details": { "Type" }` es `3`.

Sin embargo, hay un problema.
Es posible que notes errores que dicen `jq: error (at <stdin>:10636): Cannot index string with string "Type"`.
Cada vez que veas el error `Cannot index string with string`, significa que le estás indicando a `jq` que genere un campo que no existe o que es del tipo incorrecto.
Puedes deshacerte de estos errores agregando un `?` al final del campo.
Esto le indica a `jq` que ignore los errores.

Ejemplo: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

Ahora, después de filtrar por ciertos criterios, podemos usar un `|` dentro de la consulta de `jq` para ahora seleccionar ciertos campos de interés.

Por ejemplo, extraigamos el nombre de usuario objetivo `TgtUser` y la dirección IP de origen `SrcIP`:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

Nuevamente, agregamos la opción `-j` (join) a `jq` para seleccionar múltiples campos para generar.
Luego puedes ejecutar `sort`, `uniq -c`, etc... como en los ejemplos anteriores para averiguar cuántas veces una determinada dirección IP inició sesión en un usuario a través de un inicio de sesión de red de tipo 3.

## 4. Guardar la salida en formato CSV

Desafortunadamente, los campos en los registros de eventos de Windows difieren completamente según el tipo de evento, por lo que no es fácilmente posible crear líneas de tiempo separadas por comas por campos sin tener cientos de columnas.
Sin embargo, es posible crear líneas de tiempo separadas por campos para tipos individuales de eventos.
Dos ejemplos comunes son los de Security `4624` (Inicios de sesión exitosos) y `4625` (Inicios de sesión fallidos) para comprobar el movimiento lateral y la adivinación/pulverización de contraseñas.

En este ejemplo, estamos extrayendo solo los registros de Security 4624 y generando la marca de tiempo, el nombre del equipo y toda la información de `Details`.
Lo guardamos en un archivo CSV usando `| @csv`, sin embargo, necesitamos pasar los datos como un arreglo.
Podemos hacerlo seleccionando los campos que queremos generar como hicimos previamente y encerrándolos con corchetes `[ ]` para convertirlos en un arreglo.

Ejemplo: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

Notas:
  * Para seleccionar todos los campos del objeto `Details` agregamos `[]`.
  * Hay casos en los que `Details` es una cadena y no un arreglo y dará errores `Cannot iterate over string` por lo que necesitas agregar un `?`.
  * Agregamos la opción `-r` (salida sin procesar) a `jq` para no escapar las comillas dobles con barra invertida.

Resultados:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

Si solo estamos comprobando quién tuvo inicios de sesión exitosos, es posible que no necesitemos el último campo `LID` (ID de inicio de sesión).
Puedes eliminar cualquier columna innecesaria con la función `del`.

Ejemplo: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

El arreglo cuenta desde `0` por lo que para eliminar el 7.º campo, usamos `6`.

Ahora puedes guardar el archivo CSV agregando `> 4624-logs.csv` y luego importarlo a Excel o Timeline Explorer para un análisis posterior.

Ten en cuenta que necesitarás agregar un encabezado para realizar el filtrado.
Si bien es posible agregar un encabezado dentro de la consulta de `jq`, normalmente es más fácil simplemente agregar manualmente una fila superior después de guardar el archivo.

## 5. Encontrar las fechas con más alertas

Hayabusa, de forma predeterminada, te indicará las fechas que tuvieron más alertas según los niveles de severidad.
Sin embargo, es posible que también quieras encontrar la segunda, tercera, etc... fecha con más alertas.
Podemos hacerlo recortando la cadena de la marca de tiempo para agrupar por año, mes o fecha según tus necesidades.

Ejemplo: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` le indica a `jq` que extraiga solo los primeros 10 bytes de `Timestamp`.

Esto nos dará las fechas con más eventos:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

Si quieres saber el mes con más eventos, puedes simplemente cambiar `.[:10]` a `.[:7]` para extraer los primeros 7 bytes.

Si quieres listar las fechas con más alertas `high`, puedes hacer esto:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

Puedes seguir agregando condiciones de filtro a la función `select` según el nombre del equipo, el ID de evento, etc... dependiendo de tus necesidades.

## 6. Reconstrucción de registros de PowerShell

Algo desafortunado sobre los registros de PowerShell es que los registros a menudo se dividen en múltiples registros, lo que dificulta su lectura.
Podemos hacer que los registros sean mucho más fáciles de leer extrayendo solo los comandos que ejecutó el atacante.

Por ejemplo, si tienes registros de ScriptBlock del EID `4104`, puedes extraer solo ese campo para crear una línea de tiempo fácil de leer.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

Esto dará como resultado una línea de tiempo de la siguiente manera:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. Encontrar conexiones de red sospechosas

Primero puedes obtener una lista de todas las direcciones IP objetivo con el siguiente comando:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

Si tienes inteligencia de amenazas, puedes comprobar si alguna de las direcciones IP es conocida por ser maliciosa.

Puedes contar las veces que se conectó a una determinada dirección IP objetivo con lo siguiente:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

Al cambiar `TgtIP` por `SrcIP`, puedes realizar la misma comprobación de inteligencia de amenazas para direcciones IP maliciosas basándote en las direcciones IP de origen.

Supongamos que encontraste que la dirección IP maliciosa `93.184.220.29` se está conectando desde tu entorno.
Puedes obtener detalles sobre esos eventos con la siguiente consulta:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

Esto te dará los resultados JSON como este:
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

Si quieres listar los dominios que fueron contactados, puedes usar el siguiente comando:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> Nota: Agregué un filtro grep para `.` para eliminar los nombres de host NETBIOS.

## 8. Extracción de hashes de binarios ejecutables

En los registros de Creación de procesos del EID `1` de Sysmon, sysmon puede configurarse para calcular hashes del binario.
Los analistas de seguridad pueden comparar estos hashes con hashes maliciosos conocidos mediante inteligencia de amenazas.
Puedes extraer el campo `Hashes` con lo siguiente:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

Esto te dará una lista de hashes como esta:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

Sysmon normalmente calculará múltiples hashes como `MD5`, `SHA1` e `IMPHASH`.
Puedes extraer estos hashes con expresiones regulares en `jq` o simplemente usar el recorte de cadenas para un mejor rendimiento.

Por ejemplo, puedes extraer los hashes MD5 y eliminar duplicados con lo siguiente:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. Extraer registros de PowerShell

Los registros de Scriptblock de PowerShell (EID: 4104) normalmente se dividen en muchos registros y, al generar en formato CSV, Hayabusa eliminará las tabulaciones y los caracteres de retorno para hacer la salida más concisa.
Sin embargo, es más fácil analizar los registros de powershell con el formato original de tabulación y caracteres de retorno y combinando los registros.
Aquí hay un ejemplo de extracción de los registros de PowerShell EID 4104 de `COMPUTER-A` y guardarlos en un archivo `.ps1` para abrirlos y analizarlos en VSCode, etc...
Después de extraer el campo ScriptBlock, usamos `awk` para reemplazar `\r\n` y `\n` por caracteres de retorno y `\t` por tabulaciones.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

Después de que el analista analice los registros en busca de comandos maliciosos de PowerShell, normalmente necesitará buscar cuándo se ejecutaron esos comandos.
Aquí hay un ejemplo de generar la marca de tiempo y los registros de PowerShell en un archivo CSV para buscar la hora en que se ejecutó un comando:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

Nota: El delimitador de cadena utilizado es `¦` porque las comillas simples y dobles se encuentran a menudo en los registros de PowerShell y corromperán la salida CSV.
Cuando importes el archivo CSV, necesitas especificarle a la aplicación el delimitador de cadena `¦`.
