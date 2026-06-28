# Campo de detección

## Fundamentos de selection

Primero, se explicarán los fundamentos de cómo crear una regla de selection.

### Cómo escribir lógica AND y OR

Para escribir lógica AND, usamos diccionarios anidados.
La regla de detección a continuación define que **ambas condiciones** tienen que ser verdaderas para que la regla coincida.
- EventID tiene que ser exactamente `7040`.
- **AND**
- Channel tiene que ser exactamente `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

Para escribir lógica OR, usamos listas (diccionarios que comienzan con `-`).
En la regla de detección a continuación, **cualquiera** de las condiciones hará que la regla se active.
- EventID tiene que ser exactamente `7040`.
- **OR**
- Channel tiene que ser exactamente `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

También podemos combinar lógica `AND` y `OR` como se muestra a continuación.
En este caso, la regla coincide cuando las siguientes dos condiciones son ambas verdaderas.
- EventID es exactamente `7040` **OR** `7041`.
- **AND**
- Channel es exactamente `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

A continuación se muestra un extracto de un registro de eventos de Windows, formateado en el XML original.
El campo `Event.System.Channel` en el ejemplo de archivo de regla anterior hace referencia a la etiqueta XML original: `<Event><System><Channel>System<Channel><System></Event>`
Las etiquetas XML anidadas se reemplazan por nombres de etiquetas separados por puntos (`.`).
En las reglas de hayabusa, estas cadenas de campos conectadas entre sí con puntos se denominan `eventkeys`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Alias de Eventkey

Los eventkeys largos con muchas separaciones de `.` son comunes, por lo que hayabusa usará alias para que sean más fáciles de manejar. Los alias se definen en el archivo `rules/config/eventkey_alias.txt`. Este archivo es un archivo CSV compuesto por asignaciones de `alias` y `event_key`. Puede reescribir la regla anterior como se muestra a continuación con alias que hacen que la regla sea más fácil de leer.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Precaución: Alias de Eventkey no definidos

No todos los alias de eventkey están definidos en `rules/config/eventkey_alias.txt`. Si no obtiene los datos correctos en el mensaje de `details` (`Alert details`), y en su lugar obtiene `n/a` (no disponible) o si la selection en su lógica de detección no funciona correctamente, entonces es posible que necesite actualizar `rules/config/eventkey_alias.txt` con un nuevo alias.

### Cómo usar atributos XML en condiciones

Los elementos XML pueden tener atributos establecidos agregando un espacio al elemento. Por ejemplo, `Name` en `Provider Name` a continuación es un atributo XML del elemento `Provider`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

Para especificar atributos XML en un eventkey, use el formato `{eventkey}_attributes.{attribute_name}`. Por ejemplo, para especificar el atributo `Name` del elemento `Provider` en un archivo de regla, se vería así:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### búsqueda grep

Hayabusa puede realizar búsquedas grep en archivos de registro de eventos de Windows al no especificar ningún eventkey.

Para hacer una búsqueda grep, especifique la detección como se muestra a continuación. En este caso, si las cadenas `mimikatz` o `metasploit` están incluidas en el registro de eventos de Windows, coincidirá. También es posible especificar comodines.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Nota: Hayabusa convierte internamente los datos del registro de eventos de Windows a formato JSON antes de procesar los datos, por lo que no es posible coincidir con etiquetas XML.

### EventData

Los registros de eventos de Windows se dividen en dos partes: la parte `System` donde se escriben los datos fundamentales (Event ID, Timestamp, Record ID, Nombre del registro (Channel)) y la parte `EventData` o `UserData` donde se escriben datos arbitrarios según el Event ID.
Un problema que surge a menudo es que los nombres de los campos anidados en `EventData` se llaman todos `Data`, por lo que los eventkeys descritos hasta ahora no pueden distinguir entre `SubjectUserSid` y `SubjectUserName`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

Para hacer frente a este problema, puede especificar el valor asignado en `Data Name`. Por ejemplo, si desea usar `SubjectUserName` y `SubjectDomainName` en el EventData como condición de una regla, puede describirlo de la siguiente manera:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Patrones anormales en EventData

Algunas de las etiquetas anidadas en `EventData` no tienen un atributo `Name`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

Para detectar un registro de eventos como el anterior, puede especificar un eventkey llamado `Data`.
En este caso, la condición coincidirá siempre que alguna de las etiquetas `Data` anidadas sea igual a `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Generación de datos de campos a partir de varios nombres de campos con el mismo nombre

Algunos eventos guardarán sus datos en nombres de campos llamados todos `Data` como en el ejemplo anterior.
Si especifica `%Data%` en `details:`, todos los datos se generarán en un array.

Por ejemplo:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Si desea imprimir solo los datos del primer campo `Data`, puede especificar `%Data[1]%` en su cadena de alerta `details:` y solo se generará `rundll32.exe`.

## Modificadores de campo

Se puede usar un carácter de barra vertical con eventkeys como se muestra a continuación para coincidir con cadenas.
Todas las condiciones que hemos descrito hasta ahora usan coincidencias exactas, pero al usar modificadores de campo, puede describir reglas de detección más flexibles.
En el siguiente ejemplo, si un valor de `Data` contiene la cadena `EngineVersion=2`, coincidirá con la condición.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

Las coincidencias de cadenas no distinguen entre mayúsculas y minúsculas. Sin embargo, distinguen entre mayúsculas y minúsculas cuando se usa `|re` o `|equalsfield`.

### Modificadores de campo de Sigma admitidos

Hayabusa es actualmente la única herramienta de código abierto que admite completamente toda la especificación de Sigma.

Puede consultar el estado actual de todos los modificadores de campo admitidos, así como cuántas veces se usan estos modificadores en las reglas de Sigma y Hayabusa en https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
Este documento se actualiza dinámicamente cada vez que hay una actualización de las reglas de Sigma o Hayabusa.

- `'|all':`: Este modificador de campo es diferente de los anteriores porque no se aplica a un campo determinado sino a todos los campos.

    En este ejemplo, ambas cadenas `Keyword-1` y `Keyword-2` deben existir, pero pueden existir en cualquier lugar de cualquier campo:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Los datos se codificarán en base64 de tres maneras diferentes según su posición en la cadena codificada. Este modificador codificará una cadena en las tres variaciones y verificará si la cadena está codificada en algún lugar de la cadena base64.
- `|cased`: Hace que la búsqueda distinga entre mayúsculas y minúsculas.
- `|cidr`: Verifica si un valor de campo coincide con una notación CIDR IPv4 o IPv6. (Ej: `192.0.2.0/24`)
- `|contains`: Verifica si un valor de campo contiene una determinada cadena.
- `|contains|all`: Verifica si varias palabras están contenidas en los datos.
- `|contains|all|windash`: Igual que `|contains|windash` pero todas las palabras clave deben estar presentes.
- `|contains|cased`: Verifica si un valor de campo contiene una determinada cadena que distingue entre mayúsculas y minúsculas.
- `|contains|expand`: Verifica si un valor de campo contiene una cadena en el archivo de configuración `expand` dentro de `/config/expand/`.
- `|contains|windash`: Verificará la cadena tal cual, además de convertir el primer carácter `-` en permutaciones de los caracteres `/`, `–` (guion corto), `—` (guion largo) y `―` (barra horizontal).
- `|endswith`: Verifica si un valor de campo termina con una determinada cadena.
- `|endswith|cased`: Verifica si un valor de campo termina con una determinada cadena que distingue entre mayúsculas y minúsculas.
- `|endswith|windash`: Verifica el final de la cadena y realiza variaciones para los guiones.
- `|exists`: Verifica si un campo existe.
- `|expand`: Verifica si un valor de campo es igual a una cadena en el archivo de configuración `expand` dentro de `/config/expand/`.
- `|fieldref`: Verifica si los valores en dos campos son iguales. Puede usar `not` en el `condition` si desea verificar si dos campos son diferentes.
- `|fieldref|contains`: Verifica si el valor de un campo está contenido en otro campo.
- `|fieldref|endswith`: Verifica si el campo de la izquierda termina con la cadena del campo de la derecha. Puede usar `not` en el `condition` para verificar si son diferentes.
- `|fieldref|startswith`: Verifica si el campo de la izquierda comienza con la cadena del campo de la derecha. Puede usar `not` en el `condition` para verificar si son diferentes.
- `|gt`: Verifica si un valor de campo es mayor que un determinado número.
- `|gte`: Verifica si un valor de campo es mayor o igual que un determinado número.
- `|lt`: Verifica si un valor de campo es menor que un determinado número.
- `|lte`: Verifica si un valor de campo es menor o igual que un determinado número.
- `|re`: Usa expresiones regulares que distinguen entre mayúsculas y minúsculas. (Estamos usando el crate regex, así que consulte la documentación en <https://docs.rs/regex/latest/regex/#syntax> para aprender a escribir expresiones regulares admitidas.)
    > Precaución: [La sintaxis de expresiones regulares en las reglas de Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) usa PCRE con ciertos metacaracteres para clases de caracteres, lookbehind, agrupación atómica, etc... que no son compatibles. El crate regex de Rust debería poder usar todas las expresiones regulares en las reglas de Sigma, pero existe la posibilidad de incompatibilidad. 
- `|re|i`: (Insensible) Usa expresiones regulares que no distinguen entre mayúsculas y minúsculas.
- `|re|m`: (Multilínea) Coincide a través de varias líneas. `^` / `$` coinciden con el inicio/fin de línea.
- `|re|s`: (Línea única) el punto (`.`) coincide con todos los caracteres, incluido el carácter de nueva línea.
- `|startswith`: Verifica si un valor de campo comienza con una determinada cadena.
- `|startswith|cased`: Verifica si un valor de campo comienza con una determinada cadena que distingue entre mayúsculas y minúsculas.
- `|utf16|base64offset|contains`: Verifica si una determinada cadena UTF-16 está codificada dentro de una cadena base64.
- `|utf16be|base64offset|contains`: Verifica si una determinada cadena UTF-16 big-endian está codificada dentro de una cadena base64.
- `|utf16le|base64offset|contains`: Verifica si una determinada cadena UTF-16 little-endian está codificada dentro de una cadena base64.
- `|wide|base64offset|contains`: Alias de `utf16le|base64offset|contains`, que verifica cadenas UTF-16 little-endian.

### Modificadores de campo obsoletos

Los siguientes modificadores ahora están obsoletos y se reemplazan por modificadores que se adhieren más a las especificaciones de sigma.

- `|equalsfield`: Ahora se reemplaza por `|fieldref`.
- `|endswithfield`: Ahora se reemplaza por `|fieldref|endswith`.

### Modificadores de campo Expand

Los modificadores de campo `expand` son únicos en el sentido de que son el único modificador de campo que requiere configuración previa para su uso.
Por ejemplo, usan marcadores de posición como `%DC-MACHINE-NAME%` y requieren un archivo de configuración llamado `/config/expand/DC-MACHINE-NAME.txt` que contiene todos los posibles nombres de máquinas DC.

Cómo configurar esto se explica con más detalle [aquí](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## Comodines

Se pueden usar comodines en los eventkeys. En el ejemplo a continuación, si `ProcessCommandLine` comienza con la cadena "malware", la regla coincidirá.
La especificación es fundamentalmente la misma que los comodines de las reglas de sigma, por lo que no distinguirá entre mayúsculas y minúsculas.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Se pueden usar los siguientes dos comodines.
- `*`: Coincide con cualquier cadena de cero o más caracteres. (Internamente se convierte en la expresión regular `.*`)
- `?`: Coincide con cualquier carácter individual. (Internamente convertido en la expresión regular `.`)

Sobre el escape de comodines:
- Los comodines (`*` y `?`) pueden escaparse usando una barra invertida: `\*`, `\?`.
- Si desea usar una barra invertida justo antes de un comodín, entonces escriba `\\*` o `\\?`.
- No se requiere escape si está usando barras invertidas por sí solas.

## palabra clave null

La palabra clave `null` se puede usar para verificar si un campo no existe.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Nota: Esto es diferente de `ProcessCommandLine: ''` que verifica si el valor de un campo está vacío.

## condition

Con la notación que explicamos anteriormente, puede expresar lógica `AND` y `OR`, pero será confuso si está tratando de definir una lógica compleja.
Cuando desee crear reglas más complejas, debe usar la palabra clave `condition` como se muestra a continuación.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

Las siguientes expresiones se pueden usar para `condition`.
- `{expression1} and {expression2}`: Requiere ambas {expression1} AND {expression2}
- `{expression1} or {expression2}`: Requiere {expression1} OR {expression2}
- `not {expression}`: Invierte la lógica de {expression}
- `( {expression} )`: Establece la precedencia de {expression}. Sigue la misma lógica de precedencia que en matemáticas.

En el ejemplo anterior, se usan nombres de selection como `SELECTION_1`, `SELECTION_2`, etc... pero se les puede dar cualquier nombre siempre que solo contengan los siguientes caracteres: `a-z A-Z 0-9 _`
> Sin embargo, utilice la convención estándar de `selection_1`, `selection_2`, `filter_1`, `filter_2`, etc... para que las cosas sean fáciles de leer siempre que sea posible.

## lógica not

Muchas reglas resultarán en falsos positivos, por lo que es muy común tener una selection para firmas que buscar, pero también una selection de filtro para no alertar sobre falsos positivos.
Por ejemplo:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Correlaciones de Sigma

Hemos implementado todas las correlaciones de Sigma versión 2.0.0 como se define [aquí](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

Correlaciones admitidas:
- Recuento de eventos (`event_count`)
- Recuento de valores (`value_count`)
- Proximidad temporal (`temporal`)
- Proximidad temporal ordenada (`temporal_ordered`)

Las nuevas reglas de correlación de "métricas" (`value_sum`, `value_avg`, `value_percentile`) lanzadas el 12 de septiembre de 2025 en Sigma versión 2.1.0 actualmente no son compatibles.
