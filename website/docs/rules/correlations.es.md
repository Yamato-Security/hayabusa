## Reglas de Conteo de Eventos (Event Count)

Estas son reglas que cuentan ciertos eventos y alertan si ocurren demasiados o muy pocos de estos eventos dentro de un periodo de tiempo.
Ejemplos comunes de detección de muchos eventos dentro de cierto periodo de tiempo son la detección de ataques de adivinación de contraseñas, ataques de rociado de contraseñas (password spray) y ataques de denegación de servicio.
También podrías usar estas reglas para detectar problemas de fiabilidad de la fuente de registros, como cuando ciertos eventos caen por debajo de cierto umbral.

### Ejemplo de regla de Conteo de Eventos:

El siguiente ejemplo usa dos reglas para detectar ataques de adivinación de contraseñas.
Habrá una alerta cuando la regla referenciada coincida 5 o más veces dentro de 5 minutos y el campo `IpAddress` sea el mismo para esos eventos.

> Ten en cuenta que solo hemos incluido los campos necesarios para entender el concepto.
> La regla completa en la que se basa este ejemplo está ubicada [aquí](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) para tu referencia.

### Regla de correlación de Conteo de Eventos:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Regla de Inicio de Sesión Fallido - Contraseña Incorrecta:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### Ejemplo de regla `count` obsoleta (deprecated):

La correlación anterior y las reglas referenciadas proporcionan los mismos resultados que la siguiente regla, que usa el modificador `count` más antiguo:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Salida de la regla de Conteo de Eventos:

Las reglas anteriores crearán la siguiente salida:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Reglas de Conteo de Valores (Value Count)

Estas reglas cuentan los mismos eventos dentro de un periodo de tiempo con valores **diferentes** de un campo dado.

Ejemplos:
- Escaneos de red donde una sola dirección IP de origen intenta conectarse a muchas direcciones IP y/o puertos de destino diferentes.
- Ataques de rociado de contraseñas (password spraying) donde un solo origen falla al autenticarse con muchos usuarios diferentes.
- Detectar herramientas como BloodHound que enumeran muchos grupos de AD con privilegios altos dentro de un corto periodo de tiempo.

### Ejemplo de regla de Conteo de Valores:

La siguiente regla detecta cuando un atacante está intentando adivinar nombres de usuario.
Es decir, cuando la **misma** dirección IP de origen (`IpAddress`) falla al iniciar sesión con más de 3 nombres de usuario **diferentes** (`TargetUserName`) dentro de 5 minutos.

> Ten en cuenta que solo hemos incluido los campos necesarios para entender el concepto.
> La regla completa en la que se basa este ejemplo está ubicada [aquí](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) para tu referencia.

### Regla de correlación de Conteo de Valores:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Regla de Conteo de Valores de Fallo de Inicio de Sesión (Usuario Inexistente):

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### Regla del modificador `count` obsoleta (deprecated):

La correlación anterior y las reglas referenciadas proporcionan los mismos resultados que la siguiente regla, que usa el modificador `count` más antiguo:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Salida de la regla de Conteo de Valores:

Las reglas anteriores crearán la siguiente salida:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Reglas de Proximidad Temporal (Temporal Proximity)

Todos los eventos definidos por las reglas referidas por el campo rule deben ocurrir en el periodo de tiempo definido por timespan.
Los valores de los campos definidos en `group-by` deben tener todos el mismo valor (ej: mismo host, usuario, etc...).

### Ejemplo de regla de Proximidad Temporal:

Ejemplo: Comandos de reconocimiento definidos en tres reglas Sigma son invocados en orden arbitrario dentro de 5 minutos en un sistema por el mismo usuario.

### Regla de correlación de Proximidad Temporal:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Reglas de Proximidad Temporal Ordenada (Ordered Temporal Proximity)

El tipo de correlación `temporal_ordered` se comporta como `temporal` y requiere además que los eventos aparezcan en el orden proporcionado en el atributo `rules`.

### Ejemplo de regla de Proximidad Temporal Ordenada:

Ejemplo: muchos inicios de sesión fallidos como se definió anteriormente son seguidos por un inicio de sesión exitoso de la misma cuenta de usuario dentro de 1 hora:

### Regla de correlación de Proximidad Temporal Ordenada:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## Notas sobre las reglas de correlación

1. Debes incluir todas tus reglas de correlación y reglas referenciadas en un solo archivo y separarlas con un separador YAML de `---`.

2. Por defecto, las reglas de correlación referenciadas no serán mostradas en la salida. Si quieres ver la salida de las reglas referenciadas, entonces necesitas añadir `generate: true` bajo `correlation`. Esto es muy útil para activar y comprobar al crear reglas de correlación.

    Ejemplo:
    ```
    correlation:
        generate: true
    ```
3. Puedes usar nombres de alias en lugar de IDs de regla al referenciar reglas para hacer las cosas más fáciles de entender.

4. Puedes referenciar múltiples reglas.

5. Puedes usar múltiples campos en `group-by`. Si lo haces, entonces todos los valores en esos campos deben ser iguales o de lo contrario no obtendrás una alerta. La mayoría de las veces, escribirás reglas que filtran ciertos campos con `group-by` para reducir los falsos positivos, sin embargo, es posible omitir `group-by` para crear una regla más genérica.

6. La marca de tiempo de la regla de correlación será el comienzo mismo del ataque, por lo que deberías comprobar los eventos posteriores a eso para confirmar si es un falso positivo o no.
