# Curación de reglas Sigma para los registros de eventos de Windows

Esta página documenta cómo Yamato Security cura las reglas [Sigma](https://github.com/SigmaHQ/sigma) del proyecto original para los registros de eventos de Windows y las convierte en una forma más utilizable, desabstrayendo el campo `logsource` y filtrando las reglas que no se pueden usar o que son difíciles de usar. Esto se realiza con la herramienta [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter), que se utiliza principalmente para crear el conjunto de reglas Sigma curadas alojado en [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules). Ese conjunto de reglas es utilizado por [Hayabusa](https://github.com/Yamato-Security/hayabusa) y [Velociraptor](https://github.com/Velocidex/velociraptor).

!!! info "Fuente"
    Esta documentación se mantiene junto con la herramienta de conversión en [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter). Esperamos que esta información también sea útil para otros proyectos que quieran usar reglas Sigma para detectar ataques en los registros de eventos de Windows. Consulte también [Creación de archivos de reglas](creating-rules.md) y [Modificadores de campos](field-modifiers.md).

## Resumen

* Desabstraer el campo `logsource` y crear nuevos archivos de reglas `.yml` tanto para las reglas integradas (built-in) como para las reglas originales basadas en Sysmon facilita el soporte completo de eventos integrados para las reglas Sigma y hace que las reglas sean más fáciles de leer para los analistas.
* Al escribir reglas Sigma para los registros de eventos de Windows, es importante comprender las diferencias entre los registros originales basados en Sysmon y los registros integrados compatibles y, en el mejor de los casos, escribir las reglas de forma que sean compatibles con ambos.
* Muchas organizaciones no pueden o no quieren instalar y mantener agentes Sysmon en todos sus endpoints de Windows porque no disponen de los recursos dedicados para gestionarlo, o porque quieren evitar el riesgo de ralentizaciones o fallos causados por Sysmon. Por ello, es importante habilitar tantos registros de eventos integrados como sea posible y utilizar herramientas capaces de detectar ataques en dichos registros integrados.

## Retos de las reglas Sigma originales para los registros de eventos de Windows

En nuestra experiencia, el principal reto para crear un analizador de reglas Sigma nativo para los registros de eventos de Windows ha sido dar soporte al campo `logsource`. Actualmente, esta es una de las pocas cosas que Hayabusa todavía no admite de forma nativa, ya que sigue siendo muy compleja y es un trabajo en curso. Por el momento, lo solucionamos convirtiendo las reglas originales a un formato más fácil de usar, como se explica en detalle más adelante.

### Acerca del campo `logsource`

En las reglas Sigma para los registros de eventos de Windows, el campo `product` se establece en `windows`, seguido de un campo `service` o de un campo `category`.

Ejemplo del campo `service`:

```yaml
logsource:
    product: windows
    service: application
```

Ejemplo del campo `category`:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Campos service

Los campos `service` son relativamente sencillos de manejar e indican al backend que esté usando la regla Sigma que busque en un único canal o en varios canales según el campo `Channel` del registro de eventos XML de Windows.

**Ejemplo de un solo canal**

`service: application` es lo mismo que añadir una condición de selección de `Channel: Application` a la regla Sigma.

**Ejemplo de varios canales**

`service: applocker` es actualmente el que genera más canales que hay que examinar, ya que AppLocker guarda la información en cuatro registros diferentes. Para buscar correctamente solo en los registros de AppLocker, es necesario añadir la siguiente condición a la lógica de la regla Sigma:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Lista actual de asignaciones de service**

| Service                                    | Channel                                                                                                                             |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**Fuentes de las asignaciones de service**

Hemos creado archivos de asignación YAML de servicios a nombres de canales, que mantenemos periódicamente y alojamos en el repositorio de la herramienta de conversión. Se basan en la información de asignación de servicios de [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml): aunque no parece ser un archivo de configuración genérico oficial para que la gente lo use, sí parece ser el más actualizado.

#### Campos category

La mayoría de los campos `category` simplemente añaden una condición para comprobar determinados ID de evento en el campo `EventID`, además de buscar un `Channel` específico. Los nombres de las categorías se basan mayoritariamente en los eventos de [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), con algunas categorías adicionales para los registros integrados de PowerShell y Windows Defender.

**Ejemplo del campo category**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Lista actual de asignaciones de category**

Algunas categorías se asignan a más de un servicio/EventID (mostrados en **negrita**).

| Category                  | Service            | EventIDs                                                               |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**Retos de los campos category**

Como se muestra arriba, una misma `category` puede usar varios servicios e ID de evento (indicados en **negrita**). Esto significa que es posible utilizar algunas reglas Sigma diseñadas para `sysmon` con registros de eventos `security` integrados de Windows similares, si los campos que utiliza la regla también existen en el registro de eventos integrado. En ese caso, es posible que los nombres de los campos —y a veces también los valores— deban convertirse para que coincidan con los nombres de campos y los valores del registro de eventos `security` integrado. Aunque esto puede ser tan sencillo como renombrar algunos nombres de campos para determinadas categorías, para otras categorías puede requerir también diversas conversiones en los valores de los campos. Cómo realizamos esta conversión, así como la compatibilidad entre los registros `sysmon` y los registros `security`, se explican en detalle [más adelante](#sysmon-builtin-comparison).

**Fuentes de las asignaciones de category**

Los archivos de asignación YAML de las categorías también se alojan en el repositorio de la herramienta de conversión y también se basan en la información de [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

## Beneficios y retos de abstraer la fuente de registro

Abstraer la fuente de registro y crear asignaciones para diferentes `Channel`, `EventID` y campos en el backend tiene tanto beneficios como retos.

### Beneficios

1. Puede ser más fácil convertir los nombres de los campos `Channel` y `EventID` a los nombres de campo adecuados del backend al convertir reglas Sigma a otras consultas de backend.
2. Es posible consolidar dos reglas en una. Por ejemplo, los eventos de creación de procesos se pueden registrar tanto en `Sysmon 1` como en `Security 4688`. En lugar de escribir dos reglas que examinen diferentes canales, ID de evento y campos, pero que por lo demás contengan la misma lógica, es posible estandarizar los campos a lo que usa Sysmon y luego hacer que un conversor de backend añada los campos `Channel` y `EventID` y convierta otra información de campos si es necesario. Esto facilita el mantenimiento de las reglas, ya que hay menos reglas que mantener.
3. Aunque es muy poco frecuente, si una fuente de registro comienza a registrar sus datos en un `Channel` o `EventID` diferente, solo es necesario actualizar la lógica de asignación en lugar de actualizar todas las reglas Sigma, lo que facilita el mantenimiento.

### Retos

1. ¿Qué ocurre si la regla Sigma original basada en Sysmon utiliza un campo que no existe en los registros integrados para filtrar falsos positivos? ¿Debería crear la regla de todos modos, priorizando la posible detección, o ignorarla para priorizar menos falsos positivos? Idealmente, sería necesario crear dos reglas con diferente `severity`, `status` e información de falsos positivos para que el usuario pueda gestionarlo mejor.
2. Dificulta el filtrado de reglas, ya que no se puede filtrar simplemente en función de los campos `Channel` o `EventID` del archivo `.yml` o de la ruta del archivo de la regla si el archivo aún no se ha creado, porque se trata de una regla derivada para un registro integrado en lugar de la regla original de Sysmon. Además, como el ID de la regla es el mismo, no se puede filtrar por ID de regla.
3. Dificulta la confirmación de la alerta cuando esta procede de una regla para registros integrados que se derivó de un registro de Sysmon. Los nombres de los campos y los valores no coincidirán, por lo que el analista debe comprender el proceso de conversión, que es algo complejo.
4. Hace más compleja la creación de la lógica del backend.

Aunque no podemos hacer nada respecto al primer problema, salvo crear y mantener nuevas reglas cuando haya un caso de uso significativo que justifique el esfuerzo, para abordar los problemas 2 a 4 hemos decidido desabstraer el campo `logsource` y crear dos conjuntos de reglas para cualquier regla que pueda generar varias reglas. Las reglas que pueden detectar ataques en registros integrados se generan en el directorio `builtin`, y las reglas para Sysmon se generan en el directorio `sysmon`.

## Ejemplo de conversión

Aquí tiene un ejemplo sencillo para comprender mejor el proceso de conversión.

**Antes de la conversión**: la regla Sigma original:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Después de la conversión**: una regla compatible con Hayabusa para los registros de Sysmon:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

...y una regla compatible con Hayabusa para los registros integrados de Windows:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

Como puede ver, se han creado dos reglas: una para los registros de Sysmon 1 y otra para los registros integrados de Security 4688. Se ha añadido una nueva condición `process_creation` con la información del canal y del ID de evento, y se ha añadido al campo `condition` para exigir esta condición. Además, el nombre del campo original `Image` se ha cambiado a `NewProcessName`.

## Aspectos comunes de la conversión

Antes de explicar en detalle cómo convertimos categorías específicas, aquí está la parte de la conversión que se aplica a todas las reglas.

1. Se ignora cualquier regla que tenga un ID en `ignore-uuid-list.txt`. Actualmente solo ignoramos las reglas que causan falsos positivos en Windows Defender porque contienen palabras clave como `mimikatz`.
2. Las reglas de tipo "placeholder" (marcador de posición) se ignoran porque no se pueden usar tal cual. Se trata de reglas ubicadas en la carpeta [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) del repositorio de Sigma.
3. Se descartan las reglas que utilizan modificadores de campo incompatibles. Hayabusa admite la mayoría de los modificadores de campo, por lo que el conversor no generará ninguna regla que utilice un modificador distinto de estos, con el fin de evitar errores de análisis (consulte [Modificadores de campos](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Las reglas con errores de sintaxis no se convierten.
5. Las etiquetas de las reglas `deprecated` y `unsupported` se actualizan del formato V1 al formato V2, que usa `-` en lugar de `_`, con el fin de mantener todo coherente y gestionar más fácilmente las abreviaturas en Hayabusa. Ejemplo: `initial_access` se convierte en `initial-access`.
6. Dado que estamos añadiendo información de `Channel` y `EventID` a las reglas, creamos un nuevo ID UUIDv4 utilizando el hash MD5 del ID original, especificamos el ID original en el campo `related` y marcamos el `type` como `derived`. Para las reglas que se pueden convertir en varias reglas (`sysmon` y `builtin`), también necesitamos crear nuevos ID de regla para las reglas `builtin` derivadas. Para ello, calculamos un hash MD5 del ID de la regla `sysmon` y lo usamos como ID UUIDv4. Por ejemplo:

    Regla Sigma original:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Nueva regla `sysmon`:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Nueva regla `builtin`:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Las reglas que detectan cosas en los registros de eventos integrados de Windows se generan en el directorio `builtin`, mientras que las reglas que dependen de los registros de Sysmon se generan en el directorio `sysmon`, con subdirectorios que coinciden con los directorios del repositorio original de Sigma.

## Limitaciones de la conversión

Por el momento solo hay un [error conocido](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2): las líneas de comentario de las reglas Sigma no se incluirán en las reglas generadas a menos que los comentarios sigan a algún código fuente.

## Comparación entre eventos de Sysmon e integrados y conversión de reglas { #sysmon-builtin-comparison }

### Creación de procesos

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Registro integrado
    * Channel: `Security`
    * Event ID: `4688`

**Comparación**

![Comparación de creación de procesos](../assets/rules-doc/process_creation_comparison.png)

**Notas de conversión**

1. La información del campo `User` debe separarse en los campos `SubjectUserName` y `SubjectDomainName`.
2. El nombre del campo `LogonId` cambia a `SubjectLogonId`, y cualquier letra del valor hexadecimal debe pasar a minúscula.
3. El nombre del campo `ProcessId` cambia a `NewProcessId`, y el valor debe convertirse a hexadecimal.
4. El nombre del campo `Image` cambia a `NewProcessName`.
5. El nombre del campo `ParentProcessId` cambia a `ProcessId`, y el valor debe convertirse a hexadecimal.
6. El nombre del campo `ParentImage` cambia a `ParentProcessName`.
7. El nombre del campo `IntegrityLevel` cambia a `MandatoryLabel`, y es necesaria la siguiente conversión de valores:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. Si la regla contiene los siguientes campos que solo existen en los eventos `Security 4688`, no creamos una regla `Sysmon 1`:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Si la regla contiene los siguientes campos que solo existen en los eventos `Sysmon 1`, no creamos una regla `Security 4688`:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. Existe una excepción a los puntos 8 y 9: incluso si se utiliza un campo que solo existe en un evento de registro, si ese campo está en una condición `OR`, aun así se debería crear esa regla. Por ejemplo, la siguiente regla **no** debería generar una regla `Security 4688` porque el campo `OriginalFileName` es obligatorio (lógica `AND` dentro de la selección):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    Sin embargo, una regla con la siguiente condición **sí** debería crear una regla `Security 4688` porque `OriginalFileName` es opcional (lógica `OR` dentro de la selección):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    La cosa se complica porque el analizador tiene que comprender no solo la lógica dentro de las selecciones, sino también la del campo `condition`. Por ejemplo, la siguiente regla **no** debería crear una regla `Security 4688` porque utiliza lógica `AND`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    Sin embargo, la siguiente regla **sí** debería crear una regla `Security 4688` porque utiliza lógica `OR`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Otras notas**

* El campo `SubjectUserSid` en `Security 4688` muestra el SID; sin embargo, en el `Message` renderizado del registro de eventos se convierte a `DOMAIN\User`.
* Los eventos `Security 4688` pueden no incluir información sobre las opciones de la línea de comandos en `CommandLine`, según la configuración.
* `TokenElevationType` se muestra tal cual en el `Message` y no se renderiza.
* `S-1-16-4096`, etc. dentro de `MandatoryLabel` se convierte en `Mandatory Label\Low Mandatory Level`, etc. en el `Message` renderizado.

**Configuración de los registros integrados**

!!! warning "No habilitado de forma predeterminada"
    Los importantes registros de eventos de creación de procesos integrados `Security 4688` no están habilitados de forma predeterminada. Es necesario habilitar tanto los eventos `4688` como el registro de las opciones de la línea de comandos para poder utilizar la mayoría de las reglas Sigma.

*Habilitación mediante directiva de grupo:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*Habilitación desde la línea de comandos:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Conexión de red

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Registro integrado
    * Channel: `Security`
    * Event ID: `5156`

**Comparación**

![Comparación de conexión de red](../assets/rules-doc/network_connection_comparison.png)

**Notas de conversión**

1. El nombre del campo `ProcessId` cambia a `ProcessID`.
2. El nombre del campo `Image` cambia a `Application`, y `C:\` cambia a `\device\harddiskvolume?\`. (Nota: como no conocemos el número de volumen del disco duro, lo sustituimos por un comodín de un solo carácter `?`.)
3. El valor del campo `Protocol` de `tcp` cambia a `6` y `udp` cambia a `17`.
4. El nombre del campo `Initiated` cambia a `Direction`, y el valor de `true` cambia a `%%14593` y `false` cambia a `%%14592`.
5. El nombre del campo `SourceIp` cambia a `SourceAddress`.
6. El nombre del campo `DestinationIp` cambia a `DestAddress`.
7. El nombre del campo `DestinationPort` cambia a `DestPort`.

**Configuración de los registros integrados**

!!! warning "No habilitado de forma predeterminada"
    Los registros de conexión de red integrados `Security 5156` no están habilitados de forma predeterminada. Generan una gran cantidad de registros, que pueden sobrescribir otros registros importantes del registro de eventos `Security` y potencialmente ralentizar el sistema si este tiene un elevado número de conexiones de red. Asegúrese de que el tamaño máximo del archivo del registro `Security` sea alto y haga pruebas para comprobar que no haya efectos adversos en el sistema.

*Habilitación mediante directiva de grupo:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*Habilitación desde la línea de comandos:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...o lo siguiente si utiliza una configuración regional que no esté en inglés:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Consulte también"
    Para obtener más información sobre cómo habilitar los registros de eventos integrados de Windows necesarios para capturar la evidencia en la que se basan estas reglas, consulte [Registro de Windows y Sysmon](../resources/logging.md) y el proyecto [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

## Consejos para escribir reglas Sigma

!!! tip
    Si utiliza cualquier campo que exista en un registro `sysmon` pero no en un registro `builtin`, asegúrese de que ese campo sea opcional, de modo que siga siendo posible usar la regla para los registros `builtin`.

Por ejemplo:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Esta selección busca los casos en los que el proceso (`Image`) se llama `addinutil.exe`. El problema es que un atacante podría simplemente renombrar el archivo para eludir la regla. El campo `OriginalFileName`, que solo existe en los registros de Sysmon, es el nombre de archivo que se incrusta en el binario en tiempo de compilación. Aunque un atacante renombre el archivo, el nombre incrustado no cambiará, por lo que esta regla puede detectar ataques en los que el atacante ha renombrado el archivo cuando se usa Sysmon, y también puede detectar ataques en los que no se cambió el nombre del archivo cuando se usan los registros integrados estándar.

## Reglas Sigma preconvertidas

Las reglas Sigma curadas de la forma descrita en esta página —desabstrayendo el campo `logsource`— se alojan en el repositorio [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) dentro de la carpeta `sigma`.

## Entorno de la herramienta

Si desea convertir localmente las reglas Sigma al formato compatible con Hayabusa, primero debe instalar [Poetry](https://python-poetry.org/). Consulte la [documentación de instalación](https://python-poetry.org/docs/#installation) oficial de Poetry.

## Uso de la herramienta

`sigma-to-hayabusa-converter.py` es nuestra herramienta principal para convertir el campo `logsource` de las reglas Sigma al formato compatible con Hayabusa. Realice las siguientes tareas para ejecutarla:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Tras ejecutar los comandos anteriores, las reglas convertidas al formato compatible con Hayabusa se generarán en el directorio `./converted_sigma_rules`.
