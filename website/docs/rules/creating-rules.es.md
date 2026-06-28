# Creación de archivos de reglas

## Acerca de Hayabusa-Rules

Este es un repositorio que contiene reglas sigma seleccionadas que detectan ataques en los registros de eventos de Windows.
Se utiliza principalmente para las reglas de detección y archivos de configuración de [Hayabusa](https://github.com/Yamato-Security/hayabusa), así como para la detección sigma integrada de [Velociraptor](https://github.com/Velocidex/velociraptor).
La ventaja de usar este repositorio en lugar del [repositorio sigma original](https://github.com/SigmaHQ/sigma) es que incluimos solo reglas que la mayoría de las herramientas nativas de sigma deberían poder analizar.
También de-abstraemos el campo `logsource` añadiendo los campos `Channel`, `EventID`, etc... necesarios a las reglas para facilitar la comprensión de lo que la regla está filtrando y, lo que es más importante, reducir los falsos positivos.
También creamos nuevas reglas con nombres de campos y valores convertidos para las reglas `process_creation` y las reglas basadas en `registry`, de modo que las reglas sigma no solo detecten en registros de Sysmon, sino que también detecten en los registros integrados de Windows.

## Acerca de la creación de archivos de reglas

Las reglas de detección de Hayabusa se escriben en formato [YAML](https://en.wikipedia.org/wiki/YAML) con una extensión de archivo `.yml`. (Los archivos `.yaml` serán ignorados.)
Son un subconjunto de las reglas sigma, pero también contienen algunas funciones añadidas.
Intentamos hacerlas lo más parecidas posible a las reglas sigma para que sea fácil convertir las reglas de Hayabusa de nuevo a sigma y devolverlas a la comunidad.
Las reglas de Hayabusa pueden expresar reglas de detección complejas combinando no solo la coincidencia simple de cadenas, sino también expresiones regulares, condiciones `AND`, `OR` y otras.
En esta sección, explicaremos cómo escribir reglas de detección de Hayabusa.

### Formato del archivo de reglas

Ejemplo:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## Sección del autor

- **author [obligatorio]**: Nombre del autor o autores.
- **date [obligatorio]**: Fecha en que se creó la regla.
- **modified** [opcional]: Fecha en que se actualizó la regla.

> ## Sección de alerta

- **title [obligatorio]**: Título del archivo de reglas. Este también será el nombre de la alerta que se muestra, por lo que cuanto más breve, mejor. (No debe tener más de 85 caracteres.)
- **details** [opcional]: Los detalles de la alerta que se muestra. Por favor, muestra cualquier campo del registro de eventos de Windows que sea útil para el análisis. Los campos se separan con `" ¦ "`. Los marcadores de posición de campo se encierran con un `%` (Ejemplo: `%MemberName%`) y deben definirse en `rules/config/eventkey_alias.txt`. (Explicado a continuación.)
- **description** [opcional]: Una descripción de la regla. Esta no se muestra, por lo que puedes hacerla larga y detallada.

> ## Sección de la regla

- **id [obligatorio]**: Un UUID versión 4 generado aleatoriamente que se utiliza para identificar de forma única la regla. Puedes generar uno [aquí](https://www.uuidgenerator.net/version4).
- **level [obligatorio]**: Nivel de gravedad basado en la [definición de sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Por favor, escribe uno de los siguientes: `informational`,`low`,`medium`,`high`,`critical`
- **status[obligatorio]**: Estado basado en la [definición de sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Por favor, escribe uno de los siguientes: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [obligatorio]**: Aunque actualmente Hayabusa no lo utiliza en realidad, definimos logsource de la misma manera que sigma para ser compatible con las reglas sigma.
- **detection  [obligatorio]**: Aquí va la lógica de detección. (Explicado a continuación.)
- **falsepositives [obligatorio]**: Las posibilidades de falsos positivos. Por ejemplo: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Si se desconoce, por favor escribe `unknown`.
- **tags** [opcional]: Si la técnica es una técnica [LOLBINS/LOLBAS](https://lolbas-project.github.io/), por favor añade la etiqueta `lolbas`. Si la alerta puede asignarse a una técnica del marco [MITRE ATT&CK](https://attack.mitre.org/), por favor añade el ID de la táctica (Ejemplo: `attack.t1098`) y cualquier táctica aplicable a continuación:
  - `attack.reconnaissance` -> Reconnaissance (Recon)
  - `attack.resource-development` -> Resource Development  (ResDev)
  - `attack.initial-access` -> Initial Access (InitAccess)
  - `attack.execution` -> Execution (Exec)
  - `attack.persistence` -> Persistence (Persis)
  - `attack.privilege-escalation` -> Privilege Escalation (PrivEsc)
  - `attack.stealth` -> Stealth (Stealth)
  - `attack.defense-impairment` -> Defense Impairment (DefImpair)
  - `attack.credential-access` -> Credential Access (CredAccess)
  - `attack.discovery` -> Discovery (Disc)
  - `attack.lateral-movement` -> Lateral Movement (LatMov)
  - `attack.collection` -> Collection (Collect)
  - `attack.command-and-control` -> Command and Control (C2)
  - `attack.exfiltration` -> Exfiltration (Exfil)
  - `attack.impact` -> Impact (Impact)
- **references** [opcional]: Cualquier enlace a referencias.
- **ruletype [obligatorio]**: `Hayabusa` para las reglas de hayabusa. Las reglas convertidas automáticamente desde las reglas de Windows de sigma serán `Sigma`.

> ## Evento XML de muestra

- **sample-message [obligatorio]**: De ahora en adelante, pedimos a los autores de reglas que incluyan mensajes de muestra para sus reglas. Este es el mensaje renderizado que muestra el Visor de eventos de Windows.
- **sample-evtx [obligatorio]**: De ahora en adelante, pedimos a los autores de reglas que incluyan eventos XML de muestra para sus reglas.
