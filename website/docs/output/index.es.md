# Salida de la línea de tiempo

## Perfiles de salida

Hayabusa tiene 5 perfiles de salida predefinidos para usar en `config/profiles.yaml`:

1. `minimal`
2. `standard` (predeterminado)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Puede personalizar fácilmente o agregar sus propios perfiles editando este archivo.
También puede cambiar fácilmente el perfil predeterminado con `set-default-profile --profile <profile>`.
Use el comando `list-profiles` para mostrar los perfiles disponibles y su información de campos.

### 1. Salida del perfil `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. Salida del perfil `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. Salida del perfil `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. Salida del perfil `all-field-info`

En lugar de mostrar la información mínima de `details`, se mostrará toda la información de campos de las secciones `EventData` y `UserData` junto con sus nombres de campo originales.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. Salida del perfil `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. Salida del perfil `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. Salida del perfil `timesketch-minimal`

Salida a un formato compatible con la importación a [Timesketch](https://timesketch.org/).

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. Salida del perfil `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Comparación de perfiles

Los siguientes benchmarks se realizaron en un Lenovo P51 de 2018 (CPU Xeon de 4 núcleos / 64 GB de RAM) con 3 GB de datos evtx y 3891 reglas habilitadas. (2023/06/01)

| Perfil | Tiempo de procesamiento | Tamaño del archivo de salida | Aumento del tamaño del archivo |
| :---: | :---: | :---: | :---: |
| minimal | 8 minutos 50 segundos | 770 MB | -30% |
| standard (predeterminado) | 9 minutos 00 segundos | 1.1 GB | Ninguno |
| verbose | 9 minutos 10 segundos | 1.3 GB | +20% |
| all-field-info | 9 minutos 3 segundos | 1.2 GB | +10% |
| all-field-info-verbose | 9 minutos 10 segundos | 1.3 GB | +20% |
| super-verbose | 9 minutos 12 segundos | 1.5 GB | +35% |

### Alias de campos de perfil

La siguiente información puede mostrarse con los perfiles de salida integrados:

| Nombre del alias | Información de salida de Hayabusa|
| :--- | :--- |
|%AllFieldInfo% | Toda la información de campos. |
|%Channel% | El nombre del registro. Campo `<Event><System><Channel>`. |
|%Computer% | El campo `<Event><System><Computer>`. |
|%Details% | El campo `details` en la regla de detección YML; sin embargo, solo las reglas de hayabusa tienen este campo. Este campo proporciona información adicional sobre la alerta o el evento y puede extraer datos útiles de los campos en los registros de eventos. Por ejemplo, nombres de usuario, información de línea de comandos, información de procesos, etc... Cuando un marcador de posición apunta a un campo que no existe o hay una asignación de alias incorrecta, se mostrará como `n/a` (no disponible). Si el campo `details` no está especificado (es decir, reglas sigma), se mostrarán los mensajes `details` predeterminados para extraer los campos definidos en `./rules/config/default_details.txt`. Puede agregar más mensajes `details` predeterminados añadiendo el `Provider Name`, `EventID` y el mensaje `details` que desea mostrar en `default_details.txt`. Cuando no se define ningún campo `details` en una regla ni en `default_details.txt`, todos los campos se mostrarán en la columna `details`. |
|%ExtraFieldInfo% | Imprime la información de campos que no se mostró en %Details%. |
|%EventID% | El campo `<Event><System><EventID>`. |
|%EvtxFile% | El nombre del archivo evtx que causó la alerta o el evento. |
|%Level% | El campo `level` en la regla de detección YML. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | [Tácticas](https://attack.mitre.org/tactics/enterprise/) de MITRE ATT&CK (Ej: Initial Access, Lateral Movement, etc...). |
|%MitreTags% | ID de grupo, ID de técnica e ID de software de MITRE ATT&CK. |
|%OtherTags% | Cualquier palabra clave en el campo `tags` de una regla de detección YML que no esté incluida en `MitreTactics` o `MitreTags`. |
|%Provider% | El atributo `Name` en el campo `<Event><System><Provider>`. |
|%RecordID% | El ID de registro de evento del campo `<Event><System><EventRecordID>`. |
|%RuleAuthor% | El campo `author` en la regla de detección YML. |
|%RuleCreationDate% | El campo `date` en la regla de detección YML. |
|%RuleFile% | El nombre del archivo de la regla de detección que generó la alerta o el evento. |
|%RuleID% | El campo `id` en la regla de detección YML. |
|%RuleModifiedDate% | El campo `modified` en la regla de detección YML. |
|%RuleTitle% | El campo `title` en la regla de detección YML. |
|%Status% | El campo `status` en la regla de detección YML. |
|%Timestamp% | El formato predeterminado es `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. Campo `<Event><System><TimeCreated SystemTime>` en el registro de eventos. La zona horaria predeterminada será la zona horaria local, pero puede cambiar la zona horaria a UTC con la opción `--UTC`. |

#### Alias de campo de perfil adicional

También puede agregar estos alias adicionales a su perfil de salida si lo necesita:

| Nombre del alias | Información de salida de Hayabusa|
| :--- | :--- |
|%RenderedMessage% | El campo `<Event><RenderingInfo><Message>` en los registros reenviados por WEC. |

Nota: este **no** está incluido en ningún perfil integrado, por lo que deberá editar manualmente el archivo `config/default_profile.yaml` y agregar la siguiente línea:

```
Message: "%RenderedMessage%"
```

También puede definir [alias de claves de evento](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) para mostrar otros campos.
