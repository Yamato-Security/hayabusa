# Reglas de Hayabusa

Las reglas de detección de Hayabusa están escritas en un formato YML similar a sigma y se encuentran en la carpeta `rules`.
Las reglas están alojadas en [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), así que por favor envía cualquier incidencia y pull request relacionada con las reglas allí en lugar de en el repositorio principal de Hayabusa.

Consulta [Creación de Archivos de Reglas](creating-rules.md), [Campos de Detección](detection-fields.md) y [Correlaciones de Sigma](correlations.md) en esta sección para entender el formato de las reglas y cómo crearlas. (Fuente: el [repositorio hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).)

Todas las reglas del repositorio hayabusa-rules deben colocarse en la carpeta `rules`.
Las reglas de nivel `informational` se consideran `events`, mientras que cualquier cosa con un `level` de `low` o superior se considera `alerts`.

La estructura de directorios de reglas de hayabusa está separada en 2 directorios:

* `builtin`: registros que pueden ser generados por la funcionalidad integrada de Windows.
* `sysmon`: registros que son generados por [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

Las reglas se separan además en directorios por tipo de registro (Ejemplo: Security, System, etc...) y se nombran con el siguiente formato:

Por favor, revisa las reglas actuales para usarlas como plantilla al crear nuevas o para comprobar la lógica de detección.

## Reglas de Sigma v.s. Hayabusa (Compatibles con Sigma integrado)

Hayabusa admite reglas de Sigma de forma nativa con la única excepción del manejo interno de los campos `logsource`.
Para reducir los falsos positivos, las reglas de Sigma deben ejecutarse a través de nuestro conversor explicado [aquí](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md).
Esto añadirá el `Channel` y `EventID` adecuados, y realizará el mapeo de campos para ciertas categorías como `process_creation`.

Casi todas las reglas de Hayabusa son compatibles con el formato Sigma, por lo que puedes usarlas igual que las reglas de Sigma para convertirlas a otros formatos SIEM.
Las reglas de Hayabusa están diseñadas únicamente para el análisis de registros de eventos de Windows y tienen los siguientes beneficios:

1. Un campo `details` adicional para mostrar información adicional tomada únicamente de los campos útiles del registro.
2. Todas están probadas contra registros de muestra y se sabe que funcionan.
3. Agregadores adicionales que no se encuentran en sigma, como `|equalsfield` y `|endswithfield`.

Hasta donde sabemos, hayabusa proporciona el mayor soporte nativo para reglas de sigma de cualquier herramienta de código abierto de análisis de registros de eventos de Windows.
