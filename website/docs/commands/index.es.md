# Lista de comandos

## Comandos de análisis:
* `computer-metrics`: Imprime el número de eventos según los nombres de los equipos.
* `eid-metrics`: Imprime el número y el porcentaje de eventos según el Event ID.
* `expand-list`: Extrae los marcadores de posición `expand` de la carpeta `rules`.
* `extract-base64`: Extrae y decodifica cadenas base64 de los eventos.
* `log-metrics`: Imprime métricas de los archivos de registro.
* `logon-summary`: Imprime un resumen de los eventos de inicio de sesión.
* `pivot-keywords-list`: Imprime una lista de palabras clave sospechosas sobre las que pivotar.
* `search`: Busca todos los eventos por palabra(s) clave o expresiones regulares

## Comandos de configuración:
* `config-critical-systems`: Encuentra sistemas críticos como controladores de dominio y servidores de archivos.

## Comandos de cronología DFIR:
* `csv-timeline`: Guarda la cronología en formato CSV.
* `json-timeline`: Guarda la cronología en formato JSON/JSONL.
* `level-tuning`: Ajusta de forma personalizada el `level` de las alertas.
* `list-profiles`: Lista los perfiles de salida disponibles.
* `set-default-profile`: Cambia el perfil predeterminado.
* `update-rules`: Sincroniza las reglas con las reglas más recientes del repositorio de GitHub [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

## Comandos generales:
* `help`: Imprime este mensaje o la ayuda del subcomando o subcomandos indicados
* `list-contributors`: Imprime la lista de colaboradores
