# Características

* Soporte multiplataforma: Windows, Linux, macOS.
* Desarrollado en Rust para ser seguro en memoria y rápido.
* Soporte multihilo que ofrece una mejora de velocidad de hasta 5 veces.
* Crea líneas de tiempo únicas y fáciles de analizar para investigaciones forenses y respuesta a incidentes.
* Caza de amenazas basada en firmas IoC escritas en reglas hayabusa basadas en YML, fáciles de leer/crear/editar.
* Soporte de reglas Sigma para convertir reglas sigma en reglas hayabusa.
* Actualmente soporta la mayor cantidad de reglas sigma en comparación con otras herramientas similares e incluso soporta reglas de conteo y nuevos agregadores como `|equalsfield` y `|endswithfield`.
* Métricas de equipos. (Útil para filtrar a favor o en contra de ciertos equipos con una gran cantidad de eventos.)
* Métricas de Event ID. (Útil para obtener una visión de qué tipos de eventos hay y para ajustar la configuración de tus registros.)
* Configuración de ajuste de reglas excluyendo reglas innecesarias o ruidosas.
* Mapeo de tácticas MITRE ATT&CK.
* Ajuste del nivel de reglas.
* Crea una lista de palabras clave de pivote únicas para identificar rápidamente usuarios, nombres de host, procesos, etc. anómalos, así como correlacionar eventos.
* Genera todos los campos para investigaciones más exhaustivas.
* Resumen de inicios de sesión exitosos y fallidos.
* Caza de amenazas y DFIR a nivel empresarial en todos los endpoints con [Velociraptor](https://docs.velociraptor.app/).
* Salida a informes de resumen en CSV, JSON/JSONL y HTML.
* Actualizaciones diarias de reglas Sigma.
* Soporte para entrada de registros en formato JSON.
* Normalización de campos de registro. (Conversión de múltiples campos con diferentes convenciones de nomenclatura en el mismo nombre de campo.)
* Enriquecimiento de registros añadiendo información GeoIP (ASN, ciudad, país) a las direcciones IP.
* Busca en todos los eventos palabras clave o expresiones regulares.
* Mapeo de datos de campos. (Ej.: `0xc0000234` -> `ACCOUNT LOCKED`)
* Extracción (carving) de registros evtx desde el espacio libre (slack space) de evtx.
* Eliminación de duplicados de eventos al generar la salida. (Útil cuando la recuperación de registros está habilitada o cuando se incluyen archivos evtx respaldados, archivos evtx de VSS, etc.)
* Asistente de configuración de escaneo para ayudar a elegir más fácilmente qué reglas habilitar. (Para reducir falsos positivos, etc.)
* Análisis y extracción de campos de registros clásicos de PowerShell.
* Bajo uso de memoria. (Nota: esto es posible al no ordenar los resultados. Ideal para ejecutar en agentes o con grandes volúmenes de datos.)
* Filtrado en Channels y Rules para el rendimiento más eficiente.
* Detecta, extrae y decodifica cadenas Base64 encontradas en los registros.
* Ajuste del nivel de alerta basado en sistemas críticos.
