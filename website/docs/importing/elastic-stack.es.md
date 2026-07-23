- [Importación de resultados en SOF-ELK (Elastic Stack)](#importing-results-into-sof-elk-elastic-stack)
  - [Instalar e iniciar SOF-ELK](#install-and-start-sof-elk)
    - [Problemas de conectividad de red en Macs](#network-connectivity-trouble-on-macs)
  - [¡Actualice SOF-ELK!](#update-sof-elk)
  - [Ejecutar Hayabusa](#run-hayabusa)
  - [Opcional: Eliminar datos importados antiguos](#optional-deleting-old-imported-data)
  - [Configurar el archivo de configuración de logstash de Hayabusa en SOF-ELK](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Importar resultados de Hayabusa en SOF-ELK](#import-hayabusa-results-into-sof-elk)
  - [Verificar que la importación funcionó en Kibana](#check-that-the-import-worked-in-kibana)
  - [Ver resultados en Discover](#view-results-in-discover)
  - [Analizar resultados](#analyzing-results)
    - [Agregar columnas](#adding-columns)
    - [Filtrado](#filtering)
    - [Alternar detalles](#toggling-details)
    - [Ver documentos circundantes](#view-surrounding-documents)
    - [Obtener métricas rápidas sobre los campos](#get-quick-metrics-on-fields)
  - [Planes futuros](#future-plans)

# Importación de resultados en SOF-ELK (Elastic Stack)

## Instalar e iniciar SOF-ELK

Los resultados de Hayabusa se pueden importar fácilmente en Elastic Stack.
Recomendamos usar [SOF-ELK](https://github.com/philhagen/sof-elk), una distribución Linux gratuita de Elastic Stack centrada en investigaciones de DFIR.

Primero descargue y descomprima la imagen de VMware comprimida en 7-zip de SOF-ELK desde [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README).

Hay dos versiones, x86 para CPU Intel y una versión ARM para computadoras Apple de la serie M.

Cuando arranque la VM, obtendrá una pantalla similar a esta:

![SOF-ELK Bootup](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Tome nota de la URL de Kibana y la dirección IP del servidor SSH.

Puede iniciar sesión con las siguientes credenciales:

* Nombre de usuario: `elk_user`
* Contraseña: `forensics`

Abra Kibana en un navegador web según la URL mostrada.
Por ejemplo: http://172.16.23.128:5601/

> Nota: puede tardar un poco en cargar Kibana.

Debería ver una página web como la siguiente:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

Recomendamos que se conecte por SSH a la VM en lugar de escribir comandos dentro de la VM con `ssh elk_user@172.16.23.128`.

> Nota: la distribución de teclado predeterminada es el teclado de EE. UU.

### Problemas de conectividad de red en Macs

Si está en macOS y obtiene un error `no route to host` en la terminal o no puede acceder a Kibana en su navegador, probablemente se deba a los controles de privacidad de red local de macOS.

En `System Settings`, abra `Privacy & Security` -> `Local Network` y asegúrese de que su navegador y programa de terminal estén habilitados para poder comunicarse con dispositivos en su red local.

## ¡Actualice SOF-ELK!

Antes de importar datos, asegúrese de actualizar SOF-ELK con el comando `sudo sof-elk_update.sh`.

## Ejecutar Hayabusa

Ejecute Hayabusa y guarde los resultados en JSONL.

Ej: `./hayabusa dfir-timeline -t jsonl -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## Opcional: Eliminar datos importados antiguos

Si esta no es la primera vez que importa resultados de Hayabusa y desea borrar todo, puede hacerlo de la siguiente manera:

1. Verifique qué registros están actualmente en SOF-ELK: `sof-elk_clear.py -i list`
2. Elimine los datos actuales: `sof-elk_clear.py -a`
3. Elimine los archivos en el directorio de logstash: `rm /logstash/hayabusa/*`

## Configurar el archivo de configuración de logstash de Hayabusa en SOF-ELK

Ya hay un archivo de configuración de logstash de Hayabusa incluido en SOF-ELK que convierte los nombres de campo al formato de Elastic Common Schema.
Si se siente más cómodo con los nombres de campo de Hayabusa, recomendamos usar el que proporcionamos.

1. Primero conéctese por SSH a SOF-ELK: `ssh elk_user@172.16.23.128`
2. Elimine o mueva el archivo de configuración de logstash actual: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. Suba el nuevo archivo [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) a `/etc/logstash/conf.d/`: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. Reinicie logstash: `sudo systemctl restart logstash`

Este archivo de configuración creará campos consolidados `DetailsText` y `ExtraFieldInfoText` que le permiten ver rápidamente los campos más importantes de un vistazo en lugar de tener que tomarse el tiempo de abrir cada registro uno a la vez para revisar todos los campos.

## Importar resultados de Hayabusa en SOF-ELK

Los registros se ingieren en SOF-ELK copiando los registros en el directorio apropiado dentro del directorio `/logstash`.

Primero salga de SSH con `exit` y luego copie el archivo de resultados de Hayabusa que creó:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Verificar que la importación funcionó en Kibana

Primero tome nota de `Total detections`, `First Timestamp` y `Last Timestamp` en el `Results Summary` de su escaneo de Hayabusa.

Si no puede obtener esta información, puede ejecutar `wc -l results.jsonl` en *nix para obtener el recuento total de líneas para `Total detections`.

De forma predeterminada, Hayabusa no ordena los resultados para mejorar el rendimiento, por lo que no puede mirar las primeras y últimas líneas para obtener la primera y última marca de tiempo.
Si no conoce las marcas de tiempo exactas de la primera y la última, simplemente establezca la primera fecha en Kibana en el año 2007 y el último día como `now` para tener todos los resultados.

![UpdateDates](../assets/doc/ElasticStackImport/03-ChangeDates.png)

Ahora debería ver los `Total Records` así como las primeras y últimas marcas de tiempo de los eventos que se han importado.

A veces tarda un poco en importar todos los eventos, así que siga actualizando la página hasta que `Total Records` sea el recuento que espera.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

También puede verificar desde la terminal ejecutando `sof-elk_clear.py -i list` para ver si la importación fue exitosa.
Debería ver que su índice `evtxlogs` tiene más registros:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

Cree una incidencia en GitHub si tiene errores de análisis al importar.
Puede verificar esto mirando el final del archivo de registro `/var/log/logstash/logstash-plain.log`.

## Ver resultados en Discover

Haga clic en el icono de la barra lateral superior izquierda y haga clic en `Discover`:

![OpenDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

Probablemente verá `No results match your search criteria`.

En la esquina superior izquierda donde dice el índice `logstash-*`, haga clic en él y cámbielo a `evtxlogs-*`.
Ahora debería ver la línea de tiempo de Discover.

## Analizar resultados

La vista predeterminada de Discover debería verse similar a esto:

![Discover View](../assets/doc/ElasticStackImport/06-Discover.png)

Puede obtener una descripción general de cuándo ocurrieron los eventos y la frecuencia de los eventos mirando el histograma en la parte superior. 

### Agregar columnas

En la barra lateral izquierda, puede agregar los campos que desea mostrar en las columnas haciendo clic en el signo más después de pasar el cursor sobre un campo.
Dado que hay muchos campos, es posible que desee escribir el nombre del campo que está buscando en el cuadro de búsqueda.

![Adding Columns](../assets/doc/ElasticStackImport/07-AddingColumns.png)

Para empezar, recomendamos las siguientes columnas:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

Si su monitor es lo suficientemente ancho, es posible que también desee agregar `ExtraFieldInfoText` para ver toda la información de los campos.

Su vista de Discover ahora debería verse así:

![Discover With Columns](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### Filtrado

Puede filtrar con KQL (Kibana Query Language) para buscar ciertos eventos y alertas. Por ejemplo:
  * `Level: "crit"`: Mostrar solo alertas críticas.
  * `Level: "crit" OR Level: "high"`: Mostrar alertas altas y críticas.
  * `NOT Level: info`: No mostrar eventos informativos, solo alertas.
  * `MitreTactics: *LatMov*`: Mostrar eventos y alertas relacionados con el movimiento lateral.
  * `"PW Spray"`: Mostrar solo ataques específicos como "Password Spray".
  * `"LID: 0x8724ead"`: Mostrar toda la actividad asociada con el ID de inicio de sesión 0x8724ead.
  * `Details_TgtUser: admmig`: Buscar todos los eventos donde el usuario de destino es `admmig`.

### Alternar detalles

Para verificar todos los campos de un registro, simplemente haga clic en el icono (Toggle dialog with details) junto a la marca de tiempo:

![ToggleDetails](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### Ver documentos circundantes

Si desea ver los eventos directamente antes y después de una cierta alerta, primero abra los detalles de esa alerta y luego haga clic en `View surrounding documents` en la parte superior derecha:

![ViewSurroundingDocuments](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

En este ejemplo, estamos viendo los eventos antes y después de la alerta de ataque Pass the Hash:

![SurroundingDocuments](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Nota: Cambie los números en la parte superior `Load x newer documents` o inferior `Load x older documents` para recuperar más eventos.

### Obtener métricas rápidas sobre los campos

En la columna izquierda, si hace clic en el nombre de un campo le dará métricas rápidas sobre su uso:

![LevelMetrics](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> Tenga en cuenta que los datos se muestrean para mayor velocidad, por lo que no son 100% precisos.

## Planes futuros

* Analizadores de Logstash para CSV
* Panel predefinido
