# Análisis de los resultados de Hayabusa con Timesketch

## Acerca de

"[Timesketch](https://timesketch.org/) es una herramienta de código abierto para el análisis colaborativo de líneas de tiempo forenses. Mediante sketches, usted y sus colaboradores pueden organizar fácilmente sus líneas de tiempo y analizarlas todos al mismo tiempo. Dé significado a sus datos en bruto con anotaciones, comentarios, etiquetas y estrellas enriquecidos."

Para investigaciones pequeñas en las que analiza un archivo CSV de solo un par de cientos de MB de tamaño y trabaja solo, Timeline Explorer es adecuado; sin embargo, cuando trabaja con datos más grandes o con un equipo, una herramienta como Timesketch es mucho mejor.

Timesketch ofrece los siguientes beneficios:

1. Es muy rápido y puede manejar grandes volúmenes de datos
2. Es una herramienta colaborativa donde múltiples usuarios pueden usarla simultáneamente
3. Proporciona análisis de datos avanzados, histogramas y visualizaciones
4. No se limita a Windows
5. Admite consultas avanzadas

Hay muchos otros beneficios, como soporte de CTI, varios analizadores, notebooks interactivos, etc...
Consulte la [guía del usuario](https://timesketch.org/guides/user/upload-data/) y el [canal de YouTube](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) para obtener más información.

La única desventaja es que tendrá que configurar un servidor Timesketch en su entorno de laboratorio, pero por suerte esto es muy sencillo de hacer.

## Instalación
### Docker
Siga las instrucciones oficiales [aquí](https://docs.docker.com/compose/install).

### Ubuntu
**Nota:** Docker debe estar instalado antes de continuar. Siga las [instrucciones de instalación de Docker anteriores](#docker) si aún no ha instalado Docker.
Recomendamos usar la última edición de Ubuntu LTS Server con al menos 8 GB de memoria.
Puede descargarla [aquí](https://ubuntu.com/download/server).
Elija la instalación mínima al configurarla.
No instale docker al configurar el sistema operativo.
No tendrá `ifconfig` disponible, así que instálelo con `sudo apt install net-tools`.

Después de eso, ejecute `ifconfig` para encontrar la dirección IP de la VM y, opcionalmente, conéctese mediante ssh.

Ejecute los siguientes comandos:
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**Nota:** Antes de continuar, asegúrese de tener [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/) instalado y en ejecución en su sistema.
Clone el repositorio de Timesketch y cambie al directorio.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
Inicie el contenedor de Docker siguiendo los pasos a continuación.

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Inicio de sesión

Averigüe la dirección IP del servidor Timesketch con `ifconfig` y ábrala con un navegador web.
Será redirigido a una página de inicio de sesión.
Inicie sesión con las credenciales de usuario que usó al agregar un usuario.

## Creación de un nuevo sketch

En `Start a new investigation`, haga clic en `BLANK SKETCH`.
Asigne al sketch un nombre relevante para su investigación.

## Carga de su línea de tiempo

Después de hacer clic en `+ ADD TIMELINE`, verá un cuadro de diálogo que le pide que cargue un archivo Plaso, JSONL o CSV.
Lamentablemente, Timesketch no puede importar actualmente el formato `JSONL` de Hayabusa, así que cree y cargue una línea de tiempo CSV con el siguiente comando:

```shell
hayabusa-x.x.x-win-x64.exe csv-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --ISO-8601
```

> Nota: Es necesario elegir un perfil `timesketch*` y especificar la marca de tiempo como `--ISO-8601` para UTC o `--RFC-3339` para la hora local. Puede agregar otras opciones de Hayabusa si lo desea; sin embargo, no agregue la opción `-M, --multiline`, ya que los caracteres de nueva línea corromperán la importación.

En el cuadro de diálogo "Select file to upload", asigne a su línea de tiempo un nombre como `hayabusa`, elija el delimitador CSV `Comma (,)` y haga clic en `SUBMIT`.

> Si su archivo CSV es demasiado grande para cargarlo, puede dividir el archivo en múltiples archivos CSV con el comando [split-csv-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-csv-timeline-command) de Takajo.

Mientras se importa el archivo verá un círculo girando, así que espere hasta que termine y vea aparecer `hayabusa`.

## Consejos de análisis

### Visualización de la línea de tiempo

**Nota: Incluso después de que la importación haya finalizado con éxito, mostrará `Your search did not match any events` y habrá `0` eventos en la línea de tiempo `hayabusa`.**

Busque `*` y los eventos aparecerán como se muestra a continuación:

![Resultados de Timesketch](../assets/doc/TimesketchImport/TimesketchResults.png)

### Detalles de la alerta

Si hace clic en un título de regla de alerta bajo la columna `message`, obtendrá la información detallada sobre la alerta:

![Detalles de la alerta](../assets/doc/TimesketchImport/AlertDetails.png)

Si desea comprender la lógica de la regla sigma, buscar la descripción y las referencias, etc... busque la regla en el repositorio [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

#### Filtrado de campos

Después de abrir los detalles de un evento haciendo clic en su título de regla, puede pasar el cursor sobre cualquier campo para filtrar fácilmente el valor de forma incluyente o excluyente:

![Filtrar incluir excluir](../assets/doc/TimesketchImport/FilterInOut.png)

#### Análisis de agregación

Al pasar el cursor, si hace clic en el icono `Aggregation dialog` más a la izquierda, obtiene análisis de datos de eventos realmente excelentes sobre ese campo:

![Análisis de datos de eventos](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### Comentarios de usuario

Cuando hace clic en una alerta para obtener información detallada, se muestra un nuevo icono de cuadro de diálogo de comentarios en el lado derecho, como se muestra a continuación:

![Icono de comentario](../assets/doc/TimesketchImport/CommentIcon.png)

Aquí, los usuarios pueden iniciar un chat y escribir comentarios sobre la investigación.

> Si trabaja en equipo, probablemente debería crear una cuenta de usuario diferente para cada miembro para saber quién escribió qué.

![Chat de comentarios](../assets/doc/TimesketchImport/CommentChat.png)

> Si pasa el cursor sobre un comentario, puede editar y eliminar fácilmente los mensajes.

### Modificación de columnas

De forma predeterminada, solo se mostrarán la marca de tiempo y el título de la regla de alerta, así que haga clic en el icono `Modify columns` para personalizar los campos:

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

Esto abrirá el siguiente cuadro de diálogo:

![Seleccionar columnas](../assets/doc/TimesketchImport/SelectColumns.png)

Recomendamos agregar al menos las siguientes columnas **en orden**:

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

El orden de las columnas cambiará según el orden en que las agregue, así que agregue primero los campos más importantes.

Si todavía tiene espacio en su pantalla, recomendamos agregar también `Details`, como se muestra aquí:

![Detalles](../assets/doc/TimesketchImport/Details.png)

Si todavía tiene espacio en su pantalla, recomendamos agregar también `ExtraFieldInfo`; sin embargo, como ve aquí, si agrega demasiadas columnas, el campo `message` se volverá demasiado estrecho y ya no podrá leer los títulos de las alertas:

![Demasiados detalles](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Iconos superiores

#### Icono de elipsis

Si hace clic en el icono `···`, puede hacer las filas más compactas y eliminar el `Timeline name` para crear más espacio para los resultados:

![Más espacio](../assets/doc/TimesketchImport/MoreRoom.png)

#### Histograma de eventos

Puede activar el histograma de eventos para visualizar la línea de tiempo:

![Histograma de eventos](../assets/doc/TimesketchImport/EventHistogram.png)

Si hace clic en una de las barras, creará un filtro de tiempo para mostrar solo los resultados durante ese período de tiempo.

#### Guardar búsqueda actual

Si hace clic en el icono `Save current search` justo encima de las marcas de tiempo y a la izquierda del icono `Toggle Event Histogram`, puede guardar su consulta de búsqueda actual, así como la configuración de columnas, en `Saved Searches`.
Más tarde, desde la barra lateral izquierda puede acceder fácilmente a sus búsquedas favoritas.

### Barra de búsqueda

Aquí hay algunas consultas útiles para comenzar mostrando solo alertas con ciertos niveles de severidad:

1. `Level:crit` para mostrar solo alertas críticas.
2. `Level:crit OR Level:high` para mostrar alertas altas y críticas
3. `NOT Level:info` para ocultar alertas informativas

Puede filtrar fácilmente escribiendo el nombre del campo más `:` más el valor.
Puede combinar filtros con `AND`, `OR` y `NOT`.
Se admiten comodines y expresiones regulares.

Consulte la guía del usuario [aquí](https://timesketch.org/guides/user/search-query-guide/) para consultas más avanzadas.

#### Historial de búsqueda

Si hace clic en el icono de reloj a la izquierda de la barra de búsqueda, puede mostrar las consultas introducidas anteriormente.
También puede hacer clic en los iconos de flecha izquierda y derecha para ejecutar las consultas anterior y siguiente.

![Historial de búsqueda](../assets/doc/TimesketchImport/SearchHistory.png)

### Elipsis vertical

Si hace clic en la elipsis vertical a la izquierda de una marca de tiempo y hace clic en `Context search`, puede ver las alertas que ocurrieron antes y después de un determinado evento:

![Elipsis vertical](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

Esto mostrará lo siguiente:

![Búsqueda de contexto](../assets/doc/TimesketchImport/ContextSearch.png)

En el ejemplo anterior, se muestran los eventos antes y después de 60 segundos (`60S`), pero puede ajustarlo desde +- 1 segundo (`1S`) hasta +- 60 minutos (`60M`).

Si desea profundizar más en los eventos mostrados, haga clic en `Replace Search` para mostrar los eventos en la línea de tiempo estándar.

### Estrellas y etiquetas

Puede hacer clic en el icono de estrella a la izquierda de una marca de tiempo para destacarla y anotarla como un evento importante.

También puede agregar etiquetas a los eventos.
Esto es útil para indicar a otros que ha confirmado que un evento es sospechoso, malicioso, un falso positivo, etc...
Si trabaja en equipo, puede crear etiquetas como `under investigation by xxx` para indicar que alguien está investigando actualmente la alerta.

![Estrellas y etiquetas](../assets/doc/TimesketchImport/StarsAndTags.png)
