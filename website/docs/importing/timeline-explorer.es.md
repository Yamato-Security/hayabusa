# Análisis de los resultados de Hayabusa con Timeline Explorer

## Acerca de

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) es una herramienta gratuita pero de código cerrado para reemplazar a Excel al analizar archivos CSV con fines de DFIR.
Es una herramienta GUI exclusiva para Windows escrita en C#.
Esta herramienta es excelente para investigaciones pequeñas realizadas por un solo analista y para personas que apenas comienzan a aprender el análisis de DFIR; sin embargo, la interfaz puede ser difícil de entender al principio, así que utilice esta guía para comprender las diferentes funciones.

## Instalación y ejecución

No es necesario instalar la aplicación.
Solo descargue la última versión desde [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md), descomprímala y ejecute `TimelineExplorer.exe`.
Si no tiene el entorno de ejecución de .NET adecuado, aparecerá un mensaje indicándole que necesita instalarlo.
Al momento de escribir esto (2025/2/14), la última versión es `2.1.0`, que se ejecuta en la versión `9` de .NET.

## Carga de un archivo CSV

Simplemente haga clic en `File` -> `Open` del menú para cargar un archivo CSV.

Verá algo como esto:

![First Start](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

En la parte inferior, puede ver el nombre del archivo, `Total lines` y `Visible lines`.

Además de las columnas que se encuentran en el archivo CSV, hay dos columnas a la izquierda agregadas por Timeline Explorer: `Line` y `Tag`.
`Line` muestra el número de línea, pero normalmente no es útil para las investigaciones, por lo que es posible que desee ocultar esta columna.
`Tag` le permite colocar una marca de verificación en los eventos que desea anotar para un análisis posterior, etc...
Lamentablemente, no hay forma de agregar etiquetas personalizadas a los eventos ni escribir comentarios sobre ellos, ya que el archivo CSV se abre en modo de solo lectura para evitar que se sobrescriban los datos.

## Filtrado de datos

Si pasa el ratón por la parte superior derecha de un encabezado, verá aparecer un icono de filtro negro.

![Basic Data Filtering](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

Puede colocar marcas de verificación en el nivel de severidad para clasificar primero las alertas `high` y `crit` (`critical`).
Este filtrado también es muy útil para descartar alertas ruidosas marcando todo en `Rule Title` y luego desmarcando las reglas ruidosas.

Como se muestra a continuación, si hace clic en `Text Filters`, puede crear filtros más avanzados:

![Advanced Data Filtering](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

Sin embargo, en lugar de crear filtros aquí, normalmente es más fácil hacer clic en el icono `ABC` debajo del encabezado y aplicar los filtros allí:

![ABC Filtering](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

Lamentablemente, estos dos lugares ofrecen opciones de filtrado ligeramente diferentes, por lo que debe conocer ambos lugares para filtrar los datos.

Por ejemplo, si tiene demasiados eventos `Proc Exec` que desea descartar, puede elegir `Does not contain` y escribir `Proc Exec` para ignorar esos eventos:

![Rule Filtering](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

Si mira hacia la parte inferior, puede ver la regla del filtro en distintos colores.
Si desea desactivar temporalmente el filtro, simplemente desmárquelo.
Si desea borrar todos los filtros, haga clic en el botón `X`.

Si desea ignorar otra regla ruidosa, debe abrir el `Filter Editor` haciendo clic en `Edit Filter` en la esquina inferior derecha:

![Filter Editor](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

Copie el texto `Not Contains([Rule Title], 'Proc Exec')`, agregue `and`, pegue el mismo filtro y cambie `Proc Exec` por `Possible LOLBIN`, y ahora puede ignorar estas dos reglas:

![Multiple Filters](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

La forma más sencilla de combinar varios filtros es creando primero la sintaxis del filtro desde el icono `ABC`, luego copiar, pegar y editar ese texto y combinar los filtros con `and`, `or` y `not`.

También puede hacer clic en cualquiera de los textos de color para obtener un cuadro desplegable con las opciones posibles para editar sus filtros:

![Dropdown editing](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Opciones de encabezado

Si hace clic con el botón derecho en cualquiera de los encabezados, obtendrá las siguientes opciones:

![Header Options](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

La mayoría de estas opciones se explican por sí mismas.

* Después de ocultar una columna, puede volver a mostrarla abriendo el `Column Chooser`, haciendo clic con el botón derecho en el nombre de la columna y haciendo clic en `Show Column`.
* `Group By This Column` tiene el mismo efecto que arrastrar un encabezado de columna hacia arriba para agrupar. (Se explica con más detalle más adelante.)
* `Hide Group By Box` simplemente ocultará el texto `Drag a column header here to group by that column` y desplazará la barra de búsqueda.

### Formato condicional

Puede dar formato al texto con color, fuente en negrita, etc... haciendo clic en `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...`:

![Conditional Formatting](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

Por ejemplo, si quisiera mostrar las alertas `critical` con `Red Fill`, simplemente escriba `crit`, elija `Red Fill` de las opciones, marque `Apply formatting to an entire row` y presione `OK`.

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

Ahora las alertas `critical` aparecerán en rojo como se muestra a continuación:

![Red fill](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

Puede continuar haciendo esto agregando color también para las alertas `low`, `medium` y `high`.

## Búsqueda

De forma predeterminada, cuando escribe algún texto en la barra de búsqueda, se realizará un filtrado y solo se mostrarán los resultados que contengan el texto en algún lugar de la fila.
Puede ver cuántas coincidencias tiene comprobando el campo `Visible lines` en la parte inferior.

Puede cambiar este comportamiento haciendo clic en `Search options` en la parte inferior derecha.
Esto mostrará lo siguiente:

![Search Options](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

Si cambia el `Behavior` de `Filter` a `Search`, puede buscar texto de forma normal.

> Nota: Normalmente lleva tiempo cambiar el comportamiento y Timeline Explorer se quedará bloqueado un momento, así que tenga paciencia después de hacer clic.

El `Match criteria` predeterminado es `Mixed`, pero se puede cambiar a `Or`, `And` o `Exact`.
Si lo cambia a cualquier cosa excepto `Mixed`, podrá establecer la `Condition` de `Contains` a `Starts with`, `Like` o `Equals`.

El `Match criteria` de `Mixed` es complicado, ya que a veces usa la lógica `AND` y a veces `OR`, pero puede ser muy flexible una vez que se aprende.
Funciona de la siguiente manera:

* Si separa las palabras por espacios, se tratará como lógica `OR`.
* Si desea incluir espacios en su búsqueda, debe agregar comillas.
* Anteceda una condición con `+` para la lógica `AND`.
* Anteceda una condición con `-` para excluir resultados.
* Filtre en una columna específica con el formato `ColumnName:FilterString`.
* Si filtra en una columna específica y además incluye una palabra clave separada, será lógica `AND`.

Ejemplos:

| Criterio de búsqueda             | Descripción                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Selecciona los registros que contienen la cadena `mimikatz` en cualquier columna de búsqueda.                                                   |
| one two three                    | Selecciona los registros que contienen `one` O `two` O `three` en cualquier columna de búsqueda.                                                |
| "hoge hoge"                      | Selecciona los registros que contienen `hoge hoge` en cualquier columna de búsqueda.                                                            |
| mimikatz +"Bad Guy"              | Selecciona los registros que contienen tanto `mimikatz` Y `Bad Guy` en cualquier columna de búsqueda.                                           |
| EventID:4624 kali                | Selecciona los registros que contienen `4624` en la columna que comienza con `EventID` Y contienen `kali` en cualquier columna de búsqueda.     |
| data +entry -mark                | Selecciona los registros que contienen tanto `data` Y `entry` en cualquier columna de búsqueda, excluyendo los que contienen `mark`.            |
| manu mask -file                  | Selecciona los registros que contienen `menu` O `mask`, excluyendo los que contienen `file`.                                                    |
| From:Roller Subj:"currency mask" | Selecciona los registros que contienen `Roller` en la columna que comienza con `From` Y contienen `currency mask` en la columna que comienza con `Subj`. |
| import -From:Steve               | Selecciona los registros que contienen `import` en cualquier columna de búsqueda, excluyendo los que contienen `Steve` en la columna que comienza con `From`. |

## Congelar columnas

Aunque no es una opción de búsqueda, puede configurar la `First scrollable column` en el menú `Search options`.
La mayoría de los analistas establecen esto en `Timestamp` para poder ver siempre a qué hora ocurrieron ciertos eventos.

## Arrastrar encabezados de columna para agrupar

Si arrastra un encabezado de columna hacia `Drag a column header here to group by that column`, Timeline Explorer agrupará por esa columna.
Es común agrupar por `Level` para poder priorizar las alertas por severidad:

![Group by](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

Si tiene varios equipos en sus resultados, puede agrupar adicionalmente por `Computer` para clasificar según los diferentes niveles de severidad de cada equipo.

## Comprobación de campos

De forma predeterminada, Hayabusa separará los datos de los campos con el símbolo de barra vertical partida: `¦`.
Cuando los datos de los campos están en una línea horizontal, esto hace que sea muy fácil distinguir varios campos, ya que este carácter no se encuentra a menudo en los registros:

![Field Information](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

Sin embargo, a veces habrá demasiada información de campos en el registro y no todo cabe en una sola pantalla.
En este caso, puede hacer doble clic en la celda para obtener una ventana emergente que muestre toda la información de los campos:

![Cell Contents](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

El problema es que Timeline Explorer solo le permite dar formato a los datos de los campos mediante caracteres de salto de línea (`CRLF`, `CR`, `LF`), comas y tabulaciones.

Si utiliza la opción `-M, --multiline`, puede separar los campos por un carácter de salto de línea y, cuando haga doble clic para abrir el contenido de una celda, este tendrá el formato adecuado:

![Multi-line formatting](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

El problema es que ahora solo se mostrará el primer campo en la línea de tiempo, por lo que tendrá que hacer doble clic y abrir una nueva ventana cada vez que quiera comprobar los datos de los otros campos:

![Multiline single fiels](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

Lamentablemente, Timeline Explorer no admite múltiples líneas en la vista de la línea de tiempo.

Para solucionar esto, a partir de Hayabusa `v3.1.0`, puede separar los campos por tabulaciones:

![Tab separation](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

Es un poco más difícil distinguir dónde termina un campo y comienza el siguiente.
Además, cuando hace doble clic y abre el contenido de la celda, los campos no se formatean automáticamente:

![Tab separation not formatted](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

Sin embargo, si hace clic en `Tab` en la parte inferior y luego en `Format`, puede dar formato a los campos en una vista fácil de leer:

![Tab separation formatted](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Skins

Puede cambiar el tema de color desde `Tools` -> `Skins` si prefiere el modo oscuro, etc...

## Sesiones

Si personaliza las columnas, la apariencia, agrega filtros, etc... y desea guardar esos ajustes para más tarde, asegúrese de guardar su sesión desde `File` -> `Session` -> `Save`.
