# Visualización de salida y resumen

## Barra de progreso

La barra de progreso solo funcionará con múltiples archivos evtx.
Mostrará en tiempo real el número y el porcentaje de archivos evtx que ha terminado de analizar.

## Salida en color

Las alertas se mostrarán en color según el `level` de la alerta.
Puedes cambiar los colores predeterminados en el archivo de configuración en `./config/level_color.txt` con el formato `level,(RGB 6-digit ColorHex)`.
Si deseas desactivar la salida en color, puedes usar la opción `-K, --no-color`.

## Resumen de resultados

El total de eventos, el número de eventos con coincidencias, las métricas de reducción de datos, las detecciones totales y únicas, las fechas con más detecciones, los principales equipos con detecciones y las principales alertas se muestran después de cada escaneo.

### Cronología de frecuencia de detección

Si agregas la opción `-T, --visualize-timeline`, la función de cronología de frecuencia de eventos muestra una cronología de frecuencia tipo sparkline de los eventos detectados.
Nota: Es necesario que haya más de 5 eventos. Además, los caracteres no se renderizarán correctamente en el símbolo del sistema o en el símbolo de PowerShell predeterminados, por lo que utiliza una terminal como Windows Terminal, iTerm2, etc...
