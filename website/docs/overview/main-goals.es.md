# Objetivos principales

## Búsqueda de amenazas y DFIR a nivel empresarial

Hayabusa cuenta actualmente con más de 4000 reglas Sigma y más de 170 reglas de detección integradas de Hayabusa, y se añaden nuevas reglas con regularidad.
Puede utilizarse para la búsqueda proactiva de amenazas a nivel empresarial, así como para DFIR (análisis forense digital y respuesta a incidentes) de forma gratuita con el [artefacto Hayabusa](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) de [Velociraptor](https://docs.velociraptor.app/).
Al combinar estas dos herramientas de código abierto, esencialmente puede reproducir retroactivamente un SIEM cuando no hay una configuración de SIEM en el entorno.
Puede aprender a hacer esto viendo el tutorial de Velociraptor de [Eric Capuano](https://twitter.com/eric_capuano) [aquí](https://www.youtube.com/watch?v=Q1IoGX--814).

## Generación rápida de líneas de tiempo forenses

El análisis de los registros de eventos de Windows ha sido tradicionalmente un proceso muy largo y tedioso porque los registros de eventos de Windows están 1) en un formato de datos difícil de analizar y 2) la mayoría de los datos son ruido y no resultan útiles para las investigaciones.
El objetivo de Hayabusa es extraer únicamente los datos útiles y presentarlos en un formato lo más conciso y fácil de leer posible, que pueda ser utilizado no solo por analistas formados profesionalmente, sino por cualquier administrador de sistemas Windows.
Hayabusa espera permitir que los analistas realicen el 80 % de su trabajo en el 20 % del tiempo en comparación con el análisis tradicional de registros de eventos de Windows.

![Línea de tiempo DFIR](../assets/doc/DFIR-TimelineCreation-EN.png)
