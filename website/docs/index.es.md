---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Hayabusa](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Hayabusa</strong> es un <strong>generador rápido de líneas de tiempo forenses</strong> de registros de eventos de Windows
y una <strong>herramienta de caza de amenazas</strong> creada por
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Escrita en Rust con seguridad de memoria, multihilo para mayor velocidad, y la única herramienta de código abierto
con soporte completo de la especificación Sigma, incluidas las reglas de correlación v2.
</p>

<div class="hb-cta" markdown>
[Comenzar :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Referencia de comandos :material-console:](commands/index.md){ .md-button }
[Ver en GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
<a href="https://www.blackhat.com/asia-22/arsenal/schedule/#hayabusa-26211"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20Asia-2022-blue"></a>
<a href="https://codeblue.jp/2022/en/talks/?content=talks_24"><img src="https://img.shields.io/badge/CODE%20BLUE%20Bluebox-2022-blue"></a>
<a href="https://www.seccon.jp/2022/seccon_workshop/windows.html"><img src="https://img.shields.io/badge/SECCON-2023-blue"></a>
<a href="https://www.security-camp.or.jp/minicamp/tokyo2023.html"><img src="https://img.shields.io/badge/Security%20MiniCamp%20Tokyo-2023-blue"></a>
<a href="https://www.sans.org/cyber-security-training-events/digital-forensics-summit-2023/"><img src="https://img.shields.io/badge/SANS%20DFIR%20Summit-2023-blue"></a>
<a href="https://bsides.tokyo/2024/"><img src="https://img.shields.io/badge/BSides%20Tokyo-2024-blue"></a>
<a href="https://www.hacker.or.jp/hack-fes-2024/"><img src="https://img.shields.io/badge/Hack%20Fes.-2024-blue"></a>
<a href="https://hitcon.org/2024/CMT/"><img src="https://img.shields.io/badge/HITCON-2024-blue"></a>
<a href="https://www.blackhat.com/sector/2024/briefings/schedule/index.html#performing-dfir-and-threat-hunting-with-yamato-security-oss-tools-and-community-driven-knowledge-41347"><img src="https://img.shields.io/badge/SecTor-2024-blue"></a>
<a href="https://www.infosec-city.com/schedule/sin25-con"><img src="https://img.shields.io/badge/SINCON%20Kampung%20Workshop-2025-blue"></a>
<a href="https://www.blackhat.com/us-25/arsenal/schedule/index.html#windows-fast-forensics-with-yamato-securitys-hayabusa-45629"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2025-blue"></a>
<a href="https://codeblue.jp/en/program/time-table/day2-t3-02/"><img src="https://img.shields.io/badge/CODE%20BLUE%20-2025-blue"></a>
<a href="https://blackhat.com/us-26/arsenal/schedule/index.html#mecha-hayabusa-by-yamato-security-52897"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2026-blue"></a>
<a href="https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d"><img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg" /></a>
<a href="https://github.com/Yamato-Security/hayabusa/commits/main/"><img src="https://img.shields.io/github/commit-activity/t/Yamato-Security/hayabusa/main" /></a>
<a href="https://rust-reportcard.xuri.me/report/github.com/Yamato-Security/hayabusa"><img src="https://rust-reportcard.xuri.me/badge/github.com/Yamato-Security/hayabusa" /></a>
<a href="https://codecov.io/gh/Yamato-Security/hayabusa" ><img src="https://codecov.io/gh/Yamato-Security/hayabusa/branch/main/graph/badge.svg?token=WFN5XO9W8C"/></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## ¿Por qué Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Increíblemente rápida__

    ---

    Escrita en **Rust** con seguridad de memoria y multihilo completo para analizar montañas
    de archivos `.evtx` y producir una sola línea de tiempo lo más rápido posible.

-   :material-shield-search:{ .lg .middle } __Soporte completo de Sigma__

    ---

    La única herramienta de código abierto con soporte completo de la especificación Sigma, incluidas
    las **reglas de correlación v2**, respaldada por más de 4000 reglas de detección curadas.

-   :material-timeline-clock:{ .lg .middle } __Líneas de tiempo DFIR__

    ---

    Consolida eventos de un solo host o de miles en una única línea de tiempo forense
    **CSV / JSON / JSONL** lista para el análisis.

-   :material-server-network:{ .lg .middle } __Caza en toda la empresa__

    ---

    Ejecútala en vivo en un solo sistema, recopila registros para análisis sin conexión, o caza en toda
    la empresa con el artefacto Hayabusa de **Velociraptor**.

-   :material-chart-box:{ .lg .middle } __Salida de análisis enriquecida__

    ---

    Métricas, resúmenes de inicio de sesión, pivoteo por palabras clave, informes HTML y una línea de tiempo
    de frecuencia de detecciones para revelar rápidamente lo que importa.

-   :material-import:{ .lg .middle } __Se integra con otras herramientas__

    ---

    Importa los resultados directamente a **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**, o segmenta el JSON con **jq**.

</div>

## Velo en acción

![Creación de líneas de tiempo DFIR con Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

Explora la galería de [Capturas de pantalla](overview/screenshots.md) para ver la salida de terminal, el
resumen de resultados HTML, y el análisis en LibreOffice, Timeline Explorer y Timesketch.

## Enlaces rápidos

<div class="grid cards" markdown>

-   __:material-book-open-variant: ¿Nuevo por aquí?__

    Comienza con la [Visión general](overview/index.md), luego dirígete a
    [Primeros pasos](getting-started/index.md) para descargar y ejecutar Hayabusa.

-   __:material-console-line: ¿Trabajando con la CLI?__

    Salta a la [Lista de comandos](commands/index.md) y a la referencia por comando de
    [Análisis](commands/analysis.md), [Configuración](commands/config.md) y comandos de
    [Línea de tiempo DFIR](commands/dfir-timeline.md).

-   __:material-tune: ¿Ajustando la salida?__

    Consulta las opciones de [Perfiles de salida](output/index.md), [Abreviaturas](output/abbreviations.md)
    y [Visualización y resumen](output/display.md).

-   __:material-puzzle: ¿Quieres profundizar?__

    Explora las [Reglas](rules/index.md), el [ecosistema del proyecto](resources/index.md)
    y cómo [contribuir](resources/contributing.md).

</div>
