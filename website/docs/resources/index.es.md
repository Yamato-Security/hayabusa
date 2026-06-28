# Proyectos y ecosistema

## Proyectos complementarios

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Documentación y scripts para habilitar correctamente los registros de eventos de Windows.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Igual que el repositorio Hayabusa Rules, pero las reglas y los archivos de configuración se almacenan en un único archivo y se cifran con XOR para evitar falsos positivos por parte de los antivirus.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Reglas de detección de Hayabusa y reglas Sigma seleccionadas que utiliza Hayabusa.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - Un fork más mantenido del crate `evtx`.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Archivos evtx de ejemplo para usar en la prueba de las reglas de detección de hayabusa/sigma.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Presentaciones de las charlas que hemos dado sobre nuestras herramientas y recursos.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Adapta las reglas Sigma originales basadas en registros de eventos de Windows a una forma más fácil de usar.
* [Takajo](https://github.com/Yamato-Security/takajo) - Un analizador para los resultados de hayabusa.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - Un analizador de registros de eventos de Windows escrito en PowerShell. (Obsoleto y reemplazado por Takajo).

## Proyectos de terceros que usan Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Un flujo de trabajo de NodeRED que importa resultados de Plaso y Hayabusa a Timesketch.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - Proporciona herramientas e infraestructura de seguridad basadas en la nube que se adaptan a tus necesidades. 
* [OpenRelik](https://openrelik.org/) - Una plataforma de código abierto (Apache-2.0) diseñada para agilizar las investigaciones forenses digitales colaborativas.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Pon en marcha rápidamente una instancia de splunk con Docker para examinar registros y la salida de herramientas durante tus investigaciones.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Una herramienta para recopilar información de estado basada en hosts mediante consultas de The Velociraptor Query Language (VQL).

## Otros analizadores de registros de eventos de Windows y recursos relacionados

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Herramienta de detección de ataques escrita en Python.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Colección de recursos de Event ID útiles para el análisis forense digital y la respuesta a incidentes
* [Chainsaw](https://github.com/countercept/chainsaw) - Otra herramienta de detección de ataques basada en sigma escrita en Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Herramienta de detección de ataques escrita en Powershell por [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - Visualización de grafos para registros de eventos de Windows.
* [EventList](https://github.com/miriamxyra/EventList/) - Asigna los Event ID de las líneas base de seguridad a MITRE ATT&CK por [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - por [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - Analizador de Evtx por [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Recupera archivos de registro EVTX del espacio no asignado y de imágenes de memoria.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Herramienta de Python para enviar datos de Evtx a Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Archivos de registro de eventos de ejemplo de ataques EVTX por [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Archivos de registro de eventos de ejemplo de ataques EVTX asignados a ATT&CK por [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - la biblioteca evtx de Rust que utilizamos, escrita por [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Visualizador de registros de Sysmon y PowerShell.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Una interfaz gráfica para visualizar inicios de sesión y detectar movimiento lateral por [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - La guía de la NSA sobre qué supervisar.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Adaptación de DeepBlueCLI a Rust por Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - Reglas SIEM genéricas basadas en la comunidad.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - Una máquina virtual preempaquetada con Elastic Stack para importar datos para análisis DFIR por [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Importa archivos evtx a Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Herramienta de configuración y visualización de registros sin conexión para Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - El mejor analizador de líneas de tiempo CSV por [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - por Steve Anson de Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - Herramienta de detección de ataques basada en Sigma escrita en Python.
