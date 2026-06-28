# Projetos e Ecossistema

## Projetos Complementares

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Documentação e scripts para habilitar corretamente os registros de eventos do Windows.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - O mesmo que o repositório Hayabusa Rules, mas as regras e os arquivos de configuração são armazenados em um único arquivo e submetidos a XOR para evitar falsos positivos de antivírus.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Regras de detecção Hayabusa e regras Sigma selecionadas usadas pelo Hayabusa.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - Um fork mais mantido do crate `evtx`.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Arquivos evtx de exemplo para usar nos testes das regras de detecção hayabusa/sigma.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Apresentações de palestras que demos sobre nossas ferramentas e recursos.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Adapta regras Sigma baseadas em registros de eventos do Windows upstream para um formato mais fácil de usar.
* [Takajo](https://github.com/Yamato-Security/takajo) - Um analisador para os resultados do hayabusa.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - Um analisador de registros de eventos do Windows escrito em PowerShell. (Descontinuado e substituído pelo Takajo.)

## Projetos de Terceiros Que Usam o Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Um fluxo de trabalho NodeRED que importa resultados do Plaso e do Hayabusa para o Timesketch.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - Fornece ferramentas e infraestrutura de segurança baseadas em nuvem para atender às suas necessidades. 
* [OpenRelik](https://openrelik.org/) - Uma plataforma de código aberto (Apache-2.0) projetada para agilizar investigações forenses digitais colaborativas.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Crie rapidamente uma instância do splunk com Docker para navegar pelos logs e pela saída de ferramentas durante suas investigações.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Uma ferramenta para coletar informações de estado baseadas em host usando consultas da The Velociraptor Query Language (VQL).

## Outros Analisadores de Registros de Eventos do Windows e Recursos Relacionados

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Ferramenta de detecção de ataques escrita em Python.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Coleção de recursos sobre Event ID úteis para Forense Digital e Resposta a Incidentes
* [Chainsaw](https://github.com/countercept/chainsaw) - Outra ferramenta de detecção de ataques baseada em sigma escrita em Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Ferramenta de detecção de ataques escrita em Powershell por [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - Visualização em grafo para registros de eventos do Windows.
* [EventList](https://github.com/miriamxyra/EventList/) - Mapeia os event IDs da baseline de segurança para o MITRE ATT&CK por [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - por [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - Parser de evtx por [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Recupera arquivos de log EVTX de espaço não alocado e imagens de memória.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Ferramenta em Python para enviar dados de Evtx para o Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Arquivos de registro de eventos de exemplo de ataques EVTX por [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Arquivos de registro de eventos de exemplo de ataques EVTX mapeados para o ATT&CK por [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - a biblioteca evtx em Rust que usamos, escrita por [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Visualizador de logs do Sysmon e do PowerShell.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Uma interface gráfica para visualizar logons e detectar movimentação lateral por [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - Guia da NSA sobre o que monitorar.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Port em Rust do DeepBlueCLI pela Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - Regras SIEM genéricas baseadas na comunidade.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - Uma VM pré-empacotada com Elastic Stack para importar dados para análise DFIR por [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Importa arquivos evtx para o Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Ferramenta de configuração e visualização off-line de logs para o Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - O melhor analisador de timeline em CSV por [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - por Steve Anson da Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - Ferramenta de detecção de ataques baseada em Sigma escrita em Python.
