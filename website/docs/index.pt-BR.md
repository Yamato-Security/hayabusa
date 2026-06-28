---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
O <strong>Hayabusa</strong> é um <strong>gerador rápido de linha do tempo forense</strong> de registros de eventos do Windows
e uma <strong>ferramenta de caça a ameaças</strong> criada pela
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Escrito em Rust com segurança de memória, multithread para velocidade, e a única ferramenta de código aberto
com suporte completo à especificação Sigma — incluindo regras de correlação v2.
</p>

<div class="hb-cta" markdown>
[Começar :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Referência de Comandos :material-console:](commands/index.md){ .md-button }
[Ver no GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
</p>

</div>

---

## Por que o Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Extremamente rápido__

    ---

    Escrito em **Rust** com segurança de memória e multithreading completo para analisar montanhas
    de arquivos `.evtx` e produzir uma única linha do tempo o mais rápido possível.

-   :material-shield-search:{ .lg .middle } __Suporte completo ao Sigma__

    ---

    A única ferramenta de código aberto com suporte completo à especificação Sigma, incluindo
    **regras de correlação v2**, respaldada por mais de 4.000 regras de detecção selecionadas.

-   :material-timeline-clock:{ .lg .middle } __Linhas do tempo de DFIR__

    ---

    Consolida eventos de um host ou de milhares em uma única linha do tempo forense
    **CSV / JSON / JSONL** pronta para análise.

-   :material-server-network:{ .lg .middle } __Caça em toda a empresa__

    ---

    Execute ao vivo em um único sistema, colete registros para análise offline ou faça a caça em
    toda a empresa com o artefato Hayabusa do **Velociraptor**.

-   :material-chart-box:{ .lg .middle } __Saída de análise rica__

    ---

    Métricas, resumos de logon, pivoteamento por palavras-chave, relatórios HTML e uma linha do tempo
    de frequência de detecções para destacar rapidamente o que importa.

-   :material-import:{ .lg .middle } __Integra bem com outras ferramentas__

    ---

    Importe os resultados diretamente para o **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**, ou fatie o JSON com o **jq**.

</div>

## Veja em ação

![Criação de linha do tempo de DFIR do Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

Navegue pela galeria de [Capturas de tela](overview/screenshots.md) para ver a saída do terminal, o
resumo de resultados em HTML e a análise no LibreOffice, no Timeline Explorer e no Timesketch.

## Links rápidos

<div class="grid cards" markdown>

-   __:material-book-open-variant: Novo por aqui?__

    Comece com a [Visão geral](overview/index.md), depois vá para
    [Começar](getting-started/index.md) para baixar e executar o Hayabusa.

-   __:material-console-line: Trabalhando com a CLI?__

    Vá direto para a [Lista de comandos](commands/index.md) e para a referência por comando de
    [Análise](commands/analysis.md), [Configuração](commands/config.md) e
    [Linha do tempo de DFIR](commands/dfir-timeline.md).

-   __:material-tune: Ajustando a saída?__

    Veja [Perfis de saída](output/index.md), [Abreviações](output/abbreviations.md)
    e opções de [Exibição e resumo](output/display.md).

-   __:material-puzzle: Indo além?__

    Explore as [Regras](rules/index.md), o [ecossistema do projeto](resources/index.md)
    e como [contribuir](resources/contributing.md).

</div>
