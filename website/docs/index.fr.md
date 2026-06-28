---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> est un <strong>générateur rapide de chronologies forensiques</strong>
de journaux d'événements Windows et un <strong>outil de threat hunting</strong> créé par
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Écrit en Rust à sûreté mémoire, multithreadé pour la vitesse, et le seul outil open-source
prenant entièrement en charge la spécification Sigma — y compris les règles de corrélation v2.
</p>

<div class="hb-cta" markdown>
[Commencer :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Référence des commandes :material-console:](commands/index.md){ .md-button }
[Voir sur GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
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

## Pourquoi Hayabusa ?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Extrêmement rapide__

    ---

    Écrit en **Rust** à sûreté mémoire avec un multithreading complet pour analyser des montagnes
    de fichiers `.evtx` et produire une chronologie unique aussi rapidement que possible.

-   :material-shield-search:{ .lg .middle } __Prise en charge complète de Sigma__

    ---

    Le seul outil open-source prenant entièrement en charge la spécification Sigma, y compris
    les **règles de corrélation v2**, soutenu par plus de 4 000 règles de détection sélectionnées.

-   :material-timeline-clock:{ .lg .middle } __Chronologies DFIR__

    ---

    Consolide les événements d'un seul hôte ou de milliers d'hôtes en une seule chronologie forensique
    **CSV / JSON / JSONL** prête pour l'analyse.

-   :material-server-network:{ .lg .middle } __Threat hunting à l'échelle de l'entreprise__

    ---

    Exécutez en direct sur un seul système, collectez les journaux pour une analyse hors ligne, ou traquez à travers
    l'entreprise avec l'artefact Hayabusa pour **Velociraptor**.

-   :material-chart-box:{ .lg .middle } __Sortie d'analyse riche__

    ---

    Métriques, résumés de connexions, pivotement par mots-clés, rapports HTML et une chronologie de fréquence
    de détection pour faire ressortir rapidement ce qui compte.

-   :material-import:{ .lg .middle } __Bonne intégration avec d'autres outils__

    ---

    Importez les résultats directement dans **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**, ou découpez le JSON avec **jq**.

</div>

## Voir en action

![Création de chronologie DFIR avec Hayabusa](assets/doc/DFIR-TimelineCreation-EN.png)

Parcourez la galerie de [Captures d'écran](overview/screenshots.md) pour la sortie du terminal, le
résumé des résultats HTML, et l'analyse dans LibreOffice, Timeline Explorer et Timesketch.

## Liens rapides

<div class="grid cards" markdown>

-   __:material-book-open-variant: Nouveau ici ?__

    Commencez par la [Vue d'ensemble](overview/index.md), puis rendez-vous sur
    [Premiers pas](getting-started/index.md) pour télécharger et exécuter Hayabusa.

-   __:material-console-line: Vous travaillez avec la CLI ?__

    Accédez à la [Liste des commandes](commands/index.md) et à la référence par commande pour les commandes
    [Analyse](commands/analysis.md), [Configuration](commands/config.md) et
    [Chronologie DFIR](commands/dfir-timeline.md).

-   __:material-tune: Vous ajustez la sortie ?__

    Consultez les options [Profils de sortie](output/index.md), [Abréviations](output/abbreviations.md)
    et [Affichage et résumé](output/display.md).

-   __:material-puzzle: Vous voulez aller plus loin ?__

    Explorez les [Règles](rules/index.md), l'[écosystème du projet](resources/index.md)
    et comment [contribuer](resources/contributing.md).

</div>
