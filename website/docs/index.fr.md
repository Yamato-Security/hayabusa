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
