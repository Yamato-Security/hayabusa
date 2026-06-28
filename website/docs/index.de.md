---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong> ist ein <strong>schneller forensischer Timeline-Generator</strong> für Windows-Ereignisprotokolle
und ein <strong>Threat-Hunting-Tool</strong>, erstellt von
<a href="https://yamatosecurity.connpass.com/">Yamato Security</a>.
Geschrieben in speichersicherem Rust, für hohe Geschwindigkeit mehrfädig ausgelegt und das einzige Open-Source-Tool
mit vollständiger Unterstützung der Sigma-Spezifikation — einschließlich der v2-Korrelationsregeln.
</p>

<div class="hb-cta" markdown>
[Erste Schritte :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Befehlsreferenz :material-console:](commands/index.md){ .md-button }
[Auf GitHub ansehen :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
</p>

</div>

---

## Warum Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Blitzschnell__

    ---

    Geschrieben in speichersicherem **Rust** mit vollständigem Multithreading, um Berge
    von `.evtx`-Dateien zu parsen und so schnell wie möglich eine einzige Timeline zu erzeugen.

-   :material-shield-search:{ .lg .middle } __Vollständige Sigma-Unterstützung__

    ---

    Das einzige Open-Source-Tool mit vollständiger Unterstützung der Sigma-Spezifikation, einschließlich
    der **v2-Korrelationsregeln**, gestützt auf über 4.000 kuratierte Erkennungsregeln.

-   :material-timeline-clock:{ .lg .middle } __DFIR-Timelines__

    ---

    Konsolidiert Ereignisse von einem Host oder Tausenden zu einer einzigen forensischen
    **CSV-/JSON-/JSONL**-Timeline, die zur Analyse bereitsteht.

-   :material-server-network:{ .lg .middle } __Unternehmensweites Hunting__

    ---

    Live auf einem einzelnen System ausführen, Protokolle zur Offline-Analyse sammeln oder unternehmensweit
    mit dem **Velociraptor**-Hayabusa-Artefakt jagen.

-   :material-chart-box:{ .lg .middle } __Umfangreiche Analyseausgabe__

    ---

    Metriken, Anmeldungszusammenfassungen, Stichwort-Pivoting, HTML-Berichte und eine Erkennungs-
    häufigkeits-Timeline, um das Wesentliche schnell sichtbar zu machen.

-   :material-import:{ .lg .middle } __Spielt gut mit anderen zusammen__

    ---

    Importiere Ergebnisse direkt in **Elastic Stack**, **Timesketch**, **Timeline
    Explorer** oder zerlege JSON mit **jq**.

</div>

## In Aktion erleben

![Hayabusa DFIR-Timeline-Erstellung](assets/doc/DFIR-TimelineCreation-EN.png)

Durchstöbere die [Screenshots](overview/screenshots.md)-Galerie für Terminalausgaben, die
HTML-Ergebniszusammenfassung und Analysen in LibreOffice, Timeline Explorer und Timesketch.

## Schnellzugriffe

<div class="grid cards" markdown>

-   __:material-book-open-variant: Neu hier?__

    Beginne mit der [Übersicht](overview/index.md) und gehe dann zu
    [Erste Schritte](getting-started/index.md), um Hayabusa herunterzuladen und auszuführen.

-   __:material-console-line: Arbeitest du mit der CLI?__

    Springe zur [Befehlsliste](commands/index.md) und zur Referenz der einzelnen Befehle für
    [Analyse](commands/analysis.md), [Konfiguration](commands/config.md) und
    [DFIR-Timeline](commands/dfir-timeline.md)-Befehle.

-   __:material-tune: Ausgabe abstimmen?__

    Siehe [Ausgabeprofile](output/index.md), [Abkürzungen](output/abbreviations.md)
    und [Anzeige & Zusammenfassung](output/display.md)-Optionen.

-   __:material-puzzle: Noch tiefer einsteigen?__

    Erkunde die [Regeln](rules/index.md), das [Projekt-Ökosystem](resources/index.md)
    und wie du [beitragen](resources/contributing.md) kannst.

</div>
