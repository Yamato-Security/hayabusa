# Hauptziele

## Threat Hunting und unternehmensweite DFIR

Hayabusa verfügt derzeit über mehr als 4000 Sigma-Regeln und über 170 in Hayabusa integrierte Erkennungsregeln, wobei regelmäßig weitere Regeln hinzugefügt werden.
Es kann kostenlos für unternehmensweites proaktives Threat Hunting sowie für DFIR (Digital Forensics and Incident Response) mit dem [Hayabusa-Artefakt](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) von [Velociraptor](https://docs.velociraptor.app/) verwendet werden.
Durch die Kombination dieser beiden Open-Source-Tools können Sie im Wesentlichen rückwirkend ein SIEM nachbilden, wenn in der Umgebung kein SIEM eingerichtet ist.
Wie das funktioniert, erfahren Sie, indem Sie sich das Velociraptor-Walkthrough von [Eric Capuano](https://twitter.com/eric_capuano) [hier](https://www.youtube.com/watch?v=Q1IoGX--814) ansehen.

## Schnelle Erstellung forensischer Zeitachsen

Die Analyse von Windows-Ereignisprotokollen war traditionell ein sehr langwieriger und mühsamer Prozess, da Windows-Ereignisprotokolle 1) in einem Datenformat vorliegen, das schwer zu analysieren ist, und 2) der Großteil der Daten Rauschen darstellt und für Untersuchungen nicht nützlich ist.
Das Ziel von Hayabusa besteht darin, nur nützliche Daten zu extrahieren und sie in einem möglichst prägnanten, leicht lesbaren Format darzustellen, das nicht nur von professionell ausgebildeten Analysten, sondern von jedem Windows-Systemadministrator verwendet werden kann.
Hayabusa möchte es Analysten ermöglichen, 80 % ihrer Arbeit in 20 % der Zeit zu erledigen, verglichen mit der traditionellen Analyse von Windows-Ereignisprotokollen.

![DFIR-Zeitachse](../assets/doc/DFIR-TimelineCreation-EN.png)
