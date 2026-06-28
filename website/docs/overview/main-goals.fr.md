# Objectifs principaux

## Chasse aux menaces et DFIR à l'échelle de l'entreprise

Hayabusa dispose actuellement de plus de 4000 règles Sigma et de plus de 170 règles de détection intégrées à Hayabusa, et de nouvelles règles sont ajoutées régulièrement.
Il peut être utilisé pour la chasse proactive aux menaces à l'échelle de l'entreprise ainsi que pour le DFIR (Digital Forensics and Incident Response, investigation numérique et réponse aux incidents) gratuitement avec l'[artefact Hayabusa](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) de [Velociraptor](https://docs.velociraptor.app/).
En combinant ces deux outils open source, vous pouvez essentiellement reproduire rétroactivement un SIEM lorsqu'il n'y a pas de SIEM configuré dans l'environnement.
Vous pouvez apprendre comment procéder en regardant la présentation de Velociraptor par [Eric Capuano](https://twitter.com/eric_capuano) [ici](https://www.youtube.com/watch?v=Q1IoGX--814).

## Génération rapide de chronologies forensiques

L'analyse des journaux d'événements Windows a traditionnellement été un processus très long et fastidieux, car les journaux d'événements Windows sont 1) dans un format de données difficile à analyser et 2) la majorité des données sont du bruit et ne sont pas utiles pour les investigations.
L'objectif de Hayabusa est d'extraire uniquement les données utiles et de les présenter dans un format aussi concis et facile à lire que possible, utilisable non seulement par des analystes formés professionnellement mais aussi par n'importe quel administrateur système Windows.
Hayabusa espère permettre aux analystes d'accomplir 80 % de leur travail en 20 % du temps par rapport à l'analyse traditionnelle des journaux d'événements Windows.

![Chronologie DFIR](../assets/doc/DFIR-TimelineCreation-EN.png)
