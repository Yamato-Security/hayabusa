# Projets et écosystème

## Projets associés

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Documentation et scripts pour activer correctement les journaux d'événements Windows.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Identique au dépôt Hayabusa Rules, mais les règles et les fichiers de configuration sont stockés dans un seul fichier et passés par XOR afin d'éviter les faux positifs des antivirus.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Règles de détection Hayabusa et règles Sigma sélectionnées utilisées par Hayabusa.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - Un fork mieux maintenu de la crate `evtx`.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Exemples de fichiers evtx à utiliser pour tester les règles de détection hayabusa/sigma.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Présentations issues de conférences que nous avons données sur nos outils et ressources.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Transforme les règles Sigma basées sur les journaux d'événements Windows en amont sous une forme plus facile à utiliser.
* [Takajo](https://github.com/Yamato-Security/takajo) - Un analyseur pour les résultats de hayabusa.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - Un analyseur de journaux d'événements Windows écrit en PowerShell. (Obsolète et remplacé par Takajo.)

## Projets tiers utilisant Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Un workflow NodeRED qui importe les résultats de Plaso et Hayabusa dans Timesketch.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - Fournit des outils et une infrastructure de sécurité basés sur le cloud, adaptés à vos besoins. 
* [OpenRelik](https://openrelik.org/) - Une plateforme open source (Apache-2.0) conçue pour faciliter les investigations forensiques numériques collaboratives.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Déployez rapidement une instance splunk avec Docker pour parcourir les journaux et les sorties d'outils pendant vos investigations.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Un outil de collecte d'informations d'état basées sur l'hôte à l'aide de requêtes The Velociraptor Query Language (VQL).

## Autres analyseurs de journaux d'événements Windows et ressources connexes

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Outil de détection d'attaques écrit en Python.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Collection de ressources sur les Event ID utiles pour la criminalistique numérique et la réponse aux incidents
* [Chainsaw](https://github.com/countercept/chainsaw) - Un autre outil de détection d'attaques basé sur sigma écrit en Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Outil de détection d'attaques écrit en Powershell par [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - Visualisation graphique des journaux d'événements Windows.
* [EventList](https://github.com/miriamxyra/EventList/) - Met en correspondance les ID d'événements de référence de sécurité avec MITRE ATT&CK par [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - par [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - Analyseur Evtx par [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Récupère les fichiers journaux EVTX à partir de l'espace non alloué et des images mémoire.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Outil Python pour envoyer des données Evtx vers Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Exemples de fichiers journaux d'événements d'attaque EVTX par [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - Exemples de fichiers journaux d'événements d'attaque EVTX mis en correspondance avec ATT&CK par [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - la bibliothèque evtx en Rust que nous utilisons, écrite par [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Visualiseur de journaux Sysmon et PowerShell.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Une interface graphique pour visualiser les connexions afin de détecter les déplacements latéraux par [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - Le guide de la NSA sur ce qu'il faut surveiller.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Portage en Rust de DeepBlueCLI par Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - Règles SIEM génériques basées sur la communauté.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - Une VM préconfigurée avec Elastic Stack pour importer des données à des fins d'analyse DFIR par [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Importe des fichiers evtx dans Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Outil de configuration et de visualisation hors ligne des journaux pour Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - Le meilleur analyseur de chronologie CSV par [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - par Steve Anson de Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - Outil de détection d'attaques basé sur Sigma écrit en Python.
