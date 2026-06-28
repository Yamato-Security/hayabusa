# Fonctionnalités

* Prise en charge multiplateforme : Windows, Linux, macOS.
* Développé en Rust pour être sûr en mémoire et rapide.
* Prise en charge du multithreading offrant une amélioration de la vitesse pouvant atteindre 5x.
* Crée des chronologies uniques et faciles à analyser pour les enquêtes forensiques et la réponse aux incidents.
* Chasse aux menaces basée sur des signatures IoC écrites dans des règles hayabusa basées sur YML, faciles à lire/créer/modifier.
* Prise en charge des règles Sigma pour convertir les règles sigma en règles hayabusa.
* Actuellement, il prend en charge le plus grand nombre de règles sigma comparé aux autres outils similaires et prend même en charge les règles de comptage et de nouveaux agrégateurs tels que `|equalsfield` et `|endswithfield`.
* Métriques d'ordinateurs. (Utile pour filtrer en incluant/excluant certains ordinateurs ayant un grand nombre d'événements.)
* Métriques d'Event ID. (Utile pour avoir une vue d'ensemble des types d'événements existants et pour ajuster les paramètres de vos journaux.)
* Configuration d'ajustement des règles en excluant les règles inutiles ou bruyantes.
* Cartographie des tactiques MITRE ATT&CK.
* Ajustement du niveau des règles.
* Création d'une liste de mots-clés pivots uniques pour identifier rapidement les utilisateurs, noms d'hôtes, processus anormaux, etc... ainsi que pour corréler les événements.
* Sortie de tous les champs pour des enquêtes plus approfondies.
* Résumé des connexions réussies et échouées.
* Chasse aux menaces et DFIR à l'échelle de l'entreprise sur tous les terminaux avec [Velociraptor](https://docs.velociraptor.app/).
* Sortie vers des rapports de synthèse CSV, JSON/JSONL et HTML.
* Mises à jour quotidiennes des règles Sigma.
* Prise en charge de l'entrée de journaux au format JSON.
* Normalisation des champs de journaux. (Conversion de plusieurs champs ayant des conventions de nommage différentes vers le même nom de champ.)
* Enrichissement des journaux en ajoutant des informations GeoIP (ASN, ville, pays) aux adresses IP.
* Recherche dans tous les événements de mots-clés ou d'expressions régulières.
* Mappage des données de champs. (Ex : `0xc0000234` -> `ACCOUNT LOCKED`)
* Récupération d'enregistrements evtx depuis l'espace résiduel des evtx.
* Déduplication des événements lors de la sortie. (Utile lorsque la récupération d'enregistrements est activée ou lorsque vous incluez des fichiers evtx sauvegardés, des fichiers evtx provenant de VSS, etc...)
* Assistant de configuration d'analyse pour aider à choisir plus facilement les règles à activer. (Afin de réduire les faux positifs, etc...)
* Analyse et extraction des champs des journaux classiques PowerShell.
* Faible utilisation de la mémoire. (Remarque : ceci est possible en ne triant pas les résultats. Idéal pour une exécution sur des agents ou sur de grandes quantités de données.)
* Filtrage sur les Channels et les Rules pour des performances optimales.
* Détection, extraction et décodage des chaînes Base64 trouvées dans les journaux.
* Ajustement du niveau d'alerte en fonction des systèmes critiques.
