# Téléchargements

Veuillez télécharger la dernière version stable de Hayabusa avec les binaires compilés ou compiler le code source depuis la page [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Nous fournissons des binaires pour les architectures suivantes :

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [Pour une raison quelconque, le binaire Linux ARM MUSL ne fonctionne pas correctement](https://github.com/Yamato-Security/hayabusa/issues/1332), nous ne fournissons donc pas ce binaire. Cela échappe à notre contrôle, nous prévoyons donc de le fournir à l'avenir une fois le problème résolu.

## Packages de réponse en direct pour Windows

Depuis la v2.18.0, nous fournissons des packages Windows spéciaux qui utilisent des règles encodées en XOR fournies dans un seul fichier ainsi que tous les fichiers de configuration combinés en un seul fichier (hébergés sur le [dépôt hayabusa-encoded-rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Téléchargez simplement les packages zip dont le nom contient `live-response`.
Les fichiers zip incluent seulement trois fichiers : le binaire Hayabusa, le fichier de règles encodées en XOR et le fichier de configuration.
Le but de ces packages de réponse en direct est, lors de l'exécution de Hayabusa sur les endpoints clients, de s'assurer que les antivirus comme Windows Defender ne génèrent pas de faux positifs sur les fichiers de règles `.yml`.
De plus, nous voulons minimiser la quantité de fichiers écrits sur le système afin que les artefacts forensiques comme le USN Journal ne soient pas écrasés.
