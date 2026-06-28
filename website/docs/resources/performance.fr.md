# Guide de performance Rust pour les développeurs Hayabusa

# Auteur
Fukusuke Takahashi

# Traduction anglaise
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# À propos de ce document
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (en français : « faucon pèlerin ») est un outil d'analyse forensique rapide développé par le groupe [Yamato Security](https://yamatosecurity.connpass.com/) au Japon. Il est développé en [Rust](https://www.rust-lang.org/) afin de (traquer les menaces) aussi vite qu'un faucon pèlerin. Rust est en soi un langage rapide, cependant il existe de nombreux pièges qui peuvent entraîner des vitesses lentes et une consommation mémoire élevée. Nous avons créé ce document à partir d'améliorations de performance réelles dans Hayabusa (voir le [changelog ici](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), mais ces techniques devraient également s'appliquer à d'autres programmes Rust. Nous espérons que vous pourrez bénéficier des connaissances que nous avons acquises au fil de nos essais et erreurs.

# Amélioration de la vitesse
## Changer l'allocateur de mémoire
Le simple fait de changer l'allocateur de mémoire par défaut peut améliorer significativement la vitesse.
Par exemple, selon ces [benchmarks](https://github.com/rust-lang/rust-analyzer/issues/1441), les deux allocateurs de mémoire suivants

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

sont beaucoup plus rapides que l'allocateur de mémoire par défaut. Nous avons pu confirmer une amélioration significative de la vitesse en changeant notre allocateur de mémoire de jemalloc à mimalloc, c'est pourquoi nous avons fait de mimalloc l'allocateur par défaut depuis la version 1.8.0. (Bien que mimalloc utilise un peu plus de mémoire que jemalloc.)

### Avant  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### Après  <!-- omit in toc -->
Vous n'avez besoin d'effectuer que les 2 étapes suivantes pour changer l'[allocateur de mémoire](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) global :

1. Ajoutez le [crate mimalloc](https://crates.io/crates/mimalloc) à la [section [dependencies]](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) du fichier `Cargo.toml` :
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. Définissez que vous voulez utiliser mimalloc sous [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) quelque part dans le programme :
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
C'est tout ce que vous devez faire pour changer l'allocateur de mémoire.

### Efficacité（Exemple réel issu d'une Pull Request）  <!-- omit in toc -->
L'ampleur de l'amélioration de la vitesse dépendra du programme, mais dans l'exemple suivant

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

le changement de l'allocateur de mémoire pour [mimalloc](https://github.com/microsoft/mimalloc) a entraîné une augmentation de performance de 20 à 30 % sur les processeurs Intel. 
(Pour une raison quelconque, l'augmentation de performance n'était pas aussi significative sur les appareils macOS basés sur ARM.)

## Réduire le traitement IO dans les boucles
Le traitement IO disque est beaucoup plus lent que le traitement en mémoire. Par conséquent, il est souhaitable d'éviter autant que possible le traitement IO, en particulier dans les boucles.

### Avant  <!-- omit in toc -->
L'exemple ci-dessous montre une ouverture de fichier se produisant un million de fois dans une boucle :
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### Après  <!-- omit in toc -->
En ouvrant le fichier en dehors de la boucle comme suit
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
il y aura une augmentation de vitesse d'environ 1000 fois.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Dans l'exemple suivant, le traitement IO lors de la gestion d'un résultat de détection à la fois a pu être effectué en dehors de la boucle :

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

Cela a entraîné une amélioration de la vitesse d'environ 20 %.

## Éviter la compilation des expressions régulières dans les boucles
La compilation des expressions régulières est un processus très coûteux comparé à la correspondance d'expressions régulières. Par conséquent, il est conseillé d'éviter autant que possible la compilation d'expressions régulières, en particulier dans les boucles.

### Avant  <!-- omit in toc -->
Par exemple, le processus suivant crée 100 000 tentatives de correspondance d'une expression régulière dans une boucle :
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    for _ in 0..100000 {
        if Regex::new(match_str).unwrap().is_match(text){ // Regular expression compilation in a loop
            println!("matched!");
        }
    }
}
```
### Après  <!-- omit in toc -->
En effectuant une compilation d'expression régulière en dehors de la boucle, comme montré ci-dessous
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap(); // Compile the regular expression outside the loop
    for _ in 0..100000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
le code mis à jour est environ 100 fois plus rapide.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Dans l'exemple suivant, la compilation d'expression régulière est effectuée en dehors de la boucle et mise en cache.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

Cela a entraîné des améliorations significatives de la vitesse.

## Utiliser des IO avec tampon
Sans IO avec tampon, les IO de fichier sont lentes. Avec des IO avec tampon, les opérations IO sont effectuées à travers des tampons en mémoire, réduisant le nombre d'appels système et améliorant la vitesse.

### Avant  <!-- omit in toc -->
Par exemple, dans le processus suivant, [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) se produit 1 000 000 de fois.
```Rust
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let mut f = File::create("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.write(b"hello world!");
    }
}
```
### Après  <!-- omit in toc -->
En utilisant [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) comme suit
```Rust
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let mut f = File::create("sample.txt").unwrap();
    let mut writer = BufWriter::new(f);
    for _ in 0..1000000 {
        writer.write(b"some text");
    }
    writer.flush().unwrap();
}
```
il y a une amélioration de vitesse d'environ 50 fois.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
La méthode décrite ci-dessus a été implémentée ici

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

et a entraîné des améliorations significatives de la vitesse dans le traitement de sortie.

## Utiliser les méthodes String standard au lieu des expressions régulières
Bien que les expressions régulières puissent couvrir des motifs de correspondance complexes, elles sont plus lentes que les [méthodes String standard](https://doc.rust-lang.org/std/string/struct.String.html). Par conséquent, il est plus rapide d'utiliser les méthodes String standard pour des correspondances de chaînes simples telles que les suivantes.

- Correspondance commençant par（Regex : `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Correspondance se terminant par（Regex : `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Correspondance contenant（Regex : `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### Avant  <!-- omit in toc -->
Par exemple, le code suivant effectue une correspondance se terminant par dans une expression régulière un million de fois.
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = ".*abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
### Après  <!-- omit in toc -->
En utilisant [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) comme suit
```Rust
fn main() {
    let text = "1234567890";
    let match_str = "abc";
    for _ in 0..1000000 {
        if text.ends_with(match_str) {
            println!("matched!");
        }
    }
}
```
le traitement sera 10 fois plus rapide.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Comme Hayabusa nécessite une comparaison de chaînes insensible à la casse, nous utilisons [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) puis appliquons la méthode ci-dessus. Même dans ce cas, dans les exemples suivants

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

la vitesse s'est améliorée d'environ 15 % par rapport à avant.

## Filtrer par longueur de chaîne
Selon les caractéristiques des chaînes traitées, l'ajout d'un filtre simple peut réduire le nombre de tentatives de correspondance de chaînes et accélérer le processus. Si vous comparez souvent des chaînes de longueurs non fixes et non correspondantes, vous pouvez accélérer le processus en utilisant la longueur de chaîne comme filtre primaire.

### Avant  <!-- omit in toc -->
Par exemple, le code suivant tente un million de correspondances d'expressions régulières.
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if r.is_match(text) {
            println!("matched!");
        }
    }
}
```
### Après  <!-- omit in toc -->
En utilisant [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) comme filtre primaire, comme montré ci-dessous
```Rust
extern crate regex;
use regex::Regex;

fn main() {
    let text = "1234567890";
    let match_str = "abc";
    let r = Regex::new(match_str).unwrap();
    for _ in 0..1000000 {
        if text.len() == match_str.len() { // Primary filter by string length
            if r.is_match(text) {
                println!("matched!");
            }
        }
    }
}
```
la vitesse s'améliorera d'environ 20 fois.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Dans l'exemple suivant, la méthode ci-dessus est utilisée.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

Cela a amélioré la vitesse d'environ 15 %.

## Ne pas compiler avec codegen-units=1
De nombreux articles sur l'optimisation de performance avec Rust conseillent d'ajouter `codegen-units = 1` sous la section `[profile.release]`.
Cela entraînera des temps de compilation plus lents car la valeur par défaut est de compiler en parallèle, mais en théorie cela devrait produire un code plus optimisé et plus rapide.
Cependant, lors de nos tests, Hayabusa s'exécute en réalité plus lentement avec cette option activée et la compilation prend plus de temps, c'est pourquoi nous la laissons désactivée.
La taille binaire de l'exécutable est environ 100 ko plus petite, donc cela peut être idéal pour les systèmes embarqués où l'espace disque dur est limité.

# Réduire la consommation mémoire

## Éviter l'utilisation inutile de clone(), to_string() et to_owned()
Utiliser [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) ou [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) sont des moyens faciles de résoudre les erreurs de compilation liées à la [propriété (ownership)](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html). Cependant, elles entraînent généralement une consommation mémoire élevée et devraient être évitées. Il est toujours préférable de voir d'abord si vous pouvez les remplacer par des [références](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) à faible coût.

### Avant  <!-- omit in toc -->
Par exemple, si vous voulez itérer plusieurs fois sur le même `Vec`, vous pouvez utiliser [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) pour éliminer les erreurs de compilation.
```Rust
fn main() {
    let lst = vec![1, 2, 3];
    for x in lst.clone() { // In order to eliminate compile errors
        println!("{x}");
    }

    for x in lst {
        println!("{x}");
    }
}
```
### Après  <!-- omit in toc -->
Cependant, en utilisant des [références](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) comme montré ci-dessous, vous pouvez supprimer le besoin d'utiliser [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html).
```Rust
fn main() {
    let lst = vec![1, 2, 3];
    for x in &lst { // Eliminate compile errors with a reference
        println!("{x}");
    }

    for x in lst {
        println!("{x}");
    }
}
```
En supprimant l'utilisation de clone(), la consommation mémoire est réduite jusqu'à 50 %.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Dans l'exemple suivant, en remplaçant l'utilisation inutile de [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) et [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html),

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

nous avons pu réduire significativement la consommation mémoire.

## Utiliser Iterator au lieu de Vec
[Vec](https://doc.rust-lang.org/std/vec/) garde tous les éléments en mémoire, il utilise donc beaucoup de mémoire proportionnellement au nombre d'éléments. Si le traitement d'un élément à la fois est suffisant, alors utiliser un [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) à la place utilisera beaucoup moins de mémoire.

### Avant  <!-- omit in toc -->
Par exemple, la fonction `return_lines()` suivante lit un fichier d'environ 1 Go et retourne un [Vec](https://doc.rust-lang.org/std/vec/) :
```Rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn return_lines() -> Vec<String> {
    let f = File::open("sample.txt").unwrap();
    let buf = BufReader::new(f);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn main() {
    let lines = return_lines();
    for line in lines {
        println!("{}", line)
    }
}
```
### Après  <!-- omit in toc -->
À la place, vous devriez retourner un [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) comme suit :
```Rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn return_lines() -> impl Iterator<Item=String> {
    let f = File::open("sample.txt").unwrap();
    let buf = BufReader::new(f);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        // ここでcollect()せずに、Iteratorを戻り値として返す
}

fn main() {
    let lines = return_lines();
    for line in lines {
        println!("{}", line)
    }
}
```
Ou si le type diffère selon la branche empruntée, vous pouvez retourner un `Box<dyn Iterator<Item = T>>` comme suit :
```Rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn return_lines(need_filter:bool) -> Box<dyn Iterator<Item = String>> {
    let f = File::open("sample.txt").unwrap();
    let buf = BufReader::new(f);
    if need_filter {
        let result= buf.lines()
            .filter_map(|l| l.ok())
            .map(|l| l.replace("A", "B"));
        return Box::new(result)
    }
    let result= buf.lines()
        .map(|l| l.expect("Could not parse line"));
    Box::new(result)
}

fn main() {
    let lines = return_lines(true);
    for line in lines {
        println!("{}", line)
    }
}
```
La consommation mémoire chute significativement de 1 Go à seulement 3 Mo.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
L'exemple suivant utilise la méthode décrite ci-dessus :

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

Lors d'un test sur un fichier JSON de 1,7 Go, la mémoire a diminué de 75 %.

## Utiliser le crate compact_str pour gérer les chaînes courtes
Lorsque vous traitez un grand nombre de chaînes courtes de moins de 24 octets, le [crate compact_str](https://docs.rs/crate/compact_str/latest) peut être utilisé pour réduire la consommation mémoire.

### Avant  <!-- omit in toc -->
Dans l'exemple ci-dessous, le Vec contient 10 millions de chaînes.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### Après  <!-- omit in toc -->
Il est préférable de les remplacer par un [CompactString](https://docs.rs/compact_str/latest/compact_str/) :
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
En faisant cela, la consommation mémoire est réduite d'environ 50 %.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Dans l'exemple suivant, les chaînes courtes sont gérées avec [CompactString](https://docs.rs/compact_str/latest/compact_str/) :

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

Cela a donné une réduction de la consommation mémoire d'environ 20 %.

## Supprimer les champs inutiles dans les structures à longue durée de vie
Les structures qui continuent d'être conservées en mémoire pendant le démarrage du processus peuvent affecter la consommation mémoire globale. Dans Hayabusa, les structures suivantes (à partir de la version 2.2.2), en particulier, sont conservées en grand nombre.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

La suppression des champs associés aux structures ci-dessus a eu un certain effet sur la réduction de la consommation mémoire globale.

### Avant  <!-- omit in toc -->
Par exemple, le champ `DetectInfo` était, jusqu'à la version 1.8.1, le suivant :
```Rust
#[derive(Debug, Clone)]
pub struct DetectInfo {
    pub rulepath: CompactString,
    pub ruletitle: CompactString,
    pub level: CompactString,
    pub computername: CompactString,
    pub eventid: CompactString,
    pub detail: CompactString,
    pub record_information: CompactString,
    pub ext_field: Vec<(CompactString, Profile)>,
    pub is_condition: bool,
}
```
### Après  <!-- omit in toc -->
En supprimant le champ `record_information` comme suit
```Rust
#[derive(Debug, Clone)]
pub struct DetectInfo {
    pub rulepath: CompactString,
    pub ruletitle: CompactString,
    pub level: CompactString,
    pub computername: CompactString,
    pub eventid: CompactString,
    pub detail: CompactString,
    // remove record_information field
    pub ext_field: Vec<(CompactString, Profile)>,
    pub is_condition: bool,
}
```
une réduction de la consommation mémoire de plusieurs octets par enregistrement de résultat de détection a été obtenue.

### Efficacité（Exemple réel issu d'une Pull Request）   <!-- omit in toc -->
Dans l'exemple suivant, lors d'un test sur des données où le nombre d'enregistrements de résultats de détection était d'environ 1,5 million,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

nous avons pu obtenir une réduction de la consommation mémoire d'environ 300 Mo.

# Benchmarking
## Utiliser la fonction de statistiques de l'allocateur de mémoire.
Certains allocateurs de mémoire maintiennent leurs propres statistiques de consommation mémoire. Par exemple, dans [mimalloc](https://github.com/microsoft/mimalloc), la fonction [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) peut être appelée pour obtenir la consommation mémoire.

### Comment obtenir les statistiques  <!-- omit in toc -->
Prérequis : Vous devez utiliser mimalloc comme expliqué dans la section [Changer l'allocateur de mémoire](#change-the-memory-allocator).

1.  Dans la [section dependencies](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) de `Cargo.toml`, ajoutez le [crate libmimalloc-sys](https://crates.io/crates/libmimalloc-sys) :
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. Chaque fois que vous voulez afficher les statistiques de consommation mémoire, écrivez le code suivant et, à l'intérieur d'un bloc `unsafe`, appelez [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79). Les statistiques de consommation mémoire seront affichées sur la sortie standard.
    ```Rust
    use libmimalloc_sys::mi_stats_print_out;
    use std::ptr::null_mut;
    
    fn main() {
      
      // Write the following code where you want to measure memory usage
      unsafe {
            mi_stats_print_out(None, null_mut());
      }
    }
    ```
3. La valeur `peak/reserved` en haut à gauche correspond à la consommation mémoire maximale. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### Exemple   <!-- omit in toc -->
L'implémentation ci-dessus a été appliquée dans ce qui suit :

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

Dans Hayabusa, si vous ajoutez l'option `--debug`, les statistiques de consommation mémoire seront affichées à la fin.

## Utiliser le compteur de performance de Windows
Diverses utilisations de ressources peuvent être vérifiées à partir des statistiques que l'on peut obtenir du côté du système d'exploitation. Dans ce cas, les deux points suivants doivent être notés.

- Influence du logiciel antivirus (Windows Defender)
  - Seule la première exécution est affectée par l'analyse et est plus lente, donc les résultats de la deuxième exécution et des suivantes après la compilation conviennent pour la comparaison. (Ou vous pouvez désactiver votre antivirus pour des résultats plus précis.)
- Influence de la mise en cache des fichiers
  - Les résultats de la deuxième fois et des suivantes après le démarrage du système d'exploitation sont plus rapides que la première fois, car les evtx et autres IO de fichiers sont lus depuis le cache de fichiers en mémoire, donc les résultats de la première fois après le démarrage du système d'exploitation sont plus idéaux pour effectuer des benchmarks.

### Comment obtenir  <!-- omit in toc -->
Prérequis：La procédure suivante n'est valide que pour les environnements où `PowerShell 7` est déjà installé sur Windows.

1. Redémarrez le système d'exploitation
2. Exécutez la [commande Get-Counter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) de `PowerShell 7` qui enregistrera en continu le compteur de performance chaque seconde dans un fichier CSV. (Si vous souhaitez mesurer des ressources autres que celles listées ci-dessous, [cet article](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) est une bonne référence.)
    ```PowerShell
    Get-Counter -Counter "\Memory\Available MBytes",  "\Processor(_Total)\% Processor Time" -Continuous | ForEach {
         $_.CounterSamples | ForEach {
             [pscustomobject]@{
                 TimeStamp = $_.TimeStamp
                 Path = $_.Path
                 Value = $_.CookedValue
             }
         }
     } | Export-Csv -Path PerfMonCounters.csv -NoTypeInformation
    ```
3. Exécutez le processus que vous voulez mesurer.

### Exemple  <!-- omit in toc -->
Ce qui suit contient un exemple de procédure pour mesurer la performance avec Hayabusa.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## Utiliser heaptrack
[heaptrack](https://github.com/KDE/heaptrack) est un profileur de mémoire sophistiqué disponible pour Linux et macOS. En utilisant heaptrack, vous pouvez étudier en profondeur les goulots d'étranglement.

### Comment obtenir  <!-- omit in toc -->
Prérequis : Ci-dessous se trouve la procédure pour Ubuntu 22.04. Vous ne pouvez pas utiliser heaptrack sur Windows.

1. Installez heaptrack avec les deux commandes suivantes.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Supprimez le code mimalloc suivant de Hayabusa. (Vous ne pouvez pas utiliser le profileur de mémoire de heaptrack avec mimalloc.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Supprimez la [section [profile.release]](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) dans le fichier `Cargo.toml` de Hayabusa et changez-la comme suit :
     ```
     [profile.release]
     debug = true
     ```

4. Construisez une version release : `cargo build --release`
5. Exécutez `heaptrack hayabusa csv-timeline -d sample -o out.csv`

Maintenant, lorsque Hayabusa termine son exécution, les résultats de heaptrack s'ouvriront automatiquement dans une application GUI.

### Exemples  <!-- omit in toc -->
Un exemple des résultats de heaptrack est montré ci-dessous. Les onglets `Flame Graph` et `Top-Down` vous permettent de vérifier visuellement les fonctions à forte consommation mémoire.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# Références

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# Contributions

Ce document est basé sur les conclusions tirées de cas d'amélioration réels dans [Hayabusa](https://github.com/Yamato-Security/hayabusa). Si vous trouvez des erreurs ou des techniques qui peuvent améliorer la performance, veuillez nous envoyer une issue ou une pull request.
