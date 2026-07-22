# Guia de Performance em Rust para Desenvolvedores do Hayabusa

# Autor
Fukusuke Takahashi

# Tradução para o inglês
Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity))

# Sobre este documento
O [Hayabusa](https://github.com/Yamato-Security/hayabusa) (em inglês: "peregrine falcon", o falcão-peregrino) é uma ferramenta rápida de análise forense desenvolvida pelo grupo [Yamato Security](https://yamatosecurity.connpass.com/) no Japão. Ele é desenvolvido em [Rust](https://www.rust-lang.org/) para caçar (ameaças) tão rápido quanto um falcão-peregrino. Rust é, por si só, uma linguagem rápida, porém existem muitas armadilhas que podem resultar em baixa velocidade e alto uso de memória. Criamos este documento com base em melhorias de performance reais no Hayabusa (veja o [changelog aqui](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md)), mas essas técnicas também devem ser aplicáveis a outros programas em Rust. Esperamos que você possa se beneficiar do conhecimento que adquirimos por meio de nossa tentativa e erro.

# Melhoria de velocidade
## Troque o alocador de memória
Simplesmente trocar o alocador de memória padrão pode melhorar a velocidade significativamente.
Por exemplo, de acordo com estes [benchmarks](https://github.com/rust-lang/rust-analyzer/issues/1441), os dois alocadores de memória a seguir

- [mimalloc](https://microsoft.github.io/mimalloc/)
- [jemalloc](https://jemalloc.net/)

são muito mais rápidos que o alocador de memória padrão. Conseguimos confirmar uma melhoria significativa de velocidade ao trocar nosso alocador de memória de jemalloc para mimalloc, então tornamos o mimalloc o padrão desde a versão 1.8.0. (Embora o mimalloc use um pouco mais de memória que o jemalloc.)

### Antes  <!-- omit in toc -->
```
# Not applicable. (You do not need to declare anything to use the default memory allocator.)
```
### Depois  <!-- omit in toc -->
Você só precisa realizar os 2 passos a seguir para trocar o [alocador de memória](https://doc.rust-lang.org/stable/std/alloc/trait.GlobalAlloc.html) global:

1. Adicione o [crate mimalloc](https://crates.io/crates/mimalloc) à [seção [dependencies]](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency) do arquivo `Cargo.toml`:
    ```Toml
    [dependencies]
    mimalloc = { version = "*", default-features = false }
    ```
2. Defina que você quer usar o mimalloc sob [#[global_allocator]](https://doc.rust-lang.org/std/alloc/index.html#the-global_allocator-attribute) em algum lugar do programa:
    ```Rust
    use mimalloc::MiMalloc;
    
    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
    ```
Isso é tudo o que você precisa fazer para trocar o alocador de memória.

### Eficácia（Exemplo real de um Pull Request）  <!-- omit in toc -->
O quanto a velocidade melhora vai depender do programa, mas no exemplo a seguir

- [chg: build.rs(for vc runtime) to rustflags in config.toml and replace default global memory allocator with mimalloc. #777](https://github.com/Yamato-Security/hayabusa/pull/777)

trocar o alocador de memória para [mimalloc](https://github.com/microsoft/mimalloc) resultou em um aumento de performance de 20-30% em CPUs Intel. 
(Por algum motivo, não houve um aumento de performance tão significativo em dispositivos macOS baseados em ARM.)

## Reduza o processamento de IO em loops
O processamento de IO em disco é muito mais lento que o processamento em memória. Portanto, é desejável evitar o processamento de IO o máximo possível, especialmente em loops.

### Antes  <!-- omit in toc -->
O exemplo abaixo mostra a abertura de um arquivo ocorrendo um milhão de vezes em um loop:
```Rust
use std::fs;

fn main() {
    for _ in 0..1000000 {
        let f = fs::read_to_string("sample.txt").unwrap();
        f.len();
    }
}
```
### Depois  <!-- omit in toc -->
Ao abrir o arquivo fora do loop, da seguinte forma
```Rust
use std::fs;

fn main() {
    let f = fs::read_to_string("sample.txt").unwrap();
    for _ in 0..1000000 {
        f.len();
    }
}
```
haverá um aumento de velocidade de cerca de 1000 vezes.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
No exemplo a seguir, o processamento de IO ao lidar com um resultado de detecção por vez pôde ser realizado fora do loop:

- [Improve speed by removing IO process before insert_message() #858](https://github.com/Yamato-Security/hayabusa/pull/858)

Isso resultou em uma melhoria de velocidade de cerca de 20%.

## Evite a compilação de expressões regulares em loops
A compilação de expressões regulares é um processo muito custoso comparado à correspondência de expressões regulares. Portanto, é aconselhável evitar a compilação de expressões regulares o máximo possível, especialmente em loops.

### Antes  <!-- omit in toc -->
Por exemplo, o processo a seguir cria 100.000 tentativas de correspondência de uma expressão regular em um loop:
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
### Depois  <!-- omit in toc -->
Ao fazer a compilação da expressão regular fora do loop, como mostrado abaixo
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
o código atualizado fica cerca de 100 vezes mais rápido.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
No exemplo a seguir, a compilação de expressões regulares é realizada fora do loop e armazenada em cache.

- [cache regex for allowlist and regexes keyword. #174](https://github.com/Yamato-Security/hayabusa/pull/174)

Isso resultou em melhorias significativas de velocidade.

## Use IO com buffer
Sem IO com buffer, o IO de arquivos é lento. Com IO com buffer, as operações de IO são realizadas por meio de buffers em memória, reduzindo o número de chamadas de sistema e melhorando a velocidade.

### Antes  <!-- omit in toc -->
Por exemplo, no processo a seguir, o [write](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write) ocorre 1.000.000 de vezes.
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
### Depois  <!-- omit in toc -->
Ao usar o [BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html) da seguinte forma
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
há uma melhoria de velocidade de cerca de 50 vezes.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
O método descrito acima foi implementado aqui

- [Feature/improve output#253 #285](https://github.com/Yamato-Security/hayabusa/pull/285)

e resultou em melhorias significativas de velocidade no processamento de saída.

## Use métodos padrão de String em vez de expressões regulares
Embora as expressões regulares possam cobrir padrões de correspondência complexos, elas são mais lentas que os [métodos padrão de String](https://doc.rust-lang.org/std/string/struct.String.html). Portanto, é mais rápido usar métodos padrão de String para correspondências simples de strings, como as seguintes.

- Correspondência por início（Regex: `foo.*`）-> [String::starts_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.starts_with)
- Correspondência por fim（Regex: `.*foo`）-> [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with)
- Correspondência por conteúdo（Regex: `.*foo.*`）-> [String::contains()](https://doc.rust-lang.org/std/string/struct.String.html#method.contains)

### Antes  <!-- omit in toc -->
Por exemplo, o código a seguir realiza uma correspondência por fim com uma expressão regular um milhão de vezes.
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
### Depois  <!-- omit in toc -->
Ao usar o [String::ends_with()](https://doc.rust-lang.org/std/string/struct.String.html#method.ends_with) da seguinte forma
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
o processamento ficará 10 vezes mais rápido.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
Como o Hayabusa requer comparação de strings sem diferenciação entre maiúsculas e minúsculas, usamos o [to_lowercase()](https://doc.rust-lang.org/std/string/struct.String.html#method.to_lowercase) e então aplicamos o método acima. Mesmo assim, nos exemplos a seguir

- [Imporving speed by changing wildcard search process from regular expression match to starts_with/ends_with match #890](https://github.com/Yamato-Security/hayabusa/pull/890)
- [Improving speed by using eq_ignore_ascii_case() before regular expression match #884](https://github.com/Yamato-Security/hayabusa/pull/884)

a velocidade melhorou cerca de 15% em comparação com antes.

## Filtre por tamanho da string
Dependendo das características das strings sendo manipuladas, adicionar um filtro simples pode reduzir o número de tentativas de correspondência de strings e acelerar o processo. Se você frequentemente compara strings de tamanhos não fixos e não correspondentes, pode acelerar o processo usando o tamanho da string como filtro primário.

### Antes  <!-- omit in toc -->
Por exemplo, o código a seguir tenta um milhão de correspondências de expressões regulares.
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
### Depois  <!-- omit in toc -->
Ao usar o [String::len()](https://doc.rust-lang.org/std/string/struct.String.html#method.len) como filtro primário, como mostrado abaixo
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
a velocidade melhorará cerca de 20 vezes.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
No exemplo a seguir, o método acima é usado.

- [Improving speed by adding string length match before regular expression match #883](https://github.com/Yamato-Security/hayabusa/pull/883)

Isso melhorou a velocidade em cerca de 15%.

## Não compile com codegen-units=1
Muitos artigos sobre otimização de performance com Rust aconselham adicionar `codegen-units = 1` sob a seção `[profile.release]`.
Isso causará tempos de compilação mais lentos, já que o padrão é compilar em paralelo, mas em teoria deveria resultar em um código mais otimizado e rápido.
No entanto, em nossos testes, o Hayabusa na verdade roda mais devagar com essa opção ativada e a compilação demora mais, então mantemos isso desativado.
O tamanho do binário do executável fica cerca de 100kb menor, então isso pode ser ideal para sistemas embarcados onde o espaço em disco é limitado.

# Reduzindo o uso de memória

## Evite o uso desnecessário de clone(), to_string() e to_owned()
Usar [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) ou [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) são maneiras fáceis de resolver erros de compilação relacionados a [ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html). No entanto, eles geralmente resultam em alto uso de memória e devem ser evitados. É sempre melhor primeiro ver se você consegue substituí-los por [referências](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) de baixo custo.

### Antes  <!-- omit in toc -->
Por exemplo, se você quiser iterar o mesmo `Vec` várias vezes, pode usar o [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html) para eliminar erros de compilação.
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
### Depois  <!-- omit in toc -->
No entanto, ao usar [referências](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html) como mostrado abaixo, você pode eliminar a necessidade de usar o [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html).
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
Ao remover o uso de clone(), o uso de memória é reduzido em até 50%.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
No exemplo a seguir, ao substituir o uso desnecessário de [clone()](https://doc.rust-lang.org/std/clone/trait.Clone.html), [to_string()](https://doc.rust-lang.org/std/string/trait.ToString.html) e [to_owned()](https://doc.rust-lang.org/std/borrow/trait.ToOwned.html),

- [Reduce used memory and Skipped rule author, detect counts aggregation when --no-summary option is used #782](https://github.com/Yamato-Security/hayabusa/pull/782)

conseguimos reduzir significativamente o uso de memória.

## Use Iterator em vez de Vec
O [Vec](https://doc.rust-lang.org/std/vec/) mantém todos os elementos em memória, então usa muita memória em proporção ao número de elementos. Se processar um elemento por vez for suficiente, então usar um [Iterator](https://doc.rust-lang.org/std/iter/trait.Iterator.html) em vez disso usará muito menos memória.

### Antes  <!-- omit in toc -->
Por exemplo, a função `return_lines()` a seguir lê um arquivo de cerca de 1 GB e retorna um [Vec](https://doc.rust-lang.org/std/vec/):
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
### Depois  <!-- omit in toc -->
Em vez disso, você deve retornar um [Iterator Trait](https://doc.rust-lang.org/std/iter/trait.Iterator.html) da seguinte forma:
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
Ou se o tipo for diferente dependendo de qual ramo for tomado, você pode retornar um `Box<dyn Iterator<Item = T>>` da seguinte forma:
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
O uso de memória cai significativamente de 1 GB para apenas 3 MB.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
O exemplo a seguir usa o método descrito acima:

- [Reduce memory usage when reading JSONL file #921](https://github.com/Yamato-Security/hayabusa/pull/921)

Quando testado em um arquivo JSON de 1.7GB, a memória diminuiu em 75%.

## Use o crate compact_str ao lidar com strings curtas
Ao lidar com um grande número de strings curtas de menos de 24 bytes, o [crate compact_str](https://docs.rs/crate/compact_str/latest) pode ser usado para reduzir o uso de memória.

### Antes  <!-- omit in toc -->
No exemplo abaixo, o Vec armazena 10 milhões de strings.
```Rust
fn main() {
    let v: Vec<String> = vec![String::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
### Depois  <!-- omit in toc -->
É melhor substituí-las por uma [CompactString](https://docs.rs/compact_str/latest/compact_str/):
```Rust
use compact_str::CompactString;

fn main() {
    let v: Vec<CompactString> = vec![CompactString::from("ABCDEFGHIJKLMNOPQRSTUV"); 10000000];
    // do some kind of processing
}
```
Ao fazer isso, o uso de memória é reduzido em cerca de 50%.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
No exemplo a seguir, strings curtas são manipuladas com a [CompactString](https://docs.rs/compact_str/latest/compact_str/):

- [To reduce ram usage and performance, Replaced String with other crate #793](https://github.com/Yamato-Security/hayabusa/pull/793)

Isso proporcionou uma redução de uso de memória de cerca de 20%.

## Exclua campos desnecessários em estruturas de longa duração
Estruturas que continuam retidas em memória durante a execução do processo podem afetar o uso geral de memória. No Hayabusa, as estruturas a seguir (na versão 2.2.2), em particular, são retidas em grande quantidade.

- [DetectInfo](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/message.rs#L27-L36)
- [LeafSelectNode](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/detections/rule/selectionnodes.rs#L234-L239)

A remoção de campos associados às estruturas acima teve algum efeito na redução do uso geral de memória.

### Antes  <!-- omit in toc -->
Por exemplo, o campo `DetectInfo` era, até a versão 1.8.1, o seguinte:
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
### Depois  <!-- omit in toc -->
Ao excluir o campo `record_information` da seguinte forma
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
foi alcançada uma redução de uso de memória de vários bytes por registro de resultado de detecção.

### Eficácia（Exemplo real de um Pull Request）   <!-- omit in toc -->
No exemplo a seguir, quando testado com dados onde o número de registros de resultado de detecção era de cerca de 1,5 milhão,

- [Reduced memory usage of DetectInfo/EvtxRecordInfo #837](https://github.com/Yamato-Security/hayabusa/pull/837)
- [Reduce memory usage by removing unnecessary regex #894](https://github.com/Yamato-Security/hayabusa/pull/894)

conseguimos alcançar uma redução de cerca de 300MB no uso de memória.

# Benchmarking
## Use a função de estatísticas do alocador de memória.
Alguns alocadores de memória mantêm suas próprias estatísticas de uso de memória. Por exemplo, no [mimalloc](https://github.com/microsoft/mimalloc), a função [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79) pode ser chamada para obter o uso de memória.

### Como obter estatísticas  <!-- omit in toc -->
Pré-requisitos: Você precisa estar usando o mimalloc conforme explicado na seção [Troque o alocador de memória](#change-the-memory-allocator).

1.  No `Cargo.toml`, [seção dependencies](https://doc.rust-lang.org/cargo/guide/dependencies.html#adding-a-dependency), adicione o [crate libmimalloc-sys](https://crates.io/crates/libmimalloc-sys):
    ```Toml
    [dependencies]
    libmimalloc-sys = { version = "*",  features = ["extended"] }
    ```
2. Sempre que você quiser imprimir as estatísticas de uso de memória, escreva o código a seguir e, dentro de um bloco `unsafe`, chame a [mi_stats_print_out()](https://microsoft.github.io/mimalloc/group__extended.html#ga537f13b299ddf801e49a5a94fde02c79). As estatísticas de uso de memória serão enviadas para a saída padrão.
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
3. O valor `peak/reserved` no canto superior esquerdo é o uso máximo de memória. 

    ![mimalloc_stats_print_out](../assets/doc/./01_mi_stats_print_out.png)

### Exemplo   <!-- omit in toc -->
A implementação acima foi aplicada no seguinte:

- [add --debug option for printing mimalloc memory stats #822](https://github.com/Yamato-Security/hayabusa/pull/822)

No Hayabusa, se você adicionar a opção `--debug`, as estatísticas de uso de memória serão exibidas ao final.

## Use o contador de performance do Windows
Vários usos de recursos podem ser verificados a partir de estatísticas que podem ser obtidas do lado do SO. Neste caso, os dois pontos a seguir devem ser observados.

- Influência do software antivírus (Windows Defender)
  - Apenas a primeira execução é afetada pela varredura e é mais lenta, então os resultados da segunda execução em diante após a build são adequados para comparação. (Ou você pode desabilitar seu antivírus para resultados mais precisos.)
- Influência do cache de arquivos
  - Os resultados da segunda vez em diante após a inicialização do SO são mais rápidos que a primeira vez, porque evtx e outros IOs de arquivos são lidos do cache de arquivos em memória, então os resultados da primeira vez após o SO inicializar são mais ideais para realizar benchmarks.

### Como obter  <!-- omit in toc -->
Pré-requisitos：O procedimento a seguir só é válido para ambientes onde o `PowerShell 7` já está instalado no Windows.

1. Reinicie o SO
2. Execute o [comando Get-Counter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-counter?view=powershell-7.3#example-3-get-continuous-samples-of-a-counter) do `PowerShell 7`, que registrará continuamente o contador de performance a cada segundo em um arquivo CSV. (Se você quiser medir recursos além dos listados abaixo, [este artigo](https://jpwinsup.github.io/blog/2021/06/07/Performance/SystemResource/PerformanceLogging/) é uma boa referência.)
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
3. Execute o processo que você quer medir.

### Exemplo  <!-- omit in toc -->
O seguinte contém um procedimento de exemplo para medir performance com o Hayabusa.

- [Example of obtaining Windows performance counters](https://github.com/Yamato-Security/hayabusa/issues/778#issuecomment-1296504766)

## Use o heaptrack
O [heaptrack](https://github.com/KDE/heaptrack) é um sofisticado profiler de memória disponível para Linux e macOS. Ao usar o heaptrack, você pode investigar minuciosamente os gargalos.

### Como obter  <!-- omit in toc -->
Pré-requisitos: Abaixo está o procedimento para o Ubuntu 22.04. Você não pode usar o heaptrack no Windows.

1. Instale o heaptrack com os dois comandos a seguir.
      ```
      sudo apt install heaptrack
      sudo apt install heaptrack-gui
      ```
2. Remova o seguinte código do mimalloc do Hayabusa. (Você não pode usar o profiler de memória do heaptrack com o mimalloc.
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L32-L33
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L59-L60
   - https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/src/main.rs#L632-L634

3. Exclua a [seção [profile.release]](https://github.com/Yamato-Security/hayabusa/blob/v2.2.2/Cargo.toml#L65-L67) no arquivo `Cargo.toml` do Hayabusa e altere-a para o seguinte:
     ```
     [profile.release]
     debug = true
     ```

4. Construa uma release build: `cargo build --release`
5. Execute `heaptrack hayabusa dfir-timeline -d sample -o out.csv`

Agora, quando o Hayabusa terminar de executar, os resultados do heaptrack abrirão automaticamente em uma aplicação GUI.

### Exemplos  <!-- omit in toc -->
Um exemplo dos resultados do heaptrack é mostrado abaixo. As abas `Flame Graph` e `Top-Down` permitem que você verifique visualmente as funções com alto uso de memória.

![heaptrack01](../assets/doc/./02-heaptrack.png)

![heaptrack02](../assets/doc/./03-heaptrack.png)

# Referências

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/title-page.html)
- [Memory Leak (and Growth) Flame Graphs](https://www.brendangregg.com/FlameGraphs/memoryflamegraphs.html)

# Contribuições

Este documento é baseado em descobertas de casos reais de melhoria no [Hayabusa](https://github.com/Yamato-Security/hayabusa). Se você encontrar quaisquer erros ou técnicas que possam melhorar a performance, por favor, envie-nos uma issue ou pull request.
