# Analisando os Resultados do Hayabusa Com o Timeline Explorer

## Sobre

O [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) é uma ferramenta gratuita, porém de código fechado, criada para substituir o Excel ao analisar arquivos CSV para fins de DFIR.
É uma ferramenta GUI exclusiva para Windows escrita em C#.
Esta ferramenta é ótima para pequenas investigações feitas por um único analista e para pessoas que estão apenas começando a aprender análise de DFIR. No entanto, a interface pode ser difícil de entender no início, então use este guia para compreender os diferentes recursos.

## Instalação e Execução

Não há necessidade de instalar o aplicativo.
Basta baixar a versão mais recente em [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md), descompactá-la e executar `TimelineExplorer.exe`.
Se você não tiver o runtime .NET apropriado, uma mensagem aparecerá informando que você precisa instalá-lo.
No momento em que isto foi escrito (14/02/2025), a versão mais recente é a `2.1.0`, que roda na versão `9` do .NET.

## Carregando um arquivo CSV

Basta clicar em `File` -> `Open` no menu para carregar um arquivo CSV.

Você verá algo parecido com isto:

![Primeira Inicialização](../assets/doc/TimelineExplorerAnalysis/01-TimelineExplorerFirstStart.png)

Na parte mais inferior, você pode ver o nome do arquivo, `Total lines` e `Visible lines`.

Além das colunas encontradas no arquivo CSV, há duas colunas à esquerda adicionadas pelo Timeline Explorer: `Line` e `Tag`.
`Line` mostra o número da linha, mas normalmente não é útil para investigações, então talvez você queira ocultar essa coluna.
`Tag` permite que você marque os eventos que deseja anotar para análise posterior, etc...
Infelizmente, não há como adicionar tags personalizadas aos eventos nem escrever comentários sobre os eventos, pois o arquivo CSV é aberto em modo somente leitura para evitar que os dados sejam sobrescritos.

## Filtragem de Dados

Se você passar o mouse sobre a parte superior direita de um cabeçalho, verá aparecer um ícone preto de filtro.

![Filtragem Básica de Dados](../assets/doc/TimelineExplorerAnalysis/02-BasicDataFiltering.png)

Você pode marcar o nível de severidade para primeiro triar os alertas `high` e `crit` (`critical`).
Essa filtragem também é muito útil para filtrar alertas ruidosos, marcando tudo em `Rule Title` e depois desmarcando as regras ruidosas.

Como mostrado abaixo, se você clicar em `Text Filters`, poderá criar filtros mais avançados:

![Filtragem Avançada de Dados](../assets/doc/TimelineExplorerAnalysis/03-AdvancedDataFiltering.png)

Em vez de criar filtros aqui, porém, geralmente é mais fácil clicar no ícone `ABC` sob o cabeçalho e aplicar os filtros aqui:

![Filtragem ABC](../assets/doc/TimelineExplorerAnalysis/04-ABC-Filtering.png)

Infelizmente, esses dois locais oferecem opções de filtragem ligeiramente diferentes, então você deve conhecer ambos os lugares para filtrar dados.

Por exemplo, se você tiver muitos eventos `Proc Exec` que gostaria de filtrar, pode escolher `Does not contain` e digitar `Proc Exec` para ignorar esses eventos:

![Filtragem de Regras](../assets/doc/TimelineExplorerAnalysis/05-RuleFiltering.png)

Se você olhar para a parte inferior, verá a regra do filtro em cores diferentes.
Se quiser desativar temporariamente o filtro, basta desmarcá-lo.
Se quiser limpar todos os filtros, clique no botão `X`.

Se você quiser ignorar outra regra ruidosa, deve abrir o `Filter Editor` clicando em `Edit Filter` no canto inferior direito:

![Editor de Filtros](../assets/doc/TimelineExplorerAnalysis/06-FilterEditor.png)

Copie o texto `Not Contains([Rule Title], 'Proc Exec')`, adicione `and`, cole o mesmo filtro e altere `Proc Exec` para `Possible LOLBIN`, e agora você pode ignorar essas duas regras:

![Múltiplos Filtros](../assets/doc/TimelineExplorerAnalysis/07-MultipleFilters.png)

A maneira mais fácil de combinar vários filtros é primeiro criar a sintaxe do filtro a partir do ícone `ABC`, depois copiar, colar e editar esse texto e combinar os filtros com `and`, `or` e `not`.

Você também pode clicar em qualquer um dos textos coloridos para obter uma caixa suspensa com as opções possíveis para editar seus filtros:

![Edição via menu suspenso](../assets/doc/TimelineExplorerAnalysis/08-DropDownEditing.png)

## Opções de Cabeçalho

Se você clicar com o botão direito em qualquer um dos cabeçalhos, obterá as seguintes opções:

![Opções de Cabeçalho](../assets/doc/TimelineExplorerAnalysis/09-HeaderOptions.png)

A maioria dessas opções é autoexplicativa.

* Depois de ocultar uma coluna, você pode exibi-la novamente abrindo o `Column Chooser`, clicando com o botão direito no nome da coluna e clicando em `Show Column`.
* `Group By This Column` tem o mesmo efeito que arrastar um cabeçalho de coluna para cima para agrupar. (Explicado em mais detalhes adiante.)
* `Hide Group By Box` apenas ocultará o texto `Drag a column header here to group by that column` e moverá a barra de pesquisa para o lado.

### Formatação Condicional

Você pode formatar o texto com cor, fonte em negrito, etc... clicando em `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...`:

![Formatação Condicional](../assets/doc/TimelineExplorerAnalysis/10-ConditionalFormatting.png)

Por exemplo, se você quisesse mostrar os alertas `critical` com `Red Fill`, basta digitar `crit` e escolher `Red Fill` nas opções, marcar `Apply formatting to an entire row` e pressionar `OK`.

![Crit](../assets/doc/TimelineExplorerAnalysis/11-Crit.png)

Agora os alertas `critical` aparecerão em vermelho, como mostrado abaixo:

![Preenchimento vermelho](../assets/doc/TimelineExplorerAnalysis/12-RedFill.png)

Você pode continuar fazendo isso adicionando cor também para os alertas `low`, `medium` e `high`.

## Pesquisa

Por padrão, quando você digita um texto na barra de pesquisa, ele realizará a filtragem e mostrará apenas os resultados que contêm o texto em algum lugar da linha.
Você pode ver quantas correspondências obteve verificando o campo `Visible lines` na parte inferior.

Você pode alterar esse comportamento clicando em `Search options` no canto inferior direito.
Isso mostrará o seguinte:

![Opções de Pesquisa](../assets/doc/TimelineExplorerAnalysis/13-SearchOptions.png)

Se você alterar o `Behavior` de `Filter` para `Search`, poderá pesquisar texto normalmente.

> Nota: Geralmente leva tempo para alternar o comportamento e o Timeline Explorer travará por um instante, então seja paciente após clicar.

O `Match criteria` padrão é `Mixed`, mas pode ser alterado para `Or`, `And` ou `Exact`.
Se você alterá-lo para qualquer coisa exceto `Mixed`, poderá então definir a `Condition` de `Contains` para `Starts with`, `Like` ou `Equals`.

O `Match criteria` `Mixed` é complicado, pois às vezes usa lógica `AND` e às vezes `OR`, mas pode ser muito flexível depois de aprendido.
Ele funciona da seguinte forma:

* Se você separar as palavras por espaços, elas serão tratadas como lógica `OR`.
* Se você quiser incluir espaços na sua pesquisa, precisará adicionar aspas.
* Preceda uma condição com `+` para lógica `AND`.
* Preceda uma condição com `-` para excluir resultados.
* Filtre uma coluna específica com o formato `ColumnName:FilterString`.
* Se você filtrar uma coluna específica e também incluir uma palavra-chave separada, será lógica `AND`.

Exemplos:
| Critério de Pesquisa             | Descrição                                                                                                                                       |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Seleciona registros que contêm a string `mimikatz` em qualquer coluna de pesquisa.                                                              |
| one two three                    | Seleciona registros que contêm `one` OU `two` OU `three` em qualquer coluna de pesquisa.                                                        |
| "hoge hoge"                      | Seleciona registros que contêm `hoge hoge` em qualquer coluna de pesquisa.                                                                      |
| mimikatz +"Bad Guy"              | Seleciona registros que contêm tanto `mimikatz` QUANTO `Bad Guy` em qualquer coluna de pesquisa.                                                |
| EventID:4624 kali                | Seleciona registros que contêm `4624` na coluna que começa com `EventID` E contêm `kali` em qualquer coluna de pesquisa.                        |
| data +entry -mark                | Seleciona registros que contêm tanto `data` QUANTO `entry` em qualquer coluna de pesquisa, excluindo registros que contêm `mark`.               |
| manu mask -file                  | Seleciona registros que contêm `menu` OU `mask`, excluindo registros que contêm `file`.                                                         |
| From:Roller Subj:"currency mask" | Seleciona registros que contêm `Roller` na coluna que começa com `From` E contêm `currency mask` na coluna que começa com `Subj`.               |
| import -From:Steve               | Seleciona registros que contêm `import` em qualquer coluna de pesquisa, excluindo registros que contêm `Steve` na coluna que começa com `From`. |

## Congelando colunas

Embora não seja uma opção de pesquisa, você pode configurar a `First scrollable column` no menu `Search options`.
A maioria dos analistas define isso como `Timestamp` para que possam sempre ver em que momento certos eventos aconteceram.

## Arrastando cabeçalhos de coluna para agrupar

Se você arrastar um cabeçalho de coluna para o `Drag a column header here to group by that column`, o Timeline Explorer agrupará por essa coluna.
É comum agrupar por `Level` para que você possa priorizar os alertas por severidade:

![Agrupar por](../assets/doc/TimelineExplorerAnalysis/14-GroupBy.png)

Se você tiver vários computadores em seus resultados, pode agrupar ainda mais por `Computer` para triar com base em diferentes níveis de severidade para cada computador.

## Verificando campos

Por padrão, o Hayabusa separará os dados dos campos pelo símbolo de barra vertical quebrada: `¦`.
Quando os dados do campo estão em uma linha horizontal, isso torna muito fácil distinguir vários campos, pois esse caractere não é encontrado com frequência em logs:

![Informações de Campo](../assets/doc/TimelineExplorerAnalysis/15-FieldInformation.png)

Às vezes, no entanto, haverá informações de campo demais no log e nem tudo caberá em uma única tela.
Nesse caso, você pode dar um duplo clique na célula para obter um pop-up que mostra todas as informações do campo:

![Conteúdo da Célula](../assets/doc/TimelineExplorerAnalysis/16-CellContents.png)

O problema é que o Timeline Explorer só permite formatar os dados do campo por caracteres de nova linha (`CRLF`, `CR`, `LF`), vírgulas e tabulações.

Se você usar a opção `-M, --multiline`, poderá separar os campos por um caractere de nova linha e, quando der um duplo clique para abrir o conteúdo de uma célula, ele será formatado corretamente:

![Formatação multilinha](../assets/doc/TimelineExplorerAnalysis/17-MultilineFormatting.png)

O problema é que agora apenas o primeiro campo será mostrado na linha do tempo, então você terá que dar um duplo clique e abrir uma nova janela toda vez que quiser verificar os dados dos outros campos:

![Campo único multilinha](../assets/doc/TimelineExplorerAnalysis/18-MultilineSingleField.png)

Infelizmente, o Timeline Explorer não suporta múltiplas linhas na visualização da linha do tempo.

Para contornar isso, a partir do Hayabusa `v3.1.0`, você pode separar os campos por tabulações:

![Separação por tabulação](../assets/doc/TimelineExplorerAnalysis/19-TabSeparation.png)

É um pouco mais difícil distinguir onde um campo termina e o próximo começa.
Além disso, quando você dá um duplo clique e abre o conteúdo da célula, os campos não são formatados automaticamente:

![Separação por tabulação não formatada](../assets/doc/TimelineExplorerAnalysis/20-TabSeparationNotFormatted.png)

No entanto, se você clicar em `Tab` na parte inferior e depois em `Format`, poderá formatar os campos em uma visualização fácil de ler:

![Separação por tabulação formatada](../assets/doc/TimelineExplorerAnalysis/21-TabSeparationFormatted.png)

## Temas

Você pode alterar o tema de cores em `Tools` -> `Skins` se preferir o modo escuro, etc...

## Sessões

Se você personalizar as colunas, a aparência, adicionar filtros, etc... e quiser salvar essas configurações para mais tarde, certifique-se de salvar sua sessão em `File` -> `Session` -> `Save`.
