# Analisando Resultados do Hayabusa com o Timesketch

## Sobre

"[Timesketch](https://timesketch.org/) é uma ferramenta de código aberto para análise colaborativa de linha do tempo forense. Usando sketches, você e seus colaboradores podem organizar facilmente suas linhas do tempo e analisá-las todos ao mesmo tempo. Adicione significado aos seus dados brutos com anotações, comentários, tags e estrelas detalhados."

Para investigações pequenas, em que você está analisando um arquivo CSV de apenas algumas centenas de MBs e trabalhando sozinho, o Timeline Explorer é adequado; porém, quando você está trabalhando com dados maiores ou com uma equipe, uma ferramenta como o Timesketch é muito melhor.

O Timesketch oferece os seguintes benefícios:

1. É muito rápido e consegue lidar com grandes volumes de dados
2. É uma ferramenta colaborativa em que vários usuários podem utilizá-la simultaneamente
3. Fornece análise avançada de dados, histogramas e visualizações
4. Não se limita ao Windows
5. Oferece suporte a consultas avançadas

Há muitos outros benefícios, como suporte a CTI, diversos analisadores, notebooks interativos, etc...
Confira o [guia do usuário](https://timesketch.org/guides/user/upload-data/) e o [canal do YouTube](https://www.youtube.com/channel/UC_n6mMb0OxWRk7xiqiOOcRQ) para mais informações.

A única desvantagem é que você terá que configurar um servidor Timesketch no seu ambiente de laboratório, mas felizmente isso é muito trivial de fazer.

## Instalando
### Docker
Siga as instruções oficiais [aqui](https://docs.docker.com/compose/install).

### Ubuntu
**Nota:** O Docker deve estar instalado antes de prosseguir. Siga as [instruções de instalação do Docker acima](#docker) caso você ainda não tenha instalado o Docker.
Recomendamos usar a edição mais recente do Ubuntu LTS Server com pelo menos 8GB de memória.
Você pode baixá-la [aqui](https://ubuntu.com/download/server).
Escolha a instalação mínima ao configurá-la.
Não instale o docker ao configurar o sistema operacional.
Você não terá o `ifconfig` disponível, então instale-o com `sudo apt install net-tools`.

Depois disso, execute `ifconfig` para encontrar o endereço IP da VM e, opcionalmente, conecte-se via ssh a ela.

Execute os seguintes comandos:
``` bash
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt
sudo ~/deploy_timesketch.sh
cd timesketch
sudo docker compose up -d

# Create a user named user. Set the password here.
sudo docker compose exec timesketch-web tsctl create-user user
```
### macOS
**Nota:** Antes de prosseguir, certifique-se de ter o [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac/) instalado e em execução no seu sistema.
Clone o repositório do Timesketch e entre no diretório.
```bash
git clone https://github.com/google/timesketch.git
cd timesketch
```
Inicie o contêiner Docker seguindo os passos abaixo.

- https://github.com/google/timesketch/tree/master/docker/e2e#build-and-start-containers

## Fazendo login

Descubra o endereço IP do servidor Timesketch com `ifconfig` e abra-o em um navegador web.
Você será redirecionado para uma página de login.
Faça login com as credenciais de usuário que você utilizou ao adicionar um usuário.

## Criando um novo sketch

Em `Start a new investigation`, clique em `BLANK SKETCH`.
Nomeie o sketch com algo relevante para a sua investigação.

## Enviando sua linha do tempo

Depois de clicar em `+ ADD TIMELINE`, você verá uma caixa de diálogo pedindo para enviar um arquivo Plaso, JSONL ou CSV.
Infelizmente, o Timesketch atualmente não consegue importar o formato `JSONL` do Hayabusa, então crie e envie uma linha do tempo em CSV com o seguinte comando:

```shell
hayabusa-x.x.x-win-x64.exe csv-timeline -d <DIR> -o timesketch-import.csv -p timesketch-verbose --ISO-8601
```

> Nota: É necessário escolher um perfil `timesketch*` e especificar o timestamp como `--ISO-8601` para UTC ou `--RFC-3339` para horário local. Você pode adicionar outras opções do Hayabusa se desejar, porém, não adicione a opção `-M, --multiline`, pois os caracteres de quebra de linha corromperão a importação.

Na caixa de diálogo "Select file to upload", nomeie sua linha do tempo como algo do tipo `hayabusa`, escolha o delimitador CSV `Comma (,)` e clique em `SUBMIT`.

> Se o seu arquivo CSV for grande demais para enviar, você pode dividir o arquivo em vários arquivos CSV com o comando [split-csv-timeline](https://github.com/Yamato-Security/takajo?tab=readme-ov-file#split-csv-timeline-command) do Takajo.

Enquanto o arquivo estiver sendo importado, você verá um círculo girando, então aguarde até que termine e você veja `hayabusa` aparecer.

## Dicas de análise

### Exibindo a linha do tempo

**Nota: Mesmo após a importação ter terminado com sucesso, será exibido `Your search did not match any events` e haverá `0` eventos na linha do tempo `hayabusa`.**

Pesquise por `*` e os eventos aparecerão como mostrado abaixo:

![Resultados do Timesketch](../assets/doc/TimesketchImport/TimesketchResults.png)

### Detalhes do alerta

Se você clicar no título de uma regra de alerta na coluna `message`, você obterá as informações detalhadas sobre o alerta:

![Detalhes do alerta](../assets/doc/TimesketchImport/AlertDetails.png)

Se você quiser entender a lógica da regra sigma, consultar a descrição e as referências, etc... procure a regra no repositório [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

#### Filtragem de campos

Após abrir os detalhes de um evento clicando no título da regra, você pode passar o cursor sobre qualquer campo para filtrar facilmente o valor para incluí-lo ou excluí-lo:

![Filtrar Incluir Excluir](../assets/doc/TimesketchImport/FilterInOut.png)

#### Análise de agregação

Ao passar o cursor, se você clicar no ícone `Aggregation dialog` mais à esquerda, você obtém análises de dados de eventos realmente excelentes referentes àquele campo:

![Análise de Dados de Eventos](../assets/doc/TimesketchImport/EventDataAnalytics.png)

#### Comentários de usuários

Quando você clica em um alerta para obter informações detalhadas, um novo ícone de caixa de diálogo de comentário é exibido no lado direito, como mostrado abaixo:

![Ícone de Comentário](../assets/doc/TimesketchImport/CommentIcon.png)

Aqui, os usuários podem iniciar um chat e escrever comentários sobre a investigação.

> Se você estiver trabalhando em equipe, provavelmente deveria criar uma conta de usuário diferente para cada membro, para que você saiba quem escreveu o quê.

![Chat de comentários](../assets/doc/TimesketchImport/CommentChat.png)

> Se você passar o cursor sobre um comentário, você pode editar e excluir as mensagens facilmente.

### Modificando colunas

Por padrão, apenas o timestamp e o título da regra de alerta serão exibidos, então clique no ícone `Modify columns` para personalizar os campos:

![ModifyColumnsIcon](../assets/doc/TimesketchImport/ModifyColumnsIcon.png)

Isso abrirá a seguinte caixa de diálogo:

![Selecionar colunas](../assets/doc/TimesketchImport/SelectColumns.png)

Recomendamos adicionar pelo menos as seguintes colunas **na ordem**:

1. `Level`
2. `Computer`
3. `Channel`
4. `EventID`
5. `RecordID`

A ordem das colunas mudará dependendo da ordem em que você as adiciona, então adicione primeiro os campos mais importantes.

Se você ainda tiver espaço na tela, recomendamos também adicionar `Details`, como mostrado aqui:

![Details](../assets/doc/TimesketchImport/Details.png)

Se você ainda tiver espaço na tela, recomendamos também adicionar `ExtraFieldInfo`, porém, como você vê aqui, se adicionar colunas demais, o campo `message` ficará estreito demais e você não conseguirá mais ler os títulos dos alertas:

![Detalhes em excesso](../assets/doc/TimesketchImport/TooMuchDetails.png)

### Ícones superiores

#### Ícone de reticências

Se você clicar no ícone `···`, você pode tornar as linhas mais compactas e remover o `Timeline name` para criar mais espaço para os resultados:

![Mais espaço](../assets/doc/TimesketchImport/MoreRoom.png)

#### Histograma de eventos

Você pode ativar o histograma de eventos para visualizar a linha do tempo:

![Histograma de Eventos](../assets/doc/TimesketchImport/EventHistogram.png)

Se você clicar em uma das barras, será criado um filtro de tempo para mostrar apenas os resultados durante aquele período de tempo.

#### Salvar pesquisa atual

Se você clicar no ícone `Save current search` logo acima dos timestamps e à esquerda do ícone `Toggle Event Histogram`, você pode salvar sua consulta de pesquisa atual, bem como a configuração de colunas, em `Saved Searches`.
Mais tarde, na barra lateral esquerda, você pode acessar facilmente suas pesquisas favoritas.

### Barra de pesquisa

Aqui estão algumas consultas úteis para começar, mostrando apenas alertas com determinados níveis de severidade:

1. `Level:crit` para mostrar apenas alertas críticos.
2. `Level:crit OR Level:high` para mostrar alertas altos e críticos
3. `NOT Level:info` para ocultar alertas informativos

Você pode filtrar facilmente digitando o nome do campo mais `:` mais o valor.
Você pode combinar filtros com `AND`, `OR` e `NOT`.
Curingas e expressões regulares são suportados.

Consulte o guia do usuário [aqui](https://timesketch.org/guides/user/search-query-guide/) para consultas mais avançadas.

#### Histórico de pesquisas

Se você clicar no ícone de relógio à esquerda da barra de pesquisa, você pode exibir as consultas inseridas anteriormente.
Você também pode clicar nos ícones de seta esquerda e direita para executar as consultas anteriores e seguintes.

![Histórico de Pesquisas](../assets/doc/TimesketchImport/SearchHistory.png)

### Reticências verticais

Se você clicar nas reticências verticais à esquerda de um timestamp e clicar em `Context search`, você pode ver os alertas que aconteceram antes e depois de um determinado evento:

![Reticências verticais](../assets/doc/TimesketchImport/VerticalElipsisContext.png)

Isso abrirá o seguinte:

![Pesquisa de Contexto](../assets/doc/TimesketchImport/ContextSearch.png)

No exemplo acima, os eventos antes e depois de 60 segundos (`60S`) estão sendo exibidos, mas você pode ajustar isso de +- 1 segundo (`1S`) até +- 60 minutos (`60M`).

Se você quiser detalhar ainda mais os eventos exibidos, clique em `Replace Search` para mostrar os eventos na linha do tempo padrão.

### Estrelas e tags

Você pode clicar no ícone de estrela à esquerda de um timestamp para marcá-lo com estrela e anotá-lo como um evento importante.

Você também pode adicionar tags aos eventos.
Isso é útil para indicar a outras pessoas que você confirmou que um evento é suspeito, malicioso, um falso positivo, etc...
Se você estiver trabalhando em equipe, você pode criar tags como `under investigation by xxx` para indicar que alguém está atualmente investigando o alerta.

![Estrelas e tags](../assets/doc/TimesketchImport/StarsAndTags.png)
