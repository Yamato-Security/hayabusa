- [Importando Resultados no SOF-ELK (Elastic Stack)](#importing-results-into-sof-elk-elastic-stack)
  - [Instalar e iniciar o SOF-ELK](#install-and-start-sof-elk)
    - [Problemas de conectividade de rede em Macs](#network-connectivity-trouble-on-macs)
  - [Atualize o SOF-ELK!](#update-sof-elk)
  - [Executar o Hayabusa](#run-hayabusa)
  - [Opcional: Excluindo dados importados antigos](#optional-deleting-old-imported-data)
  - [Configurar o arquivo de configuração do logstash do Hayabusa no SOF-ELK](#configure-the-hayabusa-logstash-config-file-in-sof-elk)
  - [Importar os resultados do Hayabusa no SOF-ELK](#import-hayabusa-results-into-sof-elk)
  - [Verificar se a importação funcionou no Kibana](#check-that-the-import-worked-in-kibana)
  - [Visualizar resultados no Discover](#view-results-in-discover)
  - [Analisando resultados](#analyzing-results)
    - [Adicionando colunas](#adding-columns)
    - [Filtrando](#filtering)
    - [Alternando Detalhes](#toggling-details)
    - [Visualizar documentos adjacentes](#view-surrounding-documents)
    - [Obter métricas rápidas sobre campos](#get-quick-metrics-on-fields)
  - [Planos Futuros](#future-plans)

# Importando Resultados no SOF-ELK (Elastic Stack)

## Instalar e iniciar o SOF-ELK

Os resultados do Hayabusa podem ser facilmente importados no Elastic Stack.
Recomendamos usar o [SOF-ELK](https://github.com/philhagen/sof-elk), uma distro Linux gratuita do elastic stack focada em investigações de DFIR.

Primeiro baixe e descompacte a imagem VMware do SOF-ELK compactada em 7-zip em [https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README](https://github.com/philhagen/sof-elk/wiki/Virtual-Machine-README).

Existem duas versões, x86 para CPUs Intel e uma versão ARM para computadores Apple da série M.

Quando você inicializar a VM, verá uma tela semelhante a esta:

![Inicialização do SOF-ELK](../assets/doc/ElasticStackImport/01-SOF-ELK-Bootup.png)

Anote a URL do Kibana e o endereço IP do servidor SSH.

Você pode fazer login com as seguintes credenciais:

* Nome de usuário: `elk_user`
* Senha: `forensics`

Abra o Kibana em um navegador web de acordo com a URL exibida.
Por exemplo: http://172.16.23.128:5601/

> Nota: pode demorar um pouco para o Kibana carregar.

Você deverá ver uma página web como a seguir:

![SOF-ELK Kibana](../assets/doc/ElasticStackImport/02-Kibana.png)

Recomendamos que você faça SSH na VM em vez de digitar comandos dentro da VM com `ssh elk_user@172.16.23.128`.

> Nota: o layout de teclado padrão é o teclado dos EUA.

### Problemas de conectividade de rede em Macs

Se você estiver no macOS e receber um erro `no route to host` no terminal ou não conseguir acessar o Kibana no seu navegador, provavelmente é devido aos controles de privacidade de rede local do macOS.

Em `System Settings`, abra `Privacy & Security` -> `Local Network` e certifique-se de que seu navegador e seu programa de terminal estejam habilitados para poder se comunicar com dispositivos na sua rede local.

## Atualize o SOF-ELK!

Antes de importar dados, certifique-se de atualizar o SOF-ELK com o comando `sudo sof-elk_update.sh`.

## Executar o Hayabusa

Execute o Hayabusa e salve os resultados em JSONL.

Ex: `./hayabusa dfir-timeline -t jsonl -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl`

## Opcional: Excluindo dados importados antigos

Se esta não for a primeira vez que você importa resultados do Hayabusa e você quiser limpar tudo, pode fazê-lo da seguinte forma:

1. Verifique quais registros estão atualmente no SOF-ELK: `sof-elk_clear.py -i list`
2. Exclua os dados atuais: `sof-elk_clear.py -a`
3. Exclua os arquivos no diretório do logstash: `rm /logstash/hayabusa/*`

## Configurar o arquivo de configuração do logstash do Hayabusa no SOF-ELK

Já existe um arquivo de configuração do logstash do Hayabusa incluído no SOF-ELK que converte os nomes dos campos para o formato Elastic Common Schema.
Se você se sentir mais confortável com os nomes de campos do Hayabusa, recomendamos usar o que fornecemos.

1. Primeiro faça SSH no SOF-ELK: `ssh elk_user@172.16.23.128`
2. Exclua ou mova o arquivo de configuração atual do logstash: `sudo rm /etc/logstash/conf.d/6650-hayabusa.conf`
3. Envie o novo arquivo [6650-hayabusa-jsonl.conf](../assets/doc/ElasticStackImport/6650-hayabusa-jsonl.conf) para `/etc/logstash/conf.d/`: `sudo wget https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/doc/ElasticStackImport/6650-hayabusa-jsonl.conf -O /etc/logstash/conf.d/6650-hayabusa.conf`.
4. Reinicie o logstash: `sudo systemctl restart logstash`

Este arquivo de configuração criará campos consolidados `DetailsText` e `ExtraFieldInfoText` que permitem visualizar rapidamente os campos mais importantes de relance, em vez de ter que gastar tempo abrindo cada registro um por um para examinar todos os campos.

## Importar os resultados do Hayabusa no SOF-ELK

Os logs são ingeridos no SOF-ELK copiando os logs para o diretório apropriado dentro do diretório `/logstash`.

Primeiro saia do SSH com `exit` e então copie o arquivo de resultados do Hayabusa que você criou:
`scp ./results.jsonl elk_user@172.16.23.128:/logstash/hayabusa`

## Verificar se a importação funcionou no Kibana

Primeiro anote o `Total detections`, `First Timestamp` e `Last Timestamp` no `Results Summary` da sua varredura do Hayabusa.

Se você não conseguir obter essa informação, pode executar `wc -l results.jsonl` em *nix para obter a contagem total de linhas para `Total detections`.

Por padrão, o Hayabusa não ordena os resultados para melhorar o desempenho, então você não pode olhar a primeira e a última linha para obter o primeiro e o último timestamp.
Se você não souber os timestamps exatos do primeiro e do último, basta definir a primeira data no Kibana para o ano de 2007 e o último dia como `now`, assim você terá todos os resultados.

![AtualizarDatas](../assets/doc/ElasticStackImport/03-ChangeDates.png)

Você deverá agora ver o `Total Records` bem como o primeiro e o último timestamp dos eventos que foram importados.

Às vezes demora um pouco para importar todos os eventos, então continue atualizando a página até que o `Total Records` seja a contagem que você espera.

![TotalRecords](../assets/doc/ElasticStackImport/04-TotalRecords.png)

Você também pode verificar a partir do terminal executando `sof-elk_clear.py -i list` para ver se a importação foi bem-sucedida.
Você deverá ver que seu índice `evtxlogs` deve ter mais registros:
```
The following indices are currently active in Elasticsearch:
- evtxlogs (32,298 documents)
```

Por favor, crie um issue no GitHub se você tiver algum erro de parsing ao importar.
Você pode verificar isso olhando o final do arquivo de log `/var/log/logstash/logstash-plain.log`.

## Visualizar resultados no Discover

Clique no ícone da barra lateral superior esquerda e clique em `Discover`:

![AbrirDiscover](../assets/doc/ElasticStackImport/05-OpenDiscover.png)

Você provavelmente verá `No results match your search criteria`.

No canto superior esquerdo onde diz índice `logstash-*`, clique nele e altere para `evtxlogs-*`.
Você deverá agora ver a linha do tempo do Discover.

## Analisando resultados

A visualização padrão do Discover deve se parecer com isto:

![Visualização do Discover](../assets/doc/ElasticStackImport/06-Discover.png)

Você pode obter uma visão geral de quando os eventos ocorreram e da frequência dos eventos olhando o histograma no topo. 

### Adicionando colunas

Na barra lateral esquerda, você pode adicionar os campos que deseja exibir nas colunas clicando no sinal de mais após passar o mouse sobre um campo.
Como há muitos campos, você pode querer digitar o nome do campo que está procurando na caixa de pesquisa.

![Adicionando Colunas](../assets/doc/ElasticStackImport/07-AddingColumns.png)

Para começar, recomendamos as seguintes colunas:

- `Computer`
- `EventID`
- `Level`
- `RuleTitle`
- `DetailsText`

Se o seu monitor for largo o suficiente, você pode querer adicionar também `ExtraFieldInfoText` para ver todas as informações dos campos.

Sua visualização do Discover deve agora se parecer com isto:

![Discover Com Colunas](../assets/doc/ElasticStackImport/08-DiscoverWithColumns.png)

### Filtrando

Você pode filtrar com KQL (Kibana Query Language) para pesquisar por certos eventos e alertas. Por exemplo:
  * `Level: "crit"`: Mostrar apenas alertas críticos.
  * `Level: "crit" OR Level: "high"`: Mostrar alertas altos e críticos.
  * `NOT Level: info`: Não mostrar eventos informativos, apenas alertas.
  * `MitreTactics: *LatMov*`: Mostrar eventos e alertas relacionados a movimento lateral.
  * `"PW Spray"`: Mostrar apenas ataques específicos como "Password Spray".
  * `"LID: 0x8724ead"`: Exibir toda a atividade associada ao Logon ID 0x8724ead.
  * `Details_TgtUser: admmig`: Pesquisar todos os eventos onde o usuário alvo é `admmig`.

### Alternando Detalhes

Para verificar todos os campos em um registro, basta clicar no ícone (Toggle dialog with details) ao lado do timestamp:

![AlternarDetalhes](../assets/doc/ElasticStackImport/09-ToggleDetails.png)

### Visualizar documentos adjacentes

Se você quiser visualizar os eventos imediatamente antes e depois de um determinado alerta, primeiro abra os detalhes desse alerta e então clique em `View surrounding documents` no canto superior direito:

![VisualizarDocumentosAdjacentes](../assets/doc/ElasticStackImport/10-ViewSurroundingDocuments.png)

Neste exemplo, estamos vendo os eventos antes e depois do alerta de ataque Pass the Hash:

![DocumentosAdjacentes](../assets/doc/ElasticStackImport/11-SurroundingDocuments.png)

> Nota: Altere os números no topo `Load x newer documents` ou na parte inferior `Load x older documents` para recuperar mais eventos.

### Obter métricas rápidas sobre campos

Na coluna esquerda, se você clicar no nome de um campo, ele fornecerá métricas rápidas sobre seu uso:

![MétricasDeLevel](../assets/doc/ElasticStackImport/12-LevelMetrics.png)

> Observe que os dados são amostrados para maior velocidade, portanto não são 100% precisos.

## Planos Futuros

* Parsers do Logstash para CSV
* Dashboard pré-construído
