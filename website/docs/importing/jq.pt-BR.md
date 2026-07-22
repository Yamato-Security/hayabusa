# Analisando Resultados do Hayabusa com jq

# Autor

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2023/03/22

# Sobre

Ser capaz de identificar, extrair e criar métricas a partir de campos importantes em logs é uma habilidade essencial para analistas de DFIR e threat hunting.
Os resultados do Hayabusa geralmente são salvos em arquivos `.csv` para serem importados em programas como Excel ou Timeline Explorer para análise de linha do tempo.
No entanto, quando há centenas ou mais do mesmo evento, torna-se impraticável ou impossível verificá-los manualmente.
Nessas situações, os analistas normalmente ordenam e contam tipos similares de dados procurando por anomalias.
Isso também é conhecido como long tail analysis, stack ranking, análise de frequência, etc...
Isso pode ser realizado com o Hayabusa gerando os resultados em arquivos `.json` ou `.jsonl` e então analisando com `jq`.

Por exemplo, um analista poderia comparar os serviços instalados em todas as estações de trabalho de uma organização.
Embora seja possível que um determinado malware seja instalado em todas as estações de trabalho, é muito mais provável que ele exista apenas em um punhado de sistemas.
Nesse caso, os serviços que estão instalados em todos os sistemas têm maior probabilidade de serem benignos, enquanto serviços raros tendem a ser mais suspeitos e devem ser verificados periodicamente.

Outro caso de uso é ajudar a determinar o quão suspeito algo é.
Por exemplo, um analista poderia analisar os logs de logon malsucedido `4625` para determinar quantas vezes um determinado endereço IP falhou ao fazer logon.
Se houvesse apenas algumas falhas de logon, então é provável que um administrador apenas tenha digitado a senha errada.
No entanto, se houvesse centenas ou mais falhas de logon em um curto período de tempo por um determinado endereço IP, então é provável que o endereço IP seja malicioso.

Aprender a usar o `jq` ajudará você a dominar não apenas a análise de registros de eventos do Windows, mas de todos os logs no formato JSON.
Agora que o JSON se tornou um formato de log muito popular e a maioria dos provedores de nuvem o utiliza para seus logs, ser capaz de analisá-los com o `jq` se tornou uma habilidade essencial para o analista de segurança moderno.

Neste guia, vou primeiro explicar como utilizar o `jq` para aqueles que nunca o usaram antes e depois explicar usos mais complexos junto com exemplos do mundo real.
Recomendo usar linux, macOS ou linux no Windows para poder combinar o `jq` com outros comandos úteis como `sort`, `uniq`, `grep`, `sed`, etc...

# Instalando o jq

Por favor, consulte [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) e instale o comando `jq`.

# Sobre o Formato JSON

Os logs JSON são uma lista de objetos contidos em chaves `{` `}`.
Dentro desses objetos há pares de chave-valor separados por dois pontos.
As chaves devem ser strings, mas os valores podem ser um dos seguintes:
  * string (Ex: `"string"`)
  * número (Ex: `10`)
  * outro objeto (Ex: `{ xxxx }`)
  * array (Ex: `["string", 10]`)
  * booleano (Ex: `true`, `false`)
  * `null`

Você pode aninhar quantos objetos quiser dentro de objetos.

Neste exemplo, `Details` é um objeto aninhado dentro de um objeto raiz:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

# Sobre os Formatos JSON e JSONL com o Hayabusa

Em versões anteriores, o Hayabusa usava o formato JSON tradicional, colocando todos os objetos de log `{ xxx }` em um único array gigante.

Exemplo:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

Há dois problemas com isso.
O primeiro problema é que as consultas do `jq` se tornam mais trabalhosas, pois tudo precisa começar com um `.[]` extra para indicar que ele deve procurar dentro daquele array.
O problema muito maior é que, para que qualquer coisa analise tais logs, é necessário primeiro carregar todos os dados do array.
Isso se torna um problema se você tiver arquivos JSON muito grandes e não uma abundância de memória.
Para reduzir o uso necessário de CPU e memória, o formato JSONL (JSON Lines), que não coloca tudo em um array gigante, tornou-se mais popular.
O Hayabusa gera saída nos formatos JSON e JSONL, porém o formato JSON não é mais salvo dentro de um array.
A única diferença é que o formato JSON é mais fácil de ler em um editor de texto ou no console, enquanto o formato JSONL armazena cada objeto JSON em uma única linha.
O formato JSONL será ligeiramente mais rápido e menor em tamanho, sendo ideal se você for apenas importar os logs para um SIEM, etc... mas não visualizá-los.
O formato JSON é ideal se você também for fazer alguma verificação manual.

# Criando Arquivos de Resultados JSON

Na versão atual 2.x do Hayabusa, você pode salvar os resultados em JSON com `hayabusa dfir-timeline -t json -d <directory> -o results.json` ou `hayabusa dfir-timeline -t json -d <directory> -J -o results.jsonl` para o formato JSONL.

O Hayabusa usará o perfil `standard` padrão e salvará apenas a quantidade mínima de dados para análise no objeto `Details`.
Se você quiser salvar todas as informações de campo originais dos logs .evtx, você pode usar o perfil `all-field-info` com a opção `--profile all-field-info`.
Isso salvará todas as informações de campo no objeto `AllFieldInfo`.
Se você quiser salvar tanto o objeto `Details` quanto o `AllFieldInfo` por precaução, você pode usar o perfil `super-verbose`.

## Benefícios de Usar Details em Vez de AllFieldInfo

O primeiro benefício de usar `Details` em vez de `AllFieldInfo` é que apenas os campos importantes são salvos, e os nomes dos campos foram encurtados para economizar espaço em arquivo.
A desvantagem é que há a possibilidade de faltar dados com os quais você realmente se importava, mas que foram omitidos.
O segundo benefício é que o Hayabusa salvará os campos de uma maneira mais uniforme, normalizando os nomes dos campos.
Por exemplo, nos logs originais do Windows, o nome do usuário geralmente está em um campo `SubjectUserName` ou `TargetUserName`. 
No entanto, às vezes o nome de usuário estará em um campo `AccountName`, às vezes o usuário de destino estará na verdade no campo `SubjectUserName`, etc...
Infelizmente, há muitos nomes de campos inconsistentes nos registros de eventos do Windows.
O Hayabusa tenta normalizar esses campos, de modo que um analista só precisa analisar um nome comum em vez de ter que entender a quantidade infinita de peculiaridades e discrepâncias entre os event IDs no Windows.

Aqui está um exemplo do campo de usuário.
O Hayabusa normalizará `SubjectUserName`, `TargetUserName`, `AccountName`, etc... da seguinte maneira:
  * `SrcUser` (Source User): quando uma ação acontece **a partir de** um usuário. (Geralmente um usuário remoto.)
  * `TgtUser` (Target User): quando uma ação acontece **para** um usuário. (Por exemplo, um logon **para** um usuário.)
  * `User`: quando uma ação acontece por um usuário atualmente logado. (Não há uma direção específica na ação.)

Outro exemplo são os processos.
Nos registros de eventos originais do Windows, o campo de processo é referido com múltiplas convenções de nomenclatura: `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName`, etc...
Sem a normalização de campos, um analista teria que primeiro ter conhecimento sobre todos os diferentes nomes de campos, então extrair todos os logs com esses nomes de campos, e então combiná-los. 

Um analista pode economizar muito tempo e trabalho apenas usando o campo único normalizado `Proc` que o Hayabusa fornece no objeto `Details`.

# Lições/Receitas do jq

Vou agora listar várias lições/receitas de exemplos práticos que podem ajudá-lo no seu trabalho.

## 1. Verificação Manual com jq e Less em Cores

Esta é uma das primeiras coisas a se fazer para entender quais campos estão nos logs.
Você poderia simplesmente fazer um `less results.json`, mas uma maneira melhor é a seguinte:
`cat results.json | jq -C | less -R`

Ao passar para o `jq`, ele formatará organizadamente todos os campos para você, caso não estivessem bem formatados desde o início.
Ao usar a opção `-C` (color) com o `jq` e a opção `-R` (raw output) com o `less`, você pode rolar para cima e para baixo em cores.

## 2. Métricas

O Hayabusa já possui funcionalidade para exibir o número e o percentual de eventos com base nos event IDs, no entanto, também é bom saber como fazer isso com o `jq`.
Isso permitirá que você personalize os dados para os quais deseja criar métricas.

Vamos primeiro extrair uma lista de Event IDs com o seguinte comando:

`cat results.json | jq '.EventID'`

Isso extrairá apenas o número do Event ID de cada log.
Após o `jq`, entre aspas simples, basta digitar um `.` e o nome do campo que você deseja extrair.
Você deve ver uma longa lista como esta:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Agora, encaminhe os resultados para os comandos `sort` e `uniq -c` para contar quantas vezes os event IDs ocorreram:

`cat results.json | jq '.EventID' | sort | uniq -c`

A opção `-c` do `uniq` contará quantas vezes um event ID único ocorreu.

Você deve ver algo como isto:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
```

 À esquerda está a contagem, e à direita está o Event ID.
 Como você pode ver, não está ordenado, então é difícil dizer quais event IDs ocorreram mais.

 Você pode adicionar um `sort -n` ao final para corrigir isso:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

A opção `-n` diz ao `sort` para ordenar por número.

Você deve ver algo como isto:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

Podemos ver que os eventos `4688` (Process creation) foram os mais registrados.
O segundo evento mais registrado foi o `4625` (Failed Logon).

Se você quiser exibir os eventos mais registrados no topo, então você pode inverter a ordenação com `sort -n -r` ou `sort -nr`.
Você também pode exibir apenas os 10 eventos mais registrados encaminhando os resultados para `head -n 10`.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

Isso lhe dará:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
```

É importante considerar que os EIDs (Event IDs) não são únicos, então você pode ter eventos completamente diferentes com o mesmo Event ID.
Portanto, é importante também verificar o `Channel`.

Podemos adicionar essa informação de campo assim:

`cat results.json | jq -j ' .Channel , " " , .EventID , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Adicionamos a opção `-j` (join) ao `jq` para juntar todos os campos delimitados por vírgulas e terminando com um caractere de nova linha `\n`.

Isso nos dará:
```
12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
```

 Nota: `Security` é abreviado para `Sec`, `System` para `Sys`, e `PowerShell` para `PwSh`.

Podemos adicionar o título da regra da seguinte forma:

`cat results.json | jq -j ' .Channel , " " , .EventID , " " , .RuleTitle , "\n" ' | sort | uniq -c | sort -nr | head -n 10`

Isso nos dará:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
```

Agora você pode extrair livremente quaisquer dados dos logs e contar as ocorrências.

## 3. Filtrando Determinados Dados

Muitas vezes você vai querer filtrar por determinados Event IDs, usuários, processos, LIDs (Logon IDs), etc...
Você pode fazer isso com `select` dentro da consulta do `jq`.

Por exemplo, vamos extrair todos os eventos de logon bem-sucedido `4624`:

`cat results.json | jq 'select ( .EventID == 4624 ) '`

Isso retornará todos os objetos JSON do EID `4624`:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
```

Se você quiser filtrar por múltiplas condições, você pode usar palavras-chave como `and`, `or` e `not`.

Por exemplo, vamos procurar por eventos `4624` onde o tipo é `3` (logon de rede).

`cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type == 3 ) ) '`

Isso retornará todos os objetos onde o `EventID` é `4624` e o campo aninhado `"Details": { "Type" }` é `3`.

Há um problema, porém.
Você pode notar erros dizendo `jq: error (at <stdin>:10636): Cannot index string with string "Type"`.
Sempre que você vir o erro `Cannot index string with string`, isso significa que você está dizendo ao `jq` para gerar um campo que não existe ou é do tipo errado.
Você pode se livrar desses erros adicionando um `?` ao final do campo.
Isso diz ao `jq` para ignorar os erros.

Exemplo: `cat results.json | jq 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) '`

Agora, após filtrar por determinados critérios, podemos usar um `|` dentro da consulta do `jq` para então selecionar determinados campos de interesse.

Por exemplo, vamos extrair o nome do usuário de destino `TgtUser` e o endereço IP de origem `SrcIP`:

`cat results.json | jq -j 'select ( ( .EventID == 4624 ) and ( .Details.Type? == 3 ) ) | .Details.TgtUser , " " , .Details.SrcIP , "\n" '`

Novamente, adicionamos a opção `-j` (join) ao `jq` para selecionar múltiplos campos para gerar a saída.
Você pode então executar `sort`, `uniq -c`, etc... como nos exemplos anteriores para descobrir quantas vezes um determinado endereço IP fez logon em um usuário via um logon de rede do tipo 3.

## 4. Salvando a Saída em Formato CSV

Infelizmente, os campos nos registros de eventos do Windows diferem completamente de acordo com o tipo de evento, então não é facilmente possível criar linhas do tempo separadas por vírgula por campos sem ter centenas de colunas.
No entanto, é possível criar linhas do tempo separadas por campos para tipos únicos de eventos.
Dois exemplos comuns são Security `4624` (Logons Bem-sucedidos) e `4625` (Logons Malsucedidos) para verificar movimento lateral e adivinhação/spraying de senhas.

Neste exemplo, estamos extraindo apenas os logs do Security 4624 e gerando o timestamp, o nome do computador e todas as informações de `Details`.
Salvamos em um arquivo CSV usando `| @csv`, porém, precisamos passar os dados como um array.
Podemos fazer isso selecionando os campos que queremos gerar como fizemos anteriormente e envolvendo-os com colchetes `[ ]` para transformá-los em um array.

Exemplo: `cat results.json | jq 'select ( (.Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | @csv ' -r`

Notas:
  * Para selecionar todos os campos do objeto `Details`, adicionamos `[]`.
  * Há casos em que `Details` é uma string e não um array e dará erros `Cannot iterate over string`, então você precisa adicionar um `?`.
  * Adicionamos a opção `-r` (Raw output) ao `jq` para não escapar com barra invertida as aspas duplas.

Resultados:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

Se estivermos apenas verificando quem teve logons bem-sucedidos, talvez não precisemos do último campo `LID` (Logon ID).
Você pode excluir qualquer coluna desnecessária com a função `del`.

Exemplo: `cat results.json | jq 'select ( ( .Channel == "Sec" ) and ( .EventID == 4624 ) ) | [ .Timestamp , .Computer , .Details[]? ] | del( .[6] ) | @csv ' -r`

O array conta a partir de `0`, então para remover o 7º campo, usamos `6`.

Agora você pode salvar o arquivo CSV adicionando `> 4624-logs.csv` e então importá-lo para o Excel ou Timeline Explorer para análise adicional.

Observe que você precisará adicionar um cabeçalho para fazer a filtragem.
Embora seja possível adicionar um cabeçalho dentro da consulta do `jq`, geralmente é mais fácil apenas adicionar manualmente uma linha no topo após salvar o arquivo.

## 5. Encontrando Datas com Mais Alertas

O Hayabusa, por padrão, informará as datas que tiveram mais alertas de acordo com os níveis de severidade.
No entanto, você pode querer encontrar a segunda, terceira, etc... datas com mais alertas também.
Podemos fazer isso fatiando a string do timestamp para agrupar por ano, mês ou data dependendo das suas necessidades.

Exemplo: `cat results.json | jq ' .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

`.[:10]` diz ao `jq` para extrair apenas os primeiros 10 bytes de `Timestamp`.

Isso nos dará as datas com mais eventos:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

Se você quiser saber o mês com mais eventos, você pode apenas mudar `.[:10]` para `.[:7]` para extrair os primeiros 7 bytes.

Se você quiser listar as datas com mais alertas `high`, você pode fazer isso:

`cat results.json | jq 'select ( .Level == "high" ) | .Timestamp | .[:10] ' -r | sort | uniq -c | sort`

Você pode continuar adicionando condições de filtro à função `select` de acordo com o nome do computador, event ID, etc... dependendo das suas necessidades.

## 6. Reconstruindo Logs do PowerShell

Uma coisa infeliz sobre os logs do PowerShell é que os logs frequentemente serão divididos em múltiplos logs, tornando-os difíceis de ler.
Podemos tornar os logs muito mais fáceis de ler extraindo apenas os comandos que o atacante executou.

Por exemplo, se você tiver logs ScriptBlock do EID `4104`, você pode extrair apenas esse campo para criar uma linha do tempo fácil de ler.

`cat results.json | jq 'select ( .EventID == 4104) | .Timestamp[:16] , " " , .Details.ScriptBlock , "\n" ' -jr`

Isso resultará em uma linha do tempo da seguinte forma:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```

## 7. Encontrando Conexões de Rede Suspeitas

Você pode primeiro obter uma lista de todos os endereços IP de destino com o seguinte comando:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq`

Se você tiver threat intelligence, pode verificar se algum dos endereços IP é conhecido por ser malicioso.

Você pode contar quantas vezes um determinado endereço IP de destino foi conectado com o seguinte:

`cat results.json | jq 'select ( .Details.TgtIP? ) | .Details.TgtIP ' -r | sort | uniq -c | sort -n`

Mudando `TgtIP` para `SrcIP`, você pode fazer a mesma verificação de threat intelligence para endereços IP maliciosos com base nos endereços IP de origem.

Digamos que você descobriu que o endereço IP malicioso `93.184.220.29` estava sendo conectado a partir do seu ambiente.
Você pode obter detalhes sobre esses eventos com a seguinte consulta:

`cat results.json | jq 'select ( .Details.TgtIP? == "93.184.220.29" ) '`

Isso lhe dará os resultados JSON como este:
```
{
  "Timestamp": "2019-07-30 06:33:20.711 +09:00",
  "Computer": "MSEDGEWIN10",
  "Channel": "Sysmon",
  "EventID": 3,
  "Level": "med",
  "RecordID": 4908,
  "RuleTitle": "Net Conn (Sysmon Alert)",
  "Details": {
    "Proto": "tcp",
    "SrcIP": "10.0.2.15",
    "SrcPort": 49827,
    "SrcHost": "MSEDGEWIN10.home",
    "TgtIP": "93.184.220.29",
    "TgtPort": 80,
    "TgtHost": "",
    "User": "MSEDGEWIN10\\IEUser",
    "Proc": "C:\\Windows\\System32\\mshta.exe",
    "PID": 3164,
    "PGUID": "747F3D96-661E-5D3F-0000-00107F248700"
  }
}
```

Se você quiser listar os domínios que foram contatados, você pode usar o seguinte comando:

`cat results.json | jq 'select ( .Details.TgtHost ) ? | .Details.TgtHost ' -r | sort | uniq | grep "\."`

> Nota: Adicionei um filtro grep para `.` para remover os nomes de host NETBIOS.

## 8. Extraindo Hashes de Binários Executáveis

Nos logs de Process Creation do Sysmon EID `1`, o sysmon pode ser configurado para calcular hashes do binário.
Os analistas de segurança podem comparar esses hashes com hashes maliciosos conhecidos por meio de threat intelligence.
Você pode extrair o campo `Hashes` com o seguinte:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes ' -r`

Isso lhe dará uma lista de hashes como esta:

```
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
MD5=E112A827FAB9F8378C76040187A6F336,SHA256=ED369187681A62247E38D930320F1CD771756D0B7B67072D8EC655EF99E14AEB,IMPHASH=8EEAA9499666119D13B3F44ECD77A729
```

O Sysmon geralmente calculará múltiplos hashes como `MD5`, `SHA1` e `IMPHASH`.
Você pode extrair esses hashes com expressões regulares no `jq` ou apenas usar o fatiamento de strings para melhor desempenho.

Por exemplo, você pode extrair os hashes MD5 e remover duplicatas com o seguinte:

`cat results.json | jq 'select ( .Details.Hashes? ) | .Details.Hashes | .[4:36] ' -r | sort | uniq`

## 9. Extrair Logs do PowerShell

Os logs Scriptblock do PowerShell (EID: 4104) geralmente são divididos em muitos logs e, ao gerar a saída em formato CSV, o Hayabusa excluirá tabulações e caracteres de retorno para tornar a saída mais concisa.
No entanto, é mais fácil analisar logs do powershell com a formatação original de tabulação e caracteres de retorno e combinando os logs.
Aqui está um exemplo de extração dos logs EID 4104 do PowerShell de `COMPUTER-A` e salvando-os em um arquivo `.ps1` para abrir e analisar no VSCode, etc...
Após extrair o campo ScriptBlock, usamos `awk` para substituir `\r\n` e `\n` por caracteres de retorno e `\t` por tabulações.

```
cat results.json | jq 'select ( .EventID == 4104 and .Details.ScriptBlock? != "n/a"  and .Computer == "COMPUTER-A.domain.local" ) | .Details.ScriptBlock , "\r\n"' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/, "\t"); print; }' | awk '{ gsub(/\\n/, "\r\n"); print; }' > 4104-PowerShell-Logs.ps1
```

Depois que o analista analisa os logs em busca de comandos PowerShell maliciosos, ele geralmente precisará verificar quando esses comandos foram executados.
Aqui está um exemplo de saída do Timestamp e dos logs do PowerShell em um arquivo CSV para verificar a hora em que um comando foi executado:

```
cat results.json | jq ' select (.EventID == 4104 and .Details.ScriptBlock? != "n/a" and .Computer == "COMPUTER-A.domain.local") | .Timestamp, ",¦", .Details.ScriptBlock?, "¦\r\n" ' -j | awk '{ gsub(/\\r\\n/,"\r\n"); print; }' | awk '{ gsub(/\\t/,"\t"); print; }' | awk '{ gsub(/\\n/,"\r\n"); print; }' > 4104-PowerShell-Logs.csv
```

Nota: O delimitador de string usado é `¦` porque aspas simples e duplas são frequentemente encontradas em logs do PowerShell e corromperão a saída CSV.
Ao importar o arquivo CSV, você precisa especificar para o aplicativo o delimitador de string `¦`.
