# Campo de detecção

## Fundamentos da seleção

Primeiro, serão explicados os fundamentos de como criar uma regra de seleção.

### Como escrever lógica AND e OR

Para escrever lógica AND, usamos dicionários aninhados.
A regra de detecção abaixo define que **ambas as condições** precisam ser verdadeiras para que a regra corresponda.

- O EventID precisa ser exatamente `7040`.
- **AND**
- O Channel precisa ser exatamente `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

Para escrever lógica OR, usamos listas (dicionários que começam com `-`).
Na regra de detecção abaixo, **qualquer uma** das condições fará com que a regra seja acionada.

- O EventID precisa ser exatamente `7040`.
- **OR**
- O Channel precisa ser exatamente `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

Também podemos combinar as lógicas `AND` e `OR` como mostrado abaixo.
Neste caso, a regra corresponde quando as duas condições a seguir são ambas verdadeiras.

- O EventID é exatamente `7040` **OR** `7041`.
- **AND**
- O Channel é exatamente `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

O que segue é um trecho de um registro de eventos do Windows, formatado no XML original.
O campo `Event.System.Channel` no exemplo de arquivo de regra acima refere-se à tag XML original: `<Event><System><Channel>System<Channel><System></Event>`
Tags XML aninhadas são substituídas por nomes de tags separados por pontos (`.`).
Nas regras do hayabusa, essas strings de campos conectadas com pontos são chamadas de `eventkeys`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Aliases de Eventkey

Eventkeys longas com muitas separações por `.` são comuns, então o hayabusa usa aliases para torná-las mais fáceis de manipular. Os aliases são definidos no arquivo `rules/config/eventkey_alias.txt`. Esse arquivo é um arquivo CSV composto por mapeamentos de `alias` e `event_key`. Você pode reescrever a regra acima como mostrado abaixo com aliases, tornando a regra mais fácil de ler.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Atenção: Aliases de Eventkey não definidos

Nem todos os aliases de eventkey estão definidos em `rules/config/eventkey_alias.txt`. Se você não está obtendo os dados corretos na mensagem de `details` (`Alert details`) e, em vez disso, está obtendo `n/a` (não disponível), ou se a seleção na sua lógica de detecção não está funcionando corretamente, então talvez você precise atualizar `rules/config/eventkey_alias.txt` com um novo alias.

### Como usar atributos XML em condições

Elementos XML podem ter atributos definidos ao adicionar um espaço ao elemento. Por exemplo, `Name` em `Provider Name` abaixo é um atributo XML do elemento `Provider`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

Para especificar atributos XML em uma eventkey, use o formato `{eventkey}_attributes.{attribute_name}`. Por exemplo, para especificar o atributo `Name` do elemento `Provider` em um arquivo de regra, ficaria assim:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### Busca grep

O Hayabusa pode realizar buscas grep em arquivos de registro de eventos do Windows sem especificar nenhuma eventkey.

Para fazer uma busca grep, especifique a detecção como mostrado abaixo. Neste caso, se as strings `mimikatz` ou `metasploit` estiverem incluídas no registro de eventos do Windows, haverá correspondência. Também é possível especificar curingas.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Nota: O Hayabusa converte internamente os dados do registro de eventos do Windows para o formato JSON antes de processar os dados, portanto não é possível corresponder a tags XML.

### EventData

Os registros de eventos do Windows são divididos em duas partes: a parte `System`, onde os dados fundamentais (Event ID, Timestamp, Record ID, Nome do log (Channel)) são escritos, e a parte `EventData` ou `UserData`, onde dados arbitrários são escritos dependendo do Event ID.
Um problema que surge com frequência é que os nomes dos campos aninhados em `EventData` são todos chamados de `Data`, então as eventkeys descritas até agora não conseguem distinguir entre `SubjectUserSid` e `SubjectUserName`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

Para lidar com esse problema, você pode especificar o valor atribuído em `Data Name`. Por exemplo, se você quiser usar `SubjectUserName` e `SubjectDomainName` no EventData como condição de uma regra, você pode descrevê-la da seguinte forma:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Padrões anormais em EventData

Algumas das tags aninhadas em `EventData` não têm um atributo `Name`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

Para detectar um registro de eventos como o acima, você pode especificar uma eventkey chamada `Data`.
Neste caso, a condição corresponderá desde que qualquer uma das tags `Data` aninhadas seja igual a `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Gerando dados de campo a partir de vários nomes de campo com o mesmo nome

Alguns eventos salvam seus dados em nomes de campo todos chamados `Data`, como no exemplo anterior.
Se você especificar `%Data%` em `details:`, todos os dados serão gerados em um array.

Por exemplo:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

Se você quiser imprimir apenas os dados do primeiro campo `Data`, você pode especificar `%Data[1]%` na sua string de alerta `details:` e apenas `rundll32.exe` será gerado.

## Modificadores de Campo

Um caractere de barra vertical (pipe) pode ser usado com eventkeys, como mostrado abaixo, para corresponder a strings.
Todas as condições que descrevemos até agora usam correspondências exatas, mas, ao usar modificadores de campo, você pode descrever regras de detecção mais flexíveis.
No exemplo a seguir, se um valor de `Data` contiver a string `EngineVersion=2`, ele corresponderá à condição.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

As correspondências de strings não diferenciam maiúsculas de minúsculas. No entanto, elas passam a diferenciar maiúsculas de minúsculas sempre que `|re` ou `|equalsfield` são usados.

### Modificadores de Campo do Sigma Suportados

O Hayabusa é atualmente a única ferramenta de código aberto que oferece suporte total a toda a especificação do Sigma.

Você pode verificar o status atual de todos os modificadores de campo suportados, bem como quantas vezes esses modificadores são usados nas regras do Sigma e do Hayabusa em https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
Este documento é atualizado dinamicamente sempre que há uma atualização nas regras do Sigma ou do Hayabusa.

- `'|all':`: Este modificador de campo é diferente dos acima porque não é aplicado a um determinado campo, mas a todos os campos.

    Neste exemplo, ambas as strings `Keyword-1` e `Keyword-2` precisam existir, mas podem existir em qualquer lugar em qualquer campo:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Os dados serão codificados em base64 de três maneiras diferentes, dependendo de sua posição na string codificada. Este modificador codificará uma string em todas as três variações e verificará se a string está codificada em algum lugar da string base64.
- `|cased`: Faz a busca diferenciar maiúsculas de minúsculas.
- `|cidr`: Verifica se um valor de campo corresponde a uma notação CIDR IPv4 ou IPv6. (Ex: `192.0.2.0/24`)
- `|contains`: Verifica se um valor de campo contém uma determinada string.
- `|contains|all`: Verifica se várias palavras estão contidas nos dados.
- `|contains|all|windash`: Igual a `|contains|windash`, mas todas as palavras-chave precisam estar presentes.
- `|contains|cased`: Verifica se um valor de campo contém uma determinada string que diferencia maiúsculas de minúsculas.
- `|contains|expand`: Verifica se um valor de campo contém uma string no arquivo de configuração `expand` dentro de `/config/expand/`.
- `|contains|windash`: Verificará a string como está, bem como converterá o primeiro caractere `-` em permutações dos caracteres `/`, `–` (en dash), `—` (em dash) e `―` (barra horizontal).
- `|endswith`: Verifica se um valor de campo termina com uma determinada string.
- `|endswith|cased`: Verifica se um valor de campo termina com uma determinada string que diferencia maiúsculas de minúsculas.
- `|endswith|windash`: Verifica o final da string e realiza variações para os traços.
- `|exists`: Verifica se um campo existe.
- `|expand`: Verifica se um valor de campo é igual a uma string no arquivo de configuração `expand` dentro de `/config/expand/`.
- `|fieldref`: Verifica se os valores em dois campos são iguais. Você pode usar `not` na `condition` se quiser verificar se dois campos são diferentes.
- `|fieldref|contains`: Verifica se o valor de um campo está contido em outro campo.
- `|fieldref|endswith`: Verifica se o campo da esquerda termina com a string do campo da direita. Você pode usar `not` na `condition` para verificar se eles são diferentes.
- `|fieldref|startswith`: Verifica se o campo da esquerda começa com a string do campo da direita. Você pode usar `not` na `condition` para verificar se eles são diferentes.
- `|gt`: Verifica se um valor de campo é maior que um determinado número.
- `|gte`: Verifica se um valor de campo é maior ou igual a um determinado número.
- `|lt`: Verifica se um valor de campo é menor que um determinado número.
- `|lte`: Verifica se um valor de campo é menor ou igual a um determinado número.
- `|re`: Usa expressões regulares que diferenciam maiúsculas de minúsculas. (Estamos usando a crate regex, então consulte a documentação em <https://docs.rs/regex/latest/regex/#syntax> para aprender como escrever expressões regulares suportadas.)
    > Atenção: A [sintaxe de expressões regulares nas regras do Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) usa PCRE com certos metacaracteres para classes de caracteres, lookbehind, agrupamento atômico, etc... que não são suportados. A crate regex do Rust deve ser capaz de usar todas as expressões regulares nas regras do Sigma, mas há a possibilidade de incompatibilidade. 
- `|re|i`: (Insensitive) Usa expressões regulares que não diferenciam maiúsculas de minúsculas.
- `|re|m`: (Multi-line) Corresponde em várias linhas. `^` / `$` correspondem ao início/fim da linha.
- `|re|s`: (Single-line) o ponto (`.`) corresponde a todos os caracteres, incluindo o caractere de nova linha.
- `|startswith`: Verifica se um valor de campo começa com uma determinada string.
- `|startswith|cased`: Verifica se um valor de campo começa com uma determinada string que diferencia maiúsculas de minúsculas.
- `|utf16|base64offset|contains`: Verifica se uma determinada string UTF-16 está codificada dentro de uma string base64.
- `|utf16be|base64offset|contains`: Verifica se uma determinada string UTF-16 big-endian está codificada dentro de uma string base64.
- `|utf16le|base64offset|contains`: Verifica se uma determinada string UTF-16 little-endian está codificada dentro de uma string base64.
- `|wide|base64offset|contains`: Alias para `utf16le|base64offset|contains`, verificando strings UTF-16 little-endian.

### Modificadores de Campo Descontinuados

Os modificadores a seguir agora estão descontinuados e foram substituídos por modificadores que aderem mais às especificações do sigma.

- `|equalsfield`: Agora é substituído por `|fieldref`.
- `|endswithfield`: Agora é substituído por `|fieldref|endswith`.

### Modificadores de Campo Expand

Os modificadores de campo `expand` são únicos pois são o único modificador de campo que requer configuração prévia para uso.
Por exemplo, eles usam placeholders como `%DC-MACHINE-NAME%` e exigem um arquivo de configuração chamado `/config/expand/DC-MACHINE-NAME.txt` que contém todos os nomes possíveis de máquinas DC.

Como configurar isso é explicado em mais detalhes [aqui](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## Curingas

Curingas podem ser usados em eventkeys. No exemplo abaixo, se `ProcessCommandLine` começar com a string "malware", a regra corresponderá.
A especificação é fundamentalmente a mesma dos curingas das regras do sigma, então não diferenciará maiúsculas de minúsculas.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

Os dois curingas a seguir podem ser usados.

- `*`: Corresponde a qualquer string de zero ou mais caracteres. (Internamente é convertido para a expressão regular `.*`)
- `?`: Corresponde a qualquer caractere único. (Internamente convertido para a expressão regular `.`)

Sobre o escape de curingas:

- Curingas (`*` e `?`) podem ser escapados usando uma barra invertida: `\*`, `\?`.
- Se você quiser usar uma barra invertida imediatamente antes de um curinga, escreva `\\*` ou `\\?`.
- O escape não é necessário se você estiver usando barras invertidas sozinhas.

## palavra-chave null

A palavra-chave `null` pode ser usada para verificar se um campo não existe.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Nota: Isso é diferente de `ProcessCommandLine: ''`, que verifica se o valor de um campo está vazio.

## condition

Com a notação que explicamos acima, você pode expressar lógica `AND` e `OR`, mas será confuso se você estiver tentando definir lógica complexa.
Quando você quiser criar regras mais complexas, deve usar a palavra-chave `condition` como mostrado abaixo.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

As seguintes expressões podem ser usadas para `condition`.

- `{expression1} and {expression2}`: Requer tanto {expression1} QUANTO {expression2}
- `{expression1} or {expression2}`: Requer {expression1} OU {expression2}
- `not {expression}`: Inverte a lógica de {expression}
- `( {expression} )`: Define a precedência de {expression}. Segue a mesma lógica de precedência da matemática.

No exemplo acima, nomes de seleção como `SELECTION_1`, `SELECTION_2`, etc... são usados, mas eles podem ter qualquer nome desde que contenham apenas os seguintes caracteres: `a-z A-Z 0-9 _`
> No entanto, use a convenção padrão de `selection_1`, `selection_2`, `filter_1`, `filter_2`, etc... para facilitar a leitura sempre que possível.

## lógica not

Muitas regras resultarão em falsos positivos, então é muito comum ter uma seleção para assinaturas a serem buscadas, mas também uma seleção de filtro para não alertar sobre falsos positivos.
Por exemplo:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Correlações do Sigma

Implementamos todas as correlações da versão 2.0.0 do Sigma conforme definido [aqui](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

Correlações suportadas:

- Contagem de Eventos (`event_count`)
- Contagem de Valores (`value_count`)
- Proximidade Temporal (`temporal`)
- Proximidade Temporal Ordenada (`temporal_ordered`)

As novas regras de correlação de "métricas" (`value_sum`, `value_avg`, `value_percentile`) lançadas em 12 de setembro de 2025 na versão 2.1.0 do Sigma atualmente não são suportadas.
